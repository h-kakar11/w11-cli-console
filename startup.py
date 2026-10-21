"""
startup: apps that start with Windows. Routed from app.py ("startup" or "su").

    su ls          list every startup app with its id
    su <id>        show whether one app is enabled
    su <id> on     enable it at sign-in
    su <id> off    disable it at sign-in

Startup apps come from the Run registry keys and the Startup folders, for
this user and for all users. Turning one off or on is the same as the
switch in Task Manager's Startup tab: it changes only the StartupApproved
entry, so nothing is deleted and the change is easy to undo. Changing an
all-users app needs administrator rights.
"""

import datetime
import os
import sys
import winreg

import _core

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "startup"
ALIASES = ["su", "start"]
SUMMARY = "Enable or disable apps that start with Windows"
# extra words people use, for 'settings search'
KEYWORDS = ["boot", "login", "sign-in", "autostart", "slow startup", "run at startup"]
USAGE = "su ls | su <id> | su <id> on|off | su rm <id>   (e.g. su 3 off)"
HELP = [
    ("su ls", "list startup apps with their id and state"),
    ("su <id>", "show whether one app starts with Windows"),
    ("su <id> on|off", "let it start at sign-in, or stop it"),
    ("su rm <id>", "remove it from startup entirely (asks you to confirm first)"),
]
TIP = "on and off change only Windows' switch, so nothing is lost. Changes apply at the next sign-in."
REMOVE_WORDS = ("rm", "remove", "delete", "del")

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
APPROVED_FOLDER_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"

USER_FOLDER = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
ALL_USERS_FOLDER = os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp")

ENABLED_MARKERS = (0x02, 0x06)
DISABLED_MARKER = 0x03


class StartupError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# SOURCES — every startup entry, numbered by name
# ======================================================================
def _read_approval(hive, key_path, value_name):
    """True if enabled. No entry at all means Windows will start it."""
    try:
        with winreg.OpenKey(hive, key_path) as key:
            data, _ = winreg.QueryValueEx(key, value_name)
    except OSError:
        return True
    if not data:
        return True
    return data[0] != DISABLED_MARKER


def _run_entries(hive, scope, approved_hive):
    entries = []
    try:
        with winreg.OpenKey(hive, RUN_KEY) as key:
            index = 0
            while True:
                try:
                    name, command, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                entries.append({
                    "name": name,
                    "scope": scope,
                    "kind": "run",
                    "hive": hive,
                    "approved_hive": approved_hive,
                    "approved_key": APPROVED_RUN_KEY,
                    "approved_name": name,
                    "command": str(command),
                })
    except OSError:
        pass
    return entries


def _folder_entries(folder, scope, approved_hive):
    entries = []
    if not folder or not os.path.isdir(folder):
        return entries
    for file_name in os.listdir(folder):
        if file_name.lower() == "desktop.ini":
            continue
        entries.append({
            "name": os.path.splitext(file_name)[0],
            "scope": scope,
            "kind": "folder",
            "approved_hive": approved_hive,
            "approved_key": APPROVED_FOLDER_KEY,
            "approved_name": file_name,
            "command": os.path.join(folder, file_name),
        })
    return entries


def _entries():
    """Every startup entry, sorted by name, with its id (starting at 1)."""
    found = (
        _run_entries(winreg.HKEY_CURRENT_USER, "user", winreg.HKEY_CURRENT_USER)
        + _run_entries(winreg.HKEY_LOCAL_MACHINE, "all users", winreg.HKEY_LOCAL_MACHINE)
        + _folder_entries(USER_FOLDER, "user", winreg.HKEY_CURRENT_USER)
        + _folder_entries(ALL_USERS_FOLDER, "all users", winreg.HKEY_LOCAL_MACHINE)
    )
    found.sort(key=lambda e: (e["name"].lower(), e["scope"]))
    for index, entry in enumerate(found, start=1):
        entry["id"] = index
        entry["enabled"] = _read_approval(entry["approved_hive"], entry["approved_key"], entry["approved_name"])
    return found


def _get_entry(entry_id):
    for entry in _entries():
        if entry["id"] == entry_id:
            return entry
    raise StartupError(f"no startup app with id {entry_id}. Run 'su ls' to see them.", 2)


# ======================================================================
# ENABLE / DISABLE — writes the StartupApproved value Task Manager uses
# ======================================================================
def _set_enabled(entry, enabled):
    if enabled:
        data = bytes([ENABLED_MARKERS[0]]) + bytes(11)
    else:
        # the marker, then the time it was disabled as a Windows FILETIME
        now = datetime.datetime.now(datetime.timezone.utc)
        ticks = int((now - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds() * 10_000_000)
        data = bytes([DISABLED_MARKER]) + bytes(3) + ticks.to_bytes(8, "little")
    try:
        with winreg.CreateKeyEx(entry["approved_hive"], entry["approved_key"], 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, entry["approved_name"], 0, winreg.REG_BINARY, data)
    except PermissionError:
        raise StartupError(
            f"changing {entry['name']} needs administrator rights. Run the terminal as administrator.", 1
        )


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "startup"/"su"
# ======================================================================
def _state(entry):
    return "enabled" if entry["enabled"] else "disabled"


def _list(options):
    entries = _entries()
    if options["json"]:
        _core.print_json([_brief(e) for e in entries])
        return
    if not entries:
        print("(no startup apps found)")
        return
    print(f"{'ID':<4}{'NAME':<34}{'STATE':<10}SCOPE")
    for entry in entries:
        print(f"{entry['id']:<4}{entry['name'][:32]:<34}{_state(entry):<10}{entry['scope']}")


def _brief(entry):
    return {"id": entry["id"], "name": entry["name"], "enabled": entry["enabled"], "scope": entry["scope"]}


def _show(entry, options):
    if options["json"]:
        _core.print_json(_brief(entry))
    else:
        print(f"{entry['name']}: {_state(entry)}")

def _remove(entry):
    """Deletes the startup entry itself: its Run value, or its shortcut in the Startup folder."""
    try:
        if entry["kind"] == "run":
            with winreg.OpenKey(entry["hive"], RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, entry["name"])
        else:
            os.remove(entry["command"])
    except PermissionError:
        raise StartupError(
            f"removing {entry['name']} needs administrator rights. Run the terminal as administrator.", 1
        )
    except FileNotFoundError:
        raise StartupError(f"{entry['name']} is already gone", 1)


def _remove_command(args, options):
    if len(args) != 2:
        raise StartupError("usage: su rm <id>", 2)
    try:
        entry_id = int(args[1])
    except ValueError:
        raise StartupError("su rm needs an id from 'su ls'", 2)

    entry = _get_entry(entry_id)
    if not _core.confirm(
        f"Remove {entry['name']} from startup? It won't start with Windows again, "
        "and the app stays installed. This can't be undone. [y/N]: ",
        options["yes"],
    ):
        print("cancelled")
        return

    print(f"removing {entry['name']} from startup... expect it to vanish from 'su ls' at once.")
    _remove(entry)
    print(f"removed {entry['name']} from startup")


def _dispatch(args, options):
    if args[0].lower() in ("ls", "list"):
        if len(args) > 1:
            raise StartupError("usage: su ls", 2)
        _list(options)
        return

    if args[0].lower() in REMOVE_WORDS:
        _remove_command(args, options)
        return

    try:
        entry_id = int(args[0])
    except ValueError:
        raise StartupError(f"unknown startup command: {args[0]}\nusage: su {USAGE}", 2)

    entry = _get_entry(entry_id)

    if len(args) == 1:
        _show(entry, options)
        return

    word = args[1].lower()
    if word in ("on", "enable"):
        enabled = True
    elif word in ("off", "disable"):
        enabled = False
    else:
        raise StartupError("use on or off, e.g. su 3 off", 2)

    _set_enabled(entry, enabled)
    _show(_get_entry(entry_id), options)  # read back, so it shows what Windows has

def run(args):
    """Run one startup command; returns an exit code."""
    args, options = _core.split_flags(args)
    if not args:
        print(f"usage: su {USAGE}")
        return 0
    if args[0].lower() in ("help", "-h", "--help", "?"):
        print(f"usage: su {USAGE}")
        return 0
    try:
        _dispatch(args, options)
        return 0
    except StartupError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

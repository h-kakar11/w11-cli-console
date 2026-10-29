"""
startup: apps that start with Windows. Routed from app.py ("startup" or "su").

    su ls          list every startup app with its id
    su <id>        show whether one app is enabled
    su <id> on     enable it at sign-in
    su <id> off    disable it at sign-in
    su rm <id>     remove it from startup (the undo puts it back)

Startup apps come from the Run registry keys and the Startup folders, for
this user and for all users. Turning one off or on is the same as the
switch in Task Manager's Startup tab: it changes only the StartupApproved
entry, so nothing is deleted and the change is easy to undo. Changing an
all-users app needs administrator rights.

Every entry has a stable key (user/run/OneDrive, machine/run/Teams, user/folder/App.lnk) next to its
id. Ids follow the sorted list and shift; keys and plain names do not: su OneDrive off. A name that
matches more than one entry is refused, never guessed. Add --dry-run to see the exact change, and
--json --yes for a script. The old state is saved first and 'rb last' puts it back; 'cs' can batch
these changes (operations: enable, disable, remove).
"""

import base64
import datetime
import os
import sys
import types
import winreg

import _core
import _ops

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "startup"
ALIASES = ["su", "start"]
SUMMARY = "Enable or disable apps that start with Windows"
# extra words people use, for 'settings search'
KEYWORDS = ["boot", "login", "sign-in", "autostart", "slow startup", "run at startup"]
USAGE = "su ls | su <id|name> | su <id|name> on|off | su rm <id|name>   (e.g. su OneDrive off)"
HELP = [
    ("su ls", "list startup apps with their id and state"),
    ("su <id>", "show whether one app starts with Windows"),
    ("su <id> on|off", "let it start at sign-in, or stop it"),
    ("su rm <id>", "remove it from startup entirely (asks you to confirm first; 'rb last' puts it back)"),
]
TIP = ("on and off change only Windows' switch, so nothing is lost. Changes apply at the next sign-in. "
       "Ids shift: a name or key (su OneDrive off) always means the same app.")
DRY_RUN = True  # the changes take --dry-run, and every one is saved to the journal for 'rb'
MAX_FILE = 1_000_000  # the biggest startup shortcut a removal will save for its undo
REMOVE_WORDS = ("rm", "remove", "delete", "del")

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
APPROVED_FOLDER_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"

USER_FOLDER = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
ALL_USERS_FOLDER = os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp")

ENABLED_MARKERS = (0x02, 0x06)
DISABLED_MARKER = 0x03


class StartupError(_core.CommandError):
    """An error with an exit code: 1 for system errors, 2 for bad usage; error is the machine-readable code."""

    def __init__(self, message, code=1, error=None):
        super().__init__(message, code, error)


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


def _key(entry):
    """A name for the entry that does not move: scope/kind/name, e.g. user/run/OneDrive."""
    where = "user" if entry["scope"] == "user" else "machine"
    return f"{where}/{entry['kind']}/{entry['approved_name'] if entry['kind'] == 'folder' else entry['name']}"


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
        entry["key"] = _key(entry)
        entry["enabled"] = _read_approval(entry["approved_hive"], entry["approved_key"], entry["approved_name"])
    return found


def _get_entry(word):
    """The entry an id, a key or a name points at; a name that fits two entries is an error, never a guess."""
    return _core.resolve(_entries(), str(word), "startup app", "su ls", keys=("key", "name"))


# ======================================================================
# CHANGES — enable, disable and remove, through the shared engine (_ops): planned, confirmed, the old state
# saved to the journal, applied, read back. 'su ...' and 'cs' run the same code.
# ======================================================================
def _approval_bytes(entry):
    """The raw StartupApproved value, or None when there is none."""
    try:
        with winreg.OpenKey(entry["approved_hive"], entry["approved_key"]) as key:
            return bytes(winreg.QueryValueEx(key, entry["approved_name"])[0])
    except OSError:
        return None


def _write_approval(entry, data):
    """Write the StartupApproved value, or delete it when data is None (it did not exist before)."""
    if data is None:
        try:
            with winreg.OpenKey(entry["approved_hive"], entry["approved_key"], 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, entry["approved_name"])
        except FileNotFoundError:
            pass
        return
    with winreg.CreateKeyEx(entry["approved_hive"], entry["approved_key"], 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, entry["approved_name"], 0, winreg.REG_BINARY, data)


def _approval_for(enabled):
    if enabled:
        return bytes([ENABLED_MARKERS[0]]) + bytes(11)
    # the marker, then the time it was disabled as a Windows FILETIME
    now = datetime.datetime.now(datetime.timezone.utc)
    ticks = int((now - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds() * 10_000_000)
    return bytes([DISABLED_MARKER]) + bytes(3) + ticks.to_bytes(8, "little")


def _param(name, required, text):
    return {"name": name, "required": required, "help": text}


def _app(params):
    word = params.get("app")
    if not isinstance(word, str) or not word.strip():
        raise StartupError("app must be a name or key from 'su ls' (an id works too, but ids shift)", 2, "usage")
    return _get_entry(word.strip())


def _target(entry):
    return entry["key"]


def _plan_switch(enabled):
    def plan(params):
        entry = _app(params)
        approval = _approval_bytes(entry)
        before = entry["enabled"]
        all_users = entry["scope"] != "user"
        return {
            "target": _target(entry), "before": {"enabled": before}, "after": {"enabled": enabled},
            "noop": before == enabled, "needs_admin": all_users, "restart": "signout", "disrupts": None,
            "summary": f"{'enable' if enabled else 'disable'} {entry['name']} at sign-in "
                       f"({entry['scope']}): {'enabled' if before else 'disabled'} -> {'enabled' if enabled else 'disabled'}",
            "confirm": None, "name": entry["name"], "scope": entry["scope"],
            "approval_before": approval.hex() if approval is not None else None,
        }
    return plan


def _entry_of(plan):
    return _core.resolve(_entries(), plan["target"], "startup app", "su ls", keys=("key",))


def _apply_switch(plan):
    _write_approval(_entry_of(plan), _approval_for(plan["after"]["enabled"]))


def _read_switch(plan):
    return {"enabled": _entry_of(plan)["enabled"]}


def _restore_switch(plan):
    saved = plan["approval_before"]
    _write_approval(_entry_of(plan), bytes.fromhex(saved) if saved is not None else None)


def _plan_remove(params):
    entry = _app(params)
    if entry["kind"] == "run":
        with winreg.OpenKey(entry["hive"], RUN_KEY) as key:
            data, kind = winreg.QueryValueEx(key, entry["name"])
        binary = isinstance(data, bytes)
        saved = {"kind": "run", "value_type": kind, "value": data.hex() if binary else data, "binary": binary}
    else:
        try:
            size = os.path.getsize(entry["command"])
            if size > MAX_FILE:
                raise StartupError(f"{entry['name']} is {size} bytes, too big to save for an undo, so it is not removed.", 1, "too_large")
            with open(entry["command"], "rb") as handle:
                saved = {"kind": "folder", "path": entry["command"], "file": base64.b64encode(handle.read()).decode()}
        except FileNotFoundError:
            raise StartupError(f"{entry['name']} is already gone", 1, "not_found")
    return {
        "target": _target(entry), "before": {"exists": True}, "after": {"exists": False}, "noop": False,
        "needs_admin": entry["scope"] != "user", "restart": "signout", "disrupts": None,
        "summary": f"remove {entry['name']} ({entry['scope']}) from startup; the app itself stays installed",
        "confirm": (f"Remove {entry['name']} from startup? It won't start with Windows again, and the app stays installed. "
                    "Undo with 'rb last'. [y/N]: "),
        "name": entry["name"], "scope": entry["scope"], "saved": saved,
        "hive": "user" if entry["scope"] == "user" else "machine",
    }


def _find_for_remove(plan):
    """The entry as it was found at plan time, rebuilt from the plan so it does not depend on the list."""
    saved = plan["saved"]
    hive = winreg.HKEY_CURRENT_USER if plan["hive"] == "user" else winreg.HKEY_LOCAL_MACHINE
    return saved, hive


def _apply_remove(plan):
    saved, hive = _find_for_remove(plan)
    try:
        if saved["kind"] == "run":
            with winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, plan["name"])
        else:
            os.remove(saved["path"])
    except FileNotFoundError:
        raise StartupError(f"{plan['name']} is already gone", 1, "not_found")


def _read_remove(plan):
    saved, hive = _find_for_remove(plan)
    if saved["kind"] == "run":
        try:
            with winreg.OpenKey(hive, RUN_KEY) as key:
                winreg.QueryValueEx(key, plan["name"])
            return {"exists": True}
        except OSError:
            return {"exists": False}
    return {"exists": os.path.exists(saved["path"])}


def _restore_remove(plan):
    saved, hive = _find_for_remove(plan)
    if saved["kind"] == "run":
        with winreg.CreateKeyEx(hive, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            value = bytes.fromhex(saved["value"]) if saved.get("binary") else saved["value"]
            winreg.SetValueEx(key, plan["name"], 0, saved["value_type"], value)
    else:
        with open(saved["path"], "wb") as handle:
            handle.write(base64.b64decode(saved["file"]))


_SIGNOUT = "Takes effect at the next sign-in; nothing is started or stopped now."
OPERATIONS = {
    "enable": {
        "summary": "let a startup app run at sign-in (the switch Task Manager's Startup tab uses)",
        "params": [_param("app", True, "the app's name or key from 'su ls' (user/run/OneDrive); an id also works but shifts")],
        "changes_system": True, "needs_admin": "depends", "restart": "signout",
        "side_effects": "All-users apps need administrator. " + _SIGNOUT,
        "plan": _plan_switch(True), "apply": _apply_switch, "read": _read_switch, "restore": _restore_switch,
    },
    "disable": {
        "summary": "stop a startup app from running at sign-in (nothing is deleted)",
        "params": [_param("app", True, "the app's name or key from 'su ls' (user/run/OneDrive); an id also works but shifts")],
        "changes_system": True, "needs_admin": "depends", "restart": "signout",
        "side_effects": "All-users apps need administrator. " + _SIGNOUT,
        "plan": _plan_switch(False), "apply": _apply_switch, "read": _read_switch, "restore": _restore_switch,
    },
    "remove": {
        "summary": "delete a startup entry (its Run value or its Startup-folder shortcut; saved for the undo)",
        "params": [_param("app", True, "the app's name or key from 'su ls'; an id also works but shifts")],
        "changes_system": True, "needs_admin": "depends", "restart": "signout",
        "side_effects": "The app stays installed but no longer starts with Windows. All-users apps need administrator. " + _SIGNOUT,
        "plan": _plan_remove, "apply": _apply_remove, "read": _read_remove, "restore": _restore_remove,
    },
}
_SELF = types.SimpleNamespace(NAME=NAME, OPERATIONS=OPERATIONS)


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
    print(f"{'ID':<4}{'NAME':<34}{'STATE':<10}KEY")
    for entry in entries:
        print(f"{entry['id']:<4}{entry['name'][:32]:<34}{_state(entry):<10}{entry['key']}")


def _brief(entry):
    return {"id": entry["id"], "key": entry["key"], "name": entry["name"], "enabled": entry["enabled"], "scope": entry["scope"]}


def _show(entry, options):
    if options["json"]:
        _core.print_json(_brief(entry))
    else:
        print(f"{entry['name']}: {_state(entry)}")


def _remove_command(args, options):
    if len(args) != 2:
        raise StartupError("usage: su rm <id|name>", 2, "usage")
    return _ops.execute([{"module": _SELF, "op": "remove", "params": {"app": args[1]}}], options)


def _dispatch(args, options):
    word = args[0].lower()
    if options["dry_run"] and word in ("ls", "list"):
        raise StartupError("su ls changes nothing, so --dry-run does nothing", 2, "usage")
    if word in ("ls", "list"):
        if len(args) > 1:
            raise StartupError("usage: su ls", 2, "usage")
        _list(options)
        return 0

    if word in REMOVE_WORDS:
        return _remove_command(args, options)

    if len(args) == 1:
        if options["dry_run"]:
            raise StartupError("showing an app changes nothing, so --dry-run does nothing", 2, "usage")
        _show(_get_entry(args[0]), options)
        return 0

    switch = args[1].lower()
    if len(args) != 2 or switch not in ("on", "enable", "off", "disable"):
        raise StartupError("use on or off, e.g. su OneDrive off", 2, "usage")
    op = "enable" if switch in ("on", "enable") else "disable"
    return _ops.execute([{"module": _SELF, "op": op, "params": {"app": args[0]}}], options)


def run(args):
    """Run one startup command; returns an exit code."""
    args, options = _core.split_flags(args, _core.DRY_FLAGS)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: su {USAGE}")
        return 0
    try:
        return _dispatch(args, options)
    except _core.CommandError as e:
        return _core.report_error(e)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

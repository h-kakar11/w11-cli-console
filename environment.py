"""
environment: environment variables and the PATH, the same as Settings > System > About > Advanced system settings >
Environment Variables, with a backup before every change. Routed from app.py ("environment", "env" or "vars").

    env ls [user|system|all] [search <text>]    every variable, numbered: yours (user) and the PC's (system)
    env <name|id>                               one variable in full; PATH-style lists are shown one entry per line
    env set <NAME> <value> [--system]           set a variable (yours; --system is for every user: administrator)
    env rm <NAME|id> [--system]                 delete a variable (asks first)
    env path [user|system|all]                  the PATH entries in order, with missing folders and duplicates flagged
    env path add <folder> [--front] [--system]  add a folder to the PATH
    env path rm <n|folder> [--system]           remove an entry (asks first)
    env path move <n> up|down|top|bottom [--system]
    env path clean [--system]                   remove empty, missing and duplicate entries (shows them, asks first)
    env where <name>                            which scope wins, and what a new program gets
    env find <text>                             names, values and PATH entries that contain the text
    env expand <text>                           expand %VARIABLES% the way a new program would
    env backup [--system]                       save a backup now
    env backups [rm <n|all>]                    the saved backups, newest first
    env undo [n] [--system]                     put a backup back (the newest one for that scope, or backup n)
    env diff [n] [--system]                     what differs between now and a backup
    env export <file> [--system]                save the variables as JSON
    env import <file> [--system]                set variables from a JSON file (shows the difference, asks first)

Variables live in the registry: yours in HKCU\\Environment, the PC's in HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session
Manager\\Environment. A new program gets the system variables, then yours; a variable in both takes your value, except
PATH, where your entries come after the system's. Windows tells running programs about a change with a broadcast
(WM_SETTINGCHANGE "Environment"); a terminal that was already open keeps the copy it started with, so open a new one.
setx is not used: it cuts values at 1,024 characters and turns expandable values into plain text.

Reading needs no administrator rights. Changing a system variable does, and the page checks that before it asks
anything. Every change first saves the whole scope to a JSON file (in %LOCALAPPDATA%\\w11-cli-console\\env-backups), so
`env undo` can put it back.
"""

import contextlib
import ctypes
import json
import os
import re
import shutil
import sys
import winreg
from ctypes import wintypes
from datetime import datetime

import _core
import _net
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "environment"
ALIASES = ["env", "vars"]
SUMMARY = "Environment variables and PATH, with backup and undo"
# extra words people use, for 'settings search'
KEYWORDS = ["variables", "path", "env", "setx", "java_home", "system variables", "user variables"]
USAGE = ("env ls | env <name|id> | env set <NAME> <value> [--system] | env rm <NAME|id> | env path [add|rm|move|clean] | "
         "env where <name> | env find <text> | env expand <text> | env backups | env undo | env diff")
HELP = [
    ("env ls", "your variables and the PC's, numbered"),
    ("env <name|id>", "one variable in full; PATH-style lists one entry per line"),
    ("env set <NAME> <value>", "set a variable for you; add --system for everyone (administrator)"),
    ("env path", "the PATH entries in order, flagging missing folders and duplicates"),
    ("env path add <folder>", "add a folder to your PATH (--front puts it first)"),
    ("env undo", "put back what the last change replaced"),
    ("", "more"),
    ("env rm <NAME|id>", "delete a variable (asks first)"),
    ("env path rm <n|folder>", "remove a PATH entry (asks first)"),
    ("env path move <n> up|down|top|bottom", "change which folder is searched first"),
    ("env path clean", "remove empty, missing and duplicate PATH entries (shows them, asks first)"),
    ("env where <name>", "which scope wins, and what a new program gets"),
    ("env find <text>", "search names, values and PATH entries"),
    ("env expand <text>", "expand %VARIABLES% the way a new program would"),
    ("", "backups (every change saves one first)"),
    ("env backup", "save a backup now"),
    ("env backups", "the saved backups, newest first (env backups rm <n|all> deletes)"),
    ("env diff [n]", "what differs between now and a backup"),
    ("env export <file> | env import <file>", "save the variables as JSON, or set them from a file"),
]
TIP = ("Changes reach new terminals only: open a new one. In this console put paths in quotes, e.g. "
       'env path add "C:\\Tools", or the backslashes are lost.')

# ======================================================================
# CONSTANTS
# ======================================================================
SCOPES = {
    "user": (_win.HKCU, r"Environment"),
    "system": (_win.HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
}
SCOPE_WORDS = ("user", "system", "all")
SCOPE_TEXT = {"user": "your", "system": "the system"}
FLAGS = ("--json", "--yes", "--system", "--user", "--front")
LIST_WORDS = _net.LIST_WORDS
REMOVE_WORDS = _net.REMOVE_WORDS
TEXT_KINDS = (winreg.REG_SZ, winreg.REG_EXPAND_SZ)
KIND_WORDS = {winreg.REG_SZ: "text", winreg.REG_EXPAND_SZ: "expandable"}
KIND_NAMES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 7: "REG_MULTI_SZ",
              11: "REG_QWORD"}
MAX_VALUE = 32767  # the most characters Windows allows in one variable
LEGACY_LIMIT = 2047  # some older programs cut a value at this length
MAX_NAME = 255
MOVES = ("up", "down", "top", "bottom")
# Lists of folders (they get exists / missing flags) and lists of file extensions
FOLDER_LISTS = ("path", "psmodulepath", "lib", "libpath", "include", "classpath", "pythonpath", "node_path")
EXTENSION_LISTS = ("pathext",)
PATH_SHAPED = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|%)")  # C:\..., \\server\..., %VAR%...
LOST_SLASHES = re.compile(r"^[A-Za-z]:[^\\/]")  # C:Tools: what "C:\Tools" becomes when the console eats the backslash
VARIABLE = re.compile(r"%([^%]+)%")
# Names Windows or programs rely on. Changing or deleting one asks for the name to be typed, and --yes does not answer.
# The predefined ones are listed because a variable of the same name in the user scope would replace Windows' own.
PROTECTED = {
    "path", "pathext", "comspec", "windir", "systemroot", "systemdrive", "os", "username", "userprofile",
    "userdomain", "userdomain_roamingprofile", "computername", "logonserver", "sessionname", "appdata", "localappdata",
    "homedrive", "homepath", "homeshare", "allusersprofile", "programdata", "public", "programfiles",
    "programfiles(x86)", "programw6432", "commonprogramfiles", "commonprogramfiles(x86)", "commonprogramw6432",
    "driverdata", "number_of_processors", "psmodulepath",
}
PROTECTED_PREFIXES = ("processor_",)
TEMP_NAMES = ("temp", "tmp")  # may be changed (with a check that the folder exists) but not deleted lightly
BACKUP_DIR = "env-backups"
HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG, BROADCAST_TIMEOUT = 0xFFFF, 0x1A, 0x2, 5000
GREEN, GREY, RED, YELLOW, RESET = _net.GREEN, _net.GREY, _net.RED, _net.YELLOW, _net.RESET
NEW_TERMINAL = "Terminals and programs that are already open keep their old copy: open a new one to see the change."


class EnvError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# READING — the two Environment keys, and what a new program would get from them
# ======================================================================
def _read_scope(scope):
    """{name: (value, kind)} as saved in the registry for one scope."""
    hive, path = SCOPES[scope]
    return _win.reg_values(hive, path)


def _text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return ";".join(str(item) for item in value)
    return str(value)


def _existing(values, name):
    """(spelling, value, kind) for a name in {name: (value, kind)}, ignoring case; None if it is not there."""
    lowered = name.lower()
    for spelling, (value, kind) in values.items():
        if spelling.lower() == lowered:
            return spelling, value, kind
    return None


def _process_env():
    """This terminal's own variables, with upper-case names so that lookups ignore case."""
    return {name.upper(): value for name, value in os.environ.items()}


def _expand(text, table):
    """The text with %NAME% filled in from the table (upper-case names); (expanded, [names it could not find]).
    Names that are not found stay as written, the way Windows leaves them."""
    unknown = []

    def replace(match):
        found = table.get(match.group(1).upper())
        if found is None:
            unknown.append(match.group(1))
            return match.group(0)
        return found

    return VARIABLE.sub(replace, text), unknown


def _lookup():
    """The variables a new program would start with: this terminal's, with the saved system ones laid over them, then
    the saved user ones. PATH is the exception: the user entries go after the system ones."""
    table = _process_env()
    system_path = None
    for scope in ("system", "user"):
        for name, (value, kind) in _read_scope(scope).items():
            if kind not in TEXT_KINDS:
                continue  # Windows ignores values that are not text
            text = _text(value)
            if kind == winreg.REG_EXPAND_SZ:
                text = _expand(text, table)[0]
            key = name.upper()
            if key == "PATH":
                if scope == "system":
                    system_path = text
                elif system_path is not None:
                    text = system_path.rstrip(";") + ";" + text
            table[key] = text
    return table


def _kind_word(kind):
    return KIND_WORDS.get(kind, "other")


def _split(text):
    """The entries of a ';'-separated list, empty ones included; a ';' inside double quotes does not split."""
    if text == "":
        return []
    entries, current, quoted = [], [], False
    for char in text:
        if char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            entries.append("".join(current))
            current = []
        else:
            current.append(char)
    entries.append("".join(current))
    if len(entries) > 1 and entries[-1] == "":
        entries.pop()  # a PATH ending in ';' is normal, and not an empty entry
    return entries


def _list_kind(name, text):
    """'folders' or 'extensions' for a list-like variable, None for an ordinary one."""
    lowered = name.lower()
    if lowered in EXTENSION_LISTS:
        return "extensions"
    if lowered in FOLDER_LISTS:
        return "folders"
    parts = [part.strip().strip('"') for part in _split(text) if part.strip()]
    if len(parts) >= 2 and all(PATH_SHAPED.match(part) for part in parts):
        return "folders"
    return None


def _variables():
    """Every saved variable of both scopes, yours first when a name is in both, sorted by name and numbered from 1.
    The list and the ids both come from here, so they always agree."""
    table = _lookup()
    rows = []
    for scope in SCOPES:
        for name, (value, kind) in _read_scope(scope).items():
            text = _text(value)
            expanded = _expand(text, table)[0] if kind == winreg.REG_EXPAND_SZ else text
            listed = _list_kind(name, text) if kind in TEXT_KINDS else None
            rows.append({"name": name, "scope": scope, "kind": kind, "type": _kind_word(kind), "value": text,
                         "expanded": expanded, "list": listed is not None,
                         "entries": len(_split(text)) if listed else None})
    rows.sort(key=lambda row: (row["name"].lower(), row["scope"] != "user"))
    for number, row in enumerate(rows, start=1):
        row["id"] = number
    return rows


def _public(row):
    return {key: row[key] for key in ("id", "name", "scope", "type", "value", "expanded", "list", "entries")}


def _protected(name):
    lowered = name.lower()
    return lowered in PROTECTED or lowered.startswith(PROTECTED_PREFIXES)


# ======================================================================
# PATH-STYLE LISTS — splitting, comparing and checking entries
# ======================================================================
def _normalise(text):
    """A folder as a key for comparing: forward slashes become backslashes, repeats and a trailing backslash go,
    and case is ignored. (A drive root keeps its backslash.)"""
    text = text.strip().strip('"').replace("/", "\\")
    unc = text.startswith("\\\\")
    text = re.sub(r"\\{2,}", r"\\", text)
    if unc:
        text = "\\" + text
    if len(text) > 3 and text.endswith("\\"):
        text = text.rstrip("\\")
    return text.casefold()


def _is_dir(path):
    try:
        return os.path.isdir(path)
    except (OSError, ValueError):
        return False


def _analyse(raw_entries, table, others=frozenset(), others_name="system PATH"):
    """Each entry of a folder list with its checks. `others` holds the keys of entries that come earlier in the order
    (the system PATH, for the user PATH), so a repeat of one of those is flagged too."""
    seen, results = set(), []
    for number, raw in enumerate(raw_entries, start=1):
        text = raw.strip().strip('"')
        item = {"n": number, "entry": raw, "expanded": None, "exists": None, "problem": None, "key": ""}
        if not text:
            item["problem"] = "empty entry"
        else:
            expanded, unknown = _expand(text, table)
            item["expanded"] = expanded
            item["key"] = _normalise(expanded)
            item["exists"] = False if unknown else _is_dir(expanded)
            if unknown:
                item["problem"] = f"unknown variable %{unknown[0]}%"
            elif item["key"] in others:
                item["problem"] = f"also in the {others_name}"
            elif item["key"] in seen:
                item["problem"] = "duplicate"
            elif not item["exists"]:
                item["problem"] = "folder does not exist"
            seen.add(item["key"])
        results.append(item)
    return results


def _path_state(table):
    """Both PATHs, analysed: {"system": {...}, "user": {...}}. The user entries are checked against the system ones."""
    state, system_keys = {}, frozenset()
    for scope in ("system", "user"):
        found = _existing(_read_scope(scope), "Path")
        text = _text(found[1]) if found and found[2] in TEXT_KINDS else ""
        entries = _analyse(_split(text), table, system_keys if scope == "user" else frozenset())
        if scope == "system":
            system_keys = frozenset(item["key"] for item in entries if item["key"])
        state[scope] = {"scope": scope, "present": found is not None, "name": found[0] if found else "Path",
                        "kind": found[2] if found else None, "raw": text, "entries": entries}
    return state


def _path_public(scope_state):
    return {"present": scope_state["present"], "type": _kind_word(scope_state["kind"]) if scope_state["kind"] else None,
            "entries": [{"n": item["n"], "entry": item["entry"], "expanded": item["expanded"],
                         "exists": item["exists"], "problem": item["problem"]} for item in scope_state["entries"]]}


def _entry_diff(was, now):
    """Entries added and removed going from one list value to another (order changes do not count)."""
    old = [entry.strip().strip('"') for entry in _split(was) if entry.strip()]
    new = [entry.strip().strip('"') for entry in _split(now) if entry.strip()]
    old_keys, new_keys = {entry.casefold() for entry in old}, {entry.casefold() for entry in new}
    return {"added": [entry for entry in new if entry.casefold() not in old_keys],
            "removed": [entry for entry in old if entry.casefold() not in new_keys]}


# ======================================================================
# CHANGES — one description of "what changes", shared by set, rm, path, undo and import
# ======================================================================
def _change(name, was, was_kind, now, now_kind):
    """One variable going from `was` to `now` (None for missing). Internal keys start with '_'."""
    kind = "added" if was is None else "removed" if now is None else "changed"
    entries = None
    if was is not None and now is not None and _list_kind(name, _text(now)):
        entries = _entry_diff(_text(was), _text(now))
    return {"name": name, "change": kind, "was": None if was is None else _text(was),
            "now": None if now is None else _text(now),
            "was_type": None if was is None else _kind_word(was_kind),
            "now_type": None if now is None else _kind_word(now_kind), "entries": entries,
            "_value": now, "_was_kind": was_kind, "_now_kind": now_kind}


def _compare(old, new):
    """What it takes to turn the variables in `old` into those in `new` (both {name: (value, kind)}, names compared
    ignoring case): a list of changes sorted by name."""
    old_by = {name.lower(): (name, value, kind) for name, (value, kind) in old.items()}
    new_by = {name.lower(): (name, value, kind) for name, (value, kind) in new.items()}
    changes = []
    for key in sorted(set(old_by) | set(new_by)):
        was, now = old_by.get(key), new_by.get(key)
        if was and now:
            if (was[1], was[2]) != (now[1], now[2]):
                changes.append(_change(was[0], was[1], was[2], now[1], now[2]))
        elif now:
            changes.append(_change(now[0], None, None, now[1], now[2]))
        else:
            changes.append(_change(was[0], was[1], was[2], None, None))
    return changes


def _cut(text, width):
    text = str(text).replace("\r", " ").replace("\n", " ")
    return text if len(text) <= width else text[:max(1, width - 3)] + "..."


def _change_lines(changes):
    """The changes as coloured text lines: + added, - removed, ~ changed (list values show their entries)."""
    lines = []
    for change in changes:
        name = change["name"]
        if change["change"] == "added":
            lines.append(GREEN + f"  + {name} = {_cut(change['now'], 90)}" + RESET)
        elif change["change"] == "removed":
            lines.append(RED + f"  - {name} (was {_cut(change['was'], 90)})" + RESET)
        elif change["entries"] is not None:
            diff = change["entries"]
            lines.append(YELLOW + f"  ~ {name}" + ("" if diff["added"] or diff["removed"] else " (the order changed)")
                         + RESET)
            lines += [GREEN + f"      + {entry}" + RESET for entry in diff["added"]]
            lines += [RED + f"      - {entry}" + RESET for entry in diff["removed"]]
        else:
            lines.append(YELLOW + f"  ~ {name}: {_cut(change['was'], 60)}  ->  {_cut(change['now'], 60)}" + RESET)
    return lines


def _public_change(change):
    return _net.public(change)


def _result(action, scope, changes, backup=None, notified=None, **extra):
    """What a change command reports with --json: the same keys every time."""
    return {"action": action, "scope": scope, "changed": bool(changes),
            "changes": [_public_change(change) for change in changes],
            "backup": str(backup) if backup else None, "notified": notified, **extra}


# ======================================================================
# BACKUPS — the whole scope, saved as JSON before every change
# ======================================================================
def _is_number(word):
    """Plain digits 0-9 only: str.isdigit() also accepts characters such as '²' that int() cannot read."""
    return re.fullmatch(r"[0-9]+", word) is not None


def _pack(value, kind):
    entry = {"kind": kind, "type": KIND_NAMES.get(kind, f"type {kind}")}
    if isinstance(value, (bytes, bytearray)):
        entry["hex"] = bytes(value).hex()
    else:
        entry["value"] = value
    return entry


def _unpack(entry):
    """(value, kind) from a saved entry, or None if it cannot be read."""
    if not isinstance(entry, dict) or not isinstance(entry.get("kind"), int):
        return None
    if "hex" in entry:
        try:
            return bytes.fromhex(entry["hex"]), entry["kind"]
        except (TypeError, ValueError):
            return None
    value = entry.get("value")
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return value, entry["kind"]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value, entry["kind"]  # REG_MULTI_SZ
    return None


def _snapshot(scope, reason):
    return {"tool": "w11-cli-console", "saved": datetime.now().isoformat(timespec="microseconds"), "scope": scope,
            "reason": reason, "computer": os.environ.get("COMPUTERNAME") or "",
            "variables": {name: _pack(value, kind) for name, (value, kind) in _read_scope(scope).items()}}


def _backup_folder(create):
    folder = _win.data_dir() / BACKUP_DIR
    if create:
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise EnvError(f"could not create {folder}: {e}. Nothing was changed.")
    return folder


def _save_backup(scope, reason):
    """Save the whole scope; returns the file's path. A backup that cannot be saved stops the change."""
    folder = _backup_folder(create=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")  # microseconds: backups in one second still sort in order
    name, counter = f"env-{stamp}-{scope}.json", 2
    while (folder / name).exists():
        name = f"env-{stamp}-{scope}-{counter}.json"
        counter += 1
    try:
        return _win.save_json(f"{BACKUP_DIR}/{name}", _snapshot(scope, reason))
    except _net.NetError as e:
        raise EnvError(f"{e}. Nothing was changed, because the backup could not be saved.")


def _backups():
    """(backups newest first, how many files could not be read). Each: n, file, path, saved, scope, reason, variables."""
    folder = _backup_folder(create=False)
    items, unreadable = [], 0
    for path in (sorted(folder.glob("env-*.json")) if folder.is_dir() else []):
        data = _win.load_json(f"{BACKUP_DIR}/{path.name}")
        if (not isinstance(data, dict) or data.get("scope") not in SCOPES
                or not isinstance(data.get("variables"), dict)):
            unreadable += 1
            continue
        items.append({"file": path.name, "path": str(path), "saved": str(data.get("saved") or ""),
                      "scope": data["scope"], "reason": str(data.get("reason") or ""), "data": data})
    items.sort(key=lambda item: (item["saved"], item["file"]), reverse=True)
    for number, item in enumerate(items, start=1):
        item["n"] = number
    return items, unreadable


def _backup_values(item):
    """{name: (value, kind)} from a backup, skipping entries that cannot be read."""
    values = {}
    for name, entry in item["data"]["variables"].items():
        unpacked = _unpack(entry)
        if unpacked is not None:
            values[name] = unpacked
    return values


def _backup_public(item):
    return {"n": item["n"], "file": item["file"], "path": item["path"], "saved": item["saved"], "scope": item["scope"],
            "reason": item["reason"], "variables": len(item["data"]["variables"])}


# ======================================================================
# WRITING — apply changes, tell Windows, read back
# ======================================================================
def _broadcast():
    """Tell running programs (Explorer, so new terminals) that the environment changed. Returns whether Windows
    answered; a program that is not responding can make it time out."""
    try:
        send = ctypes.windll.user32.SendMessageTimeoutW
        send.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_wchar_p, wintypes.UINT,
                         wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
        send.restype = ctypes.c_ssize_t
        result = ctypes.c_size_t()
        return bool(send(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment", SMTO_ABORTIFHUNG, BROADCAST_TIMEOUT,
                         ctypes.byref(result)))
    except (AttributeError, OSError, ctypes.ArgumentError):
        return False


def _apply(scope, changes, reason):
    """Back the scope up, write the changes, and tell Windows. Returns (backup path, whether Windows was told)."""
    backup = _save_backup(scope, reason)
    hive, path = SCOPES[scope]
    try:
        for change in changes:
            if change["change"] == "removed":
                _win.reg_delete(hive, path, change["name"])
            else:
                _win.reg_write(hive, path, change["name"], change["_value"], change["_now_kind"])
    except _net.NetError as e:
        raise EnvError(f"{e} Part of the change may have been made: 'env undo' puts back the backup "
                       f"{os.path.basename(str(backup))}.")
    return backup, _broadcast()


def _notified_text(notified):
    if notified:
        return "Windows was told, so programs started from now on get the change. " + NEW_TERMINAL
    return ("Windows did not confirm that it told running programs (one may not be responding). " + NEW_TERMINAL
            + " If a new terminal still shows the old value, sign out and in.")


def _quiet(options):
    """With --json the questions go to stderr, so stdout stays pure JSON."""
    return contextlib.redirect_stdout(sys.stderr) if options["json"] else contextlib.nullcontext()


def _ask(question, options):
    with _quiet(options):
        return _core.confirm(question, options["yes"])


def _say(options, *lines):
    if not options["json"]:
        for line in lines:
            print(line)


def _typed_yes(name, reason, options):
    """For names Windows relies on: the person types the name. --yes cannot answer this, because an agent that was
    told 'yes' to a change was not told this one is risky."""
    if options["yes"]:
        raise EnvError(f"{name} is a variable Windows relies on, so --yes does not answer for it. {reason} Run the "
                       "command again without --yes, and type its name when asked.", 2)
    with _quiet(options):
        print(reason)
        try:
            typed = input(f"Type {name} to go ahead (anything else cancels): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
    return typed.lower() == name.lower()


def _scope_of(options):
    if options["system"] and options["user"]:
        raise EnvError("use --system or --user, not both", 2)
    return "system" if options["system"] else "user"


def _need_admin_for(scope):
    if scope == "system":
        _net.need_admin()


def _label(scope):
    return "user" if scope == "user" else "system"


def _valid_name(name):
    if not name or name != name.strip():
        raise EnvError("a variable name cannot be empty or start or end with a space", 2)
    if "=" in name or any(ord(char) < 32 for char in name):
        raise EnvError("a variable name cannot contain '=' or control characters", 2)
    if len(name) > MAX_NAME:
        raise EnvError(f"a variable name can be at most {MAX_NAME} characters", 2)


def _valid_value(value):
    """Raises for a value Windows cannot hold; returns (notes, doubts): notes are shown, doubts are shown and also
    make the page ask, even for a new variable."""
    if value == "":
        raise EnvError("an empty value sets nothing useful. Use 'env rm <NAME>' to delete a variable.", 2)
    if len(value) > MAX_VALUE:
        raise EnvError(f"a value can be at most {MAX_VALUE:,} characters; this one is {len(value):,}", 2)
    if any(ord(char) < 32 and char != "\t" for char in value):
        raise EnvError("the value contains a line break or control character, which is almost always a paste "
                       "mistake. Nothing was changed.", 2)
    notes, doubts = [], []
    if len(value) > LEGACY_LIMIT:
        notes.append(f"note: this value is {len(value):,} characters; some older programs cut a value at "
                     f"{LEGACY_LIMIT:,}.")
    if any(LOST_SLASHES.match(part.strip().strip('"')) for part in _split(value)):
        doubts.append("note: a part of this value looks like a path whose backslashes were lost (the console treats "
                      'a backslash outside quotes as an escape). Put paths in quotes, e.g. env set X "C:\\Tools".')
    return notes, doubts


def _kind_for(value, existing_kind):
    """Expandable if the value has %NAME% in it or the variable already was; plain text otherwise."""
    if VARIABLE.search(value) or existing_kind == winreg.REG_EXPAND_SZ:
        return winreg.REG_EXPAND_SZ
    return winreg.REG_SZ


# ======================================================================
# LISTING AND SHOWING — env ls, env <name|id>, env where, env find, env expand
# ======================================================================
def _row_color(row):
    if row["kind"] not in TEXT_KINDS:
        return GREY
    return GREEN if row["scope"] == "user" else YELLOW


def _ls(words, options):
    scope, search, index = "all", None, 0
    while index < len(words):
        word = words[index].lower()
        if word in SCOPE_WORDS:
            scope = word
        elif word in ("search", "find"):
            search = " ".join(words[index + 1:]).strip().lower()
            if not search:
                raise EnvError("usage: env ls [user|system|all] [search <text>]", 2)
            break
        else:
            raise EnvError("usage: env ls [user|system|all] [search <text>]", 2)
        index += 1
    if options["system"] or options["user"]:
        scope = _scope_of(options)
    rows = [row for row in _variables()
            if (scope == "all" or row["scope"] == scope)
            and (not search or search in row["name"].lower() or search in row["value"].lower())]
    if options["json"]:
        _core.print_json({"scope": scope, "search": search, "total": len(rows), "variables": [_public(r) for r in rows]})
        return 0
    if not rows:
        print("no variables match." if search else f"no {scope} variables are saved.")
        return 0
    width = max(20, shutil.get_terminal_size((110, 24)).columns - 50)
    print(f"{'ID':<6}{'NAME':<26}{'SCOPE':<8}{'TYPE':<12}VALUE")
    for row in rows:
        value = f"{row['entries']} entries" if row["list"] else row["value"]
        print(_row_color(row) + f"{row['id']:<6}{_cut(row['name'], 24):<26}{row['scope']:<8}{row['type']:<12}"
              f"{_cut(value, width)}" + RESET)
    mine = sum(1 for row in rows if row["scope"] == "user")
    print(f"\n{len(rows)} variable(s): {mine} yours (green), {len(rows) - mine} for the whole PC (yellow). "
          "Ids can shift when variables are added or removed.")
    print("'env <name>' shows one, 'env set <NAME> <value>' sets yours, 'env path' shows the PATH, "
          "'env help' lists everything.")
    return 0


def _matching_rows(word, rows):
    if _is_number(word):
        found = [row for row in rows if row["id"] == int(word)]
        if not found:
            raise EnvError(f"no variable with id {word}. Run 'env ls' to see them.", 2)
        return found
    return [row for row in rows if row["name"].lower() == word.lower()]


def _entry_lines(row, table, others=frozenset()):
    """The entries of a list-like variable, one per line, with their flags (text lines)."""
    entries = _split(row["value"])
    if _list_kind(row["name"], row["value"]) == "extensions":
        return [GREEN + f"    {number:>3}  {entry}" + RESET for number, entry in enumerate(entries, start=1)]
    lines = []
    for item in _analyse(entries, table, others, others_name="system PATH"):
        color = GREEN if not item["problem"] else (YELLOW if item["problem"].startswith(("duplicate", "also"))
                                                    else RED)
        shown = _cut(item["entry"], 70) if item["entry"] else "(empty)"
        arrow = f"  ->  {_cut(item['expanded'], 60)}" if item["expanded"] and item["expanded"] != item["entry"] else ""
        flag = f"   {item['problem']}" if item["problem"] else ""
        lines.append(color + f"    {item['n']:>3}  {shown}{arrow}{flag}" + RESET)
    return lines


def _effective(rows_by_scope, table):
    """What a new program gets for one name: {"from": "user"|"system"|"both"|None, "value": ...}."""
    user, system = rows_by_scope.get("user"), rows_by_scope.get("system")
    user = user if user and user["kind"] in TEXT_KINDS else None
    system = system if system and system["kind"] in TEXT_KINDS else None
    if user and system:
        name = user["name"]
        if name.lower() == "path":
            return {"from": "both", "value": system["expanded"].rstrip(";") + ";" + user["expanded"]}
        return {"from": "user", "value": user["expanded"]}
    if user or system:
        row = user or system
        return {"from": row["scope"], "value": row["expanded"]}
    return {"from": None, "value": None}


def _show(word, options):
    rows = _variables()
    found = _matching_rows(word, rows)
    table = _lookup()
    name = found[0]["name"] if found else word
    terminal = _process_env().get(name.upper())
    if not found and terminal is None:
        raise EnvError(f"no variable called {word}. Run 'env ls' to see them, or 'env find {word}'.", 2)
    by_scope = {row["scope"]: row for row in found}
    effective = _effective(by_scope, table)
    saved = effective["value"]
    differs = None if terminal is None or saved is None else terminal != saved
    if options["json"]:
        scopes = []
        for row in found:
            item = _public(row)
            item["items"] = None
            if row["list"]:
                item["items"] = [{k: v for k, v in entry.items() if k != "key"}
                                 for entry in _analyse(_split(row["value"]), table)]
            scopes.append(item)
        _core.print_json({"name": name, "found": bool(found), "scopes": scopes, "terminal": terminal,
                          "terminal_matches_saved": None if differs is None else not differs,
                          "effective": effective})
        return 0
    sections = []
    for row in found:
        who = "yours (user)" if row["scope"] == "user" else "the PC's (system, for every user)"
        details = [("id", row["id"]), ("type", row["type"]), ("value", row["value"])]
        if row["kind"] == winreg.REG_EXPAND_SZ and row["expanded"] != row["value"]:
            details.append(("expands to", row["expanded"]))
        if row["kind"] not in TEXT_KINDS:
            details.append(("note", "Windows ignores values that are not text, so programs never see this one"))
        sections.append((f"set as {who}", details))
    if found:
        sections.append(("a new program gets", [
            ("from", {"both": "system entries, then yours", None: "-"}.get(effective["from"], effective["from"])),
            ("value", effective["value"] if effective["value"] is not None else "-"),
        ]))
    terminal_rows = [("value", terminal if terminal is not None else "not set in this terminal")]
    if not found:
        terminal_rows.append(("note", "not saved in the registry: Windows or a program sets it when it starts"))
    elif differs:
        terminal_rows.append(("note", "differs from what is saved: this terminal opened before the last change"))
    sections.append(("this terminal", terminal_rows))
    hints = [(f"env set {name} <value>", "set yours (add --system for everyone; administrator)"),
             (f"env rm {name}", "delete it (asks first)")]
    if any(row["list"] for row in found):
        hints = [(f"env {name.lower()} / env path", "the entries as one numbered list"),
                 ("env path add <folder>", "add one (--front puts it first)")] + hints
    sections.append(("change it with", hints))
    _net.render(name, sections)
    system_keys = frozenset()
    system_row = by_scope.get("system")
    if system_row and system_row["list"] and name.lower() == "path":
        system_keys = frozenset(item["key"] for item in _analyse(_split(system_row["value"]), table) if item["key"])
    for row in found:
        if row["list"]:
            print(f"\n{row['scope']} entries ({row['entries']}), searched from the top:")
            print("\n".join(_entry_lines(row, table, system_keys if row["scope"] == "user" else frozenset())))
    return 0


def _where(words, options):
    if len(words) != 1:
        raise EnvError("usage: env where <name>", 2)
    name = words[0]
    found = [row for row in _variables() if row["name"].lower() == name.lower()]
    table = _lookup()
    by_scope = {row["scope"]: row for row in found}
    effective = _effective(by_scope, table)
    terminal = _process_env().get(name.upper())
    if effective["from"] == "both":
        summary = ("Windows puts the system entries first, then yours: "
                   f"{by_scope['system']['entries'] or 0} + {by_scope['user']['entries'] or 0} entries.")
    elif "user" in by_scope and "system" in by_scope:
        summary = "both scopes set it, so your (user) value replaces the system one."
    elif effective["from"] == "user":
        summary = "only you set it."
    elif effective["from"] == "system":
        summary = "only the system sets it, so every user gets it."
    elif terminal is not None:
        summary = "it is set only in this terminal (not saved), so a new terminal will not have it."
    else:
        summary = "it is not set anywhere."
    if options["json"]:
        _core.print_json({"name": name, "user": _public(by_scope["user"]) if "user" in by_scope else None,
                          "system": _public(by_scope["system"]) if "system" in by_scope else None,
                          "terminal": terminal, "effective": effective, "summary": summary})
        return 0
    rows = [("your (user) value", by_scope["user"]["value"] if "user" in by_scope else "not set"),
            ("system value", by_scope["system"]["value"] if "system" in by_scope else "not set"),
            ("this terminal", terminal if terminal is not None else "not set"),
            ("a new program gets", effective["value"] if effective["value"] is not None else "-"),
            ("which wins", summary)]
    _net.render(name, [("where it is set", rows)])
    return 0


def _find_cmd(words, options):
    text = " ".join(words).strip().lower()
    if not text:
        raise EnvError("usage: env find <text>", 2)
    matches = []
    for row in _variables():
        base = {"id": row["id"], "scope": row["scope"], "name": row["name"]}
        if text in row["name"].lower():
            matches.append({**base, "where": "name", "text": row["name"]})
        if text in row["value"].lower():
            if row["list"]:
                for number, entry in enumerate(_split(row["value"]), start=1):
                    if text in entry.lower():
                        matches.append({**base, "where": f"entry {number}", "text": entry})
            else:
                matches.append({**base, "where": "value", "text": row["value"]})
    if options["json"]:
        _core.print_json({"query": text, "total": len(matches), "matches": matches})
        return 0
    if not matches:
        print(f"nothing contains '{text}' in a name, a value or a PATH entry.")
        return 0
    width = max(20, shutil.get_terminal_size((110, 24)).columns - 56)
    print(f"{'ID':<6}{'NAME':<24}{'SCOPE':<8}{'WHERE':<12}TEXT")
    for match in matches:
        color = GREEN if match["scope"] == "user" else YELLOW
        print(color + f"{match['id']:<6}{_cut(match['name'], 22):<24}{match['scope']:<8}{match['where']:<12}"
              f"{_cut(match['text'], width)}" + RESET)
    print(f"\n{len(matches)} match(es) for '{text}'. 'env <id>' shows a variable in full.")
    return 0


def _expand_cmd(words, options):
    if not words:
        raise EnvError("usage: env expand <text with %VARIABLES%>", 2)
    text = " ".join(words)
    expanded, unknown = _expand(text, _lookup())
    if options["json"]:
        _core.print_json({"text": text, "expanded": expanded, "unknown": unknown})
        return 0
    print(expanded)
    if unknown:
        print(RED + "not set: " + ", ".join(f"%{name}%" for name in unknown) + RESET + " (left as written)")
    elif "%" not in text:
        print("(nothing to expand: variables are written %NAME%)")
    return 0


# ======================================================================
# SET AND REMOVE
# ======================================================================
def _set(words, options):
    if len(words) < 2:
        raise EnvError("usage: env set <NAME> <value> [--system]", 2)
    return _set_value(words[0], " ".join(words[1:]), _scope_of(options), options)


def _set_by_id(words, options):
    """env <id> <value>: the id names the variable and its scope."""
    row = _matching_rows(words[0], _variables())[0]
    return _set_value(row["name"], " ".join(words[1:]), row["scope"], options)


def _set_value(name, value, scope, options):
    _valid_name(name)
    notes, doubts = _valid_value(value)
    saved = _read_scope(scope)
    found = _existing(saved, name)
    spelling = found[0] if found else name
    if found and found[2] in TEXT_KINDS and _text(found[1]) == value:
        _say(options, f"{spelling} is already set to that for {SCOPE_TEXT[scope]} scope. Nothing changed.")
        if options["json"]:
            _core.print_json(_result("set", scope, []))
        return 0
    if spelling.lower() in TEMP_NAMES and not _is_dir(_expand(value, _lookup())[0]):
        doubts.append(f"note: the folder {value} does not exist. Programs that use {spelling} will fail until it does.")
    kind = _kind_for(value, found[2] if found else None)
    _need_admin_for(scope)
    for warning in notes + doubts:
        _say(options, warning)
    old = _text(found[1]) if found else None
    if _protected(spelling):
        reason = (f"{spelling} is used by Windows or by programs to find things. Changing it can stop programs or "
                  "sign-in working.")
        if not _typed_yes(spelling, reason, options):
            _say(options, "cancelled")
            return 0
    elif found or scope == "system" or doubts:
        who = ("Every user and service on this PC will see this change. " if scope == "system" else "")
        if found:
            question = (f"Replace {_label(scope)} variable {spelling}? Now: {_cut(old, 60)}. New: {_cut(value, 60)}. "
                        f"{who}A backup is saved first; 'env undo' puts it back. [y/N]: ")
        else:
            question = (f"Add {_label(scope)} variable {spelling} = {_cut(value, 60)}? {who}"
                        "A backup is saved first; 'env undo' puts it back. [y/N]: ")
        if not _ask(question, options):
            _say(options, "cancelled")
            return 0
    _say(options, f"setting {_label(scope)} variable {spelling}...")
    change = _change(spelling, None if not found else found[1], found[2] if found else None, value, kind)
    backup, notified = _apply(scope, [change], f"set {spelling}")
    now = _existing(_read_scope(scope), spelling)
    if now is None or _text(now[1]) != value:
        raise EnvError(f"Windows did not keep the value. It reads back as: {_text(now[1]) if now else 'not set'}.")
    if options["json"]:
        _core.print_json(_result("set", scope, [change], backup, notified, name=now[0], type=_kind_word(now[2]),
                                 value=_text(now[1])))
        return 0
    print(f"{now[0]} is now {_text(now[1])}  ({_kind_word(now[2])}, {_label(scope)} variable).")
    if kind == winreg.REG_EXPAND_SZ and VARIABLE.search(value):
        print("Stored as expandable text, because it contains %...%: Windows fills those in when a program starts.")
    print(f"Backup of the old state: {backup}   (undo: env undo{' --system' if scope == 'system' else ''})")
    print(_notified_text(notified))
    return 0


def _remove(words, options):
    if len(words) != 1:
        raise EnvError("usage: env rm <NAME|id> [--system]", 2)
    word = words[0]
    if _is_number(word):
        row = _matching_rows(word, _variables())[0]
        scope, name = row["scope"], row["name"]
    else:
        scope, name = _scope_of(options), word
    saved = _read_scope(scope)
    found = _existing(saved, name)
    if found is None:
        other = "system" if scope == "user" else "user"
        if _existing(_read_scope(other), name):
            raise EnvError(f"{name} is not a {scope} variable, but it is a {other} variable: "
                           f"{'add --system' if other == 'system' else 'leave out --system'} to remove that one.", 2)
        raise EnvError(f"{name} is not set as a {scope} variable. Run 'env ls' to see them.", 2)
    spelling = found[0]
    _need_admin_for(scope)
    old = _text(found[1])
    if _protected(spelling) or spelling.lower() in TEMP_NAMES:
        reason = (f"{spelling} is used by Windows or by programs to find things. Deleting it can stop programs or "
                  "sign-in working.")
        if not _typed_yes(spelling, reason, options):
            _say(options, "cancelled")
            return 0
    else:
        who = "Every user and service on this PC loses it. " if scope == "system" else ""
        if not _ask(f"Delete {_label(scope)} variable {spelling} ({_cut(old, 60)})? Programs that use it will not find "
                    f"it. {who}A backup is saved first; 'env undo' puts it back. [y/N]: ", options):
            _say(options, "cancelled")
            return 0
    _say(options, f"deleting {_label(scope)} variable {spelling}...")
    change = _change(spelling, found[1], found[2], None, None)
    backup, notified = _apply(scope, [change], f"removed {spelling}")
    if _existing(_read_scope(scope), spelling) is not None:
        raise EnvError(f"Windows still has {spelling} after the delete. Run 'env {spelling}' to see it.")
    other_scope = "system" if scope == "user" else "user"
    still = _existing(_read_scope(other_scope), spelling)
    if options["json"]:
        _core.print_json(_result("rm", scope, [change], backup, notified, name=spelling,
                                 still_set_in=other_scope if still else None))
        return 0
    print(f"{spelling} is no longer a {_label(scope)} variable.")
    if still:
        print(f"It is still set as a {other_scope} variable: {_cut(_text(still[1]), 80)}")
    print(f"Backup of the old state: {backup}   (undo: env undo{' --system' if scope == 'system' else ''})")
    print(_notified_text(notified))
    return 0


# ======================================================================
# PATH — list, add, remove, move and clean the entries
# ======================================================================
def _path_show(words, options):
    scope = "all"
    for word in words:
        if word.lower() in SCOPE_WORDS:
            scope = word.lower()
        elif word.lower() not in LIST_WORDS:
            raise EnvError("usage: env path [user|system|all] | env path add|rm|move|clean ...", 2)
    if options["system"] or options["user"]:
        scope = _scope_of(options)
    table = _lookup()
    state = _path_state(table)
    shown = ("system", "user") if scope == "all" else (scope,)
    problems = sum(1 for name in shown for item in state[name]["entries"] if item["problem"])
    if options["json"]:
        _core.print_json({"scope": scope, "problems": problems,
                          "system": _path_public(state["system"]), "user": _path_public(state["user"])})
        return 0
    for name in shown:
        part = state[name]
        title = "system PATH (every user)" if name == "system" else "your PATH (user)"
        entries = part["entries"]
        print(f"{title}: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}"
              + ("" if part["present"] else "  (not set)"))
        for item in entries:
            problem = item["problem"] or ""
            color = GREEN if not problem else (YELLOW if problem.startswith(("duplicate", "also")) else RED)
            shown_entry = _cut(item["entry"], 66) if item["entry"] else "(empty)"
            arrow = (f"  ->  {_cut(item['expanded'], 60)}"
                     if item["expanded"] and item["expanded"] != item["entry"].strip().strip('"') else "")
            print(color + f"  {item['n']:>3}  {shown_entry}{arrow}{('   ' + problem) if problem else ''}" + RESET)
        print()
    print("Programs are looked for in the folders from the top, system entries first, then yours. "
          f"{problems} entr{'y has' if problems == 1 else 'ies have'} a problem."
          + (" 'env path clean' removes them (it shows them and asks first)." if problems else ""))
    print("Edit with: env path add <folder> [--front] | rm <n|folder> | move <n> up|down|top|bottom | clean"
          "   (--system for the system PATH; administrator)")
    return 0


def _path_scope_state(options):
    scope = _scope_of(options)
    table = _lookup()
    return scope, table, _path_state(table)[scope]


def _rebuild(entries, kind, extra_variable=False):
    """The PATH text and registry type for these raw entries (Windows keeps the PATH expandable)."""
    text = ";".join(entries)
    if kind is None or kind == winreg.REG_SZ and (VARIABLE.search(text) or extra_variable):
        kind = winreg.REG_EXPAND_SZ
    return text, kind


def _path_write(scope, part, entries, action, reason, options, extra=None):
    """Write a new list of raw entries to the PATH of one scope, read it back, and report."""
    old_text = part["raw"]
    if not entries:
        new_text, kind = None, part["kind"]
    else:
        new_text, kind = _rebuild(entries, part["kind"] or winreg.REG_EXPAND_SZ)
    name = part["name"]
    if new_text is None:
        change = _change(name, old_text if part["present"] else None, part["kind"], None, None)
    else:
        change = _change(name, old_text if part["present"] else None, part["kind"], new_text, kind)
    _say(options, f"updating the {_label(scope)} PATH...")
    backup, notified = _apply(scope, [change], reason)
    after = _path_state(_lookup())[scope]
    if new_text is not None and after["raw"] != new_text:
        raise EnvError("Windows did not keep the PATH as written. Run 'env path' to see it, 'env undo' to go back.")
    if options["json"]:
        _core.print_json(_result(action, scope, [change], backup, notified, **(extra or {}),
                                 entries=[item["entry"] for item in after["entries"]]))
        return after, backup, notified
    return after, backup, notified


def _path_footer(scope, backup, notified):
    print(f"Backup of the old state: {backup}   (undo: env undo{' --system' if scope == 'system' else ''})")
    print(_notified_text(notified))


def _path_add(words, options):
    text = " ".join(words).strip().strip('"')
    if not text:
        raise EnvError('usage: env path add <folder> [--front] [--system]   (quote it in the console: "C:\\Tools")', 2)
    if ";" in text:
        raise EnvError("a PATH entry cannot contain ';'. Add the folders one at a time.", 2)
    if '"' in text or any(ord(char) < 32 for char in text):
        raise EnvError("a PATH entry cannot contain a double quote or a control character: a quote would make "
                       "every later ';' stop separating entries.", 2)
    if LOST_SLASHES.match(text):
        raise EnvError(f"'{text}' looks like a path whose backslashes were lost: the console treats a backslash "
                       'outside quotes as an escape. Put the folder in quotes, e.g. env path add "C:\\Tools".', 2)
    scope, table, part = _path_scope_state(options)
    if len(part["raw"]) + len(text) + 1 > MAX_VALUE:
        raise EnvError(f"the PATH would be longer than the {MAX_VALUE:,} characters Windows allows. Nothing was changed.", 2)
    expanded, unknown = _expand(text, table)
    key = _normalise(expanded)
    for item in part["entries"]:
        if item["key"] == key:
            _say(options, f"{text} is already in the {_label(scope)} PATH (entry {item['n']}). Nothing changed.")
            if options["json"]:
                _core.print_json(_result("path add", scope, [], entries=[e["entry"] for e in part["entries"]]))
            return 0
    if scope == "user":
        system = _path_state(table)["system"]
        for item in system["entries"]:
            if item["key"] == key:
                _say(options, f"{text} is already in the system PATH (entry {item['n']}), which comes first. "
                              "Nothing changed.")
                if options["json"]:
                    _core.print_json(_result("path add", scope, [], entries=[e["entry"] for e in part["entries"]]))
                return 0
    _need_admin_for(scope)
    if unknown:
        _say(options, f"note: %{unknown[0]}% is not set, so this entry will not point anywhere yet.")
    elif not _is_dir(expanded):
        _say(options, f"note: the folder {expanded} does not exist yet. It is added anyway.")
    if scope == "system" and not _ask(
            f"Add {text} to the system PATH? Every user and service on this PC will search it"
            f"{' first' if options['front'] else ' last'}. A backup is saved first; 'env undo --system' puts it back. "
            "[y/N]: ", options):
        _say(options, "cancelled")
        return 0
    entries = [item["entry"] for item in part["entries"]]
    while entries and not entries[-1].strip():
        entries.pop()
    position = 1 if options["front"] else len(entries) + 1
    entries.insert(position - 1, text)
    after, backup, notified = _path_write(scope, part, entries, "path add", f"path add {text}", options,
                                          {"added": text, "position": position})
    if options["json"]:
        return 0
    print(f"{text} is now entry {position} of {len(after['entries'])} in the {_label(scope)} PATH."
          + (" Entries higher up win when two folders hold a program with the same name." if options["front"] else ""))
    _path_footer(scope, backup, notified)
    return 0


def _path_remove(words, options):
    target = " ".join(words).strip().strip('"')
    if not target:
        raise EnvError("usage: env path rm <n|folder> [--system]", 2)
    scope, table, part = _path_scope_state(options)
    entries = part["entries"]
    if _is_number(target):
        number = int(target)
        if not 1 <= number <= len(entries):
            raise EnvError(f"the {_label(scope)} PATH has {len(entries)} entries; there is no entry {number}. "
                           "Run 'env path' to see them.", 2)
        gone = [entries[number - 1]]
    else:
        key = _normalise(_expand(target, table)[0])
        gone = [item for item in entries if item["key"] and item["key"] == key]
        if not gone:
            raise EnvError(f"{target} is not in the {_label(scope)} PATH. Run 'env path' to see the entries.", 2)
    kept = [item["entry"] for item in entries if item not in gone]
    if scope == "system" and not [entry for entry in kept if entry.strip()]:
        raise EnvError("that would leave the system PATH empty, and Windows needs it. Nothing was changed.", 2)
    _need_admin_for(scope)
    names = ", ".join(f"{item['n']}: {_cut(item['entry'] or '(empty)', 50)}" for item in gone)
    if not _ask(f"Remove {len(gone)} entr{'y' if len(gone) == 1 else 'ies'} from the {_label(scope)} PATH ({names})? "
                f"Programs in {'that folder' if len(gone) == 1 else 'those folders'} will no longer be found by name. "
                f"A backup is saved first; 'env undo{' --system' if scope == 'system' else ''}' puts it back. [y/N]: ",
                options):
        _say(options, "cancelled")
        return 0
    after, backup, notified = _path_write(scope, part, kept, "path rm", f"path rm {target}", options,
                                          {"removed": [item["entry"] for item in gone]})
    if options["json"]:
        return 0
    print(f"removed {len(gone)} entr{'y' if len(gone) == 1 else 'ies'}; the {_label(scope)} PATH has "
          f"{len(after['entries'])} left.")
    _path_footer(scope, backup, notified)
    return 0


def _path_move(words, options):
    if len(words) != 2 or not _is_number(words[0]) or words[1].lower() not in MOVES:
        raise EnvError("usage: env path move <n> up|down|top|bottom [--system]", 2)
    number, how = int(words[0]), words[1].lower()
    scope, table, part = _path_scope_state(options)
    entries = [item["entry"] for item in part["entries"]]
    if not 1 <= number <= len(entries):
        raise EnvError(f"the {_label(scope)} PATH has {len(entries)} entries; there is no entry {number}. "
                       "Run 'env path' to see them.", 2)
    target = {"up": max(1, number - 1), "down": min(len(entries), number + 1), "top": 1, "bottom": len(entries)}[how]
    if target == number:
        _say(options, f"entry {number} is already at the {'top' if how in ('up', 'top') else 'bottom'}. Nothing changed.")
        if options["json"]:
            _core.print_json(_result("path move", scope, [], entries=entries))
        return 0
    _need_admin_for(scope)
    entry = entries.pop(number - 1)
    entries.insert(target - 1, entry)
    if scope == "system" and not _ask(
            f"Move '{_cut(entry, 50)}' from {number} to {target} in the system PATH? It changes which program wins for "
            "every user. A backup is saved first; 'env undo --system' puts it back. [y/N]: ", options):
        _say(options, "cancelled")
        return 0
    after, backup, notified = _path_write(scope, part, entries, "path move", f"path move {number} {how}", options,
                                          {"moved": entry, "from": number, "to": target})
    if options["json"]:
        return 0
    print(f"moved '{_cut(entry, 60)}' from {number} to {target} in the {_label(scope)} PATH.")
    _path_footer(scope, backup, notified)
    return 0


def _path_clean(words, options):
    if words:
        raise EnvError("usage: env path clean [--system]", 2)
    scope, table, part = _path_scope_state(options)
    entries = part["entries"]
    bad = [item for item in entries if item["problem"]]
    if not bad:
        _say(options, f"nothing to clean: every entry in the {_label(scope)} PATH is fine.")
        if options["json"]:
            _core.print_json(_result("path clean", scope, [], entries=[item["entry"] for item in entries],
                                     removed=[]))
        return 0
    kept = [item["entry"] for item in entries if not item["problem"]]
    if scope == "system" and not kept:
        raise EnvError("every system PATH entry has a problem, so cleaning would leave it empty. Nothing was changed.", 2)
    _need_admin_for(scope)
    if not options["json"]:
        print(f"these {len(bad)} entr{'y' if len(bad) == 1 else 'ies'} would go from the {_label(scope)} PATH:")
        for item in bad:
            print(RED + f"  {item['n']:>3}  {_cut(item['entry'] or '(empty)', 66)}   {item['problem']}" + RESET)
    if not _ask(f"Remove {len(bad)} entr{'y' if len(bad) == 1 else 'ies'} from the {_label(scope)} PATH? A folder that "
                "looks missing may be on a drive that is not connected right now. Order and the other entries stay as "
                f"written. A backup is saved first; 'env undo{' --system' if scope == 'system' else ''}' puts it back. "
                "[y/N]: ", options):
        _say(options, "cancelled")
        return 0
    removed = [{"entry": item["entry"], "problem": item["problem"]} for item in bad]
    after, backup, notified = _path_write(scope, part, kept, "path clean", "path clean", options, {"removed": removed})
    if options["json"]:
        return 0
    print(f"removed {len(bad)}; the {_label(scope)} PATH has {len(after['entries'])} entries now.")
    _path_footer(scope, backup, notified)
    return 0


def _path_cmd(words, options):
    if not words or words[0].lower() in SCOPE_WORDS + LIST_WORDS:
        return _path_show(words, options)
    word, rest = words[0].lower(), words[1:]
    if word in ("add", "append"):
        return _path_add(rest, options)
    if word in REMOVE_WORDS:
        return _path_remove(rest, options)
    if word == "move":
        return _path_move(rest, options)
    if word == "clean":
        return _path_clean(rest, options)
    raise EnvError("usage: env path [user|system|all] | env path add|rm|move|clean ...", 2)


# ======================================================================
# BACKUPS — env backup, backups, undo, diff
# ======================================================================
def _backup_now(words, options):
    if words:
        raise EnvError("usage: env backup [--system]", 2)
    scope = _scope_of(options)
    path = _save_backup(scope, "manual backup")
    count = len(_read_scope(scope))
    if options["json"]:
        _core.print_json({"action": "backup", "scope": scope, "backup": str(path), "variables": count})
        return 0
    print(f"saved {count} {_label(scope)} variable(s) to {path}")
    print("'env backups' lists the backups, 'env diff' compares one with now, 'env undo' puts one back.")
    return 0


def _backups_cmd(words, options):
    items, unreadable = _backups()
    if words and words[0].lower() in REMOVE_WORDS:
        return _backups_remove(words[1:], items, options)
    if words:
        raise EnvError("usage: env backups [rm <n|all>]", 2)
    if options["json"]:
        _core.print_json({"folder": str(_backup_folder(create=False)), "unreadable": unreadable,
                          "backups": [_backup_public(item) for item in items]})
        return 0
    if not items:
        print("no backups yet. One is saved automatically before every change, or run 'env backup'.")
        return 0
    print(f"{'N':<5}{'SAVED':<21}{'SCOPE':<8}{'VARS':<6}WHAT CHANGED AFTER IT")
    for item in items:
        print(f"{item['n']:<5}{item['saved'].replace('T', ' ')[:19]:<21}{item['scope']:<8}"
              f"{len(item['data']['variables']):<6}{item['reason']}")
    print(f"\n{len(items)} backup(s) in {_backup_folder(create=False)}"
          + (f"; {unreadable} file(s) there could not be read" if unreadable else "") + ".")
    print("'env diff <n>' compares one with now, 'env undo <n>' puts it back, 'env backups rm <n|all>' deletes.")
    return 0


def _backups_remove(words, items, options):
    if len(words) != 1:
        raise EnvError("usage: env backups rm <n|all>", 2)
    if words[0].lower() == "all":
        chosen = items
    elif _is_number(words[0]) and 1 <= int(words[0]) <= len(items):
        chosen = [items[int(words[0]) - 1]]
    else:
        raise EnvError(f"no backup {words[0]}. Run 'env backups' to see them.", 2)
    if not chosen:
        _say(options, "no backups to delete.")
        return 0
    if not _ask(f"Delete {len(chosen)} backup file(s)? They cannot be recovered. [y/N]: ", options):
        _say(options, "cancelled")
        return 0
    deleted = []
    for item in chosen:
        try:
            os.remove(item["path"])
            deleted.append(item["file"])
        except OSError as e:
            raise EnvError(f"could not delete {item['path']}: {e}")
    if options["json"]:
        _core.print_json({"action": "backups rm", "deleted": deleted})
        return 0
    print(f"deleted {len(deleted)} backup(s).")
    return 0


def _pick_backup(words, options, usage):
    """The backup an undo or a diff is about: backup n, or the newest one for the chosen scope."""
    if len(words) > 1 or (words and not _is_number(words[0])):
        raise EnvError(usage, 2)
    items, _ = _backups()
    if words:
        number = int(words[0])
        if not 1 <= number <= len(items):
            raise EnvError(f"no backup {number}. Run 'env backups' to see them.", 2)
        return items[number - 1]
    scope = _scope_of(options)
    for item in items:
        if item["scope"] == scope:
            return item
    raise EnvError(f"there is no backup of the {_label(scope)} variables yet. One is saved before every change, "
                   "or run 'env backup'.", 2)


def _undo(words, options):
    item = _pick_backup(words, options, "usage: env undo [n] [--system]")
    scope = item["scope"]
    unreadable = [name for name, entry in item["data"]["variables"].items() if _unpack(entry) is None]
    if unreadable:
        raise EnvError(f"backup {item['n']} holds value(s) this page cannot read back ({', '.join(unreadable)}), so "
                       "undoing it could delete them. Nothing was changed.")
    changes = _compare(_read_scope(scope), _backup_values(item))
    if not changes:
        _say(options, f"the {_label(scope)} variables already match backup {item['n']} ({item['saved']}). Nothing to undo.")
        if options["json"]:
            _core.print_json(_result("undo", scope, [], backup_used=item["n"]))
        return 0
    _need_admin_for(scope)
    if not options["json"]:
        print(f"going back to backup {item['n']} ({item['saved'].replace('T', ' ')}, {_label(scope)} variables, "
              f"saved before: {item['reason']}) would change:")
        print("\n".join(_change_lines(changes)))
    touched = [change["name"] for change in changes if _protected(change["name"])
               or change["name"].lower() in TEMP_NAMES]
    if touched:
        names = ", ".join(touched)
        reason = f"This undo changes {names}, which Windows or programs rely on."
        if not _typed_yes(touched[0], reason, options):
            _say(options, "cancelled")
            return 0
    if not touched and not _ask(f"Put the {_label(scope)} variables back to backup {item['n']}? The current state is saved as a new "
                "backup first, so running 'env undo' again goes forward again. [y/N]: ", options):
        _say(options, "cancelled")
        return 0
    backup, notified = _apply(scope, changes, f"before undo of backup {item['n']}")
    left = _compare(_read_scope(scope), _backup_values(item))
    if left:
        raise EnvError(f"{len(left)} variable(s) still differ from the backup after the restore: "
                       + ", ".join(change["name"] for change in left) + ". Run 'env diff' to see them.")
    if options["json"]:
        _core.print_json(_result("undo", scope, changes, backup, notified, backup_used=item["n"]))
        return 0
    print(f"the {_label(scope)} variables now match backup {item['n']}.")
    print(f"Backup of the state before the undo: {backup}")
    print(_notified_text(notified))
    return 0


def _diff_cmd(words, options):
    item = _pick_backup(words, options, "usage: env diff [n] [--system]")
    scope = item["scope"]
    changes = _compare(_backup_values(item), _read_scope(scope))  # from the backup to now
    if options["json"]:
        _core.print_json({"backup": _backup_public(item), "same": not changes,
                          "changes": [_public_change(change) for change in changes]})
        return 0
    print(f"backup {item['n']}: {item['saved'].replace('T', ' ')}, {_label(scope)} variables, saved before: "
          f"{item['reason']}")
    if not changes:
        print(GREEN + "the variables are the same as in that backup." + RESET)
        return 0
    print(f"since then ({len(changes)} difference(s); + added, - removed, ~ changed):")
    print("\n".join(_change_lines(changes)))
    return 0


# ======================================================================
# EXPORT AND IMPORT — JSON files (a backup file can be imported too)
# ======================================================================
def _export(words, options):
    if len(words) != 1:
        raise EnvError("usage: env export <file.json> [--system]", 2)
    target = os.path.abspath(words[0])
    scope = _scope_of(options)
    if not os.path.isdir(os.path.dirname(target)):
        raise EnvError(f"the folder {os.path.dirname(target)} does not exist", 2)
    if os.path.exists(target) and not _ask(f"{target} exists. Replace it? [y/N]: ", options):
        _say(options, "cancelled")
        return 0
    data = _snapshot(scope, "export")
    try:
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, default=str)
    except OSError as e:
        raise EnvError(f"could not write {target}: {e}")
    if options["json"]:
        _core.print_json({"action": "export", "scope": scope, "file": target, "variables": len(data["variables"])})
        return 0
    print(f"saved {len(data['variables'])} {_label(scope)} variable(s) to {target}")
    return 0


def _read_import(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as e:
        raise EnvError(f"could not read {path}: {e}", 2)
    except ValueError:
        raise EnvError(f"{path} is not a JSON file", 2)
    if not isinstance(data, dict) or not isinstance(data.get("variables"), dict) or data.get("scope") not in SCOPES:
        raise EnvError(f"{path} is not a file made by 'env export' or 'env backup'", 2)
    return data


def _import(words, options):
    if len(words) != 1:
        raise EnvError("usage: env import <file.json> [--system]", 2)
    scope = _scope_of(options)
    data = _read_import(os.path.abspath(words[0]))
    if data["scope"] != scope:
        raise EnvError(f"that file holds {data['scope']} variables. "
                       f"{'Add --system to import it.' if data['scope'] == 'system' else 'Leave out --system.'} "
                       "Variables are never moved between scopes by accident.", 2)
    current = _read_scope(scope)
    wanted, skipped = dict(current), []
    for name, entry in data["variables"].items():
        unpacked = _unpack(entry)
        try:
            _valid_name(name)
        except EnvError:
            skipped.append((name, "not a valid name"))
            continue
        if unpacked is None or unpacked[1] not in TEXT_KINDS or not isinstance(unpacked[0], str) or unpacked[0] == "":
            skipped.append((name, "not text, or empty"))
        elif _protected(name):
            skipped.append((name, "a variable Windows relies on: use 'env set' or 'env path' for it"))
        elif len(unpacked[0]) > MAX_VALUE:
            skipped.append((name, "too long"))
        else:
            existing = _existing(wanted, name)
            if existing:
                del wanted[existing[0]]
            wanted[existing[0] if existing else name] = unpacked
    changes = _compare(current, wanted)
    if not changes:
        _say(options, "the file changes nothing: every variable in it is already set that way.")
        if options["json"]:
            _core.print_json(_result("import", scope, [], skipped=[{"name": n, "reason": r} for n, r in skipped]))
        return 0
    _need_admin_for(scope)
    if not options["json"]:
        print(f"importing {words[0]} would change the {_label(scope)} variables:")
        print("\n".join(_change_lines(changes)))
        for name, why in skipped:
            print(GREY + f"  skipped {name}: {why}" + RESET)
    if not _ask(f"Apply {len(changes)} change(s) to the {_label(scope)} variables? A backup is saved first; 'env undo"
                f"{' --system' if scope == 'system' else ''}' puts it back. [y/N]: ", options):
        _say(options, "cancelled")
        return 0
    backup, notified = _apply(scope, changes, f"import {os.path.basename(words[0])}")
    if options["json"]:
        _core.print_json(_result("import", scope, changes, backup, notified,
                                 skipped=[{"name": n, "reason": r} for n, r in skipped]))
        return 0
    print(f"applied {len(changes)} change(s).")
    print(f"Backup of the old state: {backup}   (undo: env undo{' --system' if scope == 'system' else ''})")
    print(_notified_text(notified))
    return 0


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "environment"/"env"
# ======================================================================
def run(args):
    """Run one environment command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args, FLAGS)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    word, rest = args[0].lower(), args[1:]
    try:
        if word in LIST_WORDS:
            return _ls(rest, options)
        if word == "set":
            return _set(rest, options)
        if word in REMOVE_WORDS:
            return _remove(rest, options)
        if word == "path":
            return _path_cmd(rest, options)
        if word == "where":
            return _where(rest, options)
        if word in ("find", "search"):
            return _find_cmd(rest, options)
        if word == "expand":
            return _expand_cmd(rest, options)
        if word == "backup":
            return _backup_now(rest, options)
        if word == "backups":
            return _backups_cmd(rest, options)
        if word in ("undo", "restore"):
            return _undo(rest, options)
        if word == "diff":
            return _diff_cmd(rest, options)
        if word == "export":
            return _export(rest, options)
        if word == "import":
            return _import(rest, options)
        if word == "show" and len(rest) == 1:
            return _show(rest[0], options)
        if _is_number(word) and rest:
            return _set_by_id(args, options)
        if len(args) == 1:
            return _show(args[0], options)
        raise EnvError(f"usage: {USAGE}", 2)
    except (EnvError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

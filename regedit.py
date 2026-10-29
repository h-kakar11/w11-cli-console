"""
regedit: browse and edit the Windows Registry, by hand or one command at a time. Routed from app.py
("regedit" or "reg").

    regedit          open the editor. The root hives are listed with numbers
    reg ls [path]                                 list a key (no path: the hives)
    reg get <path> [name]                         read a value, or a key's details
    reg set <path> <name> --type T --value V      create or change a value (creates the key if it is missing)
    reg del <path> <name>                         delete a value
    reg mkkey <path>                              create a key
    reg rmkey <path>                              delete a key and everything under it

Every direct command takes --json (data, and a clear error code), --yes (the person has agreed) and,
for the four that change the registry, --dry-run (show the exact change and stop). Every change saves
the previous value first: 'rb last' puts it back (see rollback.py).

Inside the editor:
        ls [path]              list a key's subkeys and values, numbered
        cd <path> | cd <id>    move into a key (cd .. goes up, cd \\ goes to the top)
        pwd                    show the current path
        get [name|id]          show a value, or a key's details
        add <name> [type] <data>   create a value (type defaults to sz)
        set <name> [type] <data>   change a value (keeps its type unless you give one)
        rm <name|id>           delete a value
        mkdir <name>           create a key under the current one
        rmdir <name|id>        delete a key and everything under it
        help, clear, exit      (0 also exits)

A number on its own opens that item: a key is entered and listed, a value is shown.
Quote names and paths that have spaces. Paths start with a hive (HKCU, HKLM, ...). The direct commands
use backslashes only (a key name may hold a /); the editor accepts either.
Types: sz, expand_sz, multi_sz (items separated by ;), dword, qword, binary (hex, e.g. 0A FF 10).

Changes go through the Windows registry API with Windows' own permissions. Nothing
is bypassed: an access-denied error is shown as it is. Deleting asks first, and a
key with anything under it means typing its name. The top two levels of each hive
can't be deleted. Changing HKLM needs an administrator terminal; HKCU does not.
Deleting a key saves a copy of it for the undo, but a key too large to copy (over 2000 items) is
refused rather than deleted without an undo. Key permissions (ACLs) are not saved or restored.
"""

import datetime
import hashlib
import json
import os
import re
import sys
import types
import winreg

import _core
import _ops

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "regedit"
ALIASES = ["reg"]
SUMMARY = "Browse, read and edit the Windows registry"
# extra words people use, for 'settings search'
KEYWORDS = ["registry", "hive", "key", "value", "hklm", "hkcu", "regedit", "reg"]
USAGE = ("regedit  (opens the editor)  |  reg ls|get|set|del|mkkey|rmkey <path> ...  (one command each; "
         "add --json, --yes or --dry-run)")
HELP = [
    ("regedit", "open the registry editor, with the root hives numbered"),
    ("", "one command each (for scripts and agents; --json for data, --dry-run to preview, --yes to approve)"),
    ("reg ls [path]", "list a key's subkeys and values; no path lists the hives"),
    ("reg get <path> [name]", "read one value, or a key's details"),
    ("reg set <path> <name> --type <t> --value <v>", "create or change a value (types: sz expand_sz multi_sz dword qword binary)"),
    ("reg del <path> <name>", "delete a value"),
    ("reg mkkey <path>", "create a key"),
    ("reg rmkey <path>", "delete a key and everything under it (a copy is saved for the undo)"),
    ("", "inside the editor"),
    ("ls | cd <key> | pwd", "list the current key, move into a key, show the path"),
    ("get | add | set | rm", "read, create, change or delete a value"),
    ("mkdir | rmdir", "create a key, or delete one (asks first)"),
    ("3 | 0", "open item 3 from the list, or 0 to leave the editor"),
]
TIP = ("Example: reg set HKCU\\Software\\Example Port --type dword --value 8080. Every change is saved first: "
       "'rb last' undoes it. Changing HKLM needs an administrator terminal.")
RUN_ALONE = True  # typing 'regedit' on its own opens the editor
DRY_RUN = True  # reg set / del / mkkey / rmkey take --dry-run and take part in 'cs' batches
RAW_LINE = True  # in the console, keep backslashes in registry paths

HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")
MIN_DELETE_PARTS = 3  # HKLM\SOFTWARE (2 parts) is too high up to delete; HKLM\SOFTWARE\Foo is not
MAX_BACKUP_ITEMS = 2000  # keys and values copied before a key is deleted; a bigger key is refused, not deleted without an undo
DELETE_ACCESS = 0x00010000  # the DELETE right, which winreg does not name
CONNECTIVITY_PATHS = ("\\services\\tcpip", "\\services\\dhcp", "\\services\\dnscache", "\\services\\netbt",
                      "\\services\\wlansvc", "\\control\\network", "\\networklist")  # a hint, not a full list
PROMPT_BAR = "commands: ls cd pwd get add set rm mkdir rmdir help clear exit   |   0 exits"

HIVES = (
    ("HKCR", "HKEY_CLASSES_ROOT", winreg.HKEY_CLASSES_ROOT),
    ("HKCU", "HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER),
    ("HKLM", "HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE),
    ("HKU", "HKEY_USERS", winreg.HKEY_USERS),
    ("HKCC", "HKEY_CURRENT_CONFIG", winreg.HKEY_CURRENT_CONFIG),
)
HIVE_BY_NAME = {}
for _short, _long, _handle in HIVES:
    HIVE_BY_NAME[_short.lower()] = (_short, _handle)
    HIVE_BY_NAME[_long.lower()] = (_short, _handle)

TYPE_NAMES = {
    winreg.REG_NONE: "REG_NONE",
    winreg.REG_SZ: "REG_SZ",
    winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_BINARY: "REG_BINARY",
    winreg.REG_DWORD: "REG_DWORD",
    winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    winreg.REG_QWORD: "REG_QWORD",
}
WRITABLE_TYPES = (
    winreg.REG_SZ, winreg.REG_EXPAND_SZ, winreg.REG_MULTI_SZ,
    winreg.REG_DWORD, winreg.REG_QWORD, winreg.REG_BINARY,
)
TYPE_WORDS = {}
for _kind in WRITABLE_TYPES:
    _name = TYPE_NAMES[_kind].lower()  # reg_sz
    TYPE_WORDS[_name] = _kind
    TYPE_WORDS[_name[4:]] = _kind  # sz

DEFAULT_NAMES = ("(default)", "@")  # the unnamed default value of a key
TOKEN = re.compile(r'"([^"]*)"|(\S+)')


class RegeditError(_core.CommandError):
    """A problem with one command. The editor keeps running. code 2 is bad usage, 1 a system error."""


def _tokens(line):
    """Split a line into words. Quotes group spaces. Backslashes are kept, unlike shlex."""
    return [quoted if bare == "" else bare for quoted, bare in TOKEN.findall(line)]


def _filetime(ticks):
    """A registry FILETIME (UTC, 100ns ticks since 1601) as local time."""
    if not ticks:
        return "never"
    utc = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ticks // 10)
    return utc.astimezone().strftime("%Y-%m-%d %H:%M")


def _os_error(error):
    if isinstance(error, _core.CommandError):
        return error
    if isinstance(error, PermissionError):
        return _ops.denied("the registry key")
    if isinstance(error, FileNotFoundError):
        return RegeditError("that key does not exist", 2, "not_found")
    return RegeditError(str(error))


# ======================================================================
# REGISTRY — the only place this page reads or writes. Every call is Windows' own API.
# ======================================================================
def _subkey_names(key):
    names = []
    index = 0
    while True:
        try:
            names.append(winreg.EnumKey(key, index))
        except OSError:
            return sorted(names, key=str.lower)
        index += 1


def _split(path):
    """(hive handle, subpath) for a path such as ['HKLM', 'SOFTWARE', 'Foo']."""
    return HIVE_BY_NAME[path[0].lower()][1], "\\".join(path[1:])


def _join(path, name):
    return "\\".join(path[1:] + [name]) if len(path) > 1 else name


def _text(path):
    return "\\".join(path) if path else "(top: the hives)"


def _describe(kind, data):
    if data is None:
        return "(none)"
    if kind in (winreg.REG_DWORD, winreg.REG_QWORD, winreg.REG_DWORD_BIG_ENDIAN):
        return f"{data} (0x{data:X})"
    if kind == winreg.REG_MULTI_SZ:
        return " ; ".join(data) if data else "(empty)"
    if kind == winreg.REG_BINARY:
        text = bytes(data).hex(" ")
        return text if len(text) <= 60 else text[:60] + "..."
    return f'"{data}"'


def _children(path):
    """Every item in a path, keys first then values, each numbered from 1.
    The list and the numbers both come from here, so ls and a number always agree."""
    if not path:
        items = [{"kind": "hive", "name": short, "long": long} for short, long, _ in HIVES]
        return _number(items)
    handle, subpath = _split(path)
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_READ) as key:
            keys = []
            for name in _subkey_names(key):
                count = None
                try:
                    with winreg.OpenKey(key, name, 0, winreg.KEY_READ) as child:
                        count = winreg.QueryInfoKey(child)[0]
                except OSError:
                    pass
                keys.append({"kind": "key", "name": name, "subkeys": count})
            values = []
            index = 0
            while True:
                try:
                    name, data, kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                values.append({"kind": "value", "name": name, "type": kind, "data": data})
    except OSError as error:
        raise _os_error(error)
    values.sort(key=lambda item: item["name"].lower())
    return _number(keys + values)


def _number(items):
    for number, item in enumerate(items, start=1):
        item["id"] = number
    return items


def _key_details(path):
    handle, subpath = _split(path)
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_READ) as key:
            subkeys, values, modified = winreg.QueryInfoKey(key)
    except OSError as error:
        raise _os_error(error)
    return subkeys, values, _filetime(modified)


def _read_value(path, name):
    """(data, type) of a value, or None if the value is not there."""
    handle, subpath = _split(path)
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_READ) as key:
            data, kind = winreg.QueryValueEx(key, name)
            return data, kind
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _os_error(error)


def _write_value(path, name, kind, data):
    handle, subpath = _split(path)
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, kind, data)
    except OSError as error:
        raise _os_error(error)


def _delete_value(path, name):
    handle, subpath = _split(path)
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    except OSError as error:
        raise _os_error(error)


def _make_key(path, name):
    handle, subpath = _split(path)
    try:
        with winreg.CreateKeyEx(handle, _join(path, name), 0, winreg.KEY_WRITE):
            pass
    except OSError as error:
        raise _os_error(error)


def _delete_tree(handle, subpath, removed):
    """Deletes a key and everything under it, deepest first. Counts what it removed."""
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_ALL_ACCESS) as key:
            names = _subkey_names(key)
        for name in names:
            _delete_tree(handle, f"{subpath}\\{name}", removed)
        parent, _, leaf = subpath.rpartition("\\")
        with winreg.OpenKey(handle, parent, 0, winreg.KEY_ALL_ACCESS) as parent_key:
            winreg.DeleteKey(parent_key, leaf)
        removed.append(subpath)
    except OSError as error:
        raise _os_error(error)


# ======================================================================
# VALUES — turning what the user types into what Windows stores
# ======================================================================
def _parse_type(word):
    try:
        return TYPE_WORDS[word.lower()]
    except KeyError:
        raise RegeditError(f"unknown type {word}. Use sz, expand_sz, multi_sz, dword, qword or binary.", 2, "usage")


def _parse_data(kind, text):
    if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        return text
    if kind == winreg.REG_MULTI_SZ:
        return text.split(";")
    if kind in (winreg.REG_DWORD, winreg.REG_QWORD):
        try:
            number = int(text, 0)
        except ValueError:
            raise RegeditError(f"{text} is not a number. Use decimal, or hex with 0x, e.g. 0x1F", 2, "usage")
        limit = 2**32 if kind == winreg.REG_DWORD else 2**64
        if not 0 <= number < limit:
            raise RegeditError(f"{number} does not fit in {TYPE_NAMES[kind]} (0 to {limit - 1})", 2, "usage")
        return number
    if kind == winreg.REG_BINARY:
        cleaned = re.sub(r"[\s,]", "", text)
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            raise RegeditError("binary data is hex, e.g. 0A FF 10", 2, "usage")
    raise RegeditError(f"cannot write {TYPE_NAMES.get(kind, kind)}", 2, "usage")


def _value_name(text):
    return "" if text.lower() in DEFAULT_NAMES else text


def _print_value(name, kind, data):
    print(_core.BLUE + f"{name or '(Default)'}\n  type: {TYPE_NAMES.get(kind, kind)}\n"
          f"  data: {_describe(kind, data)}" + _core.RESET)


# ======================================================================
# PATHS AND STATES — how a value or a key is written down in a plan and the undo journal
# ======================================================================
def _parse_path(text):
    """['HKCU', 'Software', 'Foo'] for 'HKCU\\Software\\Foo'. Backslashes only: a key name may hold a /."""
    if not isinstance(text, str) or not text.strip():
        raise RegeditError("a registry path is needed, e.g. HKCU\\Software\\Example", 2, "usage")
    parts = [part for part in text.strip().split("\\") if part]
    if not parts or parts[0].lower() not in HIVE_BY_NAME:
        first = parts[0] if parts else text
        hint = " Paths use backslashes, not /." if "/" in first else ""
        raise RegeditError(
            f"{first} is not a hive. The hives are {', '.join(short for short, _, _ in HIVES)}.{hint}", 2, "usage")
    parts[0] = HIVE_BY_NAME[parts[0].lower()][0]
    return parts


def _type_name(kind):
    return TYPE_NAMES.get(kind, f"REG_{kind}")


def _kind_from_name(name):
    for kind, known in TYPE_NAMES.items():
        if known == name:
            return kind
    return int(name[4:])


def _to_json(kind, data):
    """A registry value as JSON: text, a list, a number, or hex for anything else."""
    if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        return data
    if kind == winreg.REG_MULTI_SZ:
        return list(data)
    if kind in (winreg.REG_DWORD, winreg.REG_QWORD) and isinstance(data, int):
        return data
    return "" if data is None else bytes(data).hex()


def _from_json(type_name, data):
    if type_name in ("REG_SZ", "REG_EXPAND_SZ"):
        return data
    if type_name == "REG_MULTI_SZ":
        return list(data)
    if type_name in ("REG_DWORD", "REG_QWORD"):
        return data
    return bytes.fromhex(data)


def _coerce(kind, value):
    """Data for a type from what a person typed or a batch file holds (text, a number, or a list)."""
    if isinstance(value, bool):
        raise RegeditError("a value is text, a number or a list, not true/false", 2, "usage")
    if kind == winreg.REG_MULTI_SZ and isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise RegeditError("a multi_sz value is a list of text items", 2, "usage")
        return list(value)
    if isinstance(value, int) and kind in (winreg.REG_DWORD, winreg.REG_QWORD):
        value = str(value)
    if not isinstance(value, str):
        raise RegeditError(f"that value does not fit {TYPE_NAMES[kind]}", 2, "usage")
    return _parse_data(kind, value)


def _show(state):
    if not state.get("exists"):
        return "(not there)"
    data = state["data"]
    text = " ; ".join(data) if isinstance(data, list) else str(data)
    return f"{state['type']} {text if len(text) <= 60 else text[:57] + '...'}"


def _key_exists(parts):
    handle, subpath = _split(parts)
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise _os_error(error)


def _value_state(parts, name):
    found = _read_value(parts, name)
    if found is None:
        return {"exists": False}
    data, kind = found
    return {"exists": True, "type": _type_name(kind), "data": _to_json(kind, data)}


def _missing_keys(parts):
    """The keys of this path that do not exist yet, shallowest first (each is created along with the one before)."""
    missing = []
    for end in range(2, len(parts) + 1):
        if missing or not _key_exists(parts[:end]):
            missing.append("\\".join(parts[:end]))
    return missing


def _denied_by_windows(parts, access):
    """True when Windows refuses to open this key (or its nearest existing parent) with this right.
    A probe that changes nothing, so a plan can say 'needs administrator' before anything is tried."""
    for end in range(len(parts), 0, -1):
        handle, subpath = _split(parts[:end])
        try:
            with winreg.OpenKey(handle, subpath, 0, access):
                return False
        except PermissionError:
            return True
        except FileNotFoundError:
            continue
        except OSError:
            return False
    return False


def _disrupts(parts):
    low = "\\" + "\\".join(parts[1:]).lower() + "\\"
    if any(marker + "\\" in low for marker in CONNECTIVITY_PATHS):
        return "this key holds network settings; changing it may interrupt connections"
    return None


def _remove_created(keys):
    """Delete keys a change created, deepest first. Stops at the first one that has something in it now."""
    for text in reversed(keys):
        handle, subpath = _split(_parse_path(text))
        try:
            winreg.DeleteKey(handle, subpath)
        except OSError:
            return


# ----------------------------------------------------------------------
# A whole key, copied before it is deleted
# ----------------------------------------------------------------------
def _spend(budget):
    budget["left"] -= 1
    if budget["left"] < 0:
        raise RegeditError(
            f"that key holds more than {MAX_BACKUP_ITEMS} items, too many to save a copy for the undo, so it was "
            "not deleted. Delete smaller keys inside it first.", 1, "too_large")


def _dump_tree(handle, subpath, budget):
    _spend(budget)
    values = []
    try:
        with winreg.OpenKey(handle, subpath, 0, winreg.KEY_READ) as key:
            names = _subkey_names(key)
            index = 0
            while True:
                try:
                    name, data, kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                _spend(budget)
                values.append({"name": name, "type": _type_name(kind), "data": _to_json(kind, data)})
    except OSError as error:
        raise _os_error(error)
    values.sort(key=lambda item: item["name"].lower())
    keys = []
    for name in names:
        child = _dump_tree(handle, f"{subpath}\\{name}" if subpath else name, budget)
        keys.append({"name": name, **child})
    return {"values": values, "keys": keys}


def _restore_tree(handle, subpath, tree):
    try:
        with winreg.CreateKeyEx(handle, subpath, 0, winreg.KEY_WRITE) as key:
            for item in tree["values"]:
                winreg.SetValueEx(key, item["name"], 0, _kind_from_name(item["type"]), _from_json(item["type"], item["data"]))
    except OSError as error:
        raise _os_error(error)
    for child in tree["keys"]:
        _restore_tree(handle, f"{subpath}\\{child['name']}", child)


def _digest(tree):
    return hashlib.sha256(json.dumps(tree, sort_keys=True).encode()).hexdigest()[:16]


def _tree_state(parts):
    if not _key_exists(parts):
        return {"exists": False}, None
    handle, subpath = _split(parts)
    budget = {"left": MAX_BACKUP_ITEMS}
    tree = _dump_tree(handle, subpath, budget)
    return {"exists": True, "items": MAX_BACKUP_ITEMS - budget["left"], "digest": _digest(tree)}, tree


# ======================================================================
# OPERATIONS — the four changes the registry takes. Direct commands, the editor and 'cs' batches all run these.
# ======================================================================
def _text_param(params, key):
    value = params.get(key)
    if not isinstance(value, str):
        raise RegeditError(f"{key} must be text", 2, "usage")
    return value


def _key_params(params, minimum, what):
    parts = _parse_path(_text_param(params, "path"))
    if len(parts) < minimum:
        raise RegeditError(what, 2, "usage")
    return parts


def _plan_set(params):
    parts = _key_params(params, 2, "a value lives in a key. Give a key below the hive, e.g. HKCU\\Software\\Example")
    name = _value_name(_text_param(params, "name"))
    before = _value_state(parts, name)
    if params.get("type") is not None:
        kind = _parse_type(_text_param(params, "type"))
    elif before["exists"]:
        kind = _kind_from_name(before["type"])
        if kind not in WRITABLE_TYPES:
            raise RegeditError(f"the value is {before['type']}, which cannot be written. Give --type.", 2, "usage")
    else:
        raise RegeditError("a new value needs --type (sz, expand_sz, multi_sz, dword, qword or binary)", 2, "usage")
    if params.get("value") is None:
        raise RegeditError("a value to write is needed (--value)", 2, "usage")
    after = {"exists": True, "type": TYPE_NAMES[kind], "data": _to_json(kind, _coerce(kind, params["value"]))}
    missing = _missing_keys(parts)
    path, shown = "\\".join(parts), name or "(default)"
    if before["exists"]:
        summary = f"change {shown}: {_show(before)} -> {_show(after)}"
    else:
        summary = f"create {shown} = {_show(after)}"
    return {
        "target": f"{path} :: {shown}", "summary": summary, "before": before, "after": after,
        "noop": before == after, "needs_admin": _denied_by_windows(parts, winreg.KEY_WRITE),
        "disrupts": _disrupts(parts), "restart": "unknown", "confirm": None,
        "path": path, "name": name, "created_keys": missing,
    }


def _apply_set(plan):
    parts = _parse_path(plan["path"])
    kind = _kind_from_name(plan["after"]["type"])
    if plan["created_keys"]:
        _make_key(parts[:-1], parts[-1])
    _write_value(parts, plan["name"], kind, _from_json(plan["after"]["type"], plan["after"]["data"]))


def _read_set(plan):
    return _value_state(_parse_path(plan["path"]), plan["name"])


def _restore_set(plan):
    parts, before = _parse_path(plan["path"]), plan["before"]
    if before["exists"]:
        _write_value(parts, plan["name"], _kind_from_name(before["type"]), _from_json(before["type"], before["data"]))
    elif _read_value(parts, plan["name"]) is not None:
        _delete_value(parts, plan["name"])
    _remove_created(plan["created_keys"])


def _plan_del(params):
    parts = _key_params(params, 2, "a value lives in a key. Give a key below the hive, e.g. HKCU\\Software\\Example")
    name = _value_name(_text_param(params, "name"))
    path, shown = "\\".join(parts), name or "(default)"
    if not _key_exists(parts):
        raise RegeditError(f"the key {path} does not exist", 2, "not_found")
    before = _value_state(parts, name)
    return {
        "target": f"{path} :: {shown}", "summary": f"delete {shown} ({_show(before)})", "before": before,
        "after": {"exists": False}, "noop": not before["exists"],
        "needs_admin": _denied_by_windows(parts, winreg.KEY_WRITE), "disrupts": _disrupts(parts),
        "restart": "unknown",
        "confirm": f"Delete the value {shown} from {path}? Its data is saved first: undo with 'rb last'. [y/N]: ",
        "path": path, "name": name, "created_keys": [],
    }


def _apply_del(plan):
    _delete_value(_parse_path(plan["path"]), plan["name"])


def _plan_mkkey(params):
    parts = _key_params(params, 2, "give a key below the hive, e.g. HKCU\\Software\\Example")
    missing = _missing_keys(parts)
    path = "\\".join(parts)
    return {
        "target": path, "summary": f"create the key {path}", "before": {"exists": not missing},
        "after": {"exists": True}, "noop": not missing, "needs_admin": _denied_by_windows(parts, winreg.KEY_WRITE),
        "disrupts": _disrupts(parts), "restart": "unknown", "confirm": None, "path": path, "created_keys": missing,
    }


def _apply_mkkey(plan):
    parts = _parse_path(plan["path"])
    _make_key(parts[:-1], parts[-1])


def _read_mkkey(plan):
    return {"exists": _key_exists(_parse_path(plan["path"]))}


def _restore_mkkey(plan):
    _remove_created(plan["created_keys"])


def _plan_rmkey(params):
    parts = _key_params(params, MIN_DELETE_PARTS,
                        "that is too high up the registry to delete. Name a smaller key, e.g. HKCU\\Software\\Example")
    path = "\\".join(parts)
    before, tree = _tree_state(parts)
    if not before["exists"]:
        raise RegeditError(f"the key {path} does not exist", 2, "not_found")
    denied = _denied_by_windows(parts[:-1], winreg.KEY_WRITE) or _denied_by_windows(parts, winreg.KEY_READ | DELETE_ACCESS)
    return {
        "target": path, "summary": f"delete the key {path} and everything under it ({before['items']} item(s))",
        "before": before, "after": {"exists": False}, "noop": False, "needs_admin": denied,
        "disrupts": _disrupts(parts), "restart": "unknown",
        "confirm": f"Delete the key {path} and everything under it ({before['items']} item(s))? "
                   "A copy is saved first: undo with 'rb last'. [y/N]: ",
        "path": path, "created_keys": [], "backup": tree,
    }


def _apply_rmkey(plan):
    handle, subpath = _split(_parse_path(plan["path"]))
    _delete_tree(handle, subpath, [])


def _read_rmkey(plan):
    return _tree_state(_parse_path(plan["path"]))[0]


def _restore_rmkey(plan):
    handle, subpath = _split(_parse_path(plan["path"]))
    _restore_tree(handle, subpath, plan["backup"])


def _param(name, required, text):
    return {"name": name, "required": required, "help": text}


OPERATIONS = {
    "set": {
        "summary": "create or change a registry value (creates the key if it is missing)",
        "params": [
            _param("path", True, "the key, starting with a hive, e.g. HKCU\\Software\\Example"),
            _param("name", True, "the value's name; (default) or @ for the key's unnamed value"),
            _param("type", False, "sz, expand_sz, multi_sz, dword, qword or binary; kept from the existing value if left out"),
            _param("value", True, "the data: text, a number (decimal or 0x hex), a list for multi_sz, or hex for binary"),
        ],
        "changes_system": True, "needs_admin": "depends", "restart": "unknown",
        "side_effects": "HKCU needs no administrator; HKLM and other protected keys do. Windows cannot say whether a "
                        "program needs a restart or sign-out to notice the change.",
        "plan": _plan_set, "apply": _apply_set, "read": _read_set, "restore": _restore_set,
    },
    "del": {
        "summary": "delete a registry value (its data is saved for the undo)",
        "params": [
            _param("path", True, "the key, starting with a hive"),
            _param("name", True, "the value's name; (default) or @ for the key's unnamed value"),
        ],
        "changes_system": True, "needs_admin": "depends", "restart": "unknown",
        "side_effects": "A program that reads the value may fall back to its default.",
        "plan": _plan_del, "apply": _apply_del, "read": _read_set, "restore": _restore_set,
    },
    "mkkey": {
        "summary": "create a registry key (and any missing keys above it)",
        "params": [_param("path", True, "the key, starting with a hive")],
        "changes_system": True, "needs_admin": "depends", "restart": "unknown",
        "side_effects": "None by itself.",
        "plan": _plan_mkkey, "apply": _apply_mkkey, "read": _read_mkkey, "restore": _restore_mkkey,
    },
    "rmkey": {
        "summary": "delete a registry key and everything under it (a copy is saved for the undo)",
        "params": [_param("path", True, "the key, starting with a hive; at least three levels deep")],
        "changes_system": True, "needs_admin": "depends", "restart": "unknown",
        "side_effects": "Deletes every subkey and value below it. A key over 2000 items is refused. Key permissions "
                        "(ACLs) and timestamps are not restored by the undo.",
        "plan": _plan_rmkey, "apply": _apply_rmkey, "read": _read_rmkey, "restore": _restore_rmkey,
    },
}
_SELF = types.SimpleNamespace(NAME=NAME, OPERATIONS=OPERATIONS)


def _change(op, params, options=None):
    """Run one registry change through the shared engine: plan, confirm, save the old value, apply, read back."""
    return _ops.execute([{"module": _SELF, "op": op, "params": params}], options or {})


# ======================================================================
# EDITOR — keeps the current path, and runs one command at a time
# ======================================================================
class Editor:
    def __init__(self):
        self.path = []  # [] is the top, where the hives are; otherwise ["HKLM", "SOFTWARE", ...]

    def prompt(self):
        if not self.path:
            return "Registry> "
        return "Registry " + "\\".join(self.path) + "> "

    def run(self, tokens):
        """Runs one line. Returns False when the user asked to leave."""
        word = tokens[0].lower()
        if word.isdigit() and len(tokens) == 1:
            self._open(tokens[0])
            return True
        if word in ("exit", "quit", "0"):
            return False
        commands = {
            "ls": self._ls, "dir": self._ls, "cd": self._cd, "pwd": self._pwd, "get": self._get,
            "add": self._add, "set": self._set, "rm": self._rm, "mkdir": self._mkdir,
            "rmdir": self._rmdir, "help": self._help, "clear": self._clear,
        }
        if word not in commands:
            raise RegeditError(f"unknown command: {tokens[0]}. Type help for the list.")
        commands[word](tokens[1:])
        return True

    # --- finding things -------------------------------------------------
    def _find(self, token):
        items = _children(self.path)
        if token.isdigit():
            for item in items:
                if item["id"] == int(token):
                    return item
            raise RegeditError(f"no item numbered {token} here. Type ls to see them.")
        wanted = _value_name(token)
        for item in items:
            if item["name"].lower() == wanted.lower():
                return item
        raise RegeditError(f"no key or value called {token} here. Type ls to see them.")

    def _resolve(self, text):
        """The path a cd or ls text names. Relative unless it starts with a slash."""
        parts = [part for part in re.split(r"[\\/]+", text) if part]
        path = [] if text[:1] in ("\\", "/") else list(self.path)
        for part in parts:
            if part == ".":
                continue
            if part == "..":
                if path:
                    path.pop()
                continue
            path.append(part)
        if not path:
            return []
        if path[0].lower() not in HIVE_BY_NAME:
            raise RegeditError(f"no hive called {path[0]}. The hives are {', '.join(s for s, _, _ in HIVES)}.")
        path[0] = HIVE_BY_NAME[path[0].lower()][0]
        if len(path) > 1:
            handle, subpath = _split(path)
            try:
                with winreg.OpenKey(handle, subpath, 0, winreg.KEY_READ):
                    pass
            except FileNotFoundError:
                raise RegeditError("that key does not exist: " + "\\".join(path))
            except OSError as error:
                raise _os_error(error)
        return path

    def _need_key(self):
        if not self.path:
            raise RegeditError("you are at the top, where only the hives are. cd into a hive first, e.g. cd HKCU")

    # --- listing and moving --------------------------------------------
    def _show_list(self, path):
        items = _children(path)
        os.system("")  # enables ANSI colour codes in the Windows console
        if not items:
            print(_core.BLUE + "(empty: no subkeys and no values)" + _core.RESET)
            return
        lines = [f"  {'ID':<5}{'TYPE':<8}{'NAME':<34}DETAILS"]
        for item in items:
            if item["kind"] == "hive":
                lines.append(f"  {item['id']:<5}{'hive':<8}{item['name']:<34}{item['long']}")
            elif item["kind"] == "key":
                count = "" if item["subkeys"] is None else f"{item['subkeys']} subkey(s)"
                lines.append(f"  {item['id']:<5}{'key':<8}{item['name'][:32]:<34}{count}")
            else:
                shown = item["name"] or "(Default)"
                kind = TYPE_NAMES.get(item["type"], str(item["type"]))
                lines.append(f"  {item['id']:<5}{'value':<8}{shown[:32]:<34}{kind}  {_describe(item['type'], item['data'])}")
        print(_core.BLUE + "\n".join(lines) + _core.RESET)

    def _ls(self, args):
        path = self._resolve(args[0]) if args else self.path
        if len(args) > 1:
            raise RegeditError("usage: ls [path]")
        self._show_list(path)

    def _cd(self, args):
        if len(args) != 1:
            raise RegeditError("usage: cd <key>   (cd .. goes up, cd \\ goes to the top)")
        if args[0].isdigit():
            item = self._find(args[0])
            if item["kind"] == "value":
                raise RegeditError(f"{item['name'] or '(Default)'} is a value, not a key. Use get to read it.")
            self.path = self.path + [item["name"]]
        else:
            self.path = self._resolve(args[0])
        self._show_list(self.path)

    def _pwd(self, args):
        if args:
            raise RegeditError("usage: pwd")
        print("\\".join(self.path) if self.path else "(top: the hives)")

    def _open(self, token):
        item = self._find(token)
        if item["kind"] == "value":
            self._get([token])
            return
        self.path = self.path + [item["name"]]
        self._show_list(self.path)

    # --- reading --------------------------------------------------------
    def _get(self, args):
        if len(args) > 1:
            raise RegeditError("usage: get [name|id]")
        if not args:
            self._need_key()
            self._key_info(self.path)
            return
        item = self._find(args[0])
        if item["kind"] == "value":
            _print_value(item["name"], item["type"], item["data"])
        elif item["kind"] == "key":
            self._key_info(self.path + [item["name"]])
        else:
            raise RegeditError("that is a hive. cd into it to see its keys")

    def _key_info(self, path):
        subkeys, values, modified = _key_details(path)
        print(_core.BLUE + f"{_text(path)}\n  subkeys: {subkeys}\n  values: {values}\n"
              f"  last changed: {modified}" + _core.RESET)

    # --- writing: every change goes through the shared engine, so it is saved first and can be undone ---
    def _add(self, args):
        self._need_key()
        if len(args) not in (2, 3):
            raise RegeditError('usage: add <name> [type] <data>   e.g. add "Port" dword 8080', 2, "usage")
        name = _value_name(args[0])
        kind_word, data_text = ("sz", args[1]) if len(args) == 2 else (args[1], args[2])
        if _read_value(self.path, name) is not None:
            raise RegeditError(f"{args[0]} already exists. Use set to change it.", 2, "usage")
        _change("set", {"path": "\\".join(self.path), "name": args[0], "type": kind_word, "value": data_text})

    def _set(self, args):
        self._need_key()
        if len(args) not in (2, 3):
            raise RegeditError('usage: set <name> [type] <data>   e.g. set "Port" 9000', 2, "usage")
        name = _value_name(args[0])
        if _read_value(self.path, name) is None:
            raise RegeditError(f"{args[0]} does not exist here. Use add to create it.", 2, "not_found")
        params = {"path": "\\".join(self.path), "name": args[0], "value": args[-1]}
        if len(args) == 3:
            params["type"] = args[1]
        _change("set", params)

    def _rm(self, args):
        self._need_key()
        if len(args) != 1:
            raise RegeditError("usage: rm <name|id>", 2, "usage")
        item = self._find(args[0])
        if item["kind"] != "value":
            raise RegeditError("that is a key. Use rmdir to delete a key.", 2, "usage")
        _change("del", {"path": "\\".join(self.path), "name": item["name"] or "(default)"})

    def _mkdir(self, args):
        self._need_key()
        if len(args) != 1:
            raise RegeditError("usage: mkdir <name>", 2, "usage")
        _change("mkkey", {"path": "\\".join(self.path + [args[0]])})

    def _rmdir(self, args):
        if len(args) != 1:
            raise RegeditError("usage: rmdir <name|id>", 2, "usage")
        self._need_key()
        item = self._find(args[0])
        if item["kind"] != "key":
            raise RegeditError("that is not a key. Use rm to delete a value.", 2, "usage")
        target = self.path + [item["name"]]
        if len(target) < MIN_DELETE_PARTS:
            raise RegeditError(f"{_text(target)} is too high up the registry to delete. Go into it and delete a smaller key.", 2, "usage")
        subkeys, values, _ = _key_details(target)
        asked = False
        if subkeys or values:
            print(f"{item['name']} has {subkeys} subkey(s) and {values} value(s). Deleting it deletes everything under it.")
            if _ask(f"Type the key's name ({item['name']}) to delete it, or press Enter to cancel: ") != item["name"]:
                print("cancelled")
                return
            asked = True  # typing the name is the confirmation
        _change("rmkey", {"path": "\\".join(target)}, {"asked": asked})

    # --- help and the screen -------------------------------------------
    def _help(self, args):
        print(_core.BLUE + "\n".join([
            "regedit commands",
            "",
            "  ls [path]                  list a key's subkeys and values, numbered",
            "  cd <path> | cd <id>        move into a key (cd .. up, cd \\ to the top)",
            "  pwd                        show the current path",
            "  get [name|id]              show a value, or the current key's details",
            "  add <name> [type] <data>   create a value (type defaults to sz)",
            "  set <name> [type] <data>   change a value (keeps its type unless you give one)",
            "  rm <name|id>               delete a value (asks first)",
            "  mkdir <name>               create a key here",
            "  rmdir <name|id>            delete a key (asks first; a key with things in it needs its name typed)",
            "  clear                      clear the screen",
            "  exit, or 0                 leave the registry editor",
            "",
            "types: sz, expand_sz, multi_sz (items separated by ;), dword, qword, binary (hex)",
            "a number on its own opens that item: keys are entered, values are shown",
            "quote names with spaces, e.g. cd \"SOFTWARE\\Microsoft Windows\"",
            "",
            "Changing HKLM needs an administrator terminal. The top two levels of a hive can't be deleted.",
        ]) + _core.RESET)

    def _clear(self, args):
        os.system("cls")


def _ask(question):
    try:
        return input(question).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


# ======================================================================
# DIRECT COMMANDS — one command each, for scripts and agents
# ======================================================================
def _cmd_ls(args, options):
    if len(args) > 1:
        raise RegeditError("usage: reg ls [path]", 2, "usage")
    parts = _parse_path(args[0]) if args else []
    if not options["json"]:
        Editor()._show_list(parts)
        return 0
    items = _children(parts)
    if not parts:
        _core.print_json({"path": None, "hives": [{"name": i["name"], "long": i["long"]} for i in items]})
        return 0
    _core.print_json({
        "path": "\\".join(parts),
        "keys": [{"name": i["name"], "subkeys": i["subkeys"]} for i in items if i["kind"] == "key"],
        "values": [{"name": i["name"] or "(default)", "type": _type_name(i["type"]), "data": _to_json(i["type"], i["data"])}
                   for i in items if i["kind"] == "value"],
    })
    return 0


def _cmd_get(args, options):
    if not 1 <= len(args) <= 2:
        raise RegeditError("usage: reg get <path> [name]", 2, "usage")
    parts = _parse_path(args[0])
    path = "\\".join(parts)
    if len(args) == 1:
        subkeys, values, modified = _key_details(parts)
        if options["json"]:
            _core.print_json({"path": path, "subkeys": subkeys, "values": values, "last_changed": modified})
        else:
            Editor()._key_info(parts)
        return 0
    name = _value_name(args[1])
    found = _read_value(parts, name)
    if found is None:
        if not _key_exists(parts):
            raise RegeditError(f"the key {path} does not exist", 2, "not_found")
        raise RegeditError(f"no value called {args[1]} in {path}", 2, "not_found")
    data, kind = found
    if options["json"]:
        _core.print_json({"path": path, "name": name or "(default)", "exists": True,
                          "type": _type_name(kind), "data": _to_json(kind, data)})
    else:
        _print_value(name, kind, data)
    return 0


def _cmd_set(args, options):
    rest, kind = _core.take_option(args, "--type")
    rest, value = _core.take_option(rest, "--value")
    if len(rest) != 2 or value is None:
        raise RegeditError("usage: reg set <path> <name> --type <t> --value <v>", 2, "usage")
    params = {"path": rest[0], "name": rest[1], "value": value}
    if kind is not None:
        params["type"] = kind
    return _change("set", params, options)


def _cmd_del(args, options):
    if len(args) != 2:
        raise RegeditError("usage: reg del <path> <name>", 2, "usage")
    return _change("del", {"path": args[0], "name": args[1]}, options)


def _cmd_mkkey(args, options):
    if len(args) != 1:
        raise RegeditError("usage: reg mkkey <path>", 2, "usage")
    return _change("mkkey", {"path": args[0]}, options)


def _cmd_rmkey(args, options):
    if len(args) != 1:
        raise RegeditError("usage: reg rmkey <path>", 2, "usage")
    return _change("rmkey", {"path": args[0]}, options)


DIRECT = {"ls": _cmd_ls, "get": _cmd_get, "set": _cmd_set, "del": _cmd_del, "mkkey": _cmd_mkkey, "rmkey": _cmd_rmkey}


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "regedit"
# ======================================================================
def _editor():
    """Open the editor. It keeps control until the user exits."""
    editor = Editor()
    os.system("")  # enables ANSI colour codes in the Windows console
    print(_core.BLUE + "regedit: the Windows registry. Type a number to open it, help for commands, 0 to leave."
          + _core.RESET)
    editor._show_list([])
    print(_core.BLUE + PROMPT_BAR + _core.RESET)
    while True:
        try:
            line = input(editor.prompt())
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        tokens = _tokens(line.strip())
        if not tokens:
            continue
        try:
            if not editor.run(tokens):
                return 0
        except _core.CommandError as error:
            print(f"error: {error}", file=sys.stderr)
        except OSError as error:
            print(f"error: {_os_error(error)}", file=sys.stderr)


def _dispatch(args, options):
    if not args:
        if any(options.values()):
            raise RegeditError("the editor takes no flags. Use one command, e.g. reg get <path> [name]", 2, "usage")
        return _editor()
    word = args[0].lower()
    if word in HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    if word not in DIRECT:
        raise RegeditError(f"unknown command: {args[0]}\nusage: {USAGE}", 2, "usage")
    if options["dry_run"] and word not in ("set", "del", "mkkey", "rmkey"):
        raise RegeditError(f"reg {word} changes nothing, so --dry-run does nothing", 2, "usage")
    return DIRECT[word](args[1:], options)


def run(args):
    """Run one registry command, or open the editor with no words. Returns an exit code."""
    args, options = _core.split_flags(args, _core.DRY_FLAGS)
    try:
        return _dispatch(args, options)
    except _core.CommandError as error:
        return _core.report_error(error)
    except OSError as error:
        return _core.report_error(_os_error(error))


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

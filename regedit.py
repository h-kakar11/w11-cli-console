"""
regedit: an interactive Windows Registry Editor. Routed from app.py ("regedit").

    regedit          open the editor. The root hives are listed with numbers
    inside the editor:
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
Quote names and paths that have spaces. Paths use \\ or /. Types: sz, expand_sz,
multi_sz (items separated by ;), dword, qword, binary (hex, e.g. 0A FF 10).

Changes go through the Windows registry API with Windows' own permissions. Nothing
is bypassed: an access-denied error is shown as it is. Deleting asks first, and a
key with anything under it means typing its name. The top two levels of each hive
can't be deleted. Changing HKLM needs an administrator terminal; HKCU does not.
"""

import datetime
import os
import re
import sys
import winreg

import _core

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "regedit"
ALIASES = []
SUMMARY = "Browse and edit the Windows registry, interactively"
USAGE = "regedit   (opens the editor; inside it, type help)"
HELP = [
    ("regedit", "open the registry editor, with the root hives numbered"),
    ("ls | cd <key> | pwd", "list the current key, move into a key, show the path"),
    ("get | add | set | rm", "read, create, change or delete a value"),
    ("mkdir | rmdir", "create a key, or delete one (asks first)"),
    ("3 | 0", "open item 3 from the list, or 0 to leave the editor"),
]
TIP = "Type help inside the editor for every command. Changing HKLM needs an administrator terminal."
RUN_ALONE = True  # typing 'regedit' on its own opens the editor

HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")
MIN_DELETE_PARTS = 3  # HKLM\SOFTWARE (2 parts) is too high up to delete; HKLM\SOFTWARE\Foo is not
ACCESS_DENIED = "access denied by Windows. Some keys need administrator rights (run the terminal as administrator)."
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


class RegeditError(Exception):
    """A problem with one editor command. The editor keeps running."""


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
    if isinstance(error, PermissionError):
        return RegeditError(ACCESS_DENIED)
    if isinstance(error, FileNotFoundError):
        return RegeditError("that key does not exist")
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
        raise RegeditError(f"unknown type {word}. Use sz, expand_sz, multi_sz, dword, qword or binary.")


def _parse_data(kind, text):
    if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        return text
    if kind == winreg.REG_MULTI_SZ:
        return text.split(";")
    if kind in (winreg.REG_DWORD, winreg.REG_QWORD):
        try:
            number = int(text, 0)
        except ValueError:
            raise RegeditError(f"{text} is not a number. Use decimal, or hex with 0x, e.g. 0x1F")
        limit = 2**32 if kind == winreg.REG_DWORD else 2**64
        if not 0 <= number < limit:
            raise RegeditError(f"{number} does not fit in {TYPE_NAMES[kind]} (0 to {limit - 1})")
        return number
    if kind == winreg.REG_BINARY:
        cleaned = re.sub(r"[\s,]", "", text)
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            raise RegeditError("binary data is hex, e.g. 0A FF 10")
    raise RegeditError(f"cannot write {TYPE_NAMES.get(kind, kind)}")


def _value_name(text):
    return "" if text.lower() in DEFAULT_NAMES else text


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
            shown = item["name"] or "(Default)"
            print(_core.BLUE + f"{shown}\n  type: {TYPE_NAMES.get(item['type'], item['type'])}\n"
                  f"  data: {_describe(item['type'], item['data'])}" + _core.RESET)
        elif item["kind"] == "key":
            self._key_info(self.path + [item["name"]])
        else:
            raise RegeditError("that is a hive. cd into it to see its keys")

    def _key_info(self, path):
        subkeys, values, modified = _key_details(path)
        print(_core.BLUE + f"{_text(path)}\n  subkeys: {subkeys}\n  values: {values}\n"
              f"  last changed: {modified}" + _core.RESET)

    # --- writing --------------------------------------------------------
    def _add(self, args):
        self._need_key()
        if len(args) not in (2, 3):
            raise RegeditError('usage: add <name> [type] <data>   e.g. add "Port" dword 8080')
        name = _value_name(args[0])
        kind, data_text = (winreg.REG_SZ, args[1]) if len(args) == 2 else (_parse_type(args[1]), args[2])
        if _read_value(self.path, name) is not None:
            raise RegeditError(f"{args[0]} already exists. Use set to change it.")
        _write_value(self.path, name, kind, _parse_data(kind, data_text))
        print(f"added {args[0]} ({TYPE_NAMES[kind]})")

    def _set(self, args):
        self._need_key()
        if len(args) not in (2, 3):
            raise RegeditError('usage: set <name> [type] <data>   e.g. set "Port" 9000')
        name = _value_name(args[0])
        existing = _read_value(self.path, name)
        if existing is None:
            raise RegeditError(f"{args[0]} does not exist here. Use add to create it.")
        kind = existing[1] if len(args) == 2 else _parse_type(args[1])
        data_text = args[1] if len(args) == 2 else args[2]
        _write_value(self.path, name, kind, _parse_data(kind, data_text))
        print(f"set {args[0]} ({TYPE_NAMES[kind]})")

    def _rm(self, args):
        self._need_key()
        if len(args) != 1:
            raise RegeditError("usage: rm <name|id>")
        item = self._find(args[0])
        if item["kind"] != "value":
            raise RegeditError("that is a key. Use rmdir to delete a key.")
        shown = item["name"] or "(Default)"
        if not _confirm(f"Delete the value {shown} from {_text(self.path)}? This can't be undone. [y/N]: "):
            print("cancelled")
            return
        _delete_value(self.path, item["name"])
        print(f"deleted {shown}")

    def _mkdir(self, args):
        self._need_key()
        if len(args) != 1:
            raise RegeditError("usage: mkdir <name>")
        _make_key(self.path, args[0])
        print(f"created key {args[0]}")

    def _rmdir(self, args):
        if len(args) != 1:
            raise RegeditError("usage: rmdir <name|id>")
        self._need_key()
        item = self._find(args[0])
        if item["kind"] != "key":
            raise RegeditError("that is not a key. Use rm to delete a value.")
        target = self.path + [item["name"]]
        if len(target) < MIN_DELETE_PARTS:
            raise RegeditError(f"{_text(target)} is too high up the registry to delete. Go into it and delete a smaller key.")
        subkeys, values, _ = _key_details(target)
        if subkeys or values:
            print(f"{item['name']} has {subkeys} subkey(s) and {values} value(s). Deleting it deletes everything under it.")
            typed = _ask(f"Type the key's name ({item['name']}) to delete it, or press Enter to cancel: ")
            if typed != item["name"]:
                print("cancelled")
                return
        elif not _confirm(f"Delete the empty key {item['name']}? This can't be undone. [y/N]: "):
            print("cancelled")
            return
        removed = []
        handle, subpath = _split(target)
        try:
            _delete_tree(handle, subpath, removed)
        except RegeditError as error:
            raise RegeditError(f"{error}. {len(removed)} key(s) were deleted before this.")
        print(f"deleted {item['name']} ({len(removed)} key(s) in all)")

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


def _confirm(question):
    try:
        return input(question).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _ask(question):
    try:
        return input(question).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "regedit"
# ======================================================================
def run(args):
    """Open the editor. It keeps control until the user exits, then returns an exit code."""
    if args:
        if args[0].lower() in HELP_WORDS:
            print(f"usage: {USAGE}")
            return 0
        print("error: regedit takes no words. Type regedit alone, then use the editor's commands.", file=sys.stderr)
        return 2
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
        except RegeditError as error:
            print(f"error: {error}", file=sys.stderr)
        except OSError as error:
            print(f"error: {error}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

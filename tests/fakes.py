"""
Stand-ins for Windows, so the tests run anywhere. They are NOT Windows: they prove this code's logic
(arguments, exit codes, confirmation, the undo journal, failures part-way through a batch), not that Windows
accepts the calls. tests/SMOKE.md says how to check the real thing on a disposable Windows machine.

  install()   put a fake winreg in sys.modules (before any page is imported) and return it
  Sandbox     a test case mixin: a fresh registry, a fresh data folder, an administrator switch, captured output
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HIVE_IDS = {name: 0x80000000 + number for number, name in enumerate(
    ["HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CURRENT_CONFIG"])}


class FakeKey:
    def __init__(self, node, path, access):
        self.node, self.path, self.access = node, path, access

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def build():
    """A new fake winreg module with an empty registry. fake.denied is a set of lower-case paths Windows refuses."""
    fake = types.ModuleType("winreg")
    for name, value in HIVE_IDS.items():
        setattr(fake, name, value)
    consts = dict(REG_NONE=0, REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3, REG_DWORD=4, REG_DWORD_BIG_ENDIAN=5,
                  REG_LINK=6, REG_MULTI_SZ=7, REG_QWORD=11, KEY_QUERY_VALUE=1, KEY_SET_VALUE=2, KEY_CREATE_SUB_KEY=4,
                  KEY_ENUMERATE_SUB_KEYS=8, KEY_READ=0x20019, KEY_WRITE=0x20006, KEY_ALL_ACCESS=0xF003F)
    for name, value in consts.items():
        setattr(fake, name, value)
    fake.roots = {hive: {"keys": {}, "values": {}} for hive in HIVE_IDS.values()}
    fake.denied = set()  # lower-case full paths such as "hklm\\software\\locked"
    fake.fail_on = {}  # {("SetValueEx", value name): OSError} to break one call
    write_bits = consts["KEY_SET_VALUE"] | consts["KEY_CREATE_SUB_KEY"] | 0x10000

    def walk(handle, sub, create=False):
        """(node, full path) for a hive handle or an open FakeKey plus a sub path."""
        if isinstance(handle, FakeKey):
            node, parts = handle.node, handle.path
        else:
            node, parts = fake.roots[handle], (handle,)
        for part in [p for p in sub.split("\\") if p]:
            low = part.lower()
            found = next((k for k in node["keys"] if k.lower() == low), None)
            if found is None:
                if not create:
                    raise FileNotFoundError(2, "The system cannot find the file specified")
                node["keys"][part] = {"keys": {}, "values": {}}
                found = part
            node = node["keys"][found]
            parts = parts + (found,)
        return node, parts

    def check(parts, access):
        text = "\\".join(str(p) for p in parts[1:]).lower()
        hive = {v: k for k, v in HIVE_IDS.items()}[parts[0]]
        full = {"HKEY_LOCAL_MACHINE": "hklm", "HKEY_CURRENT_USER": "hkcu", "HKEY_CLASSES_ROOT": "hkcr"}.get(hive, hive.lower())
        full = full + ("\\" + text if text else "")
        for blocked in fake.denied:
            if (full == blocked or full.startswith(blocked + "\\")) and access & (write_bits | 0x10000):
                raise PermissionError(5, "Access is denied")

    def OpenKey(handle, sub, reserved=0, access=0x20019):
        node, parts = walk(handle, sub)
        check(parts, access)
        return FakeKey(node, parts, access)

    def CreateKeyEx(handle, sub, reserved=0, access=0x20006):
        existing = None
        try:
            existing = walk(handle, sub)
        except FileNotFoundError:
            pass
        if existing is None:
            # permission check against the nearest existing parent
            segments = [p for p in sub.split("\\") if p]
            for end in range(len(segments), -1, -1):
                try:
                    _, parts = walk(handle, "\\".join(segments[:end]))
                    check(parts, write_bits)
                    break
                except FileNotFoundError:
                    continue
        node, parts = walk(handle, sub, create=True)
        check(parts, access)
        return FakeKey(node, parts, access)

    def EnumKey(key, index):
        names = list(key.node["keys"])
        if index >= len(names):
            raise OSError(259, "No more data")
        return names[index]

    def EnumValue(key, index):
        items = list(key.node["values"].items())
        if index >= len(items):
            raise OSError(259, "No more data")
        name, (data, kind) = items[index]
        return name, data, kind

    def QueryValueEx(key, name):
        for existing, (data, kind) in key.node["values"].items():
            if existing.lower() == name.lower():
                return data, kind
        raise FileNotFoundError(2, "The system cannot find the file specified")

    def QueryInfoKey(key):
        return len(key.node["keys"]), len(key.node["values"]), 0

    def SetValueEx(key, name, reserved, kind, data):
        failure = fake.fail_on.get(("SetValueEx", name))
        if failure:
            raise failure
        if not key.access & 2:
            raise PermissionError(5, "Access is denied")
        for existing in list(key.node["values"]):
            if existing.lower() == name.lower():
                del key.node["values"][existing]
        key.node["values"][name] = (data, kind)

    def DeleteValue(key, name):
        for existing in list(key.node["values"]):
            if existing.lower() == name.lower():
                del key.node["values"][existing]
                return
        raise FileNotFoundError(2, "The system cannot find the file specified")

    def DeleteKey(handle, sub):
        parent_path, _, leaf = sub.rpartition("\\")
        parent, parts = walk(handle, parent_path)
        check(parts + (leaf,), write_bits)
        found = next((k for k in parent["keys"] if k.lower() == leaf.lower()), None)
        if found is None:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        child = parent["keys"][found]
        if child["keys"]:
            raise OSError(145, "The directory is not empty")
        del parent["keys"][found]

    for function in (OpenKey, CreateKeyEx, EnumKey, EnumValue, QueryValueEx, QueryInfoKey, SetValueEx, DeleteValue, DeleteKey):
        setattr(fake, function.__name__, function)
    fake.HKEY_ID = HIVE_IDS
    return fake


def put(fake, path, **values):
    """Make a key (and its parents) with values: put(fake, 'HKCU\\Software\\X', Port=(80, fake.REG_DWORD))."""
    names = {"HKCU": fake.HKEY_CURRENT_USER, "HKLM": fake.HKEY_LOCAL_MACHINE, "HKCR": fake.HKEY_CLASSES_ROOT}
    head, _, rest = path.partition("\\")
    node, _ = _walk_create(fake, names[head], rest)
    for name, pair in values.items():
        node["values"][name] = pair
    return node


def _walk_create(fake, hive, rest):
    node = fake.roots[hive]
    for part in [p for p in rest.split("\\") if p]:
        node = node["keys"].setdefault(part, {"keys": {}, "values": {}})
    return node, None


def get(fake, path):
    """The node at a path, or None."""
    names = {"HKCU": fake.HKEY_CURRENT_USER, "HKLM": fake.HKEY_LOCAL_MACHINE, "HKCR": fake.HKEY_CLASSES_ROOT}
    head, _, rest = path.partition("\\")
    node = fake.roots[names[head]]
    for part in [p for p in rest.split("\\") if p]:
        found = next((k for k in node["keys"] if k.lower() == part.lower()), None)
        if found is None:
            return None
        node = node["keys"][found]
    return node


# One fake winreg for the whole test run: pages import it once. Each test empties and refills it.
FAKE = build()
sys.modules["winreg"] = FAKE


class Sandbox(unittest.TestCase):
    """A fresh registry and data folder for every test, plus run() helpers that capture output."""

    admin = True

    def setUp(self):
        import _core

        FAKE.roots = {hive: {"keys": {}, "values": {}} for hive in HIVE_IDS.values()}
        FAKE.denied = set()
        FAKE.fail_on = {}
        self.data = tempfile.mkdtemp(prefix="w11-tests-")
        self.addCleanup(shutil.rmtree, self.data, True)
        patch = unittest.mock.patch.dict(os.environ, {"LOCALAPPDATA": self.data})
        patch.start()
        self.addCleanup(patch.stop)
        self.admin_now = type(self).admin
        patch = unittest.mock.patch.object(_core, "is_admin", lambda: self.admin_now)
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(setattr, _core, "_registry", _core._registry)
        _core._registry = {}  # only the pages a test names; loading every page needs Windows-only modules
        self.answers = []
        patch = unittest.mock.patch("builtins.input", lambda prompt="": self._answer(prompt))
        patch.start()
        self.addCleanup(patch.stop)
        self.prompts = []

    def use(self, *modules):
        """Make these pages known to _core.registry(), the way app.py would (rollback finds a page by name)."""
        import _core

        for module in modules:
            for key in [module.NAME, *getattr(module, "ALIASES", [])]:
                _core._registry[key.lower()] = module

    def _answer(self, prompt):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def call(self, function, *args):
        """(exit code, stdout, stderr) of function(*args)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = function(*args)
        return code, out.getvalue(), err.getvalue()

    def journal(self):
        path = Path(self.data) / "w11-cli-console" / "journal.json"
        return json.loads(path.read_text()) if path.exists() else []


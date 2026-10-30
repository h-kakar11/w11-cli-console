"""
Stand-ins for the parts of Windows the tests must never touch.

The pages import winreg, ctypes.windll, pycaw and psutil at the top of the file, so on Linux (or any
machine without those) they are replaced here before a page is loaded. On Windows the real modules are
used for importing, but the tests still swap in FakeRegistry and block subprocess, so no test changes the PC.
"""

import sys
import types
from unittest import mock


class FakeRegistry:
    """A dictionary-backed winreg. Keys are (hive, lower-cased path); a key holds {name: (value, type)}."""

    HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE = 0x80000000, 0x80000001, 0x80000002
    HKEY_USERS, HKEY_CURRENT_CONFIG = 0x80000003, 0x80000005
    KEY_READ, KEY_WRITE, KEY_SET_VALUE, KEY_ALL_ACCESS = 0x20019, 0x20006, 0x2, 0xF003F
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN = 0, 1, 2, 3, 4, 5
    REG_MULTI_SZ, REG_QWORD = 7, 11
    error = OSError

    def __init__(self, deny_writes=False):
        self.keys = {}
        self.deny_writes = deny_writes  # True acts like a terminal that is not elevated: writes raise PermissionError
        self.writes = []                # every change that was attempted: ("set" | "delete", hive, path, name, value)

    class _Handle:
        def __init__(self, key):
            self.key = key

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def Close(self):
            pass

    @staticmethod
    def _norm(path):
        return path.strip("\\").lower()

    def put(self, hive, path, name=None, value=None, kind=None):
        """Test helper: create the key, and a value in it when a name is given."""
        values = self.keys.setdefault((hive, self._norm(path)), {})
        if name is not None:
            values[name] = (value, kind if kind is not None else self.REG_DWORD)

    def get(self, hive, path, name):
        return self.keys.get((hive, self._norm(path)), {}).get(name, (None,))[0]

    def OpenKey(self, hive, path, reserved=0, access=0):
        hive = hive.key[0] if isinstance(hive, self._Handle) else hive
        key = (hive, self._norm(path))
        if key not in self.keys:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return self._Handle(key)

    def CreateKeyEx(self, hive, path, reserved=0, access=0):
        if self.deny_writes:
            raise PermissionError(5, "Access is denied")
        hive = hive.key[0] if isinstance(hive, self._Handle) else hive
        self.keys.setdefault((hive, self._norm(path)), {})
        return self._Handle((hive, self._norm(path)))

    def CloseKey(self, handle):
        pass

    def QueryValueEx(self, handle, name):
        values = self.keys[handle.key]
        if name not in values:
            raise FileNotFoundError(2, "The system cannot find the file specified")
        return values[name]

    def SetValueEx(self, handle, name, reserved, kind, value):
        if self.deny_writes:
            raise PermissionError(5, "Access is denied")
        self.keys[handle.key][name] = (value, kind)
        self.writes.append(("set", *handle.key, name, value))

    def DeleteValue(self, handle, name):
        if self.deny_writes:
            raise PermissionError(5, "Access is denied")
        del self.keys[handle.key][name]
        self.writes.append(("delete", *handle.key, name, None))

    def DeleteKey(self, hive, path):
        if self.deny_writes:
            raise PermissionError(5, "Access is denied")
        self.keys.pop((hive, self._norm(path)), None)
        self.writes.append(("delete", hive, self._norm(path), None, None))

    def _children(self, handle):
        hive, path = handle.key
        prefix = path + "\\" if path else ""
        names = []
        for (h, p) in self.keys:
            if h == hive and p.startswith(prefix) and p != path:
                first = p[len(prefix):].split("\\")[0]
                if first not in names:
                    names.append(first)
        return names

    def EnumKey(self, handle, index):
        names = self._children(handle)
        if index >= len(names):
            raise OSError(259, "No more data is available")
        return names[index]

    def EnumValue(self, handle, index):
        items = list(self.keys[handle.key].items())
        if index >= len(items):
            raise OSError(259, "No more data is available")
        name, (value, kind) = items[index]
        return name, value, kind

    def QueryInfoKey(self, handle):
        return len(self._children(handle)), len(self.keys[handle.key]), 0


def install():
    """Make every page importable on a machine without Windows. Harmless on Windows."""
    if "winreg" not in sys.modules:
        try:
            import winreg  # noqa: F401
        except ImportError:
            module = types.ModuleType("winreg")
            fake = FakeRegistry()
            for name in dir(fake):
                if name.isupper() or name in ("error", "OpenKey", "CreateKeyEx", "CloseKey", "QueryValueEx", "SetValueEx",
                                              "DeleteValue", "DeleteKey", "EnumKey", "EnumValue", "QueryInfoKey"):
                    setattr(module, name, getattr(fake, name))
            sys.modules["winreg"] = module
    import ctypes
    if not hasattr(ctypes, "windll"):
        ctypes.windll = mock.MagicMock(name="windll")  # device.py reads ctypes.windll.cfgmgr32 at import time
    # a real attribute, not an auto-created one: monkeypatch deleting a MagicMock attribute makes it raise afterwards.
    # The default is "not an administrator", the safe answer if a test forgets to say.
    ctypes.windll.shell32.IsUserAnAdmin = lambda: 0
    try:
        import pycaw.pycaw  # noqa: F401
    except Exception:
        pkg, module = types.ModuleType("pycaw"), types.ModuleType("pycaw.pycaw")
        module.AudioUtilities = mock.MagicMock(name="AudioUtilities")
        pkg.pycaw = module
        sys.modules["pycaw"], sys.modules["pycaw.pycaw"] = pkg, module

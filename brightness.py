import ctypes
import subprocess
import sys
from ctypes import wintypes

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "brightness"
ALIASES = ["bn", "b", "bright", "brightness", "screen", "monitor", "display"]
SUMMARY = "Alter monitor screen brightness"
USAGE = "bn [set] <number> | bn get | bn up [step] | bn down [step]   (set is optional: bn 40 = bn set 40)"

# ======================================================================
# CONFIG
# ======================================================================
DEFAULT_STEP = 5  # percent per up/down when no step is given


class BrightnessError(Exception):
    """An error with an exit code: 1 for device errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# BRIGHTNESS — DDC/CI first, then WMI. Monitor handles are opened per
# command and released in close(), since each command is short-lived.
# ======================================================================
class _PhysicalMonitor(ctypes.Structure):
    _fields_ = [
        ("hPhysicalMonitor", wintypes.HANDLE),
        ("szPhysicalMonitorDescription", wintypes.WCHAR * 128),
    ]


MONITOR_DEFAULTTOPRIMARY = 1


def _powershell(script):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise BrightnessError(result.stderr.strip() or "PowerShell command failed")
    return result.stdout.strip()


class Brightness:
    def __init__(self):
        self.mode = ""
        self._handle = None
        self._monitors = None
        self._count = 0
        self._min = 0
        self._max = 100
        if not self._open_ddc():
            self._open_wmi()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- setup ---------------------------------------------------------
    def _open_ddc(self):
        try:
            user32 = ctypes.windll.user32
            dxva2 = ctypes.windll.dxva2
        except OSError:
            return False

        user32.MonitorFromWindow.restype = wintypes.HMONITOR
        user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
        hmon = user32.MonitorFromWindow(None, MONITOR_DEFAULTTOPRIMARY)
        if not hmon:
            return False

        n = wintypes.DWORD(0)
        if not dxva2.GetNumberOfPhysicalMonitorsFromHMONITOR(hmon, ctypes.byref(n)) or not n.value:
            return False

        monitors = (_PhysicalMonitor * n.value)()
        if not dxva2.GetPhysicalMonitorsFromHMONITOR(hmon, n, monitors):
            return False

        handle = monitors[0].hPhysicalMonitor
        mn, cur, mx = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        if dxva2.GetMonitorBrightness(handle, ctypes.byref(mn), ctypes.byref(cur), ctypes.byref(mx)):
            self.mode = "ddc"
            self._handle = handle
            self._monitors = monitors
            self._count = n.value
            self._min = mn.value
            self._max = mx.value if mx.value > mn.value else 100
            return True

        dxva2.DestroyPhysicalMonitors(n, monitors)
        return False

    def _open_wmi(self):
        try:
            out = _powershell(
                "@(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness"
                " -ErrorAction Stop).Count"
            )
        except (BrightnessError, OSError):
            return
        if out.isdigit() and int(out) > 0:
            self.mode = "wmi"

    def close(self):
        if self.mode == "ddc" and self._monitors is not None:
            try:
                ctypes.windll.dxva2.DestroyPhysicalMonitors(self._count, self._monitors)
            except OSError:
                pass
            self._monitors = None

    # -- get / set -----------------------------------------------------
    def get(self):
        if self.mode == "ddc":
            mn, cur, mx = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
            if ctypes.windll.dxva2.GetMonitorBrightness(
                self._handle, ctypes.byref(mn), ctypes.byref(cur), ctypes.byref(mx)
            ):
                span = mx.value - mn.value
                return round((cur.value - mn.value) * 100 / span) if span > 0 else cur.value
            raise BrightnessError("DDC/CI read failed")
        if self.mode == "wmi":
            out = _powershell(
                "(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness"
                " | Select-Object -First 1).CurrentBrightness"
            )
            if out.isdigit():
                return int(out)
        raise BrightnessError("WMI brightness read failed")

    def set(self, pct):
        pct = max(0, min(100, round(pct)))
        if self.mode == "ddc":
            raw = self._min + round((self._max - self._min) * pct / 100)
            if not ctypes.windll.dxva2.SetMonitorBrightness(self._handle, wintypes.DWORD(raw)):
                raise BrightnessError("DDC/CI write failed")
        elif self.mode == "wmi":
            _powershell(
                "Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightnessMethods"
                " | Invoke-CimMethod -MethodName WmiSetBrightness"
                f" -Arguments @{{Timeout=[uint32]1; Brightness=[byte]{pct}}} | Out-Null"
            )
        return pct


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "brightness"/"bn"
# ======================================================================
def _number(text, message):
    try:
        return float(text)
    except (TypeError, ValueError):
        raise BrightnessError(message, 2)


def _is_number(text):
    try:
        float(text)
        return True
    except (TypeError, ValueError):
        return False


def _dispatch(args):
    sub = args[0].lower()
    arg = args[1] if len(args) > 1 else None

    if sub not in ("get", "set", "up", "down", "info"):
        raise BrightnessError(f"unknown brightness command: {args[0]}\nusage: brightness {USAGE}", 2)

    if sub == "set":
        value = _number(arg, "set needs a number from 0 to 100")
    elif sub in ("up", "down"):
        value = DEFAULT_STEP if arg is None else _number(arg, f"{sub} needs a number for the step size")

    with Brightness() as b:
        if not b.mode:
            raise BrightnessError(
                "no brightness control found. Turn on DDC/CI in the monitor's OSD menu,"
                " or run on a laptop panel."
            )
        if sub == "info":
            print(b.mode)
        elif sub == "get":
            print(b.get())
        elif sub == "set":
            print(b.set(value))
        elif sub == "up":
            print(b.set(b.get() + value))
        elif sub == "down":
            print(b.set(b.get() - value))


def run(args):
    """Run one brightness command; returns an exit code."""
    if not args:
        print(f"error: usage: brightness {USAGE}", file=sys.stderr)
        return 2
    if args[0].lower() in ("help", "-h", "--help", "?"):
        print(f"usage: brightness {USAGE}")
        return 0
    # "set" is optional: "bn 40" means "bn set 40"
    if _is_number(args[0]):
        args = ["set", *args]
    try:
        _dispatch(args)
        return 0
    except BrightnessError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

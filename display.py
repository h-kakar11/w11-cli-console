"""
display: resolution, refresh rate, orientation, HDR, arrangement and scale, the same as Settings > System >
Display. Routed from app.py ("display", "dsp", "res" or "resolution").

    dsp                           each display: resolution, refresh rate, scale, HDR and where it sits
    dsp <id>                      one display in full, and what could be better
    dsp <id> modes [--all]        the resolutions and refresh rates it supports
    dsp <id> res <W>x<H> [@hz]    change the resolution (1080p, 1440p and 4k work too)
    dsp <id> hz <hz>              change the refresh rate
    dsp <id> rotate 0|90|180|270  change the orientation (landscape, portrait, and the two flipped ones)
    dsp <id> primary              make it the main display
    dsp <id> right-of|left-of|above|below <id>    place it next to another display; or dsp <id> pos <x> <y>
    dsp layout                    draw where the displays sit
    dsp <id> hdr on|off           turn HDR on or off
    dsp project internal|external|duplicate|extend      the Win+P choices
    dsp scale                     each display's scale and the one Windows recommends
    dsp nightlight                opens Settings (Windows has no way for a program to read or change Night light)
    dsp brightness [n]            the same as bn
    dsp identify | dsp open       where each display is | open Settings > Display

Without an id the main display is used, so "dsp res 1920x1080" and "res 1080p" change the main display.
Nothing here needs administrator rights.

A change to the picture can leave the screen black, so Windows' own rule is followed: the old setting comes back
after 15 seconds unless y is pressed. res, hz and rotate are applied without being saved. primary, pos and placement
have to be saved to be applied together, so they are put back by this program if the answer is no or the time runs
out; if this program is killed during the 15 seconds, the new arrangement stays (fix it with 'dsp layout'). With --yes (an agent whose person already agreed) the change is tested and saved
straight away. Where a console is not available, the change is only made after a y/N question.

Everything goes through the documented display functions in user32 and shcore (EnumDisplayDevices,
EnumDisplaySettingsEx, ChangeDisplaySettingsEx, EnumDisplayMonitors, GetDpiForMonitor, QueryDisplayConfig,
DisplayConfigGetDeviceInfo, DisplayConfigSetDeviceInfo, SetDisplayConfig). The one thing read from an
undocumented place is the scale Windows recommends, which is only read, never written (see _scale_choices).
Windows has no documented way for a program to change the scale or Night light, so those open Settings.
"""

import contextlib
import ctypes
import os
import re
import sys
import time
from ctypes import (POINTER, Structure, Union, byref, c_int16, c_int32, c_ssize_t, c_uint16, c_uint32, c_uint64,
                    c_void_p, c_wchar_p)

import _core
import _net
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "display"
ALIASES = ["dsp", "res", "resolution"]
SUMMARY = "Resolution, refresh rate, HDR, layout and scale"
# extra words people use, for 'settings search'
KEYWORDS = ["monitor", "resolution", "refresh rate", "hz", "hdr", "night light", "scale", "dpi", "rotate",
            "orientation", "multiple monitors", "extend", "duplicate", "screen"]
USAGE = ("dsp | dsp <id> | dsp <id> modes | dsp <id> res <W>x<H> [@hz] | dsp <id> hz <hz> | dsp <id> rotate 0|90|180|270 | "
         "dsp <id> primary | dsp <id> right-of|left-of|above|below <id> | dsp <id> pos <x> <y> | dsp <id> hdr on|off | "
         "dsp project extend|duplicate|internal|external | dsp layout | dsp scale | dsp nightlight | dsp brightness [n]")
HELP = [
    ("dsp", "list the displays: resolution, refresh rate, scale and HDR"),
    ("dsp <id>", "one display in full, and what could be better"),
    ("dsp <id> res <W>x<H>", "change the resolution, e.g. dsp 1 res 1920x1080 (1080p, 1440p and 4k work too)"),
    ("dsp <id> hz <hz>", "change the refresh rate, e.g. dsp 1 hz 144"),
    ("dsp <id> modes", "every resolution and refresh rate the display supports"),
    ("dsp project extend", "the Win+P choices: extend, duplicate, internal (PC screen only), external"),
    ("", "arrangement"),
    ("dsp layout", "draw where the displays sit"),
    ("dsp <id> primary", "make a display the main one"),
    ("dsp 2 right-of 1", "place a display next to another (left-of, above, below), or: dsp 2 pos 1920 0"),
    ("", "more"),
    ("dsp <id> rotate 0|90|180|270", "landscape, portrait, and the two flipped ones"),
    ("dsp <id> hdr on|off", "turn HDR on or off, where the display supports it"),
    ("dsp scale", "each display's scale, and the one Windows recommends"),
    ("dsp nightlight", "opens Settings: Windows has no way for a program to change Night light"),
    ("dsp brightness [n]", "the same as bn"),
    ("dsp identify", "which display is which, and where each one sits"),
    ("dsp open", "open Settings > System > Display"),
]
TIP = ("Nothing here needs administrator rights. A change to the picture goes back after 15 seconds unless you "
       "press y, so a bad mode does not leave you on a black screen. Ids shift when a display is plugged in or out: run 'dsp' first. "
       "Without an id, the main display is used.")
RUN_ALONE = True  # typing 'dsp' on its own lists the displays, which changes nothing

LIST_WORDS = ("ls", "list")
KEEP_SECONDS = 15  # how long a changed picture stays before it goes back, the same as Settings
MAX_MODES = 4000  # a safety stop when asking a driver for its modes
MAP_COLUMNS = 66  # how wide `dsp layout` draws the arrangement

# ======================================================================
# CONSTANTS — values from winuser.h and wingdi.h
# ======================================================================
ENUM_CURRENT_SETTINGS = 0xFFFFFFFF  # (DWORD)-1: the mode in use now
ENUM_REGISTRY_SETTINGS = 0xFFFFFFFE  # (DWORD)-2: the mode saved for next time
EDS_RAWMODE = 0x2  # also list modes the monitor does not report as supported
CDS_UPDATEREGISTRY, CDS_TEST, CDS_SET_PRIMARY, CDS_NORESET = 0x1, 0x2, 0x10, 0x10000000
DM_POSITION, DM_DISPLAYORIENTATION, DM_BITSPERPEL = 0x20, 0x80, 0x40000
DM_PELSWIDTH, DM_PELSHEIGHT, DM_DISPLAYFREQUENCY = 0x80000, 0x100000, 0x400000
DM_INTERLACED = 0x2  # in dmDisplayFlags
DISPLAY_DEVICE_ATTACHED_TO_DESKTOP, DISPLAY_DEVICE_PRIMARY_DEVICE, DISPLAY_DEVICE_MIRRORING_DRIVER = 0x1, 0x4, 0x8
QDC_ALL_PATHS, QDC_ONLY_ACTIVE_PATHS = 0x1, 0x2
DISPLAYCONFIG_PATH_ACTIVE = 0x1
ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED = 122, 87, 50
MDT_EFFECTIVE_DPI = 0
DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
PROCESS_PER_MONITOR_DPI_AWARE = 2
# DISPLAYCONFIG_DEVICE_INFO_TYPE
GET_SOURCE_NAME, GET_TARGET_NAME, GET_TARGET_PREFERRED_MODE = 1, 2, 3
GET_ADVANCED_COLOR_INFO, SET_ADVANCED_COLOR_STATE, GET_SDR_WHITE_LEVEL = 9, 10, 11
GET_ADVANCED_COLOR_INFO_2, SET_HDR_STATE = 15, 16
GET_DPI_SCALE = -3  # not in the SDK headers; only ever used to read
SDC_APPLY = 0x80
SDC_TOPOLOGY = {"internal": 0x1, "duplicate": 0x2, "extend": 0x4, "external": 0x8}
DISPLAYSWITCH_ARGUMENTS = {"internal": "/internal", "duplicate": "/clone", "extend": "/extend", "external": "/external"}

# What ChangeDisplaySettingsEx returns when it does not return 0 (DISP_CHANGE_*)
CHANGE_RESULTS = {
    -1: "Windows could not change the display (the driver refused)",
    -2: "this display does not support that mode",
    -3: "Windows could not save the setting",
    -4: "Windows was given a bad flag (this is a bug in this page)",
    -5: "Windows was given a bad value (this is a bug in this page)",
    -6: "the displays cannot be set up that way together",
}
RESTART_NEEDED = 1  # DISP_CHANGE_RESTART: it worked, but only after a restart

# DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY, as unsigned numbers
OUTPUT_TECHNOLOGY = {
    0xFFFFFFFF: "other", 0: "VGA", 1: "S-Video", 2: "composite", 3: "component", 4: "DVI", 5: "HDMI",
    6: "built-in panel (LVDS)", 8: "D-Jpn", 9: "SDI", 10: "DisplayPort", 11: "built-in panel (DisplayPort)", 12: "UDI",
    13: "built-in panel (UDI)", 14: "TV dongle", 15: "Miracast (wireless)", 16: "USB or network display",
    17: "virtual display", 18: "DisplayPort over USB", 0x80000000: "built-in panel",
}
BUILT_IN = {6, 11, 13, 0x80000000}

ORIENTATIONS = {0: "landscape", 90: "portrait", 180: "landscape (flipped)", 270: "portrait (flipped)"}
# DMDO_DEFAULT, DMDO_90, DMDO_180, DMDO_270
DMDO = {0: 0, 90: 1, 180: 2, 270: 3}
ORIENTATION_WORDS = {
    "0": 0, "landscape": 0, "normal": 0, "default": 0,
    "90": 90, "portrait": 90,
    "180": 180, "landscape-flipped": 180, "flipped-landscape": 180,
    "270": 270, "portrait-flipped": 270, "flipped-portrait": 270,
}
# Settings' scale choices, in order. Windows names a display's range relative to the recommended one.
SCALE_STEPS = (100, 125, 150, 175, 200, 225, 250, 300, 350, 400, 450, 500)
RESOLUTION_NAMES = {"720p": (1280, 720), "1080p": (1920, 1080), "1440p": (2560, 1440), "2160p": (3840, 2160),
                    "4k": (3840, 2160)}
RESOLUTION = re.compile(r"(\d{3,5})\s*[x×*]\s*(\d{3,5})(?:\s*@?\s*(\d{2,3})\s*(?:hz)?)?", re.I)
PROJECT_WORDS = {
    "internal": "internal", "pc": "internal", "pc-only": "internal", "pc-screen": "internal", "laptop": "internal",
    "external": "external", "second": "external", "second-screen": "external", "second-only": "external",
    "duplicate": "duplicate", "clone": "duplicate", "mirror": "duplicate",
    "extend": "extend", "extended": "extend",
}
PROJECT_TEXT = {
    "internal": "PC screen only", "external": "second screen only", "duplicate": "duplicate (the same picture on every display)",
    "extend": "extend (the desktop spans every display)",
}
PLACE_WORDS = {"right-of": "right", "rightof": "right", "left-of": "left", "leftof": "left",
               "above": "above", "over": "above", "below": "below", "under": "below"}
MODE_WORDS = ("modes", "mode")
RES_WORDS = ("res", "resolution")
HZ_WORDS = ("hz", "refresh", "refreshrate")
ROTATE_WORDS = ("rotate", "rotation", "orientation")
POS_WORDS = ("pos", "position", "move")
IMPLICIT_WORDS = (*MODE_WORDS, *RES_WORDS, *HZ_WORDS, *ROTATE_WORDS, "hdr", "primary", *POS_WORDS)


class DisplayError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# WINDOWS STRUCTURES — fixed-size types only (a Windows LONG is 32 bits and a WCHAR is 16, whatever Python
# is running on), so the sizes are the SDK's: DEVMODEW 220, DISPLAY_DEVICEW 840, MONITORINFOEXW 104,
# DISPLAYCONFIG_PATH_INFO 72, DISPLAYCONFIG_MODE_INFO 64
# ======================================================================
class _Devmode(Structure):
    """DEVMODEW. The 16 bytes after dmFields are a union; this is its display variant (position, orientation)."""
    _fields_ = [
        ("dmDeviceName", c_uint16 * 32), ("dmSpecVersion", c_uint16), ("dmDriverVersion", c_uint16),
        ("dmSize", c_uint16), ("dmDriverExtra", c_uint16), ("dmFields", c_uint32),
        ("dmPositionX", c_int32), ("dmPositionY", c_int32), ("dmDisplayOrientation", c_uint32),
        ("dmDisplayFixedOutput", c_uint32),
        ("dmColor", c_int16), ("dmDuplex", c_int16), ("dmYResolution", c_int16), ("dmTTOption", c_int16),
        ("dmCollate", c_int16), ("dmFormName", c_uint16 * 32), ("dmLogPixels", c_uint16),
        ("dmBitsPerPel", c_uint32), ("dmPelsWidth", c_uint32), ("dmPelsHeight", c_uint32),
        ("dmDisplayFlags", c_uint32), ("dmDisplayFrequency", c_uint32), ("dmICMMethod", c_uint32),
        ("dmICMIntent", c_uint32), ("dmMediaType", c_uint32), ("dmDitherType", c_uint32),
        ("dmReserved1", c_uint32), ("dmReserved2", c_uint32), ("dmPanningWidth", c_uint32),
        ("dmPanningHeight", c_uint32),
    ]


class _DisplayDevice(Structure):
    _fields_ = [("cb", c_uint32), ("DeviceName", c_uint16 * 32), ("DeviceString", c_uint16 * 128),
                ("StateFlags", c_uint32), ("DeviceID", c_uint16 * 128), ("DeviceKey", c_uint16 * 128)]


class _Rect(Structure):
    _fields_ = [("left", c_int32), ("top", c_int32), ("right", c_int32), ("bottom", c_int32)]


class _MonitorInfo(Structure):
    """MONITORINFOEXW"""
    _fields_ = [("cbSize", c_uint32), ("rcMonitor", _Rect), ("rcWork", _Rect), ("dwFlags", c_uint32),
                ("szDevice", c_uint16 * 32)]


class _Luid(Structure):
    _fields_ = [("low", c_uint32), ("high", c_int32)]


class _Rational(Structure):
    _fields_ = [("num", c_uint32), ("den", c_uint32)]


class _SourceInfo(Structure):
    """DISPLAYCONFIG_PATH_SOURCE_INFO (20 bytes). The union is read as one number: nothing here needs its bit fields."""
    _fields_ = [("adapter", _Luid), ("id", c_uint32), ("modeInfoIdx", c_uint32), ("statusFlags", c_uint32)]


class _TargetInfo(Structure):
    """DISPLAYCONFIG_PATH_TARGET_INFO (48 bytes)"""
    _fields_ = [("adapter", _Luid), ("id", c_uint32), ("modeInfoIdx", c_uint32), ("outputTechnology", c_int32),
                ("rotation", c_int32), ("scaling", c_int32), ("refreshRate", _Rational), ("scanLineOrdering", c_int32),
                ("targetAvailable", c_int32), ("statusFlags", c_uint32)]


class _PathInfo(Structure):
    _fields_ = [("source", _SourceInfo), ("target", _TargetInfo), ("flags", c_uint32)]


class _VideoSignal(Structure):
    """DISPLAYCONFIG_VIDEO_SIGNAL_INFO (48 bytes, 8-byte aligned because of the 64-bit pixel rate)"""
    _fields_ = [("pixelRate", c_uint64), ("hSyncFreq", _Rational), ("vSyncFreq", _Rational),
                ("activeSize", c_uint32 * 2), ("totalSize", c_uint32 * 2), ("videoStandard", c_uint32),
                ("scanLineOrdering", c_int32)]


class _SourceMode(Structure):
    _fields_ = [("width", c_uint32), ("height", c_uint32), ("pixelFormat", c_int32), ("x", c_int32), ("y", c_int32)]


class _DesktopImage(Structure):
    _fields_ = [("sizeX", c_int32), ("sizeY", c_int32), ("region", _Rect), ("clip", _Rect)]


class _ModeUnion(Union):
    _fields_ = [("target", _VideoSignal), ("source", _SourceMode), ("image", _DesktopImage)]


class _ModeInfo(Structure):
    """DISPLAYCONFIG_MODE_INFO (64 bytes). Only its size matters here: the arrays are filled by Windows and not read."""
    _fields_ = [("infoType", c_int32), ("id", c_uint32), ("adapter", _Luid), ("mode", _ModeUnion)]


class _Header(Structure):
    """DISPLAYCONFIG_DEVICE_INFO_HEADER (20 bytes): which kind of question, how big the packet is, and about what."""
    _fields_ = [("type", c_int32), ("size", c_uint32), ("adapter", _Luid), ("id", c_uint32)]


class _SourceName(Structure):
    _fields_ = [("header", _Header), ("viewGdiDeviceName", c_uint16 * 32)]


class _TargetName(Structure):
    _fields_ = [("header", _Header), ("flags", c_uint32), ("outputTechnology", c_int32), ("edidManufactureId", c_uint16),
                ("edidProductCodeId", c_uint16), ("connectorInstance", c_uint32),
                ("monitorFriendlyDeviceName", c_uint16 * 64), ("monitorDevicePath", c_uint16 * 128)]


class _PreferredMode(Structure):
    _fields_ = [("header", _Header), ("width", c_uint32), ("height", c_uint32), ("signal", _VideoSignal)]


class _AdvancedColor(Structure):
    """DISPLAYCONFIG_GET_ADVANCED_COLOR_INFO: bit 0 supported, 1 enabled, 2 wide colour enforced, 3 forced off."""
    _fields_ = [("header", _Header), ("value", c_uint32), ("colorEncoding", c_int32), ("bitsPerColorChannel", c_uint32)]


class _AdvancedColor2(Structure):
    """DISPLAYCONFIG_GET_ADVANCED_COLOR_INFO_2 (Windows 11 22H2 and later): bit 0 advanced colour supported, 1 active,
    3 limited by policy, 4 HDR supported, 5 HDR turned on by the user, 6 wide colour supported, 7 wide colour on."""
    _fields_ = [("header", _Header), ("value", c_uint32), ("colorEncoding", c_int32), ("bitsPerColorChannel", c_uint32),
                ("activeColorMode", c_int32)]


class _SetState(Structure):
    """DISPLAYCONFIG_SET_HDR_STATE and DISPLAYCONFIG_SET_ADVANCED_COLOR_STATE: bit 0 turns it on."""
    _fields_ = [("header", _Header), ("value", c_uint32)]


class _SdrWhite(Structure):
    _fields_ = [("header", _Header), ("level", c_uint32)]


class _DpiScale(Structure):
    """What Settings reads for its Scale list: the lowest, current and highest choice, each relative to the recommended."""
    _fields_ = [("header", _Header), ("minScaleRel", c_int32), ("curScaleRel", c_int32), ("maxScaleRel", c_int32)]


def _wstr(chars):
    """A fixed-size WCHAR array as text, up to the first NUL."""
    codes = []
    for code in chars:
        if not code:
            break
        codes.append(code)
    return b"".join(code.to_bytes(2, "little") for code in codes).decode("utf-16-le", errors="replace")


# ======================================================================
# WINDOWS CALLS — one place that knows the argument types, so the rest reads as plain Python
# ======================================================================
_api_cache = None
_aware = False


class _Api:
    def __init__(self):
        self.user32 = ctypes.windll.user32
        try:
            self.shcore = ctypes.windll.shcore
        except (AttributeError, OSError):
            self.shcore = None
        user32 = self.user32
        self.monitor_proc = ctypes.WINFUNCTYPE(c_int32, c_void_p, c_void_p, POINTER(_Rect), c_ssize_t)
        user32.EnumDisplayDevicesW.argtypes = [c_wchar_p, c_uint32, POINTER(_DisplayDevice), c_uint32]
        user32.EnumDisplayDevicesW.restype = c_int32
        user32.EnumDisplaySettingsExW.argtypes = [c_wchar_p, c_uint32, POINTER(_Devmode), c_uint32]
        user32.EnumDisplaySettingsExW.restype = c_int32
        user32.ChangeDisplaySettingsExW.argtypes = [c_wchar_p, POINTER(_Devmode), c_void_p, c_uint32, c_void_p]
        user32.ChangeDisplaySettingsExW.restype = c_int32
        user32.EnumDisplayMonitors.argtypes = [c_void_p, c_void_p, self.monitor_proc, c_ssize_t]
        user32.EnumDisplayMonitors.restype = c_int32
        user32.GetMonitorInfoW.argtypes = [c_void_p, POINTER(_MonitorInfo)]
        user32.GetMonitorInfoW.restype = c_int32
        user32.GetDisplayConfigBufferSizes.argtypes = [c_uint32, POINTER(c_uint32), POINTER(c_uint32)]
        user32.GetDisplayConfigBufferSizes.restype = c_int32
        user32.QueryDisplayConfig.argtypes = [c_uint32, POINTER(c_uint32), POINTER(_PathInfo), POINTER(c_uint32),
                                              POINTER(_ModeInfo), c_void_p]
        user32.QueryDisplayConfig.restype = c_int32
        user32.DisplayConfigGetDeviceInfo.argtypes = [c_void_p]
        user32.DisplayConfigGetDeviceInfo.restype = c_int32
        user32.DisplayConfigSetDeviceInfo.argtypes = [c_void_p]
        user32.DisplayConfigSetDeviceInfo.restype = c_int32
        user32.SetDisplayConfig.argtypes = [c_uint32, c_void_p, c_uint32, c_void_p, c_uint32]
        user32.SetDisplayConfig.restype = c_int32
        if self.shcore is not None:
            self.shcore.GetDpiForMonitor.argtypes = [c_void_p, c_int32, POINTER(c_uint32), POINTER(c_uint32)]
            self.shcore.GetDpiForMonitor.restype = c_int32


def _api():
    global _api_cache
    if _api_cache is None:
        _api_cache = _Api()
    return _api_cache


def _dpi_aware():
    """Ask Windows for real pixel sizes and the real DPI of each monitor. A program that is not DPI aware is told
    96 DPI everywhere. Done once, and only when a command runs (not when the page is loaded, which would change every
    other page in the same console). If the process already has an awareness, Windows refuses and nothing changes."""
    global _aware
    if _aware:
        return
    _aware = True
    api = _api()
    try:
        api.user32.SetProcessDpiAwarenessContext.argtypes = [c_void_p]
        api.user32.SetProcessDpiAwarenessContext.restype = c_int32
        if api.user32.SetProcessDpiAwarenessContext(c_void_p(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)):
            return
    except (AttributeError, OSError):
        pass
    try:
        api.shcore.SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE)
    except (AttributeError, OSError):
        pass


def _win_error(code):
    try:
        text = ctypes.FormatError(code).strip()
    except (OSError, ValueError):
        text = ""
    return f"{text} (error {code})" if text else f"error {code}"


def _devmode():
    mode = _Devmode()
    mode.dmSize = ctypes.sizeof(_Devmode)
    return mode


def _read_mode(device, which):
    """A display's mode as a DEVMODE: the one in use (ENUM_CURRENT_SETTINGS) or the saved one. None if Windows won't say."""
    mode = _devmode()
    if not _api().user32.EnumDisplaySettingsExW(device, which, byref(mode), 0):
        return None
    return mode


def _mode_dict(mode):
    """A DEVMODE as the few numbers this page talks about."""
    if mode is None:
        return None
    return {"width": mode.dmPelsWidth, "height": mode.dmPelsHeight, "hz": mode.dmDisplayFrequency,
            "orientation": mode.dmDisplayOrientation * 90 if mode.dmFields & DM_DISPLAYORIENTATION else 0}


def _mode_list(device, raw=False):
    """Every mode the driver lists for a display."""
    modes, index = [], 0
    user32 = _api().user32
    while index < MAX_MODES:
        mode = _devmode()
        if not user32.EnumDisplaySettingsExW(device, index, byref(mode), EDS_RAWMODE if raw else 0):
            break
        modes.append({"width": mode.dmPelsWidth, "height": mode.dmPelsHeight, "hz": mode.dmDisplayFrequency,
                      "bits": mode.dmBitsPerPel, "interlaced": bool(mode.dmDisplayFlags & DM_INTERLACED)})
        index += 1
    return modes


def _change(device, mode, flags):
    """ChangeDisplaySettingsEx. device and mode are None for the final call that applies saved changes."""
    return _api().user32.ChangeDisplaySettingsExW(device, None if mode is None else byref(mode), None, flags, None)


def _adapters():
    """The display adapters whose screen is part of the desktop: [{"device", "adapter", "primary"}]."""
    found, index = [], 0
    user32 = _api().user32
    while index < 64:
        device = _DisplayDevice()
        device.cb = ctypes.sizeof(device)
        if not user32.EnumDisplayDevicesW(None, index, byref(device), 0):
            break
        index += 1
        flags = device.StateFlags
        if flags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP and not flags & DISPLAY_DEVICE_MIRRORING_DRIVER:
            found.append({"device": _wstr(device.DeviceName), "adapter": _wstr(device.DeviceString),
                          "primary": bool(flags & DISPLAY_DEVICE_PRIMARY_DEVICE)})
    return found


def _monitor_text(device_name):
    """(description, hardware id) of the monitor on an adapter output, e.g. ("Generic PnP Monitor", "MONITOR\\GSM5B7F\\...")."""
    monitor = _DisplayDevice()
    monitor.cb = ctypes.sizeof(monitor)
    if _api().user32.EnumDisplayDevicesW(device_name, 0, byref(monitor), 0):
        return _wstr(monitor.DeviceString), _wstr(monitor.DeviceID)
    return None, None


def _monitor_handles():
    """{lower-case device name: HMONITOR}, from EnumDisplayMonitors."""
    api = _api()
    found = {}

    def collect(hmonitor, hdc, rect, lparam):
        info = _MonitorInfo()
        info.cbSize = ctypes.sizeof(info)
        if api.user32.GetMonitorInfoW(hmonitor, byref(info)):
            found[_wstr(info.szDevice).lower()] = hmonitor
        return 1

    callback = api.monitor_proc(collect)  # kept in a variable so it is not freed while Windows calls it
    api.user32.EnumDisplayMonitors(None, None, callback, 0)
    return found


def _effective_dpi(hmonitor):
    api = _api()
    if hmonitor is None or api.shcore is None:
        return None
    dpi_x, dpi_y = c_uint32(), c_uint32()
    try:
        if api.shcore.GetDpiForMonitor(hmonitor, MDT_EFFECTIVE_DPI, byref(dpi_x), byref(dpi_y)) == 0 and dpi_x.value:
            return dpi_x.value
    except (AttributeError, OSError):
        pass
    return None


def _paths(all_paths=False):
    """The display paths Windows has: the active ones, or every possible one. [] if Windows will not say."""
    user32 = _api().user32
    flags = QDC_ALL_PATHS if all_paths else QDC_ONLY_ACTIVE_PATHS
    for _ in range(3):  # the configuration can change between asking for the sizes and asking for the paths
        count_paths, count_modes = c_uint32(), c_uint32()
        if user32.GetDisplayConfigBufferSizes(flags, byref(count_paths), byref(count_modes)) != 0:
            return []
        paths = (_PathInfo * max(count_paths.value, 1))()
        modes = (_ModeInfo * max(count_modes.value, 1))()
        code = user32.QueryDisplayConfig(flags, byref(count_paths), paths, byref(count_modes), modes, None)
        if code == 0:
            return list(paths)[:count_paths.value]
        if code != ERROR_INSUFFICIENT_BUFFER:
            return []
    return []


def _ask_windows(packet, kind, adapter, ident):
    """Fill in the header of a DisplayConfigGetDeviceInfo packet and ask. True when Windows answered."""
    packet.header.type = kind
    packet.header.size = ctypes.sizeof(packet)
    packet.header.adapter = adapter
    packet.header.id = ident
    return _api().user32.DisplayConfigGetDeviceInfo(byref(packet)) == 0


def _source_name(path):
    """The Windows name (\\\\.\\DISPLAY1) of the screen a path draws on."""
    packet = _SourceName()
    if _ask_windows(packet, GET_SOURCE_NAME, path.source.adapter, path.source.id):
        return _wstr(packet.viewGdiDeviceName)
    return None


def _target_details(path):
    """The monitor at the end of a path: its model name and how it is connected."""
    packet = _TargetName()
    if not _ask_windows(packet, GET_TARGET_NAME, path.target.adapter, path.target.id):
        return None
    return {"name": _wstr(packet.monitorFriendlyDeviceName).strip(), "technology": packet.outputTechnology & 0xFFFFFFFF}


def _native_mode(path):
    """The mode the monitor itself prefers (its native resolution), or None."""
    packet = _PreferredMode()
    if not _ask_windows(packet, GET_TARGET_PREFERRED_MODE, path.target.adapter, path.target.id):
        return None
    if not packet.width or not packet.height:
        return None
    rate = packet.signal.vSyncFreq
    return {"width": packet.width, "height": packet.height, "hz": round(rate.num / rate.den) if rate.den else None}


def _hdr_state(path):
    """HDR on one display: {"state": "on" | "off" | "unsupported" | "unknown", "active_mode": "sdr" | "wcg" | "hdr" | None,
    "limited_by_policy": bool}. Windows 11 22H2 and later tell HDR apart from wide colour; older versions only say
    whether advanced colour is on."""
    adapter, ident = path.target.adapter, path.target.id
    newer = _AdvancedColor2()
    if _ask_windows(newer, GET_ADVANCED_COLOR_INFO_2, adapter, ident) and newer.activeColorMode in (0, 1, 2):
        mode = ("sdr", "wcg", "hdr")[newer.activeColorMode]
        supported = bool(newer.value & 0x10)
        state = "unsupported" if not supported else ("on" if mode == "hdr" else "off")
        return {"state": state, "active_mode": mode, "limited_by_policy": bool(newer.value & 0x8)}
    older = _AdvancedColor()
    if _ask_windows(older, GET_ADVANCED_COLOR_INFO, adapter, ident):
        supported, enabled, wide_only = bool(older.value & 0x1), bool(older.value & 0x2), bool(older.value & 0x4)
        if not supported:
            return {"state": "unsupported", "active_mode": None, "limited_by_policy": False}
        return {"state": "on" if enabled and not wide_only else "off", "active_mode": None,
                "limited_by_policy": bool(older.value & 0x8)}
    return {"state": "unknown", "active_mode": None, "limited_by_policy": False}


def _set_hdr(path, on):
    """Turn HDR on or off. Tries the Windows 11 22H2 call, then the older one. Returns None, or the last error code."""
    user32 = _api().user32
    code = 0
    for kind in (SET_HDR_STATE, SET_ADVANCED_COLOR_STATE):
        packet = _SetState()
        packet.header.type = kind
        packet.header.size = ctypes.sizeof(packet)
        packet.header.adapter = path.target.adapter
        packet.header.id = path.target.id
        packet.value = 1 if on else 0
        code = user32.DisplayConfigSetDeviceInfo(byref(packet))
        if code == 0:
            return None
        if code not in (ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED):  # those two mean "this Windows lacks that call"
            return code
    return code


def _sdr_white_nits(path):
    """How bright SDR content is shown while HDR is on, in nits (the Settings slider), or None."""
    packet = _SdrWhite()
    if _ask_windows(packet, GET_SDR_WHITE_LEVEL, path.target.adapter, path.target.id) and packet.level:
        return round(packet.level / 1000 * 80)
    return None


def _scale_choices(path):
    """(recommended scale, [the scales Settings offers]) in percent, or (None, []).
    This is the one undocumented read: DisplayConfigGetDeviceInfo with type -3 returns the lowest, current and highest
    choice relative to the recommended one, which is how Settings builds its Scale list. It is only ever read; the
    answer is checked against the known steps and dropped if it does not make sense."""
    packet = _DpiScale()
    if not _ask_windows(packet, GET_DPI_SCALE, path.source.adapter, path.source.id):
        return None, []
    low, high = packet.minScaleRel, packet.maxScaleRel
    base = abs(low)
    if low > 0 or high < 0 or base + high >= len(SCALE_STEPS):
        return None, []
    return SCALE_STEPS[base], list(SCALE_STEPS[base + low:base + high + 1])


# ======================================================================
# READING — one list of displays, built in one place: the list and every id come from here
# ======================================================================
def _device_number(device):
    match = re.search(r"DISPLAY(\d+)", device, re.I)
    return int(match.group(1)) if match else 10 ** 6


def _resolutions(modes, everything=False):
    """{(width, height): [refresh rates, highest first]} from the raw mode list: the deepest colour depth only, and no
    interlaced modes, unless everything is asked for."""
    if not modes:
        return {}
    deepest = max(mode["bits"] for mode in modes)
    found = {}
    for mode in modes:
        if not everything and (mode["bits"] < deepest or mode["interlaced"]):
            continue
        found.setdefault((mode["width"], mode["height"]), set()).add(mode["hz"])
    return {size: sorted(rates, reverse=True) for size, rates in found.items()}


def _displays():
    """Every display that is part of the desktop, numbered from 1 in the order of its Windows name (\\\\.\\DISPLAY1,
    2, ...). The list and the ids both come from here, so they always agree; ids shift when a display comes or goes."""
    _dpi_aware()
    by_device = {}
    for path in _paths():
        device = _source_name(path)
        if device:
            by_device[device.lower()] = path
    handles = _monitor_handles()
    rows = []
    for adapter in _adapters():
        device = adapter["device"]
        mode = _read_mode(device, ENUM_CURRENT_SETTINGS)
        if mode is None:
            continue
        path = by_device.get(device.lower())
        target = _target_details(path) if path is not None else None
        monitor, monitor_id = _monitor_text(device)
        technology = target["technology"] if target else None
        built_in = technology in BUILT_IN
        name = (target or {}).get("name") or ("Built-in display" if built_in else None) or monitor or "Display"
        hz, exact = mode.dmDisplayFrequency, None
        if path is not None and path.target.refreshRate.den:
            exact = round(path.target.refreshRate.num / path.target.refreshRate.den, 2)
        if hz <= 1 and exact:  # 0 and 1 mean "the hardware default"
            hz = round(exact)
        elif exact is not None and abs(exact - hz) > 1.5:
            exact = None
        dpi = _effective_dpi(handles.get(device.lower()))
        recommended, choices = _scale_choices(path) if path is not None else (None, [])
        modes = _mode_list(device)
        sizes = _resolutions(modes)
        rows.append({
            "device": device, "name": name, "adapter": adapter["adapter"], "monitor_id": monitor_id,
            "primary": adapter["primary"], "x": mode.dmPositionX, "y": mode.dmPositionY,
            "width": mode.dmPelsWidth, "height": mode.dmPelsHeight, "refresh_hz": hz, "refresh_exact_hz": exact,
            "bits": mode.dmBitsPerPel,
            "orientation": mode.dmDisplayOrientation * 90 if mode.dmFields & DM_DISPLAYORIENTATION else 0,
            "scale": round(dpi * 100 / 96) if dpi else None, "recommended_scale": recommended, "scale_choices": choices,
            "hdr": _hdr_state(path) if path is not None else {"state": "unknown", "active_mode": None,
                                                              "limited_by_policy": False},
            "connection": OUTPUT_TECHNOLOGY.get(technology) if technology is not None else None,
            "built_in": built_in, "native": _native_mode(path) if path is not None else None,
            "_path": path, "_modes": modes,
            "_rates_here": sizes.get((mode.dmPelsWidth, mode.dmPelsHeight), []),
        })
    rows.sort(key=lambda row: (_device_number(row["device"]), row["device"]))
    for number, row in enumerate(rows, start=1):
        row["id"] = number
    return rows


def _idle_displays(active):
    """Monitors that are connected but not part of the desktop right now (after 'PC screen only', for example)."""
    taken = {(row["_path"].target.adapter.low, row["_path"].target.adapter.high, row["_path"].target.id)
             for row in active if row["_path"] is not None}
    found, seen = [], set()
    for path in _paths(all_paths=True):
        key = (path.target.adapter.low, path.target.adapter.high, path.target.id)
        if path.flags & DISPLAYCONFIG_PATH_ACTIVE or not path.target.targetAvailable or key in taken or key in seen:
            continue
        seen.add(key)
        target = _target_details(path)
        if target and (target["name"] or target["technology"] in OUTPUT_TECHNOLOGY):
            found.append({"name": target["name"] or "Display", "connection": OUTPUT_TECHNOLOGY.get(target["technology"])})
    return found


def _primary(displays):
    for row in displays:
        if row["primary"]:
            return row
    return displays[0]


def _find(word, displays):
    """One display by id, by its Windows name (DISPLAY2 or \\\\.\\DISPLAY2), or by part of the monitor's name."""
    text = word.strip()
    if text.isdigit():
        for row in displays:
            if row["id"] == int(text):
                return row
        raise DisplayError(f"no display with id {text}. Run 'dsp' to see them.", 2)
    match = re.fullmatch(r"(?:\\\\\.\\)?display(\d+)", text, re.I)
    if match:
        for row in displays:
            if _device_number(row["device"]) == int(match.group(1)):
                return row
        raise DisplayError(f"Windows has no display called {text}. Run 'dsp' to see them.", 2)
    found = [row for row in displays if text.lower() in row["name"].lower()]
    if len(found) == 1:
        return found[0]
    if found:
        raise DisplayError(f"'{text}' matches more than one display. Use an id.", 2)
    raise DisplayError(f"no display called {text}. Run 'dsp' to see them.", 2)


def _is_display_word(word, displays):
    try:
        _find(word, displays)
        return True
    except DisplayError:
        return False


def _brief(row):
    return {
        "id": row["id"], "name": row["name"], "device": row["device"], "primary": row["primary"],
        "width": row["width"], "height": row["height"], "refresh_hz": row["refresh_hz"], "bits": row["bits"],
        "orientation": ORIENTATIONS.get(row["orientation"], str(row["orientation"])),
        "orientation_degrees": row["orientation"], "scale_percent": row["scale"],
        "recommended_scale_percent": row["recommended_scale"], "hdr": row["hdr"]["state"],
        "x": row["x"], "y": row["y"], "connection": row["connection"], "built_in": row["built_in"],
    }


def _size_text(row):
    return f"{row['width']}x{row['height']}"


def _mode_text(mode):
    text = f"{mode['width']}x{mode['height']}"
    if mode.get("hz"):
        text += f" at {mode['hz']} Hz"
    if mode.get("orientation"):
        text += f", {ORIENTATIONS.get(mode['orientation'], mode['orientation'])}"
    return text


def _same_size(row, native):
    """Whether the display runs at its native size (a rotated display swaps width and height)."""
    return sorted((row["width"], row["height"])) == sorted((native["width"], native["height"]))


def _hints(displays):
    """What could be better, in plain words, each with the command that fixes it."""
    found = []
    for row in displays:
        label = f"display {row['id']} ({row['name']})"
        rates = row["_rates_here"]
        if rates and max(rates) >= (row["refresh_hz"] or 0) + 10:
            found.append({"id": row["id"], "text": f"{label} runs at {row['refresh_hz']} Hz but can do {max(rates)} Hz at "
                                                  f"this resolution, so motion is less smooth than it could be",
                          "fix": f"dsp {row['id']} hz {max(rates)}"})
        native = row["native"]
        if native and not _same_size(row, native):
            found.append({"id": row["id"], "text": f"{label} is not at its native resolution "
                                                  f"({native['width']}x{native['height']}), so text can look soft",
                          "fix": f"dsp {row['id']} res {native['width']}x{native['height']}"})
        if row["scale"] and row["recommended_scale"] and row["scale"] != row["recommended_scale"]:
            found.append({"id": row["id"], "text": f"{label} is scaled to {row['scale']}% but Windows recommends "
                                                  f"{row['recommended_scale']}%",
                          "fix": f"dsp {row['id']} scale {row['recommended_scale']}"})
    return found


# ======================================================================
# SHOWING — the list, one display, the modes, the layout, the scale
# ======================================================================
def _say(options, text=""):
    """A progress line. With --json it goes to stderr, so stdout stays pure JSON."""
    print(text, file=sys.stderr if options["json"] else sys.stdout)


def _confirm(question, options):
    """_core.confirm; with --json --yes the echo of the answer goes to stderr as well."""
    if options["json"] and options["yes"]:
        with contextlib.redirect_stdout(sys.stderr):
            return _core.confirm(question, True)
    return _core.confirm(question, options["yes"])


def _hdr_label(row):
    state = row["hdr"]["state"]
    return {"unsupported": "not supported", "unknown": "unknown"}.get(state, state)


def _scale_label(row):
    return f"{row['scale']}%" if row["scale"] else "-"


def _row_text(row, width):
    label = row["name"] + (" (main)" if row["primary"] else "")
    size = _size_text(row) + ("" if row["orientation"] in (0, 180) and row["orientation"] == 0 else
                              f" {ORIENTATIONS.get(row['orientation'], '')}".rstrip())
    return (_net.GREEN + f"{row['id']:<5}{label[:width - 2]:<{width}}{size:<26}{row['refresh_hz'] or '-':<6}"
            f"{_scale_label(row):<8}{_hdr_label(row):<15}{row['x']}, {row['y']}" + _net.RESET)


def _list(options):
    displays = _displays()
    if not displays:
        raise DisplayError("Windows lists no display that is part of the desktop")
    idle = _idle_displays(displays)
    hints = _hints(displays)
    if options["json"]:
        _core.print_json({"displays": [_brief(row) for row in displays], "also_connected": idle, "hints": hints})
        return 0
    width = min(34, max(len(row["name"]) + (7 if row["primary"] else 0) for row in displays) + 2)
    print(f"{'ID':<5}{'DISPLAY':<{width}}{'RESOLUTION':<26}{'HZ':<6}{'SCALE':<8}{'HDR':<15}POSITION")
    for row in displays:
        print(_row_text(row, width))
    for other in idle:
        print(_net.GREY + f"{'-':<5}{other['name'][:width - 2]:<{width}}connected but not in use"
              + (f" ({other['connection']})" if other["connection"] else "") + _net.RESET)
    if idle:
        print(f"\n{len(idle)} connected display(s) are not in use. 'dsp project extend' turns them on.")
    for hint in hints:
        print(_net.YELLOW + f"\n{hint['text']}.\n  fix: {hint['fix']}" + _net.RESET)
    print("\n'dsp <id>' shows one display in full. 'dsp 1 res 1920x1080' changes the resolution, 'dsp layout' draws the "
          "arrangement, 'dsp help' lists everything.")
    return 0


def _detail(row, displays, options):
    hints = [hint for hint in _hints(displays) if hint["id"] == row["id"]]
    resolutions = _resolutions(row["_modes"])
    white = _sdr_white_nits(row["_path"]) if row["_path"] is not None and row["hdr"]["state"] == "on" else None
    if options["json"]:
        _core.print_json({
            **_brief(row), "adapter": row["adapter"], "monitor_id": row["monitor_id"], "native": row["native"],
            "refresh_exact_hz": row["refresh_exact_hz"], "resolutions": len(resolutions),
            "refresh_rates_here": row["_rates_here"], "scale_choices": row["scale_choices"],
            "hdr_detail": row["hdr"], "sdr_white_nits": white, "hints": hints,
        })
        return 0
    native = row["native"]
    native_text = "-"
    if native:
        native_text = f"{native['width']}x{native['height']}" + (f" at {native['hz']} Hz" if native["hz"] else "")
        native_text += "  (in use)" if _same_size(row, native) else "  (not in use)"
    scale = _scale_label(row)
    if row["scale"] and row["recommended_scale"]:
        scale += f"  (Windows recommends {row['recommended_scale']}%)"
    hdr = _hdr_label(row)
    if row["hdr"]["state"] == "unsupported":
        hdr += "  (this display or its connection cannot do HDR)"
    elif row["hdr"]["limited_by_policy"]:
        hdr += "  (limited by a policy)"
    elif white:
        hdr += f"  (SDR content at {white} nits)"
    _net.render(f"Display {row['id']}: {row['name']}", [
        ("display", [
            ("name", row["name"]), ("Windows calls it", row["device"]), ("graphics card", row["adapter"]),
            ("connected with", row["connection"]), ("main display", row["primary"]),
            ("position", f"{row['x']}, {row['y']}"),
        ]),
        ("picture", [
            ("resolution", _size_text(row)), ("native resolution", native_text),
            ("refresh rate", f"{row['refresh_exact_hz'] or row['refresh_hz'] or '-'} Hz"),
            ("colour depth", f"{row['bits']}-bit"),
            ("orientation", f"{ORIENTATIONS.get(row['orientation'], row['orientation'])} ({row['orientation']} degrees)"),
            ("scale", scale), ("HDR", hdr),
        ]),
        ("supported", [
            ("resolutions", len(resolutions)),
            ("refresh rates here", ", ".join(f"{rate} Hz" for rate in row["_rates_here"]) or "-"),
        ]),
        ("change it with", [
            (f"dsp {row['id']} res <W>x<H>", "the resolution"), (f"dsp {row['id']} hz <hz>", "the refresh rate"),
            (f"dsp {row['id']} rotate 0|90|180|270", "the orientation"), (f"dsp {row['id']} hdr on|off", "HDR"),
            (f"dsp {row['id']} modes", "everything this display supports"),
        ]),
    ])
    for hint in hints:
        print(_net.YELLOW + f"\n{hint['text']}.\n  fix: {hint['fix']}" + _net.RESET)
    return 0


def _modes_command(row, words, options):
    if any(word.lower() not in ("--all", "all") for word in words):
        raise DisplayError("usage: dsp <id> modes [--all]", 2)
    everything = bool(words)
    modes = _mode_list(row["device"], raw=everything)
    sizes = _resolutions(modes, everything)
    ordered = sorted(sizes, key=lambda size: (size[0] * size[1], size[0]), reverse=True)
    native = row["native"]
    if options["json"]:
        data = {"id": row["id"], "name": row["name"],
                "current": {"width": row["width"], "height": row["height"], "refresh_hz": row["refresh_hz"]},
                "native": native, "all": everything,
                "resolutions": [{"width": w, "height": h, "refresh_rates": sizes[(w, h)],
                                 "current": (w, h) == (row["width"], row["height"]),
                                 "native": bool(native) and (w, h) == (native["width"], native["height"])}
                                for w, h in ordered]}
        if everything:
            data["modes"] = modes
        _core.print_json(data)
        return 0
    print(f"Display {row['id']}: {row['name']}. Now {_size_text(row)} at {row['refresh_hz']} Hz.")
    print(f"\n{'RESOLUTION':<14}REFRESH RATES (Hz)")
    for width, height in ordered:
        rates = ", ".join(str(rate) for rate in sizes[(width, height)])
        marks = []
        if (width, height) == (row["width"], row["height"]):
            marks.append("in use")
        if native and (width, height) == (native["width"], native["height"]):
            marks.append("native")
        line = f"{f'{width}x{height}':<14}{rates}" + (f"   <- {', '.join(marks)}" if marks else "")
        print((_net.GREEN if "in use" in marks else _net.RESET) + line + _net.RESET)
    print(f"\n{len(ordered)} resolution(s)." + ("" if everything else
          " 'dsp {0} modes --all' also lists interlaced, lower colour depth and unconfirmed modes.".format(row["id"])))
    print(f"Change with 'dsp {row['id']} res <W>x<H> [@hz]' or 'dsp {row['id']} hz <hz>'.")
    return 0


def _neighbours(row, displays):
    """Where a display sits against the others it touches: ["right of 1", "below 3"]."""
    found = []
    for other in displays:
        if other is row:
            continue
        ax0, ay0, ax1, ay1 = _rect(row)
        bx0, by0, bx1, by1 = _rect(other)
        shares_y = min(ay1, by1) > max(ay0, by0)
        shares_x = min(ax1, bx1) > max(ax0, bx0)
        if ax0 == bx1 and shares_y:
            found.append(f"right of {other['id']}")
        elif ax1 == bx0 and shares_y:
            found.append(f"left of {other['id']}")
        elif ay0 == by1 and shares_x:
            found.append(f"below {other['id']}")
        elif ay1 == by0 and shares_x:
            found.append(f"above {other['id']}")
    return found


def _rect(row, x=None, y=None):
    left = row["x"] if x is None else x
    top = row["y"] if y is None else y
    return left, top, left + row["width"], top + row["height"]


def _draw(displays, columns=MAP_COLUMNS):
    """The arrangement as text: a box per display with its id, size and name. A terminal character is about twice as
    tall as it is wide, so the vertical scale is half the horizontal one."""
    left = min(_rect(row)[0] for row in displays)
    top = min(_rect(row)[1] for row in displays)
    right = max(_rect(row)[2] for row in displays)
    bottom = max(_rect(row)[3] for row in displays)
    scale_x = (columns - 1) / max(right - left, 1)
    scale_y = scale_x / 2
    rows = max(int((bottom - top) * scale_y) + 2, 5)
    grid = [[" "] * columns for _ in range(rows)]
    for row in displays:
        x0, y0, x1, y1 = _rect(row)
        c0 = int(round((x0 - left) * scale_x))
        c1 = max(int(round((x1 - left) * scale_x)), c0 + 8)
        r0 = int(round((y0 - top) * scale_y))
        r1 = max(int(round((y1 - top) * scale_y)), r0 + 3)
        c1, r1 = min(c1, columns - 1), min(r1, rows - 1)
        for c in range(c0, c1 + 1):
            grid[r0][c] = grid[r1][c] = "-"
        for r in range(r0, r1 + 1):
            grid[r][c0] = grid[r][c1] = "|"
        for r, c in ((r0, c0), (r0, c1), (r1, c0), (r1, c1)):
            grid[r][c] = "+"
        inner = c1 - c0 - 1
        labels = [f"{row['id']}" + (" (main)" if row["primary"] else ""), _size_text(row), row["name"]]
        middle = r0 + (r1 - r0 - len(labels)) // 2 + 1
        for offset, label in enumerate(labels):
            r = middle + offset
            if r0 < r < r1 and inner > 0:
                label = label[:inner]
                start = c0 + 1 + (inner - len(label)) // 2
                for i, character in enumerate(label):
                    grid[r][start + i] = character
    return "\n".join("".join(line).rstrip() for line in grid).rstrip()


def _layout(options):
    displays = _displays()
    if not displays:
        raise DisplayError("Windows lists no display that is part of the desktop")
    left = min(_rect(row)[0] for row in displays)
    top = min(_rect(row)[1] for row in displays)
    right = max(_rect(row)[2] for row in displays)
    bottom = max(_rect(row)[3] for row in displays)
    if options["json"]:
        _core.print_json({
            "displays": [{"id": row["id"], "name": row["name"], "primary": row["primary"], "x": row["x"], "y": row["y"],
                          "width": row["width"], "height": row["height"], "next_to": _neighbours(row, displays)}
                         for row in displays],
            "bounds": {"x": left, "y": top, "width": right - left, "height": bottom - top},
        })
        return 0
    print(_draw(displays))
    print()
    for row in displays:
        near = _neighbours(row, displays)
        print(_net.GREEN + f"{row['id']:<4}{row['name'][:30]:<32}{_size_text(row):<12}at {row['x']}, {row['y']}"
              + (f"   {', '.join(near)}" if near else "") + (" (main)" if row["primary"] else "") + _net.RESET)
    print("\nThe main display is at 0, 0. Move one with 'dsp 2 right-of 1' (left-of, above, below) or 'dsp 2 pos <x> <y>'.")
    return 0


def _identify(options):
    displays = _displays()
    if options["json"]:
        _core.print_json({"displays": [{"id": row["id"], "name": row["name"], "device": row["device"],
                                        "primary": row["primary"], "x": row["x"], "y": row["y"],
                                        "next_to": _neighbours(row, displays)} for row in displays]})
        return 0
    for row in displays:
        near = _neighbours(row, displays)
        print(_net.GREEN + f"Display {row['id']}: {row['name']} ({row['device']}), {_size_text(row)}, top-left corner at "
              f"{row['x']}, {row['y']}" + (", the main display" if row["primary"] else "")
              + (f", {', '.join(near)}" if near else "") + _net.RESET)
    return 0


def _scale_data(row):
    return {"id": row["id"], "name": row["name"], "scale_percent": row["scale"],
            "recommended_scale_percent": row["recommended_scale"], "choices": row["scale_choices"]}


def _scale_all(options):
    displays = _displays()
    if options["json"]:
        _core.print_json({"displays": [_scale_data(row) for row in displays]})
        return 0
    print(f"{'ID':<5}{'DISPLAY':<32}{'SCALE':<8}{'RECOMMENDED':<13}CHOICES")
    for row in displays:
        print(_net.GREEN + f"{row['id']:<5}{row['name'][:30]:<32}{_scale_label(row):<8}"
              f"{(str(row['recommended_scale']) + '%') if row['recommended_scale'] else '-':<13}"
              f"{', '.join(f'{c}%' for c in row['scale_choices']) or '-'}" + _net.RESET)
    print("\nScale makes text and apps bigger without changing the resolution. Windows has no documented way for a "
          "program to change it: 'dsp <id> scale <percent>' opens the Settings page where you choose it.")
    return 0


def _scale_command(row, words, options):
    if not words:
        if options["json"]:
            _core.print_json(_scale_data(row))
        else:
            print(f"Display {row['id']} ({row['name']}) is scaled to {_scale_label(row)}."
                  + (f" Windows recommends {row['recommended_scale']}%." if row["recommended_scale"] else "")
                  + (f" Choices: {', '.join(f'{c}%' for c in row['scale_choices'])}." if row["scale_choices"] else ""))
        return 0
    wanted = words[0].rstrip("%")
    if len(words) != 1 or not wanted.isdigit():
        raise DisplayError("usage: dsp <id> scale <percent>, e.g. dsp 1 scale 150", 2)
    if row["scale_choices"] and int(wanted) not in row["scale_choices"]:
        raise DisplayError(f"display {row['id']} offers {', '.join(f'{c}%' for c in row['scale_choices'])}, not {wanted}%", 2)
    return _open_settings("ms-settings:display", options,
                          f"Windows has no documented way for a program to change the scale, so Settings is open at "
                          f"System > Display. Choose display {row['id']} ({row['name']}), then Scale, then {wanted}%.")


def _open_settings(uri, options, text):
    _win.open_settings(uri)
    if options["json"]:
        _core.print_json({"opened": uri, "why": text})
    else:
        print(text)
    return 0


# ======================================================================
# CHANGING — every change is tested first, applied without saving, and kept only if the person says so
# ======================================================================
def _has_console():
    """Whether there is a console to wait for a key in (the timed question needs one)."""
    try:
        import msvcrt
        return bool(msvcrt and sys.stdin.isatty() and sys.stdout.isatty())
    except (ImportError, AttributeError, ValueError):
        return False


def _keep_prompt(options, seconds=KEEP_SECONDS):
    """Wait up to `seconds` for a key. Returns "yes" for y, "no" for any other key, "timeout" when none was pressed.
    With --json the question and the countdown go to stderr, so stdout stays JSON."""
    import msvcrt
    out = sys.stderr if options["json"] else sys.stdout
    print(f"Keep this? Press y to keep it. Any other key, or waiting {seconds} seconds, puts the old setting back.",
          file=out)
    deadline = time.monotonic() + seconds
    shown = None
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            print(file=out)
            return "timeout"
        remaining = int(left) + 1
        if remaining != shown:
            print(f"\r  going back in {remaining:>2} s ... ", end="", flush=True, file=out)
            shown = remaining
        if msvcrt.kbhit():
            key = msvcrt.getwch()
            if key in ("\x00", "\xe0"):  # the first half of an arrow or function key
                msvcrt.getwch()
                continue
            print(file=out)
            return "yes" if key.lower() == "y" else "no"
        time.sleep(0.1)


def _check(code, what):
    """Turn a ChangeDisplaySettingsEx result into an error. 1 (restart needed) is success and is returned."""
    if code in (0, RESTART_NEEDED):
        return code
    raise DisplayError(f"{what}: {CHANGE_RESULTS.get(code, _win_error(code))}")


def _result(row, before, after, outcome, saved=None):
    return {"id": row["id"], "name": row["name"], "result": outcome, "changed": outcome == "kept",
            "saved": saved, "before": before, "after": after}


def _read_back(row):
    """The display's mode as Windows reports it now, and whether that is also the saved one."""
    now = _mode_dict(_read_mode(row["device"], ENUM_CURRENT_SETTINGS))
    saved = _mode_dict(_read_mode(row["device"], ENUM_REGISTRY_SETTINGS))
    return now, (saved is not None and saved == now)


def _apply_mode(row, wanted, options):
    """Change one display's mode. wanted holds width, height, hz and optionally orientation (degrees)."""
    device = row["device"]
    old = _read_mode(device, ENUM_CURRENT_SETTINGS)
    if old is None:
        raise DisplayError(f"Windows would not say what display {row['id']} is set to now")
    new = _Devmode.from_buffer_copy(old)
    new.dmSize = ctypes.sizeof(_Devmode)
    new.dmFields |= (DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY | DM_BITSPERPEL | DM_DISPLAYORIENTATION
                     | DM_POSITION)
    new.dmPelsWidth, new.dmPelsHeight, new.dmDisplayFrequency = wanted["width"], wanted["height"], wanted["hz"]
    if "orientation" in wanted:
        new.dmDisplayOrientation = DMDO[wanted["orientation"]]
    before, target = _mode_dict(old), _mode_dict(new)
    label = f"display {row['id']} ({row['name']})"
    if before == target:
        message = f"{label} is already {_mode_text(before)}."
        if options["json"]:
            _core.print_json(_result(row, before, before, "unchanged", True))
        else:
            print(message)
        return 0
    _check(_change(device, new, CDS_TEST), f"{label} cannot be changed to {_mode_text(target)}")
    outcome, note = "kept", ""
    if options["yes"]:
        _say(options, f"changing {label} to {_mode_text(target)}...")
        if _check(_change(device, new, CDS_UPDATEREGISTRY), f"Windows would not change {label}") == RESTART_NEEDED:
            note = " Windows needs a restart before it uses this."
    elif _has_console():
        _say(options, f"changing {label} to {_mode_text(target)}...")
        _check(_change(device, new, 0), f"Windows would not change {label}")
        answer = "no"
        try:
            answer = _keep_prompt(options)
        finally:
            if answer != "yes":
                if _change(device, old, 0) not in (0, RESTART_NEEDED):  # the old mode must come back, whatever happened
                    print(f"could not restore {label}: run 'dsp {row['id']} res {before['width']}x{before['height']} "
                          f"{before['hz']}'", file=sys.stderr)
        if answer == "yes":
            if _change(device, new, CDS_UPDATEREGISTRY | CDS_NORESET) not in (0, RESTART_NEEDED):
                note = " It could not be saved, so it will go back after a restart."
        else:
            outcome = "reverted" if answer == "timeout" else "cancelled"
    else:
        if not _confirm(f"Change {label} to {_mode_text(target)}? The picture may go blank for a moment. [y/N]: ", options):
            _say(options, "cancelled")
            outcome = "cancelled"
        else:
            _check(_change(device, new, CDS_UPDATEREGISTRY), f"Windows would not change {label}")
    now, saved = _read_back(row)
    if options["json"]:
        _core.print_json(_result(row, before, now, outcome, saved))
        return 0
    if outcome == "reverted":
        print(f"No answer, so {label} is back at {_mode_text(now)}.")
    elif outcome == "cancelled":
        print(f"{label} stays at {_mode_text(now)}.")
    else:
        print(f"{label} is now {_mode_text(now)}." + (" It stays after a restart." if saved else "") + note)
        if now and (now["width"], now["height"], now["hz"]) != (target["width"], target["height"], target["hz"]):
            print(f"Windows reports {_mode_text(now)}, not the {_mode_text(target)} that was asked for.")
    return 0


def _parse_resolution(words):
    text = " ".join(words).strip().lower()
    if text in RESOLUTION_NAMES:
        return (*RESOLUTION_NAMES[text], None)
    match = RESOLUTION.fullmatch(text)
    if not match:
        first, _, rest = text.partition(" ")
        if first in RESOLUTION_NAMES and re.fullmatch(r"@?\s*\d{2,3}\s*(?:hz)?", rest or "x"):
            return (*RESOLUTION_NAMES[first], int(re.sub(r"\D", "", rest)))
        raise DisplayError("usage: dsp <id> res <W>x<H> [@hz], e.g. dsp 1 res 1920x1080 or dsp 1 res 1440p @ 144", 2)
    return int(match.group(1)), int(match.group(2)), int(match.group(3)) if match.group(3) else None


def _nearest(sizes, width, height, count=5):
    ordered = sorted(sizes, key=lambda size: (abs(size[0] - width) + abs(size[1] - height), -size[0]))
    return [f"{w}x{h}" for w, h in ordered[:count]]


def _set_resolution(row, words, options):
    width, height, hz = _parse_resolution(words)
    sizes = _resolutions(row["_modes"])
    if (width, height) not in sizes:
        raise DisplayError(f"display {row['id']} does not list {width}x{height}. Nearest: "
                           f"{', '.join(_nearest(sizes, width, height))}. 'dsp {row['id']} modes' lists them all.", 2)
    rates = sizes[(width, height)]
    if hz is None:
        hz = row["refresh_hz"] if row["refresh_hz"] in rates else rates[0]  # keep the refresh rate if it still fits
    elif hz not in rates:
        raise DisplayError(f"display {row['id']} does not do {width}x{height} at {hz} Hz. At that resolution it "
                           f"supports: {', '.join(str(rate) for rate in rates)} Hz.", 2)
    return _apply_mode(row, {"width": width, "height": height, "hz": hz}, options)


def _set_refresh(row, words, options):
    text = " ".join(words).lower().replace("hz", "").replace("@", "").strip()
    if not text.isdigit():
        raise DisplayError("usage: dsp <id> hz <hz>, whole numbers as listed by 'dsp <id> modes', e.g. dsp 1 hz 144", 2)
    hz = int(text)
    rates = row["_rates_here"]
    if hz not in rates:
        raise DisplayError(f"display {row['id']} does not do {hz} Hz at {_size_text(row)}. It supports: "
                           f"{', '.join(str(rate) for rate in rates) or 'nothing listed'} Hz. "
                           f"'dsp {row['id']} modes' lists every resolution.", 2)
    return _apply_mode(row, {"width": row["width"], "height": row["height"], "hz": hz}, options)


def _set_rotation(row, words, options):
    word = "-".join(re.sub(r"[()]", "", " ".join(words).lower()).replace("degrees", "").replace("°", "").split())
    if word not in ORIENTATION_WORDS:
        raise DisplayError("usage: dsp <id> rotate 0|90|180|270 (landscape, portrait, landscape-flipped, "
                           "portrait-flipped; degrees are from the display's natural orientation)", 2)
    degrees = ORIENTATION_WORDS[word]
    width, height = row["width"], row["height"]
    if (degrees in (90, 270)) != (row["orientation"] in (90, 270)):  # landscape <-> portrait swaps the sides
        width, height = height, width
    return _apply_mode(row, {"width": width, "height": height, "hz": row["refresh_hz"], "orientation": degrees}, options)


# -- arrangement: position and main display ------------------------------
def _layout_problem(boxes):
    """Why a set of display rectangles is not a layout Windows accepts, or None. boxes: {id: (x0, y0, x1, y1)}."""
    ids = sorted(boxes)
    for i, first in enumerate(ids):
        for second in ids[i + 1:]:
            a, b = boxes[first], boxes[second]
            if min(a[2], b[2]) > max(a[0], b[0]) and min(a[3], b[3]) > max(a[1], b[1]):
                return f"displays {first} and {second} would overlap"
    if len(ids) > 1:
        joined, queue = {ids[0]}, [ids[0]]
        while queue:
            a = boxes[queue.pop()]
            for other in ids:
                if other in joined:
                    continue
                b = boxes[other]
                touch_x = (a[2] == b[0] or b[2] == a[0]) and min(a[3], b[3]) > max(a[1], b[1])
                touch_y = (a[3] == b[1] or b[3] == a[1]) and min(a[2], b[2]) > max(a[0], b[0])
                if touch_x or touch_y:
                    joined.add(other)
                    queue.append(other)
        loose = [str(i) for i in ids if i not in joined]
        if loose:
            return (f"display {', '.join(loose)} would not touch the others. Windows needs the displays joined edge to "
                    "edge, like the boxes in 'dsp layout'")
    return None


def _stage(plan, primary_device):
    """Save new positions for several displays, then apply them together: the way Windows documents for changing more
    than one display at once. plan: [(device, DEVMODE)]."""
    for device, mode in plan:
        flags = CDS_UPDATEREGISTRY | CDS_NORESET | (CDS_SET_PRIMARY if device == primary_device else 0)
        _check(_change(device, mode, flags), f"Windows would not move {device}")
    _check(_change(None, None, 0), "Windows would not apply the new arrangement")


def _arrange(displays, positions, new_primary, options, what):
    """Move displays to positions {id: (x, y)}, and optionally make new_primary (a display) the main one."""
    prime = new_primary or _primary(displays)
    shift_x, shift_y = positions[prime["id"]]  # the main display must sit at 0, 0: everything else moves with it
    positions = {ident: (x - shift_x, y - shift_y) for ident, (x, y) in positions.items()}
    boxes = {row["id"]: _rect(row, *positions[row["id"]]) for row in displays}
    problem = _layout_problem(boxes)
    if problem:
        raise DisplayError(f"{problem}.", 2)
    if all(positions[row["id"]] == (row["x"], row["y"]) for row in displays) and prime is _primary(displays):
        print("That is how the displays already sit.")
        return 0
    old_plan, new_plan = [], []
    for row in displays:
        old = _read_mode(row["device"], ENUM_CURRENT_SETTINGS)
        if old is None:
            raise DisplayError(f"Windows would not say what display {row['id']} is set to now")
        new = _Devmode.from_buffer_copy(old)
        new.dmSize = ctypes.sizeof(_Devmode)
        new.dmFields |= DM_POSITION | DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL
        new.dmPositionX, new.dmPositionY = positions[row["id"]]
        old_plan.append((row["device"], old))
        new_plan.append((row["device"], new))
        _check(_change(row["device"], new, CDS_TEST), f"display {row['id']} cannot go there")
    old_primary = _primary(displays)["device"]
    if options["yes"]:
        _say(options, f"{what}...")
        _stage(new_plan, prime["device"])
        outcome = "kept"
    elif _has_console():
        _say(options, f"{what}...")
        answer = "no"
        try:
            _stage(new_plan, prime["device"])  # inside the try: a half-staged layout is put back too
            answer = _keep_prompt(options)
        finally:
            if answer != "yes":
                try:
                    _stage(old_plan, old_primary)
                except DisplayError as e:
                    print(f"could not put the displays back: {e}. Use 'dsp layout' and 'dsp <id> pos <x> <y>' to fix it.",
                          file=sys.stderr)
        outcome = "kept" if answer == "yes" else ("reverted" if answer == "timeout" else "cancelled")
    else:
        if not _confirm(f"{what[0].upper()}{what[1:]}? The screens may go blank for a moment. [y/N]: ", options):
            _say(options, "cancelled")
            outcome = "cancelled"
        else:
            _stage(new_plan, prime["device"])
            outcome = "kept"
    now = _displays()
    if options["json"]:
        _core.print_json({"result": outcome, "changed": outcome == "kept", "displays": [_brief(row) for row in now]})
        return 0
    if outcome == "reverted":
        print("No answer, so the displays are back where they were.")
    elif outcome == "cancelled":
        print("The displays stay as they were.")
    if outcome == "kept":
        print("Now:")
    for row in now:
        near = _neighbours(row, now)
        print(f"  display {row['id']} ({row['name']}) at {row['x']}, {row['y']}"
              + (", the main display" if row["primary"] else "") + (f", {', '.join(near)}" if near else ""))
    return 0


def _make_primary(row, displays, options):
    if row["primary"]:
        print(f"display {row['id']} ({row['name']}) is already the main display.")
        return 0
    positions = {other["id"]: (other["x"], other["y"]) for other in displays}
    return _arrange(displays, positions, row, options,
                    f"making display {row['id']} ({row['name']}) the main display")


def _move_to(row, displays, x, y, options):
    positions = {other["id"]: (other["x"], other["y"]) for other in displays}
    positions[row["id"]] = (x, y)
    return _arrange(displays, positions, None, options, f"moving display {row['id']} ({row['name']}) to {x}, {y}")


def _position_command(row, words, displays, options):
    if len(words) != 2 or not all(re.fullmatch(r"-?\d+", word) for word in words):
        raise DisplayError("usage: dsp <id> pos <x> <y>, whole numbers; the main display is at 0 0, so dsp 2 pos 2560 0 "
                           "puts display 2 just to the right of a 2560-wide main display", 2)
    return _move_to(row, displays, int(words[0]), int(words[1]), options)


def _place_command(row, side, words, displays, options):
    if len(words) == 1 and words[0].lower() == "of":
        raise DisplayError("usage: dsp <id> right-of|left-of|above|below <id>", 2)
    words = [word for word in words if word.lower() != "of"]
    if len(words) != 1:
        raise DisplayError("usage: dsp <id> right-of|left-of|above|below <id>, e.g. dsp 2 right-of 1", 2)
    anchor = _find(words[0], displays)
    if anchor is row:
        raise DisplayError("a display cannot be placed next to itself", 2)
    x = {"right": anchor["x"] + anchor["width"], "left": anchor["x"] - row["width"]}.get(side, anchor["x"])
    y = {"below": anchor["y"] + anchor["height"], "above": anchor["y"] - row["height"]}.get(side, anchor["y"])
    return _move_to(row, displays, x, y, options)


# -- HDR and the Win+P choices -------------------------------------------
def _hdr_command(row, words, options):
    if len(words) != 1 or words[0].lower() not in (*_net.ON_WORDS, *_net.OFF_WORDS):
        raise DisplayError("usage: dsp <id> hdr on|off", 2)
    on = words[0].lower() in _net.ON_WORDS
    label = f"display {row['id']} ({row['name']})"
    path = row["_path"]
    state = row["hdr"]
    if path is None or state["state"] == "unknown":
        raise DisplayError(f"Windows does not say whether {label} can do HDR")
    if state["state"] == "unsupported":
        raise DisplayError(f"{label} does not support HDR (the display, its cable or the graphics driver cannot do it)")
    if on and state["limited_by_policy"]:
        raise DisplayError(f"HDR is limited by a policy on {label}, so it cannot be turned on from here")
    if (state["state"] == "on") == on:
        message = f"HDR is already {'on' if on else 'off'} on {label}."
        if options["json"]:
            _core.print_json({"id": row["id"], "name": row["name"], "hdr": state["state"], "changed": False})
        else:
            print(message)
        return 0
    _say(options, f"turning HDR {'on' if on else 'off'} on {label}; the screen may flicker...")
    code = _set_hdr(path, on)
    if code is not None:
        raise DisplayError(f"Windows would not turn HDR {'on' if on else 'off'} on {label}: {_win_error(code)}")
    now = state
    for _ in range(10):  # the switch takes a moment
        time.sleep(0.3)
        now = _hdr_state(path)
        if now["state"] == ("on" if on else "off"):
            break
    if options["json"]:
        _core.print_json({"id": row["id"], "name": row["name"], "hdr": now["state"], "active_mode": now["active_mode"],
                          "changed": now["state"] != state["state"]})
    elif now["state"] == ("on" if on else "off"):
        print(f"HDR is now {now['state']} on {label}.")
    else:
        print(f"Windows reports HDR {now['state']} on {label}, not {'on' if on else 'off'}. "
              "Some displays only switch when the screen is in full view; 'dsp open' shows the setting.")
    return 0


def _topology_name(displays):
    if len(displays) == 1:
        return "one display"
    if len({(row["x"], row["y"]) for row in displays}) == 1:
        return "duplicate"
    return "extended"


def _project(words, options):
    if len(words) != 1 or words[0].lower() not in PROJECT_WORDS:
        raise DisplayError("usage: dsp project internal|external|duplicate|extend (internal is 'PC screen only', external "
                           "is 'second screen only')", 2)
    kind = PROJECT_WORDS[words[0].lower()]
    before = _displays()
    if kind in ("internal", "external") and len(before) > 1 and not _confirm(
            f"Switch to '{PROJECT_TEXT[kind]}'? That turns off a display now in use. To get it back: 'dsp project extend' "
            f"or Win+P. [y/N]: ", options):
        _say(options, "cancelled")
        return 0
    _say(options, f"switching to {PROJECT_TEXT[kind]}...")
    code = _api().user32.SetDisplayConfig(0, None, 0, None, SDC_APPLY | SDC_TOPOLOGY[kind])
    if code != 0:  # fall back to the program behind Win+P
        ok, text = _net.run_tool(["DisplaySwitch.exe", DISPLAYSWITCH_ARGUMENTS[kind]], timeout=30)
        if not ok:
            raise DisplayError(f"Windows would not switch to {PROJECT_TEXT[kind]} ({_win_error(code)}). "
                               "There may be no second display connected.")
    now = before
    for _ in range(8):  # Windows takes a second or two to rearrange
        time.sleep(0.5)
        now = _displays()
        if [(row["device"], row["x"], row["y"]) for row in now] != [(row["device"], row["x"], row["y"]) for row in before]:
            break
    if options["json"]:
        _core.print_json({"mode": kind, "topology": _topology_name(now), "displays": [_brief(row) for row in now]})
        return 0
    print(f"Now: {_topology_name(now)}, {len(now)} display(s).")
    for row in now:
        print(f"  display {row['id']} ({row['name']}) {_size_text(row)} at {row['x']}, {row['y']}"
              + (", the main display" if row["primary"] else ""))
    return 0


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "display"/"dsp"/"res"
# ======================================================================
def _display_command(row, words, displays, options):
    if not words:
        return _detail(row, displays, options)
    word, rest = words[0].lower(), words[1:]
    if word in MODE_WORDS:
        return _modes_command(row, rest, options)
    if word in RES_WORDS:
        return _set_resolution(row, rest, options)
    if word in HZ_WORDS:
        return _set_refresh(row, rest, options)
    if word in ROTATE_WORDS:
        return _set_rotation(row, rest, options)
    if word == "primary" and not rest:
        return _make_primary(row, displays, options)
    if word in POS_WORDS:
        return _position_command(row, rest, displays, options)
    if word in PLACE_WORDS:
        return _place_command(row, PLACE_WORDS[word], rest, displays, options)
    if word in ("right", "left") and rest and rest[0].lower() == "of":
        return _place_command(row, word, rest[1:], displays, options)
    if word == "hdr":
        return _hdr_command(row, rest, options)
    if word == "scale":
        return _scale_command(row, rest, options)
    if RESOLUTION.fullmatch(" ".join(words).lower()) or word in RESOLUTION_NAMES:
        return _set_resolution(row, words, options)
    raise DisplayError(f"usage: {USAGE}", 2)


def _brightness(words, options):
    import brightness as brightness_page  # the same page as bn
    given = list(words) or ["get"]
    given += (["--json"] if options["json"] else []) + (["--yes"] if options["yes"] else [])
    return brightness_page.run(given)


def _dispatch(args, options):
    if not args or args[0].lower() in LIST_WORDS:
        return _list(options)
    word, rest = args[0].lower(), args[1:]
    if word in ("layout", "map", "arrangement"):
        return _layout(options)
    if word == "scale" and not rest:
        return _scale_all(options)
    if word in ("nightlight", "night-light", "night"):
        return _open_settings("ms-settings:nightlight", options,
                              "Windows has no way for a program to read or change Night light, so Settings is open at "
                              "System > Display > Night light.")
    if word == "open":
        return _open_settings("ms-settings:display", options, "Settings is open at System > Display.")
    if word == "project":
        return _project(rest, options)
    if word == "brightness":
        return _brightness(rest, options)
    if word == "identify":
        return _identify(options)
    displays = _displays()
    if not displays:
        raise DisplayError("Windows lists no display that is part of the desktop")
    if word in IMPLICIT_WORDS or word == "scale" or word in RESOLUTION_NAMES or RESOLUTION.fullmatch(" ".join(args).lower()):
        return _display_command(_primary(displays), args, displays, options)  # no id: the main display
    return _display_command(_find(args[0], displays), rest, displays, options)


def run(args):
    """Run one display command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if args and args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        return _dispatch(args, options)
    except (DisplayError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    except (OSError, AttributeError, ctypes.ArgumentError) as e:  # Windows or the driver refused a call
        print(f"error: Windows would not do that ({e})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

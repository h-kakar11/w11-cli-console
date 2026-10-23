"""
device: Windows devices, the same list Device Manager shows. Routed from app.py ("device" or "dvc").

    device ls [class <name>] [mfg <text>] [working|disabled|problem|absent|present] [sort name|class|state] [page <n>]
    device <id>                  show one device: what it is, its driver, what it is connected to, its status
    device errors                devices with problems, disabled devices and missing drivers
    device drivers [<id>]        driver packages: provider, version, date and file, or one device's driver
    device tree [all]            devices by what they are plugged into (all adds the ones not connected)
    device search <text>         find by name, class, hardware ID, vendor or driver provider
    device usb|displays|audio|storage
                                 the devices in one area
    device report                the whole inventory as JSON, for scripts and agents
    device <id> enable|disable|restart
                                 turn a device on or off, or restart it (administrator; disable and restart ask first)
    device rescan                scan for hardware changes, and say what appeared (administrator)
    device driver add <file.inf> install a driver package, which is how a driver is updated (administrator; asks first)
    device driver rm <id>        remove a device's driver package (administrator; asks first)
    device rollback <id>         put back the driver the device had before its current one (administrator; asks first)
    device drivers export <folder> [<id>]
                                 copy the drivers you installed (or one device's) into a folder (administrator)
    device backup [file]         save an inventory of every device and driver as a JSON snapshot
    device backup ls|rm <n>      list the saved snapshots, or delete one (asks first)
    device diff [<n>|<file>]     what changed since a snapshot: new and missing devices, state, drivers and problems

Reading needs no administrator rights. The changes need an administrator terminal, and each one checks
that before it asks anything. Connected devices are read through the Configuration Manager
API (cfgmgr32), the same calls Device Manager makes. Devices that are not connected are read from the
Enum registry key, because the API cannot locate them. Driver packages come from WMI. The changes use
pnputil (and SetupAPI for the rollback); a change that worked but needs a restart says so. Snapshots are
saved in %LOCALAPPDATA%\\w11-cli-console\\device-snapshots, outside this folder.
"""

import contextlib
import ctypes
import json
import math
import os
import re
import socket
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import _core
import _net
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "device"
ALIASES = ["dvc"]
SUMMARY = "Devices, their status and drivers (Device Manager)"
# extra words people use, for 'settings search'
KEYWORDS = ["device manager", "driver", "hardware", "usb", "devmgmt", "rollback driver", "backup drivers"]
USAGE = ("device ls | device <id> | device <id> enable|disable|restart | device errors | device drivers | "
         "device driver add <inf>|rm <id> | device tree | device search <text> | device rescan | "
         "device rollback <id> | device drivers export <folder> [<id>] | device backup [file|ls|rm <n>] | "
         "device diff [<n>|<file>]")
HELP = [
    ("device ls", "list every device with its id, state and class"),
    ("device <id>", "show one device: its driver, what it plugs into, and its status"),
    ("device errors", "devices with problems, disabled devices and missing drivers"),
    ("device drivers", "driver packages: provider, version, date and file"),
    ("device tree", "devices by what they are plugged into"),
    ("device search <text>", "find by name, class, hardware ID, vendor or driver provider"),
    ("", "changes (administrator)"),
    ("device <id> enable|disable", "turn a device on or off"),
    ("device <id> restart", "restart a device, such as one that has stopped working"),
    ("device rescan", "scan for hardware changes, like Device Manager's button, and say what appeared"),
    ("device rollback <id>", "put back the driver the device had before its current one"),
    ("device driver add <inf>", "install a driver package: how a driver is updated"),
    ("device driver rm <id>", "remove a device's driver package"),
    ("device drivers export <dir>", "copy the drivers you installed into a folder (add a device id for just its one)"),
    ("", "backup and compare"),
    ("device backup", "save an inventory of every device and driver as a JSON snapshot"),
    ("device backup ls", "the saved snapshots ('device backup rm <n>' deletes one)"),
    ("device diff [<n>|<file>]", "what changed since a snapshot: new or missing devices, state, drivers, problems"),
]
TIP = (
    "Ids are numbered by name, so they shift when devices come and go. A name works too. "
    "Run 'device ls' first. Reading needs no administrator rights. "
    "In the console, type folder paths with forward slashes (D:/drivers): the console eats backslashes."
)

# ======================================================================
# CONSTANTS — the Configuration Manager (cfgmgr32) values this page uses
# ======================================================================
CFG = ctypes.windll.cfgmgr32
CR_SUCCESS = 0
FILTER_PRESENT = 0x100  # CM_GETIDLIST_FILTER_PRESENT: only devices that are connected now
ENUM_KEY = r"SYSTEM\CurrentControlSet\Enum"
DRIVER_STORE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "DriverStore", "FileRepository")
# CM_DRP_* registry property codes, and the matching value names in the Enum key
CM_DRP = {"desc": 1, "hardware": 2, "compatible": 3, "service": 5, "class": 8, "driver": 0xA,
          "manufacturer": 0xC, "friendly": 0xD, "location": 0xE}
MULTI_TEXT = {"hardware", "compatible"}
ENUM_NAMES = {"desc": "DeviceDesc", "hardware": "HardwareID", "compatible": "CompatibleIDs", "service": "Service",
              "class": "Class", "driver": "Driver", "manufacturer": "Mfg", "friendly": "FriendlyName",
              "location": "LocationInformation"}
DISABLED_CODES = (22, 29)  # 22: turned off in Device Manager; 29: turned off in the firmware
MISSING_DRIVER = 28
# Plain words for the problem codes Windows reports (the CM_PROB_* numbers)
PROBLEM_TEXT = {
    1: "not set up correctly", 3: "Windows ran out of memory for it", 10: "Windows could not start it",
    12: "it needs resources another device is using", 14: "it needs a restart to finish",
    18: "its drivers need reinstalling", 19: "its registry settings are damaged",
    22: "turned off (disabled)", 24: "not working, or not there", 28: "no driver is installed",
    29: "turned off in the firmware", 31: "Windows cannot load its driver", 37: "its driver failed to start",
    39: "its driver is missing or damaged", 43: "a driver reported a problem and stopped it",
    45: "not connected right now", 48: "its driver is blocked", 52: "its driver is not signed",
}
STATE_COLORS = {"working": _net.GREEN, "disabled": _net.GREY, "problem": _net.RED, "not connected": _net.GREY}
STATE_WORDS = {"working": "working", "disabled": "disabled", "problem": "problem", "problems": "problem",
               "absent": "not connected", "disconnected": "not connected"}
SORTS = ("name", "class", "state")
AREAS = {  # the classes each area shows; USB also takes anything on the USB bus
    "usb": {"USB", "USBDEVICE"},
    "displays": {"DISPLAY", "MONITOR"},
    "audio": {"AUDIOENDPOINT", "MEDIA", "SOUND"},
    "storage": {"DISKDRIVE", "SCSIADAPTER", "HDC", "VOLUME"},
}
PAGE = 40  # rows per page in the listings
# pnputil's exit codes that are not failures (https://learn.microsoft.com/windows-hardware/drivers/devtest/pnputil-return-values)
RESTART_CODES = (3010, 1641)  # ERROR_SUCCESS_REBOOT_REQUIRED / a restart was started: it worked, a restart finishes it
NO_MORE_ITEMS = 259  # ERROR_NO_MORE_ITEMS: no matching device, or every device already has a better driver
RESTART_TEXT = "Windows needs a restart to finish this."
OEM_INF = re.compile(r"oem\d+\.inf")  # the same shape _third_party_packages reads
SNAPSHOT_DIR = "device-snapshots"  # inside _win.data_dir()
ROLLBACK_FLAG_NO_UI = 0x00000001  # newdev.h: DiRollbackDriver shows no dialogs
INVALID_HANDLE = ctypes.c_void_p(-1).value


class DeviceError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# READING — the Configuration Manager API, and the Enum registry key for unplugged devices
# ======================================================================
def _id_list(flags):
    """Instance IDs of every device with these flags (0 for all, FILTER_PRESENT for connected ones)."""
    length = ctypes.c_ulong()
    CFG.CM_Get_Device_ID_List_SizeW(ctypes.byref(length), None, flags)
    buffer = ctypes.create_unicode_buffer(length.value)
    CFG.CM_Get_Device_ID_ListW(None, buffer, length.value, flags)
    return [item for item in buffer[:].split("\x00") if item]


def _cm_id(devinst):
    buffer = ctypes.create_unicode_buffer(256)
    if CFG.CM_Get_Device_IDW(devinst, buffer, 256, 0) != CR_SUCCESS:
        return None
    return buffer.value


def _cm_text(devinst, prop, multi):
    """A registry-style property of a connected device. Multi-text values come back as a list."""
    size = ctypes.c_ulong(16384)
    kind = ctypes.c_ulong()
    buffer = ctypes.create_string_buffer(size.value)
    if CFG.CM_Get_DevNode_Registry_PropertyW(devinst, prop, ctypes.byref(kind), buffer, ctypes.byref(size), 0) != CR_SUCCESS:
        return None
    parts = [part for part in buffer.raw[:size.value].decode("utf-16-le", errors="replace").split("\x00") if part]
    if multi:
        return parts
    return parts[0] if parts else None


def _plain(text):
    """Windows stores some names as '@file.inf,%key%;Plain text'. The plain text is after the ';'."""
    if isinstance(text, str) and text.startswith("@") and ";" in text:
        return text.split(";", 1)[1]
    return text


def _read(instance_id, connected):
    """One device, as a dict. Connected devices come from the API; the rest from the Enum key."""
    row = {"instance_id": instance_id, "present": connected, "problem": 0, "parent": None}
    devinst = ctypes.c_ulong()
    if connected and CFG.CM_Locate_DevNodeW(ctypes.byref(devinst), instance_id, 0) == CR_SUCCESS:
        status, problem = ctypes.c_ulong(), ctypes.c_ulong()
        CFG.CM_Get_DevNode_Status(ctypes.byref(status), ctypes.byref(problem), devinst, 0)
        row["problem"] = problem.value
        parent = ctypes.c_ulong()
        if CFG.CM_Get_Parent(ctypes.byref(parent), devinst, 0) == CR_SUCCESS:
            row["parent"] = _cm_id(parent.value)
        for key, prop in CM_DRP.items():
            row[key] = _cm_text(devinst, prop, key in MULTI_TEXT)
    else:
        row["present"] = False
        path = f"{ENUM_KEY}\\{instance_id}"
        for key, value in ENUM_NAMES.items():
            row[key] = _net.reg_read(path, value)
    row["desc"], row["friendly"] = _plain(row["desc"]), _plain(row["friendly"])
    row["manufacturer"] = _plain(row["manufacturer"])
    row["name"] = (row["friendly"] or row["desc"] or instance_id).strip()
    row["hardware"], row["compatible"] = row["hardware"] or [], row["compatible"] or []
    row["bus"] = instance_id.split("\\", 1)[0].upper()
    row["state"] = _state(row)
    row["problem_text"] = PROBLEM_TEXT.get(row["problem"], f"problem code {row['problem']}") if row["problem"] else None
    return row


def _state(row):
    if not row["present"]:
        return "not connected"
    if row["problem"] == 0:
        return "working"
    if row["problem"] in DISABLED_CODES:
        return "disabled"
    return "problem"


def _devices():
    """Every device Windows knows about, sorted by name and numbered from 1. The list and the ids both come
    from here, so they always agree."""
    connected = {item.upper() for item in _id_list(FILTER_PRESENT)}
    rows = [_read(item, item.upper() in connected) for item in _id_list(0)]
    rows.sort(key=lambda row: row["name"].lower())
    for number, row in enumerate(rows, start=1):
        row["id"] = number
        row["class"] = row["class"] or None
    return rows


def _driver_date(text):
    """WMI dates look like 20240131000000.000000+000; show them as 2024-01-31."""
    if not text or len(text) < 8:
        return None
    return f"{text[:4]}-{text[4:6]}-{text[6:8]}"


def _driver_packages():
    """{device instance ID in upper case: the driver Windows has installed for it}, from WMI."""
    found = {}
    wmi = _net._wmi("root\\cimv2")
    for row in wmi.ExecQuery("SELECT DeviceID, DriverProviderName, DriverVersion, DriverDate, InfName, Signer "
                             "FROM Win32_PnPSignedDriver"):
        device_id = _net._prop(row, "DeviceID")
        if device_id:
            found[device_id.upper()] = {
                "provider": _net._prop(row, "DriverProviderName"),
                "version": _net._prop(row, "DriverVersion"),
                "date": _driver_date(_net._prop(row, "DriverDate")),
                "inf": _net._prop(row, "InfName"),
                "signer": _net._prop(row, "Signer"),
            }
    return found


def _driver_store():
    """How many driver packages are in the driver store, or None if it cannot be read."""
    try:
        return len(os.listdir(DRIVER_STORE))
    except OSError:
        return None


# ======================================================================
# FINDING — one device by id or name
# ======================================================================
def _find(word, rows):
    if word.isdecimal():
        for row in rows:
            if row["id"] == int(word):
                return row
        raise DeviceError(f"no device with id {word}. Run 'device ls' to see them.", 2)
    lowered = word.lower()
    for row in rows:
        if row["name"].lower() == lowered or row["instance_id"].lower() == lowered:
            return row
    raise DeviceError(f"no device called {word}. Run 'device ls' to see them, or use its id.", 2)


def _brief(row):
    return {
        "id": row["id"], "name": row["name"], "class": row["class"], "manufacturer": row["manufacturer"],
        "instance_id": row["instance_id"], "state": row["state"], "present": row["present"],
        "problem": row["problem"] or None, "problem_text": row["problem_text"],
    }


def _row_text(row):
    color = STATE_COLORS.get(row["state"], _net.YELLOW)
    return color + f"{row['id']:<6}{row['name'][:36]:<38}{(row['class'] or '-')[:18]:<20}{row['state']}" + _net.RESET


ROW_HEADER = f"{'ID':<6}{'NAME':<38}{'CLASS':<20}STATE"


# ======================================================================
# CHANGES — turn a device on or off, restart it, or add or remove its driver package.
# pnputil does the work: it is the Windows tool for these, and Device Manager makes the same calls.
# Each change checks for administrator rights before it asks anything, and reads the device back after.
# ======================================================================
ACTION_WORDS = {"enable": "enable", "on": "enable", "disable": "disable", "off": "disable", "restart": "restart"}
ACTION_TEXT = {"enable": "turn on", "disable": "turn off", "restart": "restart"}
ADD_WORDS = ("add", "install")
REMOVE_WORDS = ("rm", "remove", "delete", "uninstall")
# Turning these off can cut off the keyboard, the mouse, the network or the screen, so they ask twice
CRITICAL_CLASSES = {"SYSTEM", "KEYBOARD", "MOUSE", "HIDCLASS", "NET", "DISPLAY", "MONITOR", "DISKDRIVE",
                    "HDC", "SCSIADAPTER", "USB", "USBDEVICE", "PROCESSOR", "COMPUTER"}


@contextlib.contextmanager
def _exit_codes():
    """The exit codes of the programs started inside the block. _net.run_tool says only whether the code was 0, and
    pnputil needs the number: 3010 means the change worked and a restart finishes it."""
    codes, real = [], subprocess.run

    def run_and_note(*args, **kwargs):
        result = real(*args, **kwargs)
        codes.append(result.returncode)
        return result

    subprocess.run = run_and_note
    try:
        yield codes
    finally:
        subprocess.run = real


def _pnputil_reason(text):
    """Windows' reason from pnputil's output, without its banner line. A refusal becomes the administrator hint."""
    lowered = text.lower()
    if any(word in lowered for word in ("elevation", "access is denied", "administrat")):
        return _net.ADMIN_HINT
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    lines = [line for line in lines if not line.lower().startswith("microsoft pnp utility")]
    return " ".join(lines[:2]) or "pnputil failed with no message"


def _pnputil(args, accept=()):
    """Runs pnputil. Returns (its output, whether a restart is needed to finish, its exit code). Raises DeviceError with
    Windows' reason if it fails. Exit code 3010 (it worked, a restart finishes it) is a success, and so is any code in
    accept."""
    try:
        with _exit_codes() as codes:
            ok, text = _net.run_tool(["pnputil", *args], timeout=120)
    except _net.NetError as e:
        raise DeviceError(str(e))
    code = codes[-1] if codes else (0 if ok else None)
    if code not in (0, *RESTART_CODES, *accept):
        raise DeviceError(_pnputil_reason(text))
    return text, code in RESTART_CODES, code


def _note(options, text=""):
    """A progress line. With --json it goes to stderr, so that stdout stays plain data."""
    print(text, file=sys.stderr if options["json"] else sys.stdout)


def _ask(question, options):
    """_core.confirm, with the question kept off stdout when --json is on."""
    if not options["json"]:
        return _core.confirm(question, options["yes"])
    with contextlib.redirect_stdout(sys.stderr):
        return _core.confirm(question, options["yes"])


def _reread(instance_id):
    """The device as Windows reports it now, after a change."""
    for row in _devices():
        if row["instance_id"].upper() == instance_id.upper():
            return row
    return None


def _device_action(row, action, options):
    if action == "enable" and row["state"] == "working":
        print(f"{row['name']} is already on.")
        return
    if action == "disable" and row["state"] == "disabled":
        print(f"{row['name']} is already off.")
        return
    if not row["present"]:
        raise DeviceError(f"{row['name']} is not connected right now, so Windows cannot change it. "
                          "'device ls absent' lists devices that are not connected.", 2)
    _net.need_admin()
    if action == "disable":
        if not _core.confirm(f"Turn off {row['name']}? Anything that uses it stops until it is turned on again. "
                             f"To turn it back on: 'device {row['id']} enable'. [y/N]: ", options["yes"]):
            print("cancelled")
            return
        if (row["class"] or "").upper() in CRITICAL_CLASSES and not _core.confirm(
                f"{row['name']} is a device this PC may need (keyboard, mouse, network or screen). "
                "Turn it off anyway? [y/N]: ", options["yes"]):
            print("cancelled")
            return
    if action == "restart" and not _core.confirm(
            f"Restart {row['name']}? It stops for a moment, and anything using it may fail or reconnect. [y/N]: ",
            options["yes"]):
        print("cancelled")
        return
    print(f"{ACTION_TEXT[action]} {row['name']}...")
    _, restart, _ = _pnputil([f"/{action}-device", row["instance_id"]])
    now = _reread(row["instance_id"])
    if now is None:
        print(f"{row['name']} is no longer listed. Run 'device ls' to check.")
    else:
        print(f"{row['name']} is now {now['state']}.")
        if now["problem_text"]:
            print(f"  {now['problem_text']}")
    if restart:
        print(RESTART_TEXT)
    wanted = {"enable": "working", "disable": "disabled"}.get(action)
    if wanted and (now is None or now["state"] != wanted):
        print(f"{row['name']} is not {wanted} after the change, so it did not take effect.", file=sys.stderr)
        return 1
    return 0


def _driver_add(words, options):
    if len(words) != 1 or not words[0].lower().endswith(".inf"):
        raise DeviceError("usage: device driver add <file.inf>. Installing a newer driver is how it is updated.", 2)
    path = words[0]
    if not os.path.isfile(path):
        raise DeviceError(f"no file called {path}", 2)
    _net.need_admin()
    if not _core.confirm(f"Install the driver from {os.path.basename(path)}? Windows installs it for every device "
                         "it matches, and a wrong driver can stop a device working. [y/N]: ", options["yes"]):
        print("cancelled")
        return
    print(f"installing {path}...")
    text, restart, code = _pnputil(["/add-driver", path, "/install"], accept=(NO_MORE_ITEMS,))
    print(text)
    if code == NO_MORE_ITEMS:
        print("Windows already has an equal or better driver for every device this package matches, "
              "so no device was changed.")
    if restart:
        print(RESTART_TEXT)


def _driver_remove(words, options, rows):
    if len(words) != 1:
        raise DeviceError("usage: device driver rm <id>", 2)
    row = _find(words[0], rows)
    inf = ((_driver_packages().get(row["instance_id"].upper()) or {}).get("inf") or "").lower()
    if not inf:
        raise DeviceError(f"Windows does not name a driver package for {row['name']}, so there is nothing to remove.", 2)
    if not OEM_INF.fullmatch(inf):
        raise DeviceError(f"{inf} came with Windows, not from a driver you installed, so it cannot be removed here.", 2)
    _net.need_admin()
    if not _core.confirm(f"Remove driver package {inf} ({row['name']})? Windows removes it from every device that uses "
                         f"it, so {row['name']} may stop working until a driver is installed again. [y/N]: ",
                         options["yes"]):
        print("cancelled")
        return
    print(f"removing {inf}...")
    text, restart, _ = _pnputil(["/delete-driver", inf, "/uninstall"])
    print(text)
    if inf in {p["inf"].lower() for p in _driver_packages().values() if p.get("inf")}:
        print(f"Windows still lists {inf} for a device. Run 'device drivers' to check.")
    else:
        print(f"removed {inf}.")
    if restart:
        print(RESTART_TEXT)


def _rescan(options):
    """Device Manager's 'Scan for hardware changes'. Harmless, so it does not ask; it reports what changed."""
    _net.need_admin()
    before = {row["instance_id"].upper(): row for row in _devices()}
    _note(options, "scanning for hardware changes...")
    _, restart, _ = _pnputil(["/scan-devices"])
    after = _devices()
    added = [row for row in after if row["instance_id"].upper() not in before]
    changed = [(before[row["instance_id"].upper()], row) for row in after
               if row["instance_id"].upper() in before and before[row["instance_id"].upper()]["state"] != row["state"]]
    problems = [row for row in after if row["state"] == "problem"
                and before.get(row["instance_id"].upper(), {}).get("state") != "problem"]
    if options["json"]:
        _core.print_json({
            "added": [_brief(row) for row in added],
            "changed": [{**_brief(new), "was": old["state"]} for old, new in changed],
            "new_problems": [_brief(row) for row in problems],
            "total": len(after), "restart_needed": restart,
        })
        return
    if not added and not changed:
        print(f"{_net.GREEN}nothing changed:{_net.RESET} Windows found no new hardware, and no device changed state "
              f"({len(after)} devices known).")
    if added:
        print(f"{len(added)} new device(s):")
        print(ROW_HEADER)
        for row in added:
            print(_row_text(row))
    if changed:
        print(f"{len(changed)} device(s) changed state:")
        for old, new in changed:
            color = STATE_COLORS.get(new["state"], _net.YELLOW)
            print(color + f"  {new['id']:<6}{new['name'][:36]:<38}{old['state']} -> {new['state']}" + _net.RESET)
    if problems:
        print(_net.RED + "new problems" + _net.RESET)
        for row in problems:
            print(_net.RED + f"  {row['id']:<6}{row['name'][:36]:<38}code {row['problem']}: {row['problem_text']}"
                  + _net.RESET)
        print("  'device errors' lists every device with a problem.")
    if restart:
        print(RESTART_TEXT)


def _folder_size(path):
    """The size in bytes of a folder and everything in it. What cannot be read counts as nothing."""
    total = 0
    for folder, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(folder, name))
            except OSError:
                pass
    return total


def _size_text(size):
    return "under 1 MB" if size < 1024 * 1024 else f"{size / (1024 * 1024):,.0f} MB"


def _third_party_packages(sizes=False):
    """The driver packages somebody installed (not Windows), from 'pnputil /enum-drivers':
    [{"published": "oem12.inf", "original": "netwtw10.inf", "provider": "Intel", "bytes": size or None}].
    The labels in its output change with the language of Windows, so each block is read by position, and a package by
    the shape of its published name. With sizes=True the size of each package's folder in the driver store is added
    (an estimate: the folder is found by the original name). [] if pnputil cannot list them."""
    try:
        ok, text = _net.run_tool(["pnputil", "/enum-drivers"], timeout=120)
    except _net.NetError:
        return []
    if not ok:
        return []
    packages = []
    for block in re.split(r"\r?\n\s*\r?\n", text):
        values = [line.partition(":")[2].strip() for line in block.splitlines() if ":" in line]
        if len(values) >= 2 and re.fullmatch(r"oem\d+\.inf", values[0], re.IGNORECASE):
            packages.append({"published": values[0].lower(), "original": values[1].lower(),
                             "provider": values[2] if len(values) > 2 else None, "bytes": None})
    if sizes:
        try:
            folders = os.listdir(DRIVER_STORE)
        except OSError:
            folders = []
        for package in packages:
            matching = [name for name in folders if name.lower().startswith(package["original"] + "_")]
            if matching:
                package["bytes"] = sum(_folder_size(os.path.join(DRIVER_STORE, name)) for name in matching)
    return packages


def _drivers_export(words, options):
    """Copy driver packages out of the driver store into a folder: all the ones that were installed, or one device's."""
    if not 1 <= len(words) <= 2:
        raise DeviceError("usage: device drivers export <folder> [<id>]", 2)
    target = os.path.abspath(os.path.expanduser(words[0]))
    if os.path.isfile(target):
        raise DeviceError(f"{target} is a file, not a folder", 2)
    package, name = "*", None
    if len(words) == 2:
        row = _find(words[1], _devices())
        inf = ((_driver_packages().get(row["instance_id"].upper()) or {}).get("inf") or "").lower()
        if not inf:
            raise DeviceError(f"Windows does not name a driver package for {row['name']}, so there is nothing to export.", 2)
        if not OEM_INF.fullmatch(inf):
            raise DeviceError(f"{inf} came with Windows, not from a driver you installed, so it cannot be exported here.", 2)
        package, name = inf, row["name"]
    _net.need_admin()
    packages = _third_party_packages(sizes=True)
    if package == "*":
        total = sum(p["bytes"] or 0 for p in packages)
        what = (f"all {len(packages)} driver package(s) you installed" if packages
                else "every driver package you installed") + (f", about {_size_text(total)}," if total else "")
    else:
        size = next((p["bytes"] for p in packages if p["published"] == package), None)
        what = f"{package} ({name})" + (f", about {_size_text(size)}," if size else "")
    crowded = os.path.isdir(target) and bool(os.listdir(target))
    if not _ask(f"Export {what} to {target}?" + (" That folder already has files in it." if crowded else "")
                + " Drivers that came with Windows are not exported. [y/N]: ", options):
        _note(options, "cancelled")
        return
    _note(options, f"exporting to {target}...")
    try:
        os.makedirs(target, exist_ok=True)
    except OSError as e:
        raise DeviceError(f"could not create {target}: {e}")
    _, restart, _ = _pnputil(["/export-driver", package, target])
    folders = sorted(entry for entry in os.listdir(target) if os.path.isdir(os.path.join(target, entry)))
    size = _folder_size(target)
    if not folders:
        raise DeviceError(f"pnputil finished, but {target} has no driver packages in it. "
                          "Windows may have none that you installed.")
    if options["json"]:
        _core.print_json({"folder": target, "package": package, "exported_folders": len(folders), "folders": folders,
                          "size_bytes": size, "restart_needed": restart})
        return
    print(f"exported {len(folders)} package folder(s), {_size_text(size)}, into {target}.")
    print("To install one on another PC: 'device driver add <folder>\\<package>.inf' there.")
    if restart:
        print(RESTART_TEXT)


class _Guid(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8)]


class _DevInfoData(ctypes.Structure):
    """SP_DEVINFO_DATA, which SetupAPI uses to name one device (32 bytes on 64-bit Windows)."""
    _fields_ = [("cbSize", ctypes.c_uint32), ("ClassGuid", _Guid), ("DevInst", ctypes.c_uint32),
                ("Reserved", ctypes.c_size_t)]


def _last_error(prefix):
    """prefix, then what Windows says about the last call that failed. SetupAPI's own codes (0xE000xxxx) have no
    system text, so those show only as a number."""
    code = ctypes.get_last_error() & 0xFFFFFFFF
    if code == 5:
        return _net.ADMIN_HINT
    try:
        text = ctypes.FormatError(code).strip() if code < 0xE0000000 else ""
    except (OSError, OverflowError, ValueError):
        text = ""
    return f"{prefix}: {text or 'error'} (code 0x{code:08X})."


def _di_rollback(instance_id):
    """Device Manager's Roll Back Driver: SetupAPI opens the device and newdev's DiRollbackDriver puts the previous
    driver back. Returns whether a restart is needed to finish."""
    setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
    newdev = ctypes.WinDLL("newdev", use_last_error=True)
    setupapi.SetupDiCreateDeviceInfoList.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    setupapi.SetupDiCreateDeviceInfoList.restype = ctypes.c_void_p
    setupapi.SetupDiOpenDeviceInfoW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32,
                                                ctypes.POINTER(_DevInfoData)]
    setupapi.SetupDiOpenDeviceInfoW.restype = ctypes.c_int
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]
    setupapi.SetupDiDestroyDeviceInfoList.restype = ctypes.c_int
    newdev.DiRollbackDriver.argtypes = [ctypes.c_void_p, ctypes.POINTER(_DevInfoData), ctypes.c_void_p,
                                        ctypes.c_uint32, ctypes.POINTER(ctypes.c_int)]
    newdev.DiRollbackDriver.restype = ctypes.c_int
    devices = setupapi.SetupDiCreateDeviceInfoList(None, None)
    if devices in (None, 0, INVALID_HANDLE):
        raise DeviceError(_last_error("Windows would not open its list of devices"))
    try:
        data = _DevInfoData()
        data.cbSize = ctypes.sizeof(_DevInfoData)
        if not setupapi.SetupDiOpenDeviceInfoW(devices, instance_id, None, 0, ctypes.byref(data)):
            raise DeviceError(_last_error(f"Windows would not open {instance_id}"))
        restart = ctypes.c_int(0)
        if not newdev.DiRollbackDriver(devices, ctypes.byref(data), None, ROLLBACK_FLAG_NO_UI, ctypes.byref(restart)):
            raise DeviceError(_last_error("Windows would not roll the driver back")
                              + " A rollback only works when Windows kept the driver that was installed before.")
        return bool(restart.value)
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(devices)


def _driver_text(driver):
    if not driver:
        return "none"
    return f"{driver.get('version') or 'unknown version'} ({driver.get('inf') or 'unknown file'})"


def _rollback(words, options, rows):
    """Roll the device's driver back to the one it had before the current one."""
    if len(words) != 1:
        raise DeviceError("usage: device rollback <id>", 2)
    row = _find(words[0], rows)
    if not row["present"]:
        raise DeviceError(f"{row['name']} is not connected right now, so Windows cannot change it. "
                          "'device ls absent' lists devices that are not connected.", 2)
    before = _driver_packages().get(row["instance_id"].upper())
    if not before:
        raise DeviceError(f"Windows does not name a driver for {row['name']}, so there is nothing to roll back.", 2)
    _net.need_admin()
    if not _ask(f"Roll back the driver for {row['name']}? It has {_driver_text(before)} now. Windows puts back the "
                "driver it had before, the device stops for a moment, and a restart may be needed. To go forward "
                "again, install the newer package with 'device driver add <file.inf>'. [y/N]: ", options):
        _note(options, "cancelled")
        return
    _note(options, f"rolling back the driver for {row['name']}...")
    restart = _di_rollback(row["instance_id"])
    after = _driver_packages().get(row["instance_id"].upper())
    changed = (before.get("version"), before.get("inf")) != ((after or {}).get("version"), (after or {}).get("inf"))
    if options["json"]:
        _core.print_json({"id": row["id"], "name": row["name"], "before": before, "after": after,
                          "changed": changed, "restart_needed": restart})
        return
    if changed:
        print(f"{row['name']}: driver {_driver_text(before)} -> {_driver_text(after)}.")
    else:
        print(f"{row['name']} still reports {_driver_text(after)}. "
              + ("Windows may show the earlier driver after a restart." if restart else "Run 'device drivers' to check."))
    if restart:
        print(RESTART_TEXT)


# ======================================================================
# BACKUP AND COMPARE — a JSON snapshot of every device and driver, and what changed since
# ======================================================================
def _windows_version():
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    build, revision = _net.reg_read(path, "CurrentBuild"), _net.reg_read(path, "UBR")
    return {
        "product": _net.reg_read(path, "ProductName"),
        "version": _net.reg_read(path, "DisplayVersion") or _net.reg_read(path, "ReleaseId"),
        "build": f"{build}.{revision}" if build and revision is not None else build,
    }


def _counts(rows):
    counts = {"total": len(rows)}
    for state in ("working", "disabled", "problem", "not connected"):
        counts[state.replace(" ", "_")] = sum(1 for row in rows if row["state"] == state)
    return counts


def _snapshot_device(row, driver):
    """One device as a snapshot keeps it. There is no id, because ids shift; the instance ID is the key."""
    return {
        "instance_id": row["instance_id"], "name": row["name"], "class": row["class"],
        "manufacturer": row["manufacturer"], "state": row["state"], "present": row["present"],
        "problem": row["problem"] or None, "problem_text": row["problem_text"],
        "hardware_ids": row["hardware"], "driver": driver or None,
    }


def _snapshot(rows):
    packages = _driver_packages()
    return {
        "saved": datetime.now().isoformat(timespec="seconds"),
        "computer": os.environ.get("COMPUTERNAME") or socket.gethostname(),
        "windows": _windows_version(),
        "counts": _counts(rows),
        "driver_store_packages": _driver_store(),
        "devices": [_snapshot_device(row, packages.get(row["instance_id"].upper())) for row in rows],
    }


def _snapshot_files():
    """The saved snapshots, newest first. Their numbers (1 is the newest) come from this one list."""
    return sorted((_win.data_dir() / SNAPSHOT_DIR).glob("devices-*.json"), reverse=True)


def _load_snapshot(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise DeviceError(f"could not read {path}: {e}", 2)
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        raise DeviceError(f"{path} is not a device backup. 'device backup' makes one.", 2)
    if not all(isinstance(item, dict) and isinstance(item.get("instance_id"), str) for item in data["devices"]):
        raise DeviceError(f"{path} is damaged: some of its devices have no instance ID. Make a new one with 'device backup'.", 1)
    return data


def _write_snapshot(path, data):
    temp = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(temp, path)
    except OSError as e:
        raise DeviceError(f"could not save {path}: {e}")


def _backup_save(target, options):
    if target is None:
        folder = _win.data_dir() / SNAPSHOT_DIR
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path, extra = folder / f"devices-{stamp}.json", 1
        while path.exists():
            extra += 1
            path = folder / f"devices-{stamp}-{extra}.json"
    else:
        path = Path(os.path.expanduser(target))
        if path.suffix.lower() != ".json":
            raise DeviceError("a backup file must end in .json", 2)
        if path.exists() and not _ask(f"{path} already exists. Replace it? [y/N]: ", options):
            _note(options, "cancelled")
            return
    data = _snapshot(_devices())
    _write_snapshot(path, data)
    counts = data["counts"]
    if options["json"]:
        _core.print_json({"file": str(path), "saved": data["saved"], "devices": counts["total"],
                          "problems": counts["problem"], "counts": counts})
        return
    print(f"saved {counts['total']} devices ({counts['problem']} with problems) to {path}")
    if target is not None:
        print("That file is not in the backup folder, so 'device backup ls' will not list it. "
              "Compare with: device diff <file>")
    else:
        print("Compare later with: device diff    (device backup ls lists the saved backups)")


def _backup_entries():
    """[{"n", "file", ...}] for each saved snapshot, newest first; a file that cannot be read is marked damaged."""
    entries = []
    for number, path in enumerate(_snapshot_files(), start=1):
        try:
            data = _load_snapshot(path)
        except DeviceError:
            entries.append({"n": number, "file": str(path), "damaged": True})
            continue
        entries.append({"n": number, "file": str(path), "saved": data.get("saved"), "computer": data.get("computer"),
                        "windows": data.get("windows"), "devices": len(data["devices"]),
                        "problems": (data.get("counts") or {}).get("problem", 0)})
    return entries


def _backup_list(options):
    entries = _backup_entries()
    if options["json"]:
        _core.print_json({"folder": str(_win.data_dir() / SNAPSHOT_DIR), "backups": entries})
        return
    if not entries:
        print("no backups yet. 'device backup' saves one.")
        return
    print(f"{'N':<4}{'SAVED':<22}{'AGE':<16}{'DEVICES':<10}{'PROBLEMS':<10}FILE")
    for entry in entries:
        if entry.get("damaged"):
            print(_net.RED + f"{entry['n']:<4}{'(damaged)':<22}{'':<16}{'':<10}{'':<10}{entry['file']}" + _net.RESET)
            continue
        saved = (entry["saved"] or "").replace("T", " ")
        print(f"{entry['n']:<4}{saved:<22}{_win.ago(entry['saved']):<16}{entry['devices']:<10}"
              f"{entry['problems']:<10}{os.path.basename(entry['file'])}")
    print("\n'device diff <n>' compares the devices now with one. 'device backup rm <n>' deletes one.")


def _backup_remove(words, options):
    files = _snapshot_files()
    if len(words) != 1 or not words[0].isdecimal():
        raise DeviceError("usage: device backup rm <n>   (device backup ls shows the numbers)", 2)
    number = int(words[0])
    if not 1 <= number <= len(files):
        raise DeviceError(f"there is no backup {words[0]}. 'device backup ls' lists them.", 2)
    path = files[number - 1]
    try:
        data = _load_snapshot(path)
        about = f"saved {data.get('saved')}, {len(data['devices'])} devices"
    except DeviceError:
        about = "it cannot be read"
    if not _ask(f"Delete backup {number} ({about})? This cannot be undone. [y/N]: ", options):
        _note(options, "cancelled")
        return
    try:
        path.unlink()
    except OSError as e:
        raise DeviceError(f"could not delete {path}: {e}")
    if options["json"]:
        _core.print_json({"deleted": str(path), "remaining": len(files) - 1})
        return
    print(f"deleted backup {number}. {len(files) - 1} left.")


def _backup_cmd(words, options):
    if words and words[0].lower() in _net.LIST_WORDS:
        if len(words) > 1:
            raise DeviceError("usage: device backup ls", 2)
        return _backup_list(options)
    if words and words[0].lower() in _net.REMOVE_WORDS:
        return _backup_remove(words[1:], options)
    if len(words) > 1:
        raise DeviceError("usage: device backup [file.json] | device backup ls | device backup rm <n>", 2)
    return _backup_save(words[0] if words else None, options)


def _pick_snapshot(word):
    """(path, n) of the snapshot to compare with: the newest, the nth, or a file. n is None for a file."""
    if word is not None and not word.isdecimal():
        path = Path(os.path.expanduser(word))
        if not path.is_file():
            raise DeviceError(f"no file called {word}. 'device backup ls' lists the saved backups.", 2)
        return path, None
    files = _snapshot_files()
    if not files:
        raise DeviceError("there is no backup to compare with yet. 'device backup' saves one.", 2)
    number = int(word) if word is not None else 1
    if not 1 <= number <= len(files):
        raise DeviceError(f"there is no backup {word}. 'device backup ls' lists them.", 2)
    return files[number - 1], number


def _state_change(old, new):
    """(what happened, colour) when a device goes from one state to another."""
    if new == "problem":
        return "now has a problem", _net.RED
    if old == "problem":
        return "problem gone", _net.GREEN
    if old == "not connected":
        return "connected", _net.GREEN
    if new == "not connected":
        return "no longer connected", _net.GREY
    if new == "disabled":
        return "turned off", _net.GREY
    if old == "disabled":
        return "turned on", _net.GREEN
    return f"{old} -> {new}", _net.YELLOW


def _driver_key(driver):
    driver = driver or {}
    return (driver.get("version"), driver.get("inf"), driver.get("provider"), driver.get("date"))


def _compare(snapshot, rows, packages):
    """What differs between a snapshot and the devices now: added, removed and changed devices."""
    old = {item["instance_id"].upper(): item for item in snapshot["devices"]}
    now = {row["instance_id"].upper(): (row, _snapshot_device(row, packages.get(row["instance_id"].upper())))
           for row in rows}
    added = [{**item, "id": row["id"]} for key, (row, item) in now.items() if key not in old]
    removed = [item for key, item in old.items() if key not in now]
    changed = []
    for key, (row, item) in now.items():
        was = old.get(key)
        if was is None:
            continue
        changes = []
        if was.get("state") != item["state"]:
            text, _ = _state_change(was.get("state"), item["state"])
            changes.append({"what": "state", "from": was.get("state"), "to": item["state"], "text": text})
        elif was.get("problem") != item["problem"]:
            changes.append({"what": "problem", "from": was.get("problem"), "to": item["problem"],
                            "text": f"problem code {was.get('problem')} -> {item['problem']}"})
        if _driver_key(was.get("driver")) != _driver_key(item["driver"]):
            if not was.get("driver"):
                text = f"driver installed: {_driver_text(item['driver'])}"
            elif not item["driver"]:
                text = f"driver removed (was {_driver_text(was['driver'])})"
            else:
                text = f"driver {_driver_text(was['driver'])} -> {_driver_text(item['driver'])}"
            changes.append({"what": "driver", "from": was.get("driver"), "to": item["driver"], "text": text})
        if was.get("name") != item["name"]:
            changes.append({"what": "name", "from": was.get("name"), "to": item["name"],
                            "text": f"renamed from '{was.get('name')}'"})
        if changes:
            changed.append({"id": row["id"], "instance_id": item["instance_id"], "name": item["name"],
                            "class": item["class"], "changes": changes})
    for items in (added, removed, changed):
        items.sort(key=lambda item: item["name"].lower())
    return added, removed, changed


def _diff_cmd(words, options):
    if len(words) > 1:
        raise DeviceError("usage: device diff [<n> | <file.json>]", 2)
    path, number = _pick_snapshot(words[0] if words else None)
    snapshot = _load_snapshot(path)
    rows = _devices()
    added, removed, changed = _compare(snapshot, rows, _driver_packages())
    states = sum(1 for item in changed if any(c["what"] == "state" for c in item["changes"]))
    drivers = sum(1 for item in changed if any(c["what"] == "driver" for c in item["changes"]))
    summary = {"added": len(added), "removed": len(removed), "changed": len(changed),
               "state_changes": states, "driver_changes": drivers,
               "devices_then": len(snapshot["devices"]), "devices_now": len(rows)}
    if options["json"]:
        _core.print_json({
            "snapshot": {"n": number, "file": str(path), "saved": snapshot.get("saved"),
                         "computer": snapshot.get("computer"), "windows": snapshot.get("windows"),
                         "devices": len(snapshot["devices"])},
            "added": added, "removed": removed, "changed": changed, "summary": summary,
        })
        return
    saved = snapshot.get("saved")
    print(f"compared with the backup saved {str(saved).replace('T', ' ')} ({_win.ago(saved)}"
          + (f", on {snapshot['computer']}" if snapshot.get("computer") else "") + ")")
    if not (added or removed or changed):
        print(f"{_net.GREEN}no differences:{_net.RESET} the {len(rows)} devices and their drivers are as they were.")
        return
    if added:
        print(f"\nnew devices ({len(added)})")
        for item in added:
            color = STATE_COLORS.get(item["state"], _net.YELLOW)
            print(color + f"  {item['id']:<6}{item['name'][:36]:<38}{(item['class'] or '-')[:18]:<20}{item['state']}"
                  + _net.RESET)
    if removed:
        print(f"\ndevices Windows no longer lists ({len(removed)})")
        for item in removed:
            print(_net.GREY + f"  {item['name'][:36]:<38}{(item['class'] or '-')[:18]}" + _net.RESET)
    if changed:
        print(f"\nchanged ({len(changed)})")
        for item in changed:
            for change in item["changes"]:
                color = _state_change(change["from"], change["to"])[1] if change["what"] == "state" else _net.YELLOW
                if change["what"] == "problem" and change["to"]:
                    color = _net.RED
                print(color + f"  {item['id']:<6}{item['name'][:36]:<38}{change['text']}" + _net.RESET)
    print(f"\n{len(added)} new, {len(removed)} no longer listed, {len(changed)} changed "
          f"({states} state, {drivers} driver). 'device <id>' shows one; 'device backup' saves a new baseline.")


# ======================================================================
# COMMANDS — app.py calls run(args) with everything after "device"/"dvc"
# ======================================================================
def _list_options(words):
    options = {"class": None, "mfg": None, "state": None, "present": None, "sort": "name", "page": 1}
    i = 0
    while i < len(words):
        word = words[i].lower()
        value = words[i + 1] if i + 1 < len(words) else None
        if word == "class" and value:
            options["class"] = value.lower()
        elif word in ("mfg", "manufacturer") and value:
            options["mfg"] = value.lower()
        elif word == "sort" and value and value.lower() in SORTS:
            options["sort"] = value.lower()
        elif word == "page" and value and value.isdecimal() and int(value) >= 1:
            options["page"] = int(value)
        elif word in STATE_WORDS:
            options["state"] = STATE_WORDS[word]
            i += 1
            continue
        elif word in ("present", "connected"):
            options["present"] = True
            i += 1
            continue
        else:
            raise DeviceError("usage: device ls [class <name>] [mfg <text>] [working|disabled|problem|absent|present] "
                              "[sort name|class|state] [page <n>]", 2)
        i += 2
    return options


def _matches(row, options):
    if options["class"] and (row["class"] or "").lower() != options["class"]:
        return False
    if options["mfg"] and options["mfg"] not in (row["manufacturer"] or "").lower():
        return False
    if options["state"] and row["state"] != options["state"]:
        return False
    if options["present"] and not row["present"]:
        return False
    return True


def _list(words, options):
    settings = _list_options(words)
    found = [row for row in _devices() if _matches(row, settings)]
    keys = {"name": lambda row: row["name"].lower(),
            "class": lambda row: ((row["class"] or "").lower(), row["name"].lower()),
            "state": lambda row: (row["state"], row["name"].lower())}
    found.sort(key=keys[settings["sort"]])
    pages = max(1, math.ceil(len(found) / PAGE))
    if settings["page"] > pages:
        raise DeviceError(f"there are only {pages} page(s) of devices", 2)
    start = (settings["page"] - 1) * PAGE
    shown = found[start:start + PAGE]
    if options["json"]:
        _core.print_json({"page": settings["page"], "pages": pages, "total": len(found),
                          "devices": [_brief(row) for row in shown]})
        return
    print(ROW_HEADER)
    for row in shown:
        print(_row_text(row))
    print(f"\npage {settings['page']} of {pages}, {len(found)} device(s)."
          + (f" 'device ls page {settings['page'] + 1}' for the next." if settings["page"] < pages else ""))


def _inspect(word, rows, options):
    row = _find(word, rows)
    names = {r["instance_id"].upper(): r["name"] for r in rows}
    parent = names.get((row["parent"] or "").upper())
    children = [r["name"] for r in rows if (r["parent"] or "").upper() == row["instance_id"].upper()]
    driver = _driver_packages().get(row["instance_id"].upper(), {})
    if options["json"]:
        _core.print_json({**_brief(row), "location": row["location"], "bus": row["bus"],
                          "hardware_ids": row["hardware"], "compatible_ids": row["compatible"],
                          "service": row["service"], "driver_key": row["driver"], "driver": driver or None,
                          "parent": parent, "children": children})
        return
    _net.render(row["name"], [
        ("identity", [
            ("class", row["class"]), ("manufacturer", row["manufacturer"]),
            ("instance ID", row["instance_id"]), ("bus", row["bus"]), ("location", row["location"]),
        ]),
        ("hardware IDs", [("hardware", row["hardware"]), ("compatible", row["compatible"])]),
        ("driver", [
            ("service", row["service"]), ("driver key", row["driver"]), ("provider", driver.get("provider")),
            ("version", driver.get("version")), ("date", driver.get("date")), ("INF file", driver.get("inf")),
            ("signer", driver.get("signer")),
        ]),
        ("connection", [("parent", parent), ("children", children)]),
        ("status", [("state", row["state"]), ("problem", row["problem_text"])]),
    ])


def _errors(rows, options):
    problems = [r for r in rows if r["state"] == "problem"]
    disabled = [r for r in rows if r["state"] == "disabled"]
    missing = [r for r in problems if r["problem"] == MISSING_DRIVER]
    unknown = [r for r in problems if not r["class"]]
    gone = [r for r in rows if r["state"] == "not connected"]
    if options["json"]:
        _core.print_json({
            "problems": [_brief(r) for r in problems], "disabled": [_brief(r) for r in disabled],
            "missing_drivers": [_brief(r) for r in missing], "unknown_devices": [_brief(r) for r in unknown],
            "not_connected": len(gone),
        })
        return
    if not problems and not disabled:
        print(_net.GREEN + "no devices have problems or are disabled." + _net.RESET)
    if problems:
        print(_net.RED + "problem devices" + _net.RESET)
        for row in problems:
            print(_net.RED + f"  {row['id']:<6}{row['name'][:36]:<38}code {row['problem']}: {row['problem_text']}"
                  + _net.RESET)
    if disabled:
        print(_net.GREY + "\ndisabled devices" + _net.RESET)
        for row in disabled:
            print(_net.GREY + f"  {row['id']:<6}{row['name'][:36]:<38}turn it on in Device Manager, or 'device {row['id']}'"
                  + _net.RESET)
    print(f"\nmissing drivers: {len(missing)}   unknown devices: {len(unknown)}   "
          f"not connected right now: {len(gone)} (not an error; 'device ls absent' lists them)")


def _drivers_cmd(words, options, rows):
    packages = _driver_packages()
    store = _driver_store()
    if words:
        if len(words) != 1:
            raise DeviceError("usage: device drivers [<id>]", 2)
        row = _find(words[0], rows)
        driver = packages.get(row["instance_id"].upper(), {})
        if options["json"]:
            _core.print_json({"id": row["id"], "name": row["name"], "driver": driver or None,
                              "driver_key": row["driver"], "driver_store_packages": store})
            return
        _net.render(row["name"], [
            ("driver", [("provider", driver.get("provider")), ("version", driver.get("version")),
                        ("date", driver.get("date")), ("INF file", driver.get("inf")),
                        ("signer", driver.get("signer")), ("driver key", row["driver"])]),
            ("driver store", [("packages in the store", store)]),
        ])
        return
    listed = [row for row in rows if row["instance_id"].upper() in packages]
    if options["json"]:
        _core.print_json({"driver_store_packages": store, "devices": [
            {**_brief(row), "driver": packages[row["instance_id"].upper()]} for row in listed]})
        return
    print(f"{'ID':<6}{'NAME':<38}{'CLASS':<20}{'PROVIDER':<14}{'VERSION':<16}DATE")
    for row in listed:
        driver = packages[row["instance_id"].upper()]
        print(f"{row['id']:<6}{row['name'][:36]:<38}{(row['class'] or '-')[:18]:<20}"
              f"{(driver['provider'] or '-')[:14]:<14}{(driver['version'] or '-')[:16]:<16}{driver['date'] or '-'}")
    print(f"\n{len(listed)} device(s) have a driver. Driver store: {store if store is not None else 'not readable'} "
          "package(s). 'device drivers <id>' shows one device's driver.")


def _tree_text(row):
    color = STATE_COLORS.get(row["state"], _net.YELLOW)
    return color + f"{row['name']}  [{row['class'] or 'no class'}, {row['state']}]" + _net.RESET


def _tree(rows, words):
    if words and words[0].lower() != "all" or len(words) > 1:
        raise DeviceError("usage: device tree [all]", 2)
    show_all = bool(words)
    shown = [row for row in rows if row["present"] or show_all]
    keys = {row["instance_id"].upper() for row in shown}
    children = defaultdict(list)
    roots = []
    for row in shown:
        parent = (row["parent"] or "").upper()
        if parent in keys:
            children[parent].append(row)
        else:
            roots.append(row)
    roots.sort(key=lambda row: not row["present"])  # connected devices first, then the ones not connected
    lines = []

    def walk(row, depth):
        lines.append("  " * depth + _tree_text(row))
        for child in children[row["instance_id"].upper()]:
            walk(child, depth + 1)

    for root in roots:
        walk(root, 0)
    print("\n".join(lines))


def _in_area(row, area):
    if (row["class"] or "").upper() in AREAS[area]:
        return True
    return area == "usb" and row["bus"] == "USB"


def _area(area, rows, options):
    found = [row for row in rows if _in_area(row, area)]
    packages = _driver_packages() if area == "displays" else {}
    names = {row["instance_id"].upper(): row["name"] for row in rows}
    if options["json"]:
        out = []
        for row in found:
            item = _brief(row)
            if area == "usb":
                item["vid_pid"] = _vid_pid(row["instance_id"])
            if area == "displays":
                item["driver_version"] = (packages.get(row["instance_id"].upper()) or {}).get("version")
            if area == "storage":
                item["controller"] = names.get((row["parent"] or "").upper())
            out.append(item)
        _core.print_json({"area": area, "devices": out})
        return
    print(f"{'ID':<6}{'NAME':<38}{'CLASS':<20}{'STATE':<16}DETAIL")
    for row in found:
        if area == "usb":
            detail = _vid_pid(row["instance_id"]) or "-"
        elif area == "displays":
            detail = (packages.get(row["instance_id"].upper()) or {}).get("version") or "-"
        elif area == "storage":
            detail = names.get((row["parent"] or "").upper()) or "-"
        else:
            detail = row["manufacturer"] or "-"
        color = STATE_COLORS.get(row["state"], _net.YELLOW)
        print(color + f"{row['id']:<6}{row['name'][:36]:<38}{(row['class'] or '-')[:18]:<20}"
              f"{row['state']:<16}{detail}" + _net.RESET)
    if not found:
        print(f"no {area} devices found")
    notes = {"usb": "connection speed and power are not read yet.",
             "displays": "resolutions, refresh rates and scale are in 'display ls'.",
             "storage": "the detail column is the device each one is plugged into (its parent).",
             "audio": "the detail column is the manufacturer."}
    print(f"\n{len(found)} device(s). {notes[area]}")


def _vid_pid(instance_id):
    match = re.search(r"VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})", instance_id.upper())
    return f"{match.group(1)}:{match.group(2)}" if match else None


def _search(words, rows):
    if not words:
        raise DeviceError("usage: device search <text>", 2)
    text = " ".join(words).lower()
    packages = _driver_packages()
    found = []
    for row in rows:
        provider = (packages.get(row["instance_id"].upper()) or {}).get("provider") or ""
        haystack = " ".join([row["name"], row["class"] or "", row["manufacturer"] or "", row["instance_id"],
                             " ".join(row["hardware"]), " ".join(row["compatible"]), provider]).lower()
        if text in haystack:
            found.append(row)
    if not found:
        print(f"no device matches '{text}'")
        return
    print(ROW_HEADER)
    for row in found:
        print(_row_text(row))
    print(f"\n{len(found)} device(s) match '{text}'.")


def _report(rows):
    packages = _driver_packages()
    _core.print_json({
        "counts": _counts(rows),
        "driver_store_packages": _driver_store(),
        "devices": [{**_brief(row), "hardware_ids": row["hardware"], "driver": packages.get(row["instance_id"].upper())}
                    for row in rows],
    })


def run(args):
    """Run one device command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    word, rest = args[0].lower(), args[1:]
    try:
        if word in _net.LIST_WORDS:
            _list(rest, options)
        elif word == "inspect" and len(rest) == 1:
            _inspect(rest[0], _devices(), options)
        elif word == "errors" and not rest:
            _errors(_devices(), options)
        elif word == "drivers" and rest[:1] and rest[0].lower() == "export":
            _drivers_export(rest[1:], options)
        elif word == "drivers":
            _drivers_cmd(rest, options, _devices())
        elif word == "tree":
            _tree(_devices(), rest)
        elif word == "search":
            _search(rest, _devices())
        elif word in AREAS and not rest:
            _area(word, _devices(), options)
        elif word == "report" and not rest:
            _report(_devices())
        elif word == "rescan" and not rest:
            _rescan(options)
        elif word == "rollback":
            _rollback(rest, options, _devices())
        elif word == "backup":
            _backup_cmd(rest, options)
        elif word == "diff":
            _diff_cmd(rest, options)
        elif word == "driver" and rest[:1] and rest[0].lower() in ADD_WORDS:
            _driver_add(rest[1:], options)
        elif word == "driver" and rest[:1] and rest[0].lower() in REMOVE_WORDS:
            _driver_remove(rest[1:], options, _devices())
        elif len(args) == 2 and args[1].lower() in ACTION_WORDS:
            return _device_action(_find(args[0], _devices()), ACTION_WORDS[args[1].lower()], options) or 0
        elif len(args) == 1:
            _inspect(args[0], _devices(), options)
        else:
            raise DeviceError(f"usage: {USAGE}", 2)
        return 0
    except (DeviceError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

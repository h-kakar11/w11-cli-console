"""
bluetooth: the Bluetooth radio and your Bluetooth devices, the same as Settings > Bluetooth & devices.
Routed from app.py ("bluetooth" or "bt").

    bt                           the radio, and your paired devices
    bt on | off                  turn the Bluetooth radio on or off
    bt ls                        paired devices: kind, connected or not, battery, address
    bt <id>                      one device in full: address, kind, profiles, how it is paired
    bt scan [seconds] [--all]    look for nearby devices that are in pairing mode (the result is saved)
    bt pair <n|name|address>     pair with a device from the last scan (--pin / --code for devices that ask)
    bt rm <id>                   unpair a device (asks first)
    bt why                       "Bluetooth is not working": what is wrong and the command that fixes it
    bt service [restart]         the Bluetooth Support Service (restarting it needs administrator)
    bt connect | disconnect <id> Windows has no API for these: shows the state and opens Settings
    bt send [file] | receive     Windows' Bluetooth File Transfer wizard
    bt more | open               the classic Bluetooth Settings dialog, or the Settings page

Everything is done through Windows' Bluetooth API (WinRT, through the winrt packages), the one Settings uses, so
nothing here needs administrator rights except restarting the service. A device must be in pairing mode before
'bt scan' can see it. Windows has no documented way for a program to connect or disconnect a device that is
already paired, so 'bt connect' and 'bt disconnect' open Settings instead of guessing (fashion.txt, rule 13).
Battery levels are read from a device property that many devices fill in and Microsoft does not document, so a
missing battery means "the device does not say", not "empty".
"""

import asyncio
import contextlib
import getpass
import os
import platform
import queue
import re
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

import _core
import _net
import _probe
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "bluetooth"
ALIASES = ["bt"]
SUMMARY = "Bluetooth: devices, pairing, removal and the radio"
# extra words people use, for 'settings search'
KEYWORDS = ["pair", "headphones", "earbuds", "mouse", "keyboard", "wireless", "airpods", "radio", "unpair"]
USAGE = ("bt | bt on|off | bt ls | bt <id> | bt scan [sec] | bt pair <n|name|address> | bt rm <id> | bt why | "
         "bt service [restart] | bt connect|disconnect <id> | bt send|receive | bt more | bt open")
HELP = [
    ("bt", "the Bluetooth radio, and your paired devices"),
    ("bt on | off", "turn Bluetooth on or off"),
    ("bt ls", "paired devices: what they are, connected or not, battery, address"),
    ("bt scan", "find nearby devices that are in pairing mode"),
    ("bt pair <n>", "pair with number n from the last scan"),
    ("bt rm <id>", "unpair a device (asks first)"),
    ("", "more"),
    ("bt <id>", "one device in full: address, kind, profiles, how it is paired"),
    ("bt why", "Bluetooth is not working: what is wrong and what fixes it"),
    ("bt service [restart]", "the Bluetooth Support Service (restart needs administrator)"),
    ("bt connect | disconnect <id>", "Windows has no API for these: shows the state, opens Settings"),
    ("bt send [file] | receive", "Windows' Bluetooth File Transfer wizard"),
    ("bt more", "the classic Bluetooth Settings dialog (discovery, notifications, tray icon)"),
    ("bt open", "open Settings > Bluetooth & devices"),
]
TIP = ("Put the device in pairing mode first, then 'bt scan'. Ids shift when devices come and go, so run 'bt ls' "
       "before 'bt rm'. Nothing here needs administrator rights.")
RUN_ALONE = True  # typing 'bt' on its own shows the radio and the paired devices, which changes nothing

# ======================================================================
# CONSTANTS
# ======================================================================
SETTINGS_PAGE = "ms-settings:bluetooth"
RADIOS_PRIVACY_PAGE = "ms-settings:privacy-radios"
SERVICE = "bthserv"
SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services\bthserv"
START_TYPES = {2: "automatic", 3: "manual (Windows starts it when something needs it)", 4: "disabled"}
ENUM_KEY = r"SYSTEM\CurrentControlSet\Enum"
RADIO_BUSES = ("USB", "PCI", "ACPI", "ROOT", "SD")  # where a Bluetooth adapter sits; the BTH* buses hold remote devices
BLUETOOTH_CLASS = "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}"
# Association endpoint protocol ids, from Microsoft's Device Enumeration and Pairing sample
CLASSIC_PROTOCOL = "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}"
LE_PROTOCOL = "{bb7bb05e-5972-42b5-94fc-76eaa7084d49}"
AEP_PROPERTIES = [
    "System.Devices.Aep.DeviceAddress", "System.Devices.Aep.IsConnected", "System.Devices.Aep.IsPaired",
    "System.Devices.Aep.CanPair", "System.Devices.Aep.SignalStrength", "System.Devices.Aep.Bluetooth.Le.IsConnectable",
]
SCAN_DEFAULT, SCAN_MIN, SCAN_MAX = 10, 3, 60  # seconds
SCAN_FILE = "bluetooth-scan.json"
SCAN_FRESH = 15 * 60  # seconds a scan stays usable for 'bt pair <n>'
FIND_SECONDS = 8  # 'bt pair <name>' with no saved scan looks for this long
PAIR_TIMEOUT = 60  # seconds Windows gets to finish a pairing
CALL_TIMEOUT = 30  # seconds one Windows call gets before it is treated as stuck
BASE_UUID_TAIL = "-0000-1000-8000-00805f9b34fb"  # the Bluetooth base UUID: a 16-bit id sits in front of it
# The device property Windows keeps a paired device's battery percentage in. Microsoft does not document it
# (community scripts read it the same way), so it is read-only here and a missing value is shown as "-".
BATTERY_SCRIPT = r"""
$key = '{104EA319-6EE2-4701-BD47-8DDBF425BBE5} 2'
Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName $key -ErrorAction SilentlyContinue
    if ($p -and $null -ne $p.Data) { [pscustomobject]@{ InstanceId = $_.InstanceId; Battery = [int]$p.Data } }
}
"""

RADIO_STATES = {"ON": "on", "OFF": "off", "DISABLED": "disabled", "UNKNOWN": "unknown"}
ACCESS_WORDS = {"ALLOWED": "allowed", "DENIED_BY_USER": "denied by you", "DENIED_BY_SYSTEM": "denied by the system",
                "UNSPECIFIED": "unknown"}
PAIR_PROBLEMS = {
    "NOT_READY_TO_PAIR": "the device is not ready to pair. Put it in pairing mode and try again.",
    "NOT_PAIRED": "Windows could not pair with it.",
    "CONNECTION_REJECTED": "the device refused the connection. Put it in pairing mode again.",
    "TOO_MANY_CONNECTIONS": "the device or this PC has too many Bluetooth connections.",
    "HARDWARE_FAILURE": "the Bluetooth hardware failed. Try 'bt service restart', or turn Bluetooth off and on.",
    "AUTHENTICATION_TIMEOUT": "the device did not answer in time, or the code was not entered in time.",
    "AUTHENTICATION_NOT_ALLOWED": "the device does not allow this kind of pairing.",
    "AUTHENTICATION_FAILURE": "the codes did not match, or the PIN was wrong.",
    "NO_SUPPORTED_PROFILES": "the device offers nothing this PC can use.",
    "PROTECTION_LEVEL_COULD_NOT_BE_MET": "the device cannot pair securely enough.",
    "ACCESS_DENIED": "Windows would not allow the pairing (a policy or a privacy setting).",
    "INVALID_CEREMONY_DATA": "the pairing code was not accepted.",
    "PAIRING_CANCELED": "the pairing was cancelled.",
    "OPERATION_ALREADY_IN_PROGRESS": "Windows is already pairing a device. Wait a moment and try again.",
    "REQUIRED_HANDLER_NOT_REGISTERED": "this pairing needs something this page does not provide. Use 'bt open'.",
    "REJECTED_BY_HANDLER": "the pairing was declined here, so nothing was paired.",
    "REMOTE_DEVICE_HAS_ASSOCIATION": "the device is already paired with something else. Reset it, then try again.",
    "FAILED": "Windows could not pair with it.",
}
UNPAIR_PROBLEMS = {
    "OPERATION_ALREADY_IN_PROGRESS": "Windows is already working on this device. Wait a moment and try again.",
    "ACCESS_DENIED": "Windows would not allow it (a policy or a privacy setting).",
    "FAILED": "Windows could not remove it.",
}
PROTECTION_WORDS = {"NONE": "none", "ENCRYPTION": "encrypted", "ENCRYPTION_AND_AUTHENTICATION": "encrypted and authenticated",
                    "DEFAULT": "default"}

# What a device is, from its Bluetooth class of device (classic) or appearance (low energy)
AUDIO_KINDS = {1: "headset", 2: "hands-free", 4: "microphone", 5: "speaker", 6: "headphones", 7: "portable audio",
               8: "car audio", 9: "set-top box", 10: "hi-fi audio", 11: "VCR", 12: "video camera", 13: "camcorder",
               14: "video monitor", 15: "display and speaker", 16: "video conferencing", 18: "gaming audio"}
COMPUTER_KINDS = {1: "desktop", 2: "server", 3: "laptop", 4: "handheld PC", 5: "palm-size PC", 6: "wearable computer",
                  7: "tablet"}
PHONE_KINDS = {1: "mobile phone", 2: "cordless phone", 3: "smartphone", 4: "modem", 5: "ISDN"}
WEARABLE_KINDS = {1: "watch", 2: "pager", 3: "jacket", 4: "helmet", 5: "glasses"}
HEALTH_KINDS = {1: "blood pressure monitor", 2: "thermometer", 3: "scale", 4: "glucose meter", 5: "pulse oximeter",
                6: "heart-rate monitor", 7: "health display", 8: "step counter"}
PERIPHERAL_KINDS = {1: "joystick", 2: "gamepad", 3: "remote control", 4: "sensor", 5: "drawing tablet",
                    6: "card reader", 7: "pen", 8: "scanner", 9: "gesture input"}
IMAGING_KINDS = ((0x80, "printer"), (0x40, "scanner"), (0x20, "camera"), (0x10, "display"))
TOY_KINDS = {1: "robot", 2: "vehicle", 3: "doll", 4: "controller", 5: "game"}
LE_CATEGORIES = {
    1: ("phone", "phone"), 2: ("computer", "computer"), 3: ("wearable", "watch"), 4: ("wearable", "clock"),
    5: ("other", "display"), 6: ("input", "remote control"), 7: ("wearable", "glasses"), 8: ("other", "tag"),
    9: ("other", "key finder"), 10: ("audio", "media player"), 11: ("input", "barcode scanner"),
    12: ("health", "thermometer"), 13: ("health", "heart-rate sensor"), 14: ("health", "blood pressure monitor"),
    16: ("health", "glucose meter"), 17: ("health", "running sensor"), 18: ("health", "cycling sensor"),
    49: ("health", "pulse oximeter"), 50: ("health", "scale"),
}
LE_HID_KINDS = {1: ("keyboard", "keyboard"), 2: ("mouse", "mouse"), 3: ("gamepad", "joystick"), 4: ("gamepad", "gamepad"),
                5: ("input", "drawing tablet"), 6: ("input", "card reader"), 7: ("input", "pen"),
                8: ("input", "barcode scanner")}
# The profiles and services Windows installs for a device, by their 16-bit Bluetooth id
PROFILE_NAMES = {
    0x1101: "serial port", 0x1105: "file transfer (OBEX push)", 0x1108: "headset", 0x110A: "audio source (A2DP)",
    0x110B: "audio sink (A2DP)", 0x110C: "remote control target (AVRCP)", 0x110D: "advanced audio (A2DP)",
    0x110E: "remote control (AVRCP)", 0x110F: "remote control controller (AVRCP)", 0x1112: "headset audio gateway",
    0x1115: "personal area network", 0x111E: "hands-free", 0x111F: "hands-free audio gateway",
    0x1124: "keyboard, mouse or gamepad (HID)", 0x112F: "phonebook access", 0x1132: "message access",
    0x1200: "device information (PnP)", 0x1800: "generic access", 0x1801: "generic attribute", 0x1802: "immediate alert",
    0x1803: "link loss", 0x1804: "transmit power", 0x1805: "current time", 0x1809: "thermometer", 0x180A: "device information",
    0x180D: "heart rate", 0x180F: "battery", 0x1812: "keyboard, mouse or gamepad (HID over GATT)",
    0x1816: "cycling speed and cadence", 0x181C: "user data", 0x1826: "fitness machine",
}


class BluetoothError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# WINDOWS — the Bluetooth API (WinRT), loaded only when a command needs it
# ======================================================================
_rt = None


def _winrt():
    global _rt
    if _rt is None:
        try:
            from winrt.windows.devices.bluetooth import (
                BluetoothAdapter,
                BluetoothConnectionStatus,
                BluetoothDevice,
                BluetoothLEDevice,
            )
            from winrt.windows.devices.enumeration import (
                DeviceInformation,
                DeviceInformationKind,
                DevicePairingKinds,
                DevicePairingProtectionLevel,
                DevicePairingResultStatus,
                DeviceUnpairingResultStatus,
            )
            from winrt.windows.devices.radios import Radio, RadioAccessStatus, RadioKind, RadioState
        except ImportError as e:
            missing = f" (missing: {e.name})" if getattr(e, "name", None) else ""
            raise BluetoothError(f"Bluetooth needs the winrt packages{missing}. "
                                 "Run: py -m pip install -r requirements.txt")
        _rt = {
            "adapter": BluetoothAdapter, "status": BluetoothConnectionStatus, "classic": BluetoothDevice,
            "le": BluetoothLEDevice, "info": DeviceInformation, "ikind": DeviceInformationKind,
            "kinds": DevicePairingKinds, "level": DevicePairingProtectionLevel,
            "pair_status": DevicePairingResultStatus, "unpair_status": DeviceUnpairingResultStatus,
            "radio": Radio, "access": RadioAccessStatus, "radio_kind": RadioKind, "radio_state": RadioState,
        }
    return _rt


def _wait(make, timeout=CALL_TIMEOUT):
    """Run one WinRT async call (or a coroutine that makes several) to the end and return its result."""
    async def runner():
        return await asyncio.wait_for(make(), timeout)
    try:
        return asyncio.run(runner())
    except asyncio.TimeoutError:
        raise BluetoothError(f"Windows took longer than {timeout} s to answer. Bluetooth may be stuck: "
                             "try 'bt service restart', or turn Bluetooth off and on.")
    except OSError as e:
        raise BluetoothError(f"Windows refused: {e.strerror or e}")


def _name(enum_class, value):
    """An enum value's name in upper case, such as CONNECTED. pywinrt gives Python enums; the class is applied
    first because some properties hand back the plain number."""
    try:
        return enum_class(value).name.upper()
    except (ValueError, TypeError, AttributeError):
        return str(getattr(value, "name", value)).upper()


def _get(obj, attribute, default=None):
    """A WinRT property, or the default when this Windows does not have it or refuses to say."""
    try:
        value = getattr(obj, attribute)
    except (AttributeError, OSError):
        return default
    return default if value is None else value


def _prop(props, key, default=None):
    """One value from a DeviceInformation properties map (a Python mapping, or a WinRT map view)."""
    if props is None:
        return default
    try:
        value = props.get(key)
    except (AttributeError, TypeError):
        try:
            value = props[key]
        except (KeyError, TypeError, OSError):
            return default
    except OSError:
        return default
    return default if value is None else value


def _props_dict(props):
    """A properties map as a plain dict, for values that arrive in pieces (DeviceInformationUpdate)."""
    if props is None:
        return {}
    try:
        return {key: props[key] for key in props.keys()}
    except (AttributeError, TypeError, KeyError, OSError):
        try:
            return dict(props)
        except (TypeError, ValueError, OSError):
            return {}


# ======================================================================
# ADDRESSES AND KINDS — pure functions
# ======================================================================
def _address(value):
    """A Bluetooth address as AA:BB:CC:DD:EE:FF, from the 48-bit number WinRT gives or from text. None if it is neither."""
    if isinstance(value, int) and not isinstance(value, bool):
        digits = f"{value:012X}"
    else:
        digits = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if len(digits) != 12 or digits == "0" * 12:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _parse_address(word):
    """The address in a word such as aa:bb:cc:dd:ee:ff or AABBCCDDEEFF, or None."""
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}", word or ""):
        return _address(word)
    return None


def _classic_kind(raw):
    """(group, detail) from a classic device's 24-bit class of device: 5 bits of major class, 6 bits of minor."""
    if not raw:
        return "other", "device"
    major, minor = (raw >> 8) & 0x1F, (raw >> 2) & 0x3F
    if major == 1:
        return "computer", COMPUTER_KINDS.get(minor, "computer")
    if major == 2:
        return "phone", PHONE_KINDS.get(minor, "phone")
    if major == 3:
        return "network", "network access point"
    if major == 4:
        return "audio", AUDIO_KINDS.get(minor, "audio device")
    if major == 5:  # peripherals: the top two minor bits say keyboard / pointing device, the rest what it is
        pointing, sub = (raw >> 6) & 0x3, (raw >> 2) & 0xF
        if sub in PERIPHERAL_KINDS:
            return ("gamepad" if sub in (1, 2) else "input"), PERIPHERAL_KINDS[sub]
        return {1: ("keyboard", "keyboard"), 2: ("mouse", "mouse"), 3: ("keyboard", "keyboard and mouse")}.get(
            pointing, ("input", "input device"))
    if major == 6:
        for bit, word in IMAGING_KINDS:
            if raw & bit:
                return "imaging", word
        return "imaging", "imaging device"
    if major == 7:
        return "wearable", WEARABLE_KINDS.get(minor, "wearable")
    if major == 8:
        return "toy", TOY_KINDS.get(minor, "toy")
    if major == 9:
        return "health", HEALTH_KINDS.get(minor, "health device")
    return "other", "device"


def _le_kind(raw):
    """(group, detail) from a low-energy appearance value: the category is the number above the low 6 bits."""
    if not raw:
        return "other", "device"
    category, sub = raw >> 6, raw & 0x3F
    if category == 15:
        return LE_HID_KINDS.get(sub, ("input", "input device"))
    return LE_CATEGORIES.get(category, ("other", "device"))


def _short_uuid(text):
    """The 16-bit id in a Bluetooth base UUID such as 0000110b-0000-1000-8000-00805f9b34fb, or None."""
    text = str(text or "").strip("{}").lower()
    if text.endswith(BASE_UUID_TAIL) and len(text) == 36 and text.startswith("0000"):
        try:
            return int(text[4:8], 16)
        except ValueError:
            return None
    return None


def _profile_name(number):
    return PROFILE_NAMES.get(number, f"service 0x{number:04X}")


def _plain(text):
    """Windows stores some names as '@file.inf,%key%;Plain text'. The plain text is after the ';'."""
    if isinstance(text, str) and text.startswith("@") and ";" in text:
        return text.split(";", 1)[1]
    return text


def _signal_words(dbm):
    if not isinstance(dbm, (int, float)):
        return "-"
    if dbm >= -50:
        return "strong"
    if dbm >= -70:
        return "good"
    if dbm >= -85:
        return "weak"
    return "very weak"


# ======================================================================
# THE RADIO — Windows.Devices.Radios, the API the Bluetooth switch in quick settings uses
# ======================================================================
async def _radios_async(rt):
    """(access, [Bluetooth radios]). Windows wants RequestAccess once before it lets a program change a radio."""
    access = "UNKNOWN"
    try:
        access = _name(rt["access"], await rt["radio"].request_access_async())
    except OSError:
        pass  # reading still works without it
    radios = await rt["radio"].get_radios_async()
    return access, [radio for radio in radios if _name(rt["radio_kind"], radio.kind) == "BLUETOOTH"]


def _radio():
    """The Bluetooth radio as a dict: state (on, off, disabled, unknown, none), its name, and whether access is allowed."""
    rt = _winrt()
    access, radios = _wait(lambda: _radios_async(rt))
    if not radios:
        return {"state": "none", "name": None, "count": 0, "access": ACCESS_WORDS.get(access, "unknown")}
    first = radios[0]
    state = _name(rt["radio_state"], first.state)
    return {"state": RADIO_STATES.get(state, "unknown"), "name": (_get(first, "name") or "").strip() or None,
            "count": len(radios), "access": ACCESS_WORDS.get(access, "unknown")}


def _adapter():
    """What the adapter can do, or None when Windows has no Bluetooth adapter."""
    rt = _winrt()

    async def read():
        return await rt["adapter"].get_default_async()
    adapter = _wait(read)
    if adapter is None:
        return None
    return {"address": _address(_get(adapter, "bluetooth_address")),
            "classic": _get(adapter, "is_classic_supported"), "low_energy": _get(adapter, "is_low_energy_supported"),
            "central": _get(adapter, "is_central_role_supported"),
            "peripheral": _get(adapter, "is_peripheral_role_supported")}


def _set_radio(on):
    """Ask Windows to switch the radio. Returns Windows' answer (ALLOWED, DENIED_BY_USER ...), or NONE with no radio."""
    rt = _winrt()
    target = rt["radio_state"]["ON" if on else "OFF"]

    async def change():
        _, radios = await _radios_async(rt)
        if not radios:
            return "NONE"
        for attempt in range(2):
            try:
                return _name(rt["access"], await radios[0].set_state_async(target))
            except OSError:
                if attempt:
                    raise
                await asyncio.sleep(1)  # another program was changing it at the same moment (ERROR_BUSY)
    return _wait(change)


def _radio_settled(wanted, tries=4):
    """The radio after a change, read until it shows the wanted state (Windows takes a moment)."""
    now = _radio()
    for _ in range(tries - 1):
        if now["state"] == wanted:
            break
        time.sleep(1)
        now = _radio()
    return now


# ======================================================================
# PAIRED DEVICES — one list for every command, numbered by name
# ======================================================================
async def _paired_async(rt):
    found = []
    for device_class, low_energy in ((rt["classic"], False), (rt["le"], True)):
        try:
            infos = await rt["info"].find_all_async(device_class.get_device_selector_from_pairing_state(True))
            opened = await asyncio.gather(*[device_class.from_id_async(info.id) for info in infos],
                                          return_exceptions=True)
        except OSError:
            continue  # a PC without low-energy support has nothing to list there
        for device in opened:
            if device is not None and not isinstance(device, BaseException):
                found.append(_describe(rt, device, low_energy))
    return found


def _describe(rt, device, low_energy):
    address = _address(_get(device, "bluetooth_address"))
    if low_energy:
        group, detail = _le_kind(_get(_get(device, "appearance"), "raw_value", 0))
    else:
        group, detail = _classic_kind(_get(_get(device, "class_of_device"), "raw_value", 0))
    name = (_get(device, "name") or "").strip()
    return {
        "name": name or address or "(no name)", "address": address, "kind": group, "kind_detail": detail,
        "connected": _name(rt["status"], _get(device, "connection_status")) == "CONNECTED",
        "classic": not low_energy, "low_energy": low_energy, "battery": None, "_device": device,
    }


def _merge(found):
    """Devices that speak both classic and low energy show up twice with one address: one row for each device."""
    merged = {}
    for item in found:
        key = item["address"] or item["name"].lower()
        if key not in merged:
            item["_devices"] = [item["_device"]]
            merged[key] = item
            continue
        first = merged[key]
        first["classic"], first["low_energy"] = first["classic"] or item["classic"], first["low_energy"] or item["low_energy"]
        first["connected"] = first["connected"] or item["connected"]
        first["_devices"].append(item["_device"])
        if first["kind_detail"] == "device" and item["kind_detail"] != "device":
            first["kind"], first["kind_detail"] = item["kind"], item["kind_detail"]
    return list(merged.values())


def _battery_levels():
    """{address without colons: percent} for the devices that report a battery. Empty when PowerShell or the property
    is not there: a missing battery is not an error."""
    try:
        rows = _win.powershell_json(BATTERY_SCRIPT, timeout=45)
    except _net.NetError:
        return {}
    levels = {}
    for row in rows:
        match = re.search(r"DEV_([0-9A-Fa-f]{12})", str(row.get("InstanceId") or ""))
        percent = row.get("Battery")
        if match and isinstance(percent, int) and 0 <= percent <= 100:
            levels[match.group(1).upper()] = percent
    return levels


def _paired(battery=True):
    """Every paired device, sorted by name and numbered from 1. The listing and every id come from here, so they
    always agree. The battery read (PowerShell) runs while Windows is being asked for the devices."""
    rt = _winrt()
    levels = {}
    reader = None
    if battery:
        reader = threading.Thread(target=lambda: levels.update(_battery_levels()), daemon=True)
        reader.start()
    devices = _merge(_wait(lambda: _paired_async(rt)))
    if reader is not None:
        reader.join(50)
    devices.sort(key=lambda item: (item["name"].lower(), item["address"] or ""))
    for number, item in enumerate(devices, start=1):
        item["id"] = number
        if item["address"]:
            item["battery"] = levels.get(item["address"].replace(":", ""))
    return devices


def _find(word, devices):
    """One paired device by id, address or name (an exact name, or text that only one name contains)."""
    if word.isdigit():
        for item in devices:
            if item["id"] == int(word):
                return item
        raise BluetoothError(f"no device with id {word}. Run 'bt ls' to see them.", 2)
    address = _parse_address(word)
    if address:
        for item in devices:
            if item["address"] == address:
                return item
        raise BluetoothError(f"no paired device has the address {address}. Run 'bt ls' to see them.", 2)
    lowered = word.lower()
    exact = [item for item in devices if item["name"].lower() == lowered]
    close = exact or [item for item in devices if lowered in item["name"].lower()]
    if len(close) == 1:
        return close[0]
    if close:
        raise BluetoothError(f"'{word}' matches {len(close)} devices: "
                             + ", ".join(f"{item['id']} {item['name']}" for item in close) + ". Use the id.", 2)
    raise BluetoothError(f"no paired device called {word}. Run 'bt ls' to see them, or use its id.", 2)


def _brief(item):
    return _net.public(item)


# ======================================================================
# PROFILES — what Windows has set up for a device, read from the Enum registry key (no Windows call needed)
# ======================================================================
def _profiles(address):
    """The profiles and services Windows installed for a device (audio, hands-free, keyboard ...), found by its address
    in the BTHENUM and BTHLEDEVICE entries. Empty when none are found."""
    if not address:
        return []
    needle = address.replace(":", "").lower()
    numbers = set()
    for bus in ("BTHENUM", "BTHLEDEVICE"):
        for first in _win.reg_subkeys(_win.HKLM, f"{ENUM_KEY}\\{bus}"):
            if not first.startswith("{"):
                continue
            instances = _win.reg_subkeys(_win.HKLM, f"{ENUM_KEY}\\{bus}\\{first}")
            if needle in first.lower() or any(needle in instance.lower() for instance in instances):
                number = _short_uuid(first.split("_", 1)[0])
                if number is not None:
                    numbers.add(number)
    return [_profile_name(number) for number in sorted(numbers)]


# ======================================================================
# SERVICE — the Bluetooth Support Service
# ======================================================================
def _service_data():
    state = _net.service_state(SERVICE)
    start = _net.reg_read(SERVICE_KEY, "Start")
    delayed = bool(_net.reg_read(SERVICE_KEY, "DelayedAutostart"))
    if start is None and state == "UNKNOWN":
        return {"name": SERVICE, "state": "not installed", "start_type": None}
    start_text = START_TYPES.get(start, "unknown")
    if start == 2 and delayed:
        start_text = "automatic (delayed)"
    return {"name": SERVICE, "state": state.lower(), "start_type": start_text, "start_code": start}


def _service_pid():
    """The service's process id from sc queryex, or None when it is not running."""
    _, text = _net.run_tool(["sc", "queryex", SERVICE])
    match = re.search(r"PID\s*:\s*(\d+)", text)
    return int(match.group(1)) if match and int(match.group(1)) else None


# ======================================================================
# SAYING THINGS — progress goes to stderr under --json so stdout stays one JSON document
# ======================================================================
def _say(options, text=""):
    print(text, file=sys.stderr if options["json"] else sys.stdout)


def _confirm(question, options):
    """_core.confirm, with the question kept off stdout under --json."""
    if options["json"]:
        with contextlib.redirect_stdout(sys.stderr):
            return _core.confirm(question, options["yes"])
    return _core.confirm(question, options["yes"])


def _radio_text(radio):
    state = radio["state"]
    if state == "on":
        return "on"
    if state == "off":
        return "off (turn it on with 'bt on')"
    if state == "disabled":
        return "off, switched off by airplane mode, a hardware switch or a policy ('bt why' explains)"
    if state == "none":
        return "no Bluetooth radio found ('bt why' says why)"
    return "unknown"


# ======================================================================
# SHOWING — status, the list, and one device
# ======================================================================
def _status(options):
    radio = _radio()
    adapter = _adapter() if radio["state"] != "none" else None
    devices = _paired(battery=False) if radio["state"] != "none" else []
    connected = [item for item in devices if item["connected"]]
    if options["json"]:
        _core.print_json({"radio": radio, "adapter": adapter, "paired": len(devices), "connected": len(connected),
                          "devices": [_brief(item) for item in devices]})
        return
    ordered = sorted(devices, key=lambda item: (not item["connected"], item["name"].lower()))
    sections = [
        ("radio", [("bluetooth", _radio_text(radio)), ("radio", radio["name"]),
                   ("adapter address", adapter["address"] if adapter else None),
                   ("supports", _supports(adapter) if adapter else None),
                   ("radio control", radio["access"] if radio["state"] != "none" else None)]),
        ("devices", [("paired", f"{len(devices)} ({len(connected)} connected)")]
         + [(item["name"], _state_text(item)) for item in ordered[:8]]
         + ([("...", f"and {len(ordered) - 8} more: 'bt ls'")] if len(ordered) > 8 else [])),
        ("change it with", [
            ("bt on | off", "turn Bluetooth on or off"), ("bt ls", "paired devices with battery and address"),
            ("bt scan", "find devices in pairing mode, then 'bt pair <n>'"), ("bt why", "Bluetooth is not working"),
        ]),
    ]
    sections[0] = (sections[0][0], [row for row in sections[0][1] if row[1] is not None])
    _net.render(f"Bluetooth is {radio['state'] if radio['state'] != 'none' else 'not available'}", sections)
    print("\ntype 'bt help' for everything this page can do")


def _supports(adapter):
    parts = []
    if adapter.get("classic"):
        parts.append("classic")
    if adapter.get("low_energy"):
        parts.append("low energy")
    text = " + ".join(parts) or None
    roles = [word for word, key in (("central", "central"), ("peripheral", "peripheral")) if adapter.get(key)]
    return f"{text} ({', '.join(roles)} role)" if text and roles else text


def _state_text(item):
    text = "connected" if item["connected"] else "not connected"
    if item.get("battery") is not None:
        text += f", battery {item['battery']}%"
    return text


def _kind_text(item):
    return item["kind_detail"] if item["kind_detail"] != "device" else item["kind"] if item["kind"] != "other" else "device"


def _list(options):
    radio = _radio()
    devices = _paired() if radio["state"] != "none" else []
    connected = sum(1 for item in devices if item["connected"])
    if options["json"]:
        _core.print_json({"radio": radio["state"], "paired": len(devices), "connected": connected,
                          "devices": [_brief(item) for item in devices]})
        return
    if radio["state"] == "none":
        print("this PC has no Bluetooth radio Windows can use. 'bt why' says what to check.")
        return
    if not devices:
        print("no paired devices. Put a device in pairing mode, run 'bt scan', then 'bt pair <n>'.")
        return
    rows = [[item["id"], item["name"], _kind_text(item), "connected" if item["connected"] else "paired",
             f"{item['battery']}%" if item["battery"] is not None else "-", item["address"] or "-"] for item in devices]
    lines = _probe.table(["ID", "NAME", "KIND", "STATE", "BATTERY", "ADDRESS"], rows).split("\n")
    print(lines[0])
    for item, line in zip(devices, lines[1:]):
        print((_net.GREEN if item["connected"] else _net.GREY) + line + _net.RESET)
    print(f"\n{len(devices)} paired, {connected} connected. Ids shift when devices are added or removed, so run "
          "'bt ls' before 'bt rm'. 'bt <id>' shows one.")
    if radio["state"] != "on":
        print(f"Bluetooth is {radio['state']}, so nothing can be connected. 'bt on' turns it on.")


def _one(word, options):
    devices = _paired()
    item = _find(word, devices)
    profiles = _profiles(item["address"])
    pairing = _pairing_facts(item)
    data = {**_brief(item), "profiles": profiles, "protection": pairing["protection"],
            "secure_connection": pairing["secure_connection"]}
    if options["json"]:
        _core.print_json(data)
        return
    transport = " + ".join(word for word, on in (("classic", item["classic"]), ("low energy", item["low_energy"])) if on)
    _net.render(item["name"], [
        ("device", [("kind", _kind_text(item)), ("address", item["address"]),
                    ("connected", "yes" if item["connected"] else "no"),
                    ("battery", f"{item['battery']}%" if item["battery"] is not None else "not reported"),
                    ("uses", transport)]),
        ("pairing", [("protection", pairing["protection"]), ("secure connection", pairing["secure_connection"])]),
        ("profiles", [("installed", profiles or "none found")]),
        ("what you can do", [
            (f"bt rm {item['id']}", "unpair it (asks first)"),
            (f"bt connect {item['id']} | disconnect", "Windows has no API for these: opens Settings"),
        ]),
    ])


def _pairing_facts(item):
    """How the device is paired: the protection level Windows used, and whether it was a secure connection."""
    protection, secure = None, None
    for device in item.get("_devices", []):
        info = _get(device, "device_information")
        pairing = _get(info, "pairing")
        level = _get(pairing, "protection_level")
        if level is not None and protection is None:
            protection = PROTECTION_WORDS.get(_name(_winrt()["level"], level), str(level).lower())
        flag = _get(device, "was_secure_connection_used_for_pairing")
        if flag is not None and secure is None:
            secure = bool(flag)
    return {"protection": protection, "secure_connection": secure}


# ======================================================================
# ON / OFF
# ======================================================================
def _on_off(on, options):
    radio = _radio()
    wanted = "on" if on else "off"
    if radio["state"] == "none":
        raise BluetoothError("this PC has no Bluetooth radio Windows can use. 'bt why' says what to check.")
    if radio["state"] == wanted:
        _say(options, f"Bluetooth is already {wanted}.")
        _finish_radio(options, radio)
        return
    if not on:
        try:
            connected = [item for item in _paired(battery=False) if item["connected"]]
        except BluetoothError:
            connected = []
        if connected and not _confirm(
                f"Turn Bluetooth off? {len(connected)} connected device(s) will disconnect: "
                + ", ".join(item["name"] for item in connected[:4]) + (", ..." if len(connected) > 4 else "")
                + (". A Bluetooth keyboard or mouse stops working until you turn it on again with 'bt on'. [y/N]: "
                   if any(item["kind"] in ("keyboard", "mouse", "gamepad", "input") for item in connected)
                   else ". To turn it back on: 'bt on'. [y/N]: "), options):
            _say(options, "cancelled")
            return
    _say(options, f"turning Bluetooth {wanted}...")
    answer = _set_radio(on)
    if answer == "DENIED_BY_USER":
        raise BluetoothError("Windows will not let programs control the radio: it is blocked in Settings > Privacy & "
                             "security > Radios. Allow it there ('bt open' opens Bluetooth; the Radios page is "
                             f"{RADIOS_PRIVACY_PAGE}), then try again.")
    if answer == "DENIED_BY_SYSTEM":
        raise BluetoothError("Windows refused: a policy or the system is keeping Bluetooth as it is. If airplane mode "
                             "is on, turn that off first.")
    if answer not in ("ALLOWED", "NONE"):
        raise BluetoothError("Windows refused for a reason it does not give. Try the switch in quick settings.")
    now = _radio_settled(wanted)
    if now["state"] != wanted:
        raise BluetoothError(f"Windows accepted the change but Bluetooth is still {now['state']}. "
                             "Airplane mode or a hardware switch may be holding it; 'bt why' checks.")
    _finish_radio(options, now, f"Bluetooth is now {now['state']}.")


def _finish_radio(options, radio, line=None):
    if options["json"]:
        _core.print_json({"radio": radio})
    elif line:
        print(line)


# ======================================================================
# SCAN — look for nearby devices; the result is saved so 'bt pair <n>' means that scan
# ======================================================================
def _record(info, protocol):
    """What a watcher result is, as a plain dict (the watcher's objects are touched only on its own thread)."""
    pairing = _get(info, "pairing")
    props = _props_dict(_get(info, "properties"))
    return {"id": _get(info, "id"), "name": (_get(info, "name") or "").strip(), "protocol": protocol, "props": props,
            "paired": bool(_get(pairing, "is_paired", False)), "can_pair": _get(pairing, "can_pair"), "_info": info}


def _digest(record):
    """A watcher result as a row: address, signal strength, and whether it can be paired."""
    props = record["props"]
    signal = props.get("System.Devices.Aep.SignalStrength")
    can_pair = props.get("System.Devices.Aep.CanPair", record["can_pair"])
    paired = props.get("System.Devices.Aep.IsPaired", record["paired"])
    return {
        "id": record["id"], "name": record["name"], "protocol": record["protocol"],
        "address": _address(props.get("System.Devices.Aep.DeviceAddress")) or _address(
            (re.findall(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", str(record["id"])) or [None])[-1]),
        "signal_dbm": signal if isinstance(signal, (int, float)) else None, "paired": bool(paired),
        "can_pair": None if can_pair is None else bool(can_pair),
    }


def _scan_devices(seconds, progress=None):
    """Watch for Bluetooth devices (classic and low energy) for this many seconds. Returns the digests, one per device."""
    rt = _winrt()
    records, lock = {}, threading.Lock()

    def make_handlers(protocol):
        def added(sender, info):
            record = _record(info, protocol)
            with lock:
                records[record["id"]] = record

        def updated(sender, update):
            with lock:
                record = records.get(_get(update, "id"))
                if record is not None:
                    record["props"].update(_props_dict(_get(update, "properties")))

        def removed(sender, update):
            pass  # a device that stops advertising for a moment is still worth listing
        return added, updated, removed

    started = []
    try:
        for protocol, guid in (("classic", CLASSIC_PROTOCOL), ("low energy", LE_PROTOCOL)):
            watcher = rt["info"].create_watcher(f'(System.Devices.Aep.ProtocolId:="{guid}")', AEP_PROPERTIES,
                                                rt["ikind"].ASSOCIATION_ENDPOINT)
            handlers = make_handlers(protocol)
            tokens = [watcher.add_added(handlers[0]), watcher.add_updated(handlers[1]), watcher.add_removed(handlers[2])]
            watcher.start()
            started.append((watcher, tokens))
        for second in range(int(seconds)):
            time.sleep(1)
            if progress:
                progress(second + 1)
    except OSError as e:
        raise BluetoothError(f"Windows would not start looking for devices: {e.strerror or e}")
    finally:
        for watcher, tokens in started:
            with contextlib.suppress(Exception):
                watcher.stop()
            for remove, token in zip((watcher.remove_added, watcher.remove_updated, watcher.remove_removed), tokens):
                with contextlib.suppress(Exception):
                    remove(token)
    with lock:
        digests = [_digest(record) for record in records.values()]
    return _unique(digests)


def _unique(digests):
    """One entry per address: a device seen over both classic and low energy is kept once, preferring classic."""
    kept = {}
    for item in digests:
        key = item["address"] or item["id"]
        if key in kept:
            first = kept[key]
            if first["protocol"] != "classic" and item["protocol"] == "classic":
                item["protocols"] = sorted({first["protocol"], "classic"})
                kept[key] = item
            else:
                first["protocols"] = sorted(set(first.get("protocols", [first["protocol"]])) | {item["protocol"]})
            continue
        item["protocols"] = [item["protocol"]]
        kept[key] = item
    return list(kept.values())


def _scan_rows(digests, show_all):
    """The rows 'bt scan' shows, numbered from 1, and how many unnamed devices were left out."""
    hidden = 0
    rows = []
    for item in digests:
        if not show_all:
            if item["paired"] or item["can_pair"] is False:
                continue
            if not item["name"]:
                hidden += 1
                continue
        rows.append(item)
    rows.sort(key=lambda item: (not item["name"], item["name"].lower(), item["address"] or ""))
    for number, item in enumerate(rows, start=1):
        item["n"] = number
    return rows, hidden


def _save_scan(rows, seconds):
    _win.save_json(SCAN_FILE, {
        "when": datetime.now().isoformat(timespec="seconds"), "seconds": seconds,
        "devices": [{key: item[key] for key in ("n", "id", "name", "address", "protocol", "protocols", "signal_dbm",
                                                "paired", "can_pair")} for item in rows],
    })


def _load_scan():
    """The saved scan as (devices, seconds since it was made), or (None, None)."""
    saved = _win.load_json(SCAN_FILE)
    if not isinstance(saved, dict) or not isinstance(saved.get("devices"), list):
        return None, None
    try:
        age = (datetime.now() - datetime.fromisoformat(saved["when"])).total_seconds()
    except (KeyError, ValueError, TypeError):
        return None, None
    return saved["devices"], max(0, int(age))


def _scan(words, options, extras):
    if len(words) > 1 or (words and not words[0].isdigit()):
        raise BluetoothError("usage: bt scan [seconds] [--all]   (3 to 60 seconds, 10 by default)", 2)
    seconds = int(words[0]) if words else SCAN_DEFAULT
    if not SCAN_MIN <= seconds <= SCAN_MAX:
        raise BluetoothError(f"scan for {SCAN_MIN} to {SCAN_MAX} seconds", 2)
    radio = _radio()
    if radio["state"] != "on":
        raise BluetoothError(f"Bluetooth is {_radio_text(radio)}. A scan needs it on: 'bt on'.")
    _say(options, f"looking for devices for {seconds} s. Put the device in pairing mode now "
                  "(usually hold its Bluetooth button until a light blinks)...")
    digests = _scan_devices(seconds)
    rows, hidden = _scan_rows(digests, extras["all"])
    _save_scan(rows, seconds)
    if options["json"]:
        _core.print_json({"seconds": seconds, "devices": [{**{k: v for k, v in item.items() if k not in ("protocol",)},
                                                           "signal": _signal_words(item["signal_dbm"])}
                                                          for item in rows], "hidden_unnamed": hidden})
        return
    if not rows:
        print("no devices found to pair." + (f" {hidden} unnamed device(s) were hidden: 'bt scan --all' shows them."
                                              if hidden else "") +
              " Is the device in pairing mode and close to this PC?")
        return
    table = [[item["n"], item["name"] or "(no name)", " + ".join(item["protocols"]), _signal_words(item["signal_dbm"]),
              "paired" if item["paired"] else "can pair" if item["can_pair"] else "-", item["address"] or "-"]
             for item in rows]
    lines = _probe.table(["N", "NAME", "OVER", "SIGNAL", "STATE", "ADDRESS"], table).split("\n")
    print(lines[0])
    for item, line in zip(rows, lines[1:]):
        print((_net.GREY if item["paired"] else _net.GREEN) + line + _net.RESET)
    print(f"\n{len(rows)} device(s). Pair one with 'bt pair <n>'." + (
        f" {hidden} unnamed device(s) hidden (beacons, trackers): 'bt scan --all' shows them." if hidden else ""))


# ======================================================================
# PAIR — Windows' custom pairing; the questions it has are answered here, on this thread
# ======================================================================
def _scan_target(word, options):
    """The scanned device a pair command means: a number from the saved scan, or an address or name (looked for live
    if the saved scan does not have it)."""
    saved, age = _load_scan()
    if word.isdigit():
        if saved is None:
            raise BluetoothError("there is no saved scan. Run 'bt scan' first, then 'bt pair <n>'.", 2)
        if age > SCAN_FRESH:
            raise BluetoothError(f"the saved scan is {age // 60} minutes old, so its numbers may be wrong. "
                                 "Run 'bt scan' again.", 2)
        for item in saved:
            if item.get("n") == int(word):
                return item
        raise BluetoothError(f"no device {word} in the last scan. Run 'bt scan' to see them.", 2)
    address, lowered = _parse_address(word), word.lower()

    def pick(items):
        if address:
            return [item for item in items if item.get("address") == address]
        exact = [item for item in items if (item.get("name") or "").lower() == lowered]
        return exact or [item for item in items if lowered in (item.get("name") or "").lower()]

    matches = pick(saved or [])
    if not matches:
        _say(options, f"{word} is not in the last scan; looking for {FIND_SECONDS} s...")
        found, _ = _scan_rows(_scan_devices(FIND_SECONDS), True)
        matches = pick(found)
    if not matches:
        raise BluetoothError(f"could not find {word}. Put the device in pairing mode and run 'bt scan'.")
    if len(matches) > 1:
        raise BluetoothError(f"'{word}' matches {len(matches)} devices: "
                             + ", ".join(f"{item.get('n', '?')} {item['name']} ({item['address']})" for item in matches)
                             + ". Use the address.", 2)
    return matches[0]


def _answer_request(rt, args, name, extras, options):
    """Answer one question Windows asks during pairing. Anything not accepted counts as a refusal."""
    kind = _name(rt["kinds"], args.pairing_kind)
    if kind == "CONFIRM_ONLY":
        _say(options, "Windows may show its own 'Connect' prompt: accept it.")
        args.accept()
    elif kind == "DISPLAY_PIN":
        _say(options, f"type this code on {name}: {args.pin}")
        args.accept()
    elif kind == "PROVIDE_PIN":
        pin = extras["pin"]
        if not pin:
            try:
                pin = getpass.getpass(f"PIN for {name} (often 0000 or 1234; blank to cancel): ").strip()
            except (EOFError, KeyboardInterrupt):
                pin = ""
        if pin:
            args.accept(pin)
        else:
            _say(options, "no PIN, so the pairing is not accepted")
    elif kind == "CONFIRM_PIN_MATCH":
        shown = str(args.pin)
        if extras["code"]:
            same = extras["code"] == shown
            _say(options, "the code you gave " + ("matches" if same else "does NOT match") + f" the one Windows shows ({shown})")
        else:
            _say(options, f"Windows shows the code {shown}.")
            # never answered by --yes: confirming a code is how you know no one else is in the middle
            same = _confirm(f"Does {name} show the same code, {shown}? [y/N]: ", {**options, "yes": False})
        if same:
            args.accept()
    else:
        _say(options, f"Windows asked for something this page cannot do ({kind.lower()}). Use 'bt open'.")


def _run_pairing(rt, custom, name, extras, options):
    """PairAsync, with Windows' questions queued by the handler (it runs on a thread Windows owns) and answered here."""
    requests, problems = queue.Queue(), []

    def handler(sender, args):
        try:
            requests.put((args, args.get_deferral()))
        except Exception as e:  # an exception in a handler can take down Windows' thread
            problems.append(str(e))

    kinds = rt["kinds"]
    ceremonies = kinds.CONFIRM_ONLY | kinds.DISPLAY_PIN | kinds.PROVIDE_PIN | kinds.CONFIRM_PIN_MATCH
    token = custom.add_pairing_requested(handler)
    operation = None

    async def wait_for(op):
        return await op

    async def runner():
        nonlocal operation
        operation = custom.pair_async(ceremonies, rt["level"].DEFAULT)
        task = asyncio.ensure_future(wait_for(operation))
        deadline = time.monotonic() + PAIR_TIMEOUT
        while not task.done():
            try:
                args, deferral = requests.get_nowait()
            except queue.Empty:
                if time.monotonic() > deadline:
                    task.cancel()
                    raise BluetoothError(f"{name} did not finish pairing within {PAIR_TIMEOUT} s.")
                await asyncio.sleep(0.1)
                continue
            try:
                _answer_request(rt, args, name, extras, options)
            finally:
                deferral.complete()
        return task.result()

    try:
        result = asyncio.run(runner())
    except OSError as e:
        raise BluetoothError(f"Windows refused: {e.strerror or e}")
    finally:
        if operation is not None:
            with contextlib.suppress(Exception):
                operation.cancel()  # does nothing once it has finished
        with contextlib.suppress(Exception):
            custom.remove_pairing_requested(token)
    if problems:
        raise BluetoothError("Windows' pairing question could not be read: " + problems[0])
    return result


def _pair(words, options, extras):
    if len(words) != 1:
        raise BluetoothError("usage: bt pair <n|name|address>   (n is a number from 'bt scan')", 2)
    rt = _winrt()
    target = _scan_target(words[0], options)
    name = target["name"] or target["address"] or "the device"
    label = f"{name} ({target['address']})" if target.get("address") else name
    if target.get("paired"):
        _say(options, f"{label} is already paired.")
        return
    if not _confirm(f"Pair this PC with {label}? The device must be in pairing mode, and it will be able to use "
                    "its Bluetooth connection with this PC. [y/N]: ", options):
        _say(options, "cancelled")
        return
    info = _wait(lambda: rt["info"].create_from_id_async(target["id"], AEP_PROPERTIES, rt["ikind"].ASSOCIATION_ENDPOINT))
    if info is None:
        raise BluetoothError(f"Windows no longer sees {name}. Put it in pairing mode and run 'bt scan' again.")
    pairing = _get(info, "pairing")
    if pairing is not None and _get(pairing, "is_paired"):
        _say(options, f"{label} is already paired.")
        return
    if pairing is None or _get(pairing, "can_pair") is False:
        raise BluetoothError(f"Windows says it cannot pair with {name} right now. Put the device in pairing mode, "
                             "then run 'bt scan' again.")
    _say(options, f"pairing with {label}...")
    result = _run_pairing(rt, pairing.custom, name, extras, options)
    status = _name(rt["pair_status"], result.status)
    if status not in ("PAIRED", "ALREADY_PAIRED"):
        raise BluetoothError(f"could not pair with {name}: {PAIR_PROBLEMS.get(status, status.lower())}")
    paired = _paired_after(target.get("address"), want_present=True)
    if options["json"]:
        _core.print_json({"paired": True, "name": name, "address": target.get("address"), "status": status.lower(),
                          "connected": bool(paired and paired["connected"]),
                          "id": paired["id"] if paired else None})
        return
    print(f"paired with {name}." + (f" It is device {paired['id']} in 'bt ls' and "
                                   f"{'connected' if paired['connected'] else 'not connected yet'}."
                                   if paired else " Run 'bt ls' to see it."))
    if paired and not paired["connected"]:
        print("Windows connects it by itself once it is switched on and nearby; 'bt open' opens Settings if it does not.")


def _paired_after(address, want_present, tries=4):
    """The device with this address in the paired list, read until it is (or is no longer) there."""
    found = None
    for attempt in range(tries):
        found = next((item for item in _paired(battery=False) if address and item["address"] == address), None)
        if bool(found) == want_present:
            break
        if attempt < tries - 1:
            time.sleep(1)
    return found


# ======================================================================
# REMOVE — unpair
# ======================================================================
def _remove(words, options):
    if len(words) != 1:
        raise BluetoothError("usage: bt rm <id|name|address>   (ids from 'bt ls')", 2)
    rt = _winrt()
    item = _find(words[0], _paired(battery=False))
    label = f"{item['name']} ({item['address']})" if item["address"] else item["name"]
    if not _confirm(f"Remove {label}? Windows forgets the pairing, so you will have to pair it again (put it in pairing "
                    "mode, then 'bt scan' and 'bt pair'). [y/N]: ", options):
        _say(options, "cancelled")
        return
    _say(options, f"removing {item['name']}...")
    status = "UNPAIRED"
    for device in item["_devices"]:
        pairing = _get(_get(device, "device_information"), "pairing")
        if pairing is None:
            info = _wait(lambda: rt["info"].create_from_id_async(device.device_id))
            pairing = _get(info, "pairing")
        if pairing is None:
            raise BluetoothError(f"Windows gave no way to unpair {item['name']}. Use 'bt open'.")
        result = _wait(lambda: pairing.unpair_async())
        status = _name(rt["unpair_status"], result.status)
        if status not in ("UNPAIRED", "ALREADY_UNPAIRED"):
            raise BluetoothError(f"could not remove {item['name']}: {UNPAIR_PROBLEMS.get(status, status.lower())}")
    still = _paired_after(item["address"], want_present=False) if item["address"] else None
    if options["json"]:
        _core.print_json({"removed": still is None, "name": item["name"], "address": item["address"],
                          "status": status.lower()})
        return
    if still is not None:
        print(f"Windows still lists {item['name']}. Give it a moment and run 'bt ls'.")
    else:
        print(f"removed {item['name']}. To use it again: put it in pairing mode, then 'bt scan' and 'bt pair'.")


# ======================================================================
# CONNECT / DISCONNECT — no Windows API, so Settings does it
# ======================================================================
def _connection(word, wanted, options):
    item = _find(word, _paired(battery=False))
    now = "connected" if item["connected"] else "not connected"
    if options["json"]:
        _core.print_json({"name": item["name"], "address": item["address"], "connected": item["connected"],
                          "settings_opened": True})
        _win.open_settings(SETTINGS_PAGE)
        return
    print(f"{item['name']} is {now} right now.")
    print(f"Windows has no way for a program to {wanted} a paired device, so this page does not try to fake it. "
          f"Opening Settings: choose {item['name']}, then {wanted[0].upper() + wanted[1:]}.")
    _win.open_settings(SETTINGS_PAGE)


# ======================================================================
# SERVICE AND WHY
# ======================================================================
def _service_command(words, options):
    if words and (len(words) != 1 or words[0].lower() != "restart"):
        raise BluetoothError("usage: bt service [restart]", 2)
    data = _service_data()
    if not words:
        if options["json"]:
            _core.print_json(data)
            return
        _net.render("Bluetooth Support Service", [
            ("service", [("name", f"{SERVICE} (Bluetooth Support Service)"), ("state", data["state"]),
                         ("starts", data["start_type"])]),
            ("notes", [("stopped?", "normal when no device needs it: Windows starts it on demand"),
                       ("restart", "bt service restart (administrator; devices reconnect)")]),
        ])
        return
    if data["state"] == "not installed":
        raise BluetoothError("the Bluetooth Support Service is not installed on this PC.")
    _net.need_admin()
    if not _confirm("Restart the Bluetooth Support Service? Bluetooth devices disconnect for a moment and "
                    "reconnect by themselves. [y/N]: ", options):
        _say(options, "cancelled")
        return
    before = _service_pid()
    _say(options, "restarting the Bluetooth Support Service...")
    _net.restart_service(SERVICE)
    now = _service_data()
    after = _service_pid()
    restarted = now["state"] == "running" and (before is None or after != before)
    if options["json"]:
        _core.print_json({**now, "restarted": restarted})
        return
    if now["state"] != "running":
        print(f"the service is {now['state']} after the restart. Windows starts it again when a device needs it.")
    elif not restarted:
        print("the service is running, but Windows did not restart it (other services depend on it). "
              "Turning Bluetooth off and on ('bt off', 'bt on') does much the same.")
    else:
        print("the Bluetooth Support Service restarted and is running.")


def _known_adapters():
    """Bluetooth adapters Windows has a record of, from the Enum registry key: [{'name', 'instance_id'}]."""
    found = []
    for bus in RADIO_BUSES:
        for device in _win.reg_subkeys(_win.HKLM, f"{ENUM_KEY}\\{bus}"):
            for instance in _win.reg_subkeys(_win.HKLM, f"{ENUM_KEY}\\{bus}\\{device}"):
                path = f"{ENUM_KEY}\\{bus}\\{device}\\{instance}"
                if (str(_net.reg_read(path, "Class") or "").lower() == "bluetooth"
                        or str(_net.reg_read(path, "ClassGUID") or "").lower() == BLUETOOTH_CLASS):
                    name = _plain(_net.reg_read(path, "FriendlyName") or _net.reg_read(path, "DeviceDesc") or device)
                    found.append({"name": str(name), "instance_id": f"{bus}\\{device}\\{instance}"})
    return found


def _check(name, status, detail, fix=None):
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def _why_checks():
    """Everything that stops Bluetooth working, as checks: status is ok, problem or info."""
    checks = []
    if struct.calcsize("P") == 4 and platform.machine().upper() in ("AMD64", "ARM64"):
        checks.append(_check("python", "problem", "this is 32-bit Python on 64-bit Windows, and Windows hides the "
                             "Bluetooth radio from 32-bit programs", "install 64-bit Python"))
    adapters = _known_adapters()
    try:
        radio = _radio()
    except BluetoothError as e:
        checks.append(_check("windows api", "problem", str(e), "py -m pip install -r requirements.txt"))
        radio = None
    if not adapters:
        checks.append(_check("adapter", "problem" if not radio or radio["state"] == "none" else "info",
                             "Windows has no Bluetooth adapter on record. This PC may not have Bluetooth, the adapter "
                             "may be switched off in the BIOS, or its driver was never installed",
                             "dvc errors   (look for unknown devices), and check the BIOS / the device's manual"))
    else:
        checks.append(_check("adapter", "ok", "Windows knows of: " + ", ".join(item["name"] for item in adapters)))
    if radio is not None:
        if radio["state"] == "none":
            if adapters:
                checks.append(_check("radio", "problem", f"Windows has the adapter ({adapters[0]['name']}) but offers no "
                                     "Bluetooth radio to programs. It is probably disabled or has a driver problem",
                                     "dvc ls class bluetooth   then   dvc errors"))
        else:
            word = {"on": "ok", "off": "problem", "disabled": "problem"}.get(radio["state"], "info")
            detail = {"on": "the radio is on", "off": "the radio is turned off",
                      "disabled": "the radio is switched off by airplane mode, a hardware switch or a policy"
                      }.get(radio["state"], "Windows does not say whether the radio is on")
            fix = {"off": "bt on", "disabled": "turn off airplane mode (Settings > Network & internet), or use the "
                                                "laptop's wireless key"}.get(radio["state"])
            checks.append(_check("radio", word, detail, fix))
            if radio["access"] in ("denied by you", "denied by the system"):
                checks.append(_check("radio access", "problem", f"programs may not control the radio ({radio['access']})",
                                     f"allow it in Settings > Privacy & security > Radios ({RADIOS_PRIVACY_PAGE})"))
    service = _service_data()
    if service["state"] == "not installed":
        checks.append(_check("service", "problem", "the Bluetooth Support Service is not installed"))
    elif service.get("start_code") == 4:
        checks.append(_check("service", "problem", "the Bluetooth Support Service is disabled, so no device can connect",
                             f"svc {SERVICE} manual   (administrator)"))
    elif service["state"] == "running":
        checks.append(_check("service", "ok", "the Bluetooth Support Service is running"))
    else:
        checks.append(_check("service", "ok", f"the Bluetooth Support Service is {service['state']}, which is normal: "
                             "Windows starts it when a device needs it"))
    if radio is not None and radio["state"] == "on":
        try:
            devices = _paired(battery=False)
            checks.append(_check("devices", "info", f"{len(devices)} paired, {sum(1 for d in devices if d['connected'])} "
                                 "connected", "bt ls"))
        except BluetoothError as e:
            checks.append(_check("devices", "problem", f"the paired devices could not be listed: {e}",
                                 "bt service restart   (administrator)"))
    return checks


def _why(options):
    checks = _why_checks()
    problems = [check for check in checks if check["status"] == "problem"]
    verdict = "problem" if problems else "ok"
    if options["json"]:
        _core.print_json({"verdict": verdict, "checks": checks})
        return
    os.system("")  # enables ANSI colour codes in the Windows console
    print("Bluetooth looks fine." if not problems else f"{len(problems)} thing(s) may be stopping Bluetooth working:")
    colors = {"ok": _net.GREEN, "problem": _net.RED, "info": _net.GREY}
    marks = {"ok": "ok     ", "problem": "PROBLEM", "info": "info   "}
    for item in checks:
        print(colors[item["status"]] + f"  {marks[item['status']]}  {item['name']:<13}{item['detail']}" + _net.RESET)
        if item["fix"] and item["status"] != "ok":
            print(colors[item["status"]] + f"           {'':<13}fix: {item['fix']}" + _net.RESET)
    if not problems:
        print("\nIf one device will not connect, switch it off and on, move it closer, or remove it ('bt rm <id>') "
              "and pair it again.")


# ======================================================================
# FILE TRANSFER, THE CLASSIC DIALOG, AND SETTINGS
# ======================================================================
def _file_transfer(word, rest, options):
    if word == "receive" and rest:
        raise BluetoothError("usage: bt receive", 2)
    if len(rest) > 1:
        raise BluetoothError("usage: bt send [file]", 2)
    command = [os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "fsquirt.exe"),
               "-send" if word == "send" else "-receive"]
    if rest:
        if not os.path.isfile(rest[0]):
            raise BluetoothError(f"no file called {rest[0]}", 2)
        command.append(os.path.abspath(rest[0]))
    try:
        subprocess.Popen(command, creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
    except OSError as e:
        raise BluetoothError(f"could not start Windows' Bluetooth File Transfer wizard: {e}")
    text = ("opened Windows' Bluetooth File Transfer wizard. Choose the device to send to." if word == "send" else
            "opened Windows' Bluetooth File Transfer wizard, waiting for a file. Send it from the other device.")
    if options["json"]:
        _core.print_json({"opened": "file transfer", "mode": word})
    else:
        print(text)


def _more(options):
    try:
        subprocess.Popen(["rundll32.exe", "shell32.dll,Control_RunDLL", "bthprops.cpl,,1"],
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
    except OSError:
        _win.open_settings(SETTINGS_PAGE)
        print("could not open the classic dialog, so Settings > Bluetooth & devices is open instead.")
        return
    if options["json"]:
        _core.print_json({"opened": "bluetooth settings dialog"})
    else:
        print("opened the classic Bluetooth Settings dialog: its Options tab has discovery, new-device alerts and the "
              "notification-area icon.")


def _open(options):
    _win.open_settings(SETTINGS_PAGE)
    if options["json"]:
        _core.print_json({"opened": SETTINGS_PAGE})
    else:
        print("opened Settings > Bluetooth & devices.")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "bluetooth"/"bt"
# ======================================================================
def _extra_flags(args):
    """Takes --pin <digits>, --code <digits> and --all out of the words. Returns (words, {'pin', 'code', 'all'})."""
    extras, words, skip = {"pin": None, "code": None, "all": False}, [], False
    for index, word in enumerate(args):
        if skip:
            skip = False
            continue
        lowered = word.lower()
        if lowered in ("--pin", "--code"):
            value = args[index + 1] if index + 1 < len(args) else ""
            if not value.isdigit():
                raise BluetoothError(f"{lowered} needs the digits, e.g. {lowered} 0000", 2)
            extras[lowered[2:]] = value
            skip = True
        elif lowered == "--all":
            extras["all"] = True
        else:
            words.append(word)
    return words, extras


DEVICE_ACTIONS = {"rm": "rm", "remove": "rm", "unpair": "rm", "forget": "rm", "delete": "rm", "del": "rm",
                  "connect": "connect", "disconnect": "disconnect"}


def _dispatch(args, options, extras):
    word, rest = args[0].lower(), args[1:]
    if word == "status" and not rest:
        _status(options)
    elif word in _net.ON_WORDS and not rest:
        _on_off(True, options)
    elif word in _net.OFF_WORDS and not rest:
        _on_off(False, options)
    elif word in _net.LIST_WORDS and not rest:
        _list(options)
    elif word == "scan":
        _scan(rest, options, extras)
    elif word == "pair":
        _pair(rest, options, extras)
    elif word in ("rm", "remove", "unpair", "forget", "delete", "del"):
        _remove(rest, options)
    elif word in ("connect", "disconnect"):
        if len(rest) != 1:
            raise BluetoothError(f"usage: bt {word} <id|name|address>", 2)
        _connection(rest[0], word, options)
    elif word == "why" and not rest:
        _why(options)
    elif word in ("service", "svc"):
        _service_command(rest, options)
    elif word in ("send", "receive"):
        _file_transfer(word, rest, options)
    elif word == "more" and not rest:
        _more(options)
    elif word == "open" and not rest:
        _open(options)
    elif not rest:
        _one(args[0], options)
    elif len(rest) == 1 and rest[0].lower() in DEVICE_ACTIONS:
        action = DEVICE_ACTIONS[rest[0].lower()]
        if action == "rm":
            _remove([args[0]], options)
        else:
            _connection(args[0], action, options)
    else:
        raise BluetoothError(f"unknown Bluetooth command: {args[0]}\nusage: {USAGE}", 2)


def run(args):
    """Run one Bluetooth command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    try:
        args, extras = _extra_flags(args)
        if not args:
            args = ["status"]
        elif args[0].lower() in _core.HELP_WORDS:
            print(f"usage: {USAGE}")
            return 0
        _dispatch(args, options, extras)
        return 0
    except (BluetoothError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        print("\ncancelled", file=sys.stderr)
        return 1
    except Exception as e:  # a surprise from Windows' API should be a message, not a traceback
        print(f"error: Windows gave an answer this page did not expect ({type(e).__name__}: {e})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

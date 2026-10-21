"""
sound: the PC's sound devices, the same list as Settings > System > Sound. Routed from app.py
("sound", "snd" or "audio").

    snd                          the playback and recording devices, with the default ones marked
    snd <id>                     one device in full: format, volume, level, and what you can do
    snd default <id> [role]      make it the default speakers or microphone
    snd <id> volume <0-100>      set the device's volume (snd <id> <0-100> works too)
    snd <id> mute|unmute|toggle
    snd out | snd in             the default speakers / microphone on one line; snd out volume 40, snd in mute
    snd level [seconds] [listen] live level meter for the default output and input
    snd test                     play a short tone through the default output
    snd why [out|in]             no sound, or a silent microphone: the usual causes, each with its fix
    snd mono                     whether Mono audio is on (changing it opens Settings)
    snd startup [on|off|default] the Windows startup sound, set as a policy (administrator to change)
    snd classic [tab]            the classic Sound dialog: enhancements, spatial sound, formats
    snd apps | snd enable <id> | snd disable <id> | snd open    pages of Settings, where Windows has no way in

Nothing here needs administrator rights, except changing the startup sound. One app's volume is vm.

Devices, volume, mute and the level meter are read and changed through the Core Audio COM interfaces
(IMMDeviceEnumerator, IAudioEndpointVolume, IAudioMeterInformation), the ones the volume mixer uses. They are
declared here with comtypes, so the page does not depend on how pycaw wraps them.

Windows has no documented way to choose the default device. The default is changed through IPolicyConfig, an
undocumented interface that SoundVolumeView, AudioDeviceCmdlets and SoundSwitch also use. Its method order was
checked against an open-source header: after IUnknown come GetMixFormat, GetDeviceFormat, ResetDeviceFormat,
SetDeviceFormat, GetProcessingPeriod, SetProcessingPeriod, GetShareMode, SetShareMode, GetPropertyValue,
SetPropertyValue, SetDefaultEndpoint and SetEndpointVisibility. After every change the default is read back; if it
did not change, the page says so and opens Settings > System > Sound instead.
"""

import contextlib
import ctypes
import math
import os
import struct
import subprocess
import sys
import time
import types

import _core
import _net
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "sound"
ALIASES = ["snd", "audio"]
SUMMARY = "Default sound devices, device volume, and levels"
USAGE = ("snd | snd <id> | snd default <id> [role] | snd <id> volume <0-100> | snd <id> mute|unmute|toggle | "
         "snd out|in | snd level | snd test | snd why [out|in] | snd mono | snd startup | snd classic | snd open")
HELP = [
    ("snd", "list the playback and recording devices; the default ones are marked"),
    ("snd default <id>", "make a device the default speakers or microphone"),
    ("snd <id>", "one device in full: format, volume, level, and what you can do"),
    ("snd <id> volume <0-100>", "set a device's volume (one app's volume is vm)"),
    ("snd <id> mute | unmute", "mute or unmute a device"),
    ("snd why", "no sound? the usual causes, each with the command that fixes it"),
    ("", "more"),
    ("snd out | snd in", "the default speakers / microphone on one line"),
    ("snd level [seconds]", "live level meter for the default output and input"),
    ("snd test", "play a short tone through the default output"),
    ("snd why in", "a silent microphone: the usual causes"),
    ("snd mono", "whether Mono audio is on (changing it opens Settings)"),
    ("snd startup [on|off]", "the Windows startup sound, set as a policy (administrator)"),
    ("snd classic [tab]", "the classic Sound dialog: enhancements, spatial sound, sample rate"),
    ("snd apps", "which device each app plays through (opens Settings)"),
    ("snd enable | disable <id>", "turn a device on or off (opens Settings)"),
    ("snd open", "open Settings > System > Sound"),
]
TIP = (
    "Ids are numbered playback first, then recording, so they shift when a device is plugged in or removed: run "
    "'snd' first. One app's volume is 'vm'. Nothing here needs administrator rights, except 'snd startup'."
)
RUN_ALONE = True  # typing 'snd' on its own lists the devices, which changes nothing

# ======================================================================
# CONSTANTS — Core Audio values (mmdeviceapi.h, endpointvolume.h, audioclient.h)
# ======================================================================
RENDER, CAPTURE = 0, 1  # EDataFlow: playback devices, recording devices
FLOW_NAMES = {RENDER: "playback", CAPTURE: "recording"}
ROLES = {"console": 0, "multimedia": 1, "communications": 2}  # ERole
ROLE_WORDS = {
    "all": "all", "default": "default", "console": "console", "multimedia": "multimedia", "media": "multimedia",
    "communications": "communications", "communication": "communications", "calls": "communications",
    "call": "communications", "comms": "communications",
}
ACTIVE, DISABLED, NOT_PRESENT, UNPLUGGED = 1, 2, 4, 8  # DEVICE_STATE_*
STATE_NAMES = {ACTIVE: "active", DISABLED: "disabled", NOT_PRESENT: "not present", UNPLUGGED: "unplugged"}
LISTED = ACTIVE | DISABLED | UNPLUGGED  # devices Windows only remembers (not present) cannot be used, so they are not listed
STGM_READ = 0
CLSCTX_INPROC_SERVER = 1
# Property keys (functiondiscoverykeys_devpkey.h): the endpoint's name, its adapter's name, and its shared-mode format
KEY_NAME = ("{A45C254E-DF1C-4EFD-8020-67D146A850E0}", 14)
KEY_ADAPTER = ("{026E516E-B814-414B-83CD-856D6FEF4822}", 2)
KEY_FORMAT = ("{F19F064D-082C-4E27-BC73-6882A1BB8E4C}", 0)
VT_LPWSTR, VT_BLOB = 31, 65
E_NOTFOUND = 0x80070490  # what Windows says when there is no default device of a kind
HRESULT_TEXT = {
    0x80070490: "Windows does not have that device (it may have been unplugged)",
    0x88890004: "the device changed while this was running",
    0x8889000A: "another program is using the device exclusively",
    0x80070005: "Windows refused access to it",
    0x80040154: "this Windows does not have that component",
    0x80004002: "this Windows does not offer that feature",
}

MONO_KEY, MONO_VALUE = r"Software\Microsoft\Multimedia\Audio", "AccessibilityMonoMixState"  # 1 = Mono audio on
STARTUP_KEY, STARTUP_VALUE = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "DisableStartupSound"
MIC_CONSENT = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
MIC_POLICY = (r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsAccessMicrophone")  # 2 = apps are denied

SETTINGS_SOUND = "ms-settings:sound"
SETTINGS_DEVICES = "ms-settings:sound-devices"
SETTINGS_MIXER = "ms-settings:apps-volume"
SETTINGS_MONO = "ms-settings:easeofaccess-audio"
CLASSIC_TABS = {"playback": 0, "out": 0, "recording": 1, "in": 1, "sounds": 2, "communications": 3, "calls": 3}

LIST_FILTERS = {"playback": "playback", "out": "playback", "speakers": "playback",
                "recording": "recording", "in": "recording", "mic": "recording", "microphones": "recording"}
NAME_WIDTH = 44  # a device name longer than this is cut with "..."
LEVEL_DEFAULT, LEVEL_MAX = 10, 300  # seconds `snd level` runs
LEVEL_STEP = 0.1  # seconds between meter readings
BAR = 24  # width of a level bar
LOUD = 80  # a test tone asks first when the volume is at or above this
QUIET = 5  # a volume at or below this is treated as silent
TONES = (660, 880)  # hertz; two short notes


class SoundError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# CORE AUDIO — the COM interfaces, declared the first time they are needed
# ======================================================================
_declared = None


def _declare():
    """The Core Audio interfaces, declared with comtypes. Done on first use, so the page loads without comtypes."""
    global _declared
    if _declared is not None:
        return _declared
    try:
        import comtypes
        from comtypes import COMMETHOD, GUID, HRESULT, IUnknown
    except ImportError:
        raise SoundError("this needs the comtypes package. Run: py -m pip install -r requirements.txt")
    from ctypes import POINTER, Structure, Union, c_float, c_longlong, c_uint32, c_ushort, c_void_p, c_wchar_p
    from ctypes.wintypes import BOOL, DWORD, LPCWSTR, LPWSTR, UINT, WORD

    class PROPERTYKEY(Structure):
        _fields_ = [("fmtid", GUID), ("pid", DWORD)]

    class _Blob(Structure):
        _fields_ = [("cbSize", c_uint32), ("pBlobData", c_void_p)]

    class _Data(Union):
        _fields_ = [("pwszVal", c_wchar_p), ("blob", _Blob)]

    class PROPVARIANT(Structure):  # 16 bytes on 32-bit Windows, 24 on 64-bit, as in propidl.h
        _fields_ = [("vt", c_ushort), ("wReserved1", c_ushort), ("wReserved2", c_ushort), ("wReserved3", c_ushort),
                    ("data", _Data)]

    class WAVEFORMATEX(Structure):
        _pack_ = 1
        _fields_ = [("wFormatTag", WORD), ("nChannels", WORD), ("nSamplesPerSec", DWORD), ("nAvgBytesPerSec", DWORD),
                    ("nBlockAlign", WORD), ("wBitsPerSample", WORD), ("cbSize", WORD)]

    class IPropertyStore(IUnknown):
        _iid_ = GUID("{886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}")
        _methods_ = (
            COMMETHOD([], HRESULT, "GetCount", (["out"], POINTER(DWORD), "cProps")),
            COMMETHOD([], HRESULT, "GetAt", (["in"], DWORD, "iProp"), (["out"], POINTER(PROPERTYKEY), "pkey")),
            COMMETHOD([], HRESULT, "GetValue", (["in"], POINTER(PROPERTYKEY), "key"),
                      (["out"], POINTER(PROPVARIANT), "pv")),
            COMMETHOD([], HRESULT, "SetValue", (["in"], POINTER(PROPERTYKEY), "key"),
                      (["in"], POINTER(PROPVARIANT), "propvar")),
            COMMETHOD([], HRESULT, "Commit"),
        )

    class IMMDevice(IUnknown):
        _iid_ = GUID("{D666063F-1587-4E43-81F1-B948E807363F}")
        _methods_ = (
            COMMETHOD([], HRESULT, "Activate", (["in"], POINTER(GUID), "iid"), (["in"], DWORD, "dwClsCtx"),
                      (["in"], c_void_p, "pActivationParams"), (["out"], POINTER(POINTER(IUnknown)), "ppInterface")),
            COMMETHOD([], HRESULT, "OpenPropertyStore", (["in"], DWORD, "stgmAccess"),
                      (["out"], POINTER(POINTER(IPropertyStore)), "ppProperties")),
            COMMETHOD([], HRESULT, "GetId", (["out"], POINTER(LPWSTR), "ppstrId")),
            COMMETHOD([], HRESULT, "GetState", (["out"], POINTER(DWORD), "pdwState")),
        )

    class IMMDeviceCollection(IUnknown):
        _iid_ = GUID("{0BD7A1BE-7A1A-44DB-8397-CC5392387B5E}")
        _methods_ = (
            COMMETHOD([], HRESULT, "GetCount", (["out"], POINTER(UINT), "pcDevices")),
            COMMETHOD([], HRESULT, "Item", (["in"], UINT, "nDevice"), (["out"], POINTER(POINTER(IMMDevice)), "ppDevice")),
        )

    class IMMDeviceEnumerator(IUnknown):
        _iid_ = GUID("{A95664D2-9614-4F35-A746-DE8DB63617E6}")
        _methods_ = (
            COMMETHOD([], HRESULT, "EnumAudioEndpoints", (["in"], DWORD, "dataFlow"), (["in"], DWORD, "dwStateMask"),
                      (["out"], POINTER(POINTER(IMMDeviceCollection)), "ppDevices")),
            COMMETHOD([], HRESULT, "GetDefaultAudioEndpoint", (["in"], DWORD, "dataFlow"), (["in"], DWORD, "role"),
                      (["out"], POINTER(POINTER(IMMDevice)), "ppEndpoint")),
            COMMETHOD([], HRESULT, "GetDevice", (["in"], LPCWSTR, "pwstrId"), (["out"], POINTER(POINTER(IMMDevice)), "ppDevice")),
            COMMETHOD([], HRESULT, "RegisterEndpointNotificationCallback", (["in"], c_void_p, "pClient")),
            COMMETHOD([], HRESULT, "UnregisterEndpointNotificationCallback", (["in"], c_void_p, "pClient")),
        )

    class IAudioEndpointVolume(IUnknown):
        _iid_ = GUID("{5CDF2C82-841E-4546-9722-0CF74078229A}")
        _methods_ = (
            COMMETHOD([], HRESULT, "RegisterControlChangeNotify", (["in"], c_void_p, "pNotify")),
            COMMETHOD([], HRESULT, "UnregisterControlChangeNotify", (["in"], c_void_p, "pNotify")),
            COMMETHOD([], HRESULT, "GetChannelCount", (["out"], POINTER(UINT), "pnChannelCount")),
            COMMETHOD([], HRESULT, "SetMasterVolumeLevel", (["in"], c_float, "fLevelDB"),
                      (["in"], POINTER(GUID), "pguidEventContext")),
            COMMETHOD([], HRESULT, "SetMasterVolumeLevelScalar", (["in"], c_float, "fLevel"),
                      (["in"], POINTER(GUID), "pguidEventContext")),
            COMMETHOD([], HRESULT, "GetMasterVolumeLevel", (["out"], POINTER(c_float), "pfLevelDB")),
            COMMETHOD([], HRESULT, "GetMasterVolumeLevelScalar", (["out"], POINTER(c_float), "pfLevel")),
            COMMETHOD([], HRESULT, "SetChannelVolumeLevel", (["in"], UINT, "nChannel"), (["in"], c_float, "fLevelDB"),
                      (["in"], POINTER(GUID), "pguidEventContext")),
            COMMETHOD([], HRESULT, "SetChannelVolumeLevelScalar", (["in"], UINT, "nChannel"), (["in"], c_float, "fLevel"),
                      (["in"], POINTER(GUID), "pguidEventContext")),
            COMMETHOD([], HRESULT, "GetChannelVolumeLevel", (["in"], UINT, "nChannel"),
                      (["out"], POINTER(c_float), "pfLevelDB")),
            COMMETHOD([], HRESULT, "GetChannelVolumeLevelScalar", (["in"], UINT, "nChannel"),
                      (["out"], POINTER(c_float), "pfLevel")),
            COMMETHOD([], HRESULT, "SetMute", (["in"], BOOL, "bMute"), (["in"], POINTER(GUID), "pguidEventContext")),
            COMMETHOD([], HRESULT, "GetMute", (["out"], POINTER(BOOL), "pbMute")),
            COMMETHOD([], HRESULT, "GetVolumeStepInfo", (["out"], POINTER(UINT), "pnStep"),
                      (["out"], POINTER(UINT), "pnStepCount")),
            COMMETHOD([], HRESULT, "VolumeStepUp", (["in"], POINTER(GUID), "pguidEventContext")),
            COMMETHOD([], HRESULT, "VolumeStepDown", (["in"], POINTER(GUID), "pguidEventContext")),
            COMMETHOD([], HRESULT, "QueryHardwareSupport", (["out"], POINTER(DWORD), "pdwHardwareSupportMask")),
            COMMETHOD([], HRESULT, "GetVolumeRange", (["out"], POINTER(c_float), "pfLevelMinDB"),
                      (["out"], POINTER(c_float), "pfLevelMaxDB"), (["out"], POINTER(c_float), "pfVolumeIncrementDB")),
        )

    class IAudioMeterInformation(IUnknown):
        _iid_ = GUID("{C02216F6-8C67-4B5B-9D00-D008E73E0064}")
        _methods_ = (
            COMMETHOD([], HRESULT, "GetPeakValue", (["out"], POINTER(c_float), "pfPeak")),
            COMMETHOD([], HRESULT, "GetMeteringChannelCount", (["out"], POINTER(UINT), "pnChannelCount")),
            COMMETHOD([], HRESULT, "GetChannelsPeakValues", (["in"], UINT, "u32ChannelCount"),
                      (["in"], POINTER(c_float), "afPeakValues")),
            COMMETHOD([], HRESULT, "QueryHardwareSupport", (["out"], POINTER(DWORD), "pdwHardwareSupportMask")),
        )

    class IAudioClient(IUnknown):  # only used to open a recording device for a moment, so its level can be measured
        _iid_ = GUID("{1CB9AD4C-DBFA-4C32-B178-C2F568A703B2}")
        _methods_ = (
            COMMETHOD([], HRESULT, "Initialize", (["in"], DWORD, "ShareMode"), (["in"], DWORD, "StreamFlags"),
                      (["in"], c_longlong, "hnsBufferDuration"), (["in"], c_longlong, "hnsPeriodicity"),
                      (["in"], POINTER(WAVEFORMATEX), "pFormat"), (["in"], POINTER(GUID), "AudioSessionGuid")),
            COMMETHOD([], HRESULT, "GetBufferSize", (["out"], POINTER(UINT), "pNumBufferFrames")),
            COMMETHOD([], HRESULT, "GetStreamLatency", (["out"], POINTER(c_longlong), "phnsLatency")),
            COMMETHOD([], HRESULT, "GetCurrentPadding", (["out"], POINTER(UINT), "pNumPaddingFrames")),
            COMMETHOD([], HRESULT, "IsFormatSupported", (["in"], DWORD, "ShareMode"),
                      (["in"], POINTER(WAVEFORMATEX), "pFormat"), (["out"], POINTER(POINTER(WAVEFORMATEX)), "ppClosestMatch")),
            COMMETHOD([], HRESULT, "GetMixFormat", (["out"], POINTER(POINTER(WAVEFORMATEX)), "ppDeviceFormat")),
            COMMETHOD([], HRESULT, "GetDevicePeriod", (["out"], POINTER(c_longlong), "phnsDefaultDevicePeriod"),
                      (["out"], POINTER(c_longlong), "phnsMinimumDevicePeriod")),
            COMMETHOD([], HRESULT, "Start"),
            COMMETHOD([], HRESULT, "Stop"),
            COMMETHOD([], HRESULT, "Reset"),
            COMMETHOD([], HRESULT, "SetEventHandle", (["in"], c_void_p, "eventHandle")),
            COMMETHOD([], HRESULT, "GetService", (["in"], POINTER(GUID), "riid"), (["out"], POINTER(c_void_p), "ppv")),
        )

    class IPolicyConfig(IUnknown):  # undocumented: only the position of SetDefaultEndpoint matters, the rest fill the table
        _iid_ = GUID("{F8679F50-850A-41CF-9C72-430F290290C8}")
        _methods_ = (
            COMMETHOD([], HRESULT, "GetMixFormat", (["in"], LPCWSTR, "pszDeviceName"), (["out"], POINTER(c_void_p), "ppFormat")),
            COMMETHOD([], HRESULT, "GetDeviceFormat", (["in"], LPCWSTR, "pszDeviceName"), (["in"], BOOL, "bDefault"),
                      (["out"], POINTER(c_void_p), "ppFormat")),
            COMMETHOD([], HRESULT, "ResetDeviceFormat", (["in"], LPCWSTR, "pszDeviceName")),
            COMMETHOD([], HRESULT, "SetDeviceFormat", (["in"], LPCWSTR, "pszDeviceName"),
                      (["in"], c_void_p, "pEndpointFormat"), (["in"], c_void_p, "pMixFormat")),
            COMMETHOD([], HRESULT, "GetProcessingPeriod", (["in"], LPCWSTR, "pszDeviceName"), (["in"], BOOL, "bDefault"),
                      (["out"], POINTER(c_longlong), "pmftDefaultPeriod"), (["out"], POINTER(c_longlong), "pmftMinimumPeriod")),
            COMMETHOD([], HRESULT, "SetProcessingPeriod", (["in"], LPCWSTR, "pszDeviceName"),
                      (["in"], POINTER(c_longlong), "pmftPeriod")),
            COMMETHOD([], HRESULT, "GetShareMode", (["in"], LPCWSTR, "pszDeviceName"), (["out"], POINTER(c_void_p), "pMode")),
            COMMETHOD([], HRESULT, "SetShareMode", (["in"], LPCWSTR, "pszDeviceName"), (["in"], c_void_p, "pMode")),
            COMMETHOD([], HRESULT, "GetPropertyValue", (["in"], LPCWSTR, "pszDeviceName"),
                      (["in"], POINTER(PROPERTYKEY), "key"), (["out"], POINTER(PROPVARIANT), "pv")),
            COMMETHOD([], HRESULT, "SetPropertyValue", (["in"], LPCWSTR, "pszDeviceName"),
                      (["in"], POINTER(PROPERTYKEY), "key"), (["in"], POINTER(PROPVARIANT), "pv")),
            COMMETHOD([], HRESULT, "SetDefaultEndpoint", (["in"], LPCWSTR, "pszDeviceName"), (["in"], DWORD, "role")),
            COMMETHOD([], HRESULT, "SetEndpointVisibility", (["in"], LPCWSTR, "pszDeviceName"), (["in"], BOOL, "bVisible")),
        )

    _declared = types.SimpleNamespace(
        comtypes=comtypes, GUID=GUID, PROPERTYKEY=PROPERTYKEY, PROPVARIANT=PROPVARIANT,
        IMMDeviceEnumerator=IMMDeviceEnumerator, IAudioEndpointVolume=IAudioEndpointVolume,
        IAudioMeterInformation=IAudioMeterInformation, IAudioClient=IAudioClient, IPolicyConfig=IPolicyConfig,
        CLSID_MMDeviceEnumerator=GUID("{BCDE0395-E52F-467C-8E3D-C4579291692E}"),
        CLSID_PolicyConfigClient=GUID("{870AF99C-171D-4F9E-AF0D-E63DF40C2BC9}"),
    )
    return _declared


def _hresult(error):
    """The HRESULT inside a COMError or OSError as an unsigned number, or None."""
    code = error.args[0] if error.args else None
    return code & 0xFFFFFFFF if isinstance(code, int) else None


def _hresult_text(error):
    code = _hresult(error)
    if code in HRESULT_TEXT:
        return HRESULT_TEXT[code]
    if len(error.args) > 1 and isinstance(error.args[1], str) and error.args[1]:
        return error.args[1].strip()
    return f"Windows error 0x{code:08X}" if code is not None else str(error)


def _parse_format(blob):
    """{rate, bits, channels, float} from a WAVEFORMATEX or WAVEFORMATEXTENSIBLE, or None if it is too short."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 16:
        return None
    tag, channels, rate, _, _, bits = struct.unpack_from("<HHIIHH", blob, 0)
    is_float = tag == 3  # WAVE_FORMAT_IEEE_FLOAT
    if tag == 0xFFFE and len(blob) >= 40:  # extensible: the valid bits are at offset 18, the sub-format GUID at 24
        bits = struct.unpack_from("<H", blob, 18)[0] or bits
        is_float = blob[24:28] == b"\x03\x00\x00\x00"
    return {"rate": rate, "bits": bits, "channels": channels, "float": is_float}


class _Listener:
    """A recording device held open so Windows keeps measuring it. close() lets it go."""

    def __init__(self, client):
        self.client = client

    def close(self):
        if self.client is not None:
            with contextlib.suppress(Exception):
                self.client.Stop()
            self.client = None


class _ComAudio:
    """The Core Audio calls this page needs. All the COM happens in here and comes out as plain Python values, so the
    rest of the page does not care how Windows is asked."""

    def __init__(self):
        self.api = _declare()
        with contextlib.suppress(OSError):
            self.api.comtypes.CoInitialize()  # already done on this thread, in another mode, is fine
        self._enumerator = None

    @contextlib.contextmanager
    def _errors(self, what):
        try:
            yield
        except (self.api.comtypes.COMError, OSError) as e:
            raise SoundError(f"{what}: {_hresult_text(e)}")

    def _enum(self):
        if self._enumerator is None:
            with self._errors("could not reach Windows' sound system"):
                self._enumerator = self.api.comtypes.CoCreateInstance(
                    self.api.CLSID_MMDeviceEnumerator, self.api.IMMDeviceEnumerator, CLSCTX_INPROC_SERVER)
        return self._enumerator

    def _device(self, endpoint_id):
        with self._errors("could not open the sound device"):
            return self._enum().GetDevice(endpoint_id)

    def _activate(self, endpoint_id, interface):
        device = self._device(endpoint_id)
        with self._errors("could not open the sound device"):
            pointer = device.Activate(interface._iid_, self.api.comtypes.CLSCTX_ALL, None)
            return pointer.QueryInterface(interface)

    def _property(self, store, key):
        """One value from a property store: text for a string, bytes for a blob, None for anything else."""
        api = self.api
        wanted = api.PROPERTYKEY()
        wanted.fmtid = api.GUID(key[0])
        wanted.pid = key[1]
        value = store.GetValue(wanted)
        try:
            if value.vt == VT_LPWSTR:
                return value.data.pwszVal
            if value.vt == VT_BLOB and value.data.blob.pBlobData:
                return ctypes.string_at(value.data.blob.pBlobData, value.data.blob.cbSize)
            return None
        finally:
            ctypes.windll.ole32.PropVariantClear(ctypes.byref(value))

    def devices(self, flow):
        """[{endpoint_id, name, adapter, state}] for the playback (RENDER) or recording (CAPTURE) devices."""
        found = []
        with self._errors("could not list the sound devices"):
            collection = self._enum().EnumAudioEndpoints(flow, LISTED)
            for index in range(collection.GetCount()):
                device = collection.Item(index)
                endpoint_id, name, adapter = device.GetId(), None, None
                try:
                    store = device.OpenPropertyStore(STGM_READ)
                    name, adapter = self._property(store, KEY_NAME), self._property(store, KEY_ADAPTER)
                except (self.api.comtypes.COMError, OSError):
                    pass  # a device whose name cannot be read is still listed, by its id
                found.append({"endpoint_id": endpoint_id, "name": name or endpoint_id, "adapter": adapter,
                              "state": device.GetState()})
        return found

    def default_id(self, flow, role):
        """The endpoint id that is the default for this role, or None when there is none."""
        try:
            return self._enum().GetDefaultAudioEndpoint(flow, ROLES[role]).GetId()
        except (self.api.comtypes.COMError, OSError) as e:
            if _hresult(e) == E_NOTFOUND:
                return None
            raise SoundError(f"could not read the default device: {_hresult_text(e)}")

    def volume(self, endpoint_id):
        """{percent, muted, db, db_min, db_max, channels} for a device."""
        endpoint = self._activate(endpoint_id, self.api.IAudioEndpointVolume)
        with self._errors("could not read the volume"):
            low, high, _ = endpoint.GetVolumeRange()
            return {"percent": endpoint.GetMasterVolumeLevelScalar() * 100, "muted": bool(endpoint.GetMute()),
                    "db": endpoint.GetMasterVolumeLevel(), "db_min": low, "db_max": high,
                    "channels": endpoint.GetChannelCount()}

    def set_volume(self, endpoint_id, percent):
        endpoint = self._activate(endpoint_id, self.api.IAudioEndpointVolume)
        with self._errors("could not set the volume"):
            endpoint.SetMasterVolumeLevelScalar(percent / 100, None)

    def set_mute(self, endpoint_id, muted):
        endpoint = self._activate(endpoint_id, self.api.IAudioEndpointVolume)
        with self._errors("could not change the mute"):
            endpoint.SetMute(1 if muted else 0, None)

    def peak(self, endpoint_id):
        """The loudest sample just now, from 0.0 to 1.0."""
        meter = self._activate(endpoint_id, self.api.IAudioMeterInformation)
        with self._errors("could not read the level"):
            return float(meter.GetPeakValue())

    def format(self, endpoint_id):
        """The shared-mode format Windows mixes this device at: {rate, bits, channels, float}, or None."""
        device = self._device(endpoint_id)
        with self._errors("could not read the format"):
            blob = self._property(device.OpenPropertyStore(STGM_READ), KEY_FORMAT)
        return _parse_format(blob)

    def set_default(self, endpoint_id, role):
        with self._errors("could not change the default device"):
            policy = self.api.comtypes.CoCreateInstance(
                self.api.CLSID_PolicyConfigClient, self.api.IPolicyConfig, self.api.comtypes.CLSCTX_ALL)
            policy.SetDefaultEndpoint(endpoint_id, ROLES[role])

    def listen(self, endpoint_id):
        """Open a recording device in shared mode so the engine runs and its meter moves. Returns a _Listener."""
        client = self._activate(endpoint_id, self.api.IAudioClient)
        with self._errors("could not open the microphone"):
            mix = client.GetMixFormat()
            try:
                client.Initialize(0, 0, 10000000, 0, mix, None)  # shared mode, a one-second buffer
            finally:
                ctypes.windll.ole32.CoTaskMemFree(ctypes.cast(mix, ctypes.c_void_p))
            client.Start()
        return _Listener(client)


_backend = None


def _audio():
    global _backend
    if _backend is None:
        _backend = _ComAudio()
    return _backend


# ======================================================================
# DEVICES — one numbered list: playback devices first, then recording devices
# ======================================================================
def _devices(levels=True):
    """Every playback device then every recording device, each group sorted by name, numbered from 1. The list and the
    ids both come from here, so they always agree. levels=False skips reading each device's volume."""
    audio = _audio()
    rows = []
    for flow in (RENDER, CAPTURE):
        defaults = {role: audio.default_id(flow, role) for role in ROLES}
        for device in sorted(audio.devices(flow), key=lambda d: (d["name"].lower(), d["endpoint_id"])):
            rows.append({
                "endpoint_id": device["endpoint_id"], "name": device["name"], "adapter": device.get("adapter"),
                "kind": FLOW_NAMES[flow], "flow": flow, "state": STATE_NAMES.get(device["state"], "unknown"),
                "roles": [role for role, endpoint in defaults.items() if endpoint == device["endpoint_id"]],
                "volume": None, "muted": None,
            })
    for number, row in enumerate(rows, start=1):
        row["id"] = number
        if levels and row["state"] == "active":
            try:
                info = audio.volume(row["endpoint_id"])
            except SoundError:
                continue  # a device with no volume control is still listed
            row["volume"], row["muted"] = round(info["percent"]), info["muted"]
    return rows


def _find(word, rows):
    if word.isdigit():
        for row in rows:
            if row["id"] == int(word):
                return row
        raise SoundError(f"no sound device with id {word}. Run 'snd' to see them.", 2)
    lowered = word.lower()
    exact = [row for row in rows if lowered in (row["name"].lower(), row["endpoint_id"].lower())]
    if len(exact) == 1:
        return exact[0]
    partial = exact or [row for row in rows if lowered in row["name"].lower()]
    if len(partial) == 1:
        return partial[0]
    if partial:
        raise SoundError(f"'{word}' matches more than one device: "
                         + ", ".join(f"{row['id']} {row['name']}" for row in partial) + ". Use the id.", 2)
    raise SoundError(f"no sound device called {word}. Run 'snd' to see them, or use its id.", 2)


def _default_row(kind, rows):
    """The device that is the default playback or recording device, or None."""
    candidates = [row for row in rows if row["kind"] == kind]
    for role in ("console", "multimedia"):
        for row in candidates:
            if role in row["roles"]:
                return row
    return None


def _brief(row):
    return {"id": row["id"], "name": row["name"], "kind": row["kind"], "state": row["state"],
            "default_for": row["roles"], "volume": row["volume"], "muted": row["muted"],
            "adapter": row["adapter"], "endpoint_id": row["endpoint_id"]}


def _role_text(roles):
    """'default', 'default, calls' or 'calls' for the roles a device is the default for."""
    parts = []
    if "console" in roles and "multimedia" in roles:
        parts.append("default")
    elif roles:
        parts.extend(f"default ({role})" for role in ("console", "multimedia") if role in roles)
    if "communications" in roles:
        parts.append("calls")
    return ", ".join(parts)


def _roles(words):
    """The roles named by these words, in order. None or 'all' means all three; 'default' is console and multimedia."""
    if not words:
        return list(ROLES)
    chosen = []
    for word in words:
        key = ROLE_WORDS.get(word.lower())
        if key is None:
            raise SoundError(f"'{word}' is not a role. Use all, default, calls, console, multimedia or communications.", 2)
        for role in {"all": list(ROLES), "default": ["console", "multimedia"]}.get(key, [key]):
            if role not in chosen:
                chosen.append(role)
    return chosen


def _cut(text, width=NAME_WIDTH):
    return text if len(text) <= width else text[:width - 3] + "..."


def _say(options, text=""):
    if not options["json"]:
        print(text)


def _confirm(question, options):
    """_core.confirm, except that --json --yes asks silently: the question would break the JSON."""
    if options["json"] and options["yes"]:
        return True
    return _core.confirm(question, options["yes"])


def _level_text(row):
    if row["volume"] is None:
        return "-"
    return "muted" if row["muted"] else f"{row['volume']}%"


def _volume_line(row):
    if row["volume"] is None:
        return f"{row['name']}: no volume control"
    return f"{row['name']}: {row['volume']}%" + (" (muted)" if row["muted"] else "")


def _sample(audio, row, readings=5):
    """The loudest of a few quick meter readings, as a percent; None if the device cannot be measured."""
    best = None
    for index in range(readings):
        try:
            peak = audio.peak(row["endpoint_id"])
        except SoundError:
            return None
        best = peak if best is None else max(best, peak)
        if index + 1 < readings:
            time.sleep(0.05)
    return round(best * 100)


def _active_in_kind(rows, kind):
    return [row for row in rows if row["kind"] == kind and row["state"] == "active"]


# ======================================================================
# LISTING — the devices, and one device in full
# ======================================================================
def _defaults_json(rows):
    out = {}
    for kind in ("playback", "recording"):
        out[kind] = {role: next((row["id"] for row in rows if row["kind"] == kind and role in row["roles"]), None)
                     for role in ROLES}
    return out


def _row_text(row):
    color = _net.GREEN if row["state"] == "active" else _net.GREY
    return color + (f"{row['id']:<5}{_cut(row['name']):<{NAME_WIDTH + 2}}{row['state']:<12}"
                    f"{_level_text(row):<8}{_role_text(row['roles'])}") + _net.RESET


def _list(words, options):
    kind = None
    if words:
        kind = LIST_FILTERS.get(words[0].lower()) if len(words) == 1 else None
        if kind is None:
            raise SoundError("usage: snd ls [playback|recording]", 2)
    every = _devices()
    rows = [row for row in every if kind in (None, row["kind"])]
    if options["json"]:
        _core.print_json({"devices": [_brief(row) for row in rows], "defaults": _defaults_json(every)})
        return 0
    if not every:
        print("no sound devices found. 'dvc audio' lists the audio hardware Windows knows about.")
        return 0
    header = f"{'ID':<5}{'DEVICE':<{NAME_WIDTH + 2}}{'STATE':<12}{'VOLUME':<8}DEFAULT"
    for title, group in (("playback", "PLAYBACK  (speakers and headphones)"), ("recording", "RECORDING  (microphones)")):
        found = [row for row in rows if row["kind"] == title]
        if not found:
            continue
        print(group)
        print(header)
        for row in found:
            print(_row_text(row))
        print()
    speakers, microphone = _default_row("playback", every), _default_row("recording", every)
    print(f"default speakers: {speakers['name'] if speakers else 'none'}    "
          f"default microphone: {microphone['name'] if microphone else 'none'}")
    print("'snd <id>' shows one device, 'snd default <id>' switches, 'snd why' finds the cause of no sound, "
          "'snd help' lists everything.")
    return 0


def _format_text(fmt):
    if not fmt:
        return "not reported"
    layout = {1: " (mono)", 2: " (stereo)"}.get(fmt["channels"], "")
    plural = "" if fmt["channels"] == 1 else "s"
    return (f"{fmt['rate']} Hz, {fmt['bits']}-bit{' float' if fmt['float'] else ''}, "
            f"{fmt['channels']} channel{plural}{layout}")


def _detail(row, options):
    audio = _audio()
    active = row["state"] == "active"
    info = fmt = peak = None
    if active:
        with contextlib.suppress(SoundError):
            info = audio.volume(row["endpoint_id"])
        with contextlib.suppress(SoundError):
            fmt = audio.format(row["endpoint_id"])
        peak = _sample(audio, row)
    if options["json"]:
        _core.print_json({**_brief(row), "channels": info["channels"] if info else None,
                          "volume_db": round(info["db"], 1) if info else None,
                          "volume_range_db": [round(info["db_min"], 1), round(info["db_max"], 1)] if info else None,
                          "format": fmt, "peak": peak})
        return 0
    seen = ""
    if peak is not None:
        seen = f"{peak}%" + (" (nothing is playing, or an app's own volume is 0)" if peak == 0 and row["kind"] == "playback"
                             else " (Windows only measures a microphone while a program uses it)" if peak == 0 else "")
    sections = [
        ("device", [("kind", row["kind"]), ("state", row["state"]), ("adapter", row["adapter"]),
                    ("default for", _role_text(row["roles"]) or "not the default"),
                    ("endpoint id", row["endpoint_id"])]),
        ("volume", [("volume", "-" if row["volume"] is None else f"{row['volume']}%"),
                    ("muted", row["muted"]),
                    ("level", f"{info['db']:.1f} dB (range {info['db_min']:.1f} to {info['db_max']:.1f} dB)" if info else "-"),
                    ("channels", info["channels"] if info else None)]),
        ("format and level", [("format", _format_text(fmt)), ("level now", seen or "-")]),
    ]
    todo = []
    if active and not row["roles"]:
        todo.append((f"snd default {row['id']}", f"make it the default {row['kind']} device"))
    if active:
        todo += [(f"snd {row['id']} volume <0-100>", "set its volume"),
                 (f"snd {row['id']} {'unmute' if row['muted'] else 'mute'}", "mute or unmute it"),
                 ("snd classic " + row["kind"], "enhancements, spatial sound, exclusive mode, sample rate")]
    else:
        todo.append((f"snd enable {row['id']}", "how to turn it on (opens Settings)"))
    sections.append(("what you can do", todo))
    _net.render(row["name"], sections)
    return 0


# ======================================================================
# CHANGES — default device, volume and mute. Each is read back from Windows afterwards.
# ======================================================================
def _need_active(row):
    if row["state"] != "active":
        raise SoundError(f"{row['name']} is {row['state']}, so Windows cannot use it. 'snd enable {row['id']}' says how "
                         "to turn a device on.", 2)


def _fallback(row):
    """The default did not change: say so, and open Settings at the page that can do it."""
    where = "Output" if row["flow"] == RENDER else "Input"
    print(f"error: Windows did not make {row['name']} the default {row['kind']} device.", file=sys.stderr)
    print(f"Opening Settings > System > Sound: under {where}, choose {row['name']}.")
    _win.open_settings(SETTINGS_SOUND)
    return 1


def _default_cmd(words, options, row=None):
    if row is None:
        if not words:
            raise SoundError("usage: snd default <id> [all|default|calls|console|multimedia|communications]", 2)
        row = _find(words[0], _devices(levels=False))
        words = words[1:]
    roles = _roles(words)
    _need_active(row)
    wanted = [role for role in roles if role not in row["roles"]]
    if not wanted:
        _say(options, f"{row['name']} is already the default {row['kind']} device"
                      + (f" for {_role_text(roles)}" if len(roles) < 3 else "") + ".")
        if options["json"]:
            _core.print_json(_brief(row))
        return 0
    before = _devices(levels=False)
    previous = {role: next((r["name"] for r in before if r["kind"] == row["kind"] and role in r["roles"]), "none")
                for role in wanted}
    _say(options, f"making {row['name']} the default {row['kind']} device...")
    audio = _audio()
    try:
        for role in wanted:
            audio.set_default(row["endpoint_id"], role)
    except SoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return _fallback(row)
    now = _devices()
    new = next((r for r in now if r["endpoint_id"] == row["endpoint_id"]), None)
    if new is None or any(role not in new["roles"] for role in wanted):
        return _fallback(row)
    if options["json"]:
        _core.print_json({**_brief(new), "changed_roles": wanted})
        return 0
    if len(set(previous.values())) == 1:
        print(f"default {row['kind']} device ({_role_text(wanted)}): {next(iter(previous.values()))} -> {new['name']}")
    else:
        for role in wanted:
            print(f"default {row['kind']} device for {role}: {previous[role]} -> {new['name']}")
    return 0


def _number(word):
    """A percent from '40' or '40%', or None if it is not a number."""
    try:
        value = float(word.rstrip("%"))
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _volume_cmd(row, word, options):
    percent = _number(word)
    if percent is None or not 0 <= percent <= 100:
        raise SoundError("volume needs a number from 0 to 100", 2)
    _need_active(row)
    _audio().set_volume(row["endpoint_id"], round(percent))
    now = next(r for r in _devices() if r["endpoint_id"] == row["endpoint_id"])
    if options["json"]:
        _core.print_json(_brief(now))
    else:
        print(_volume_line(now))
    return 0


def _mute_cmd(row, word, options):
    _need_active(row)
    audio = _audio()
    if word == "toggle":
        muted = not audio.volume(row["endpoint_id"])["muted"]
    else:
        muted = word == "mute"
    audio.set_mute(row["endpoint_id"], muted)
    now = next(r for r in _devices() if r["endpoint_id"] == row["endpoint_id"])
    if options["json"]:
        _core.print_json(_brief(now))
    elif now["muted"]:
        print(f"{now['name']}: muted (its volume is {now['volume']}%)")
    else:
        print(f"{now['name']}: unmuted, volume {now['volume']}%")
    return 0


def _device_cmd(row, words, options):
    """What follows a device id: nothing (show it), volume, mute, unmute, toggle, or default."""
    if not words:
        return _detail(row, options)
    word, rest = words[0].lower(), words[1:]
    if word == "volume" and len(rest) == 1:
        return _volume_cmd(row, rest[0], options)
    if len(words) == 1 and _number(word) is not None:
        return _volume_cmd(row, word, options)
    if word in ("mute", "unmute", "toggle") and not rest:
        return _mute_cmd(row, word, options)
    if word == "default":
        return _default_cmd(rest, options, row)
    raise SoundError("usage: snd <id> [volume <0-100> | mute | unmute | toggle | default [role]]", 2)


def _default_device_cmd(kind, words, options):
    """snd out / snd in: the default speakers or microphone, shown or changed like any device."""
    row = _default_row(kind, _devices())
    if row is None:
        raise SoundError(f"there is no default {kind} device. 'snd' lists the devices.", 1)
    if not words:
        if options["json"]:
            _core.print_json(_brief(row))
        else:
            print(_volume_line(row))
        return 0
    return _device_cmd(row, words, options)


# ======================================================================
# LEVEL AND TEST — is anything coming out, or going in?
# ======================================================================
def _bar(percent):
    filled = round(min(percent, 100) / 100 * BAR)
    color = _net.GREEN if percent < 70 else _net.YELLOW if percent < 90 else _net.RED
    return color + "#" * filled + _net.GREY + "." * (BAR - filled) + _net.RESET


def _level(words, options):
    seconds, listen = LEVEL_DEFAULT, False
    for word in words:
        if word.lower() == "listen":
            listen = True
        elif word.isdigit() and 1 <= int(word) <= LEVEL_MAX:
            seconds = int(word)
        else:
            raise SoundError(f"usage: snd level [seconds 1-{LEVEL_MAX}] [listen]", 2)
    rows = _devices(levels=False)
    speakers, microphone = _default_row("playback", rows), _default_row("recording", rows)
    if speakers is None and microphone is None:
        raise SoundError("there is no default playback or recording device. 'snd' lists the devices.", 1)
    audio = _audio()
    listener = None
    if listen:
        if microphone is None:
            raise SoundError("there is no default recording device to listen to.", 1)
        if not _confirm(f"Open the microphone ({microphone['name']}) so Windows can measure it? Windows will show its "
                        "microphone indicator while it is open. Nothing is recorded. [y/N]: ", options):
            print("cancelled")
            return 0
        listener = audio.listen(microphone["endpoint_id"])
    try:
        if options["json"]:
            if listener is not None:
                time.sleep(0.3)  # let the engine start before the meter is read
            _core.print_json({
                "output": {"id": speakers["id"], "name": speakers["name"], "peak": _sample(audio, speakers)} if speakers else None,
                "input": {"id": microphone["id"], "name": microphone["name"], "peak": _sample(audio, microphone)} if microphone else None,
                "listening": listener is not None,
            })
            return 0
        return _level_loop(audio, speakers, microphone, seconds, listener is not None)
    finally:
        if listener is not None:
            listener.close()


def _level_loop(audio, speakers, microphone, seconds, listening):
    loudest = {"out": 0, "in": 0}
    if speakers:
        print(f"output: {speakers['name']}")
    if microphone:
        print(f"input:  {microphone['name']}" + (" (open for measuring)" if listening else ""))
    print(f"watching for {seconds} s. Ctrl+C stops.")
    interactive = sys.stdout.isatty()
    start = last = time.monotonic()
    try:
        while time.monotonic() - start < seconds:
            parts = []
            for key, row in (("out", speakers), ("in", microphone)):
                if row is None:
                    continue
                percent = _sample(audio, row, readings=1)
                if percent is None:
                    parts.append(f"{key} n/a")
                    continue
                loudest[key] = max(loudest[key], percent)
                parts.append(f"{key} {_bar(percent)} {percent:>3}%")
            line = "   ".join(parts)
            if interactive:
                print("\r" + line + "   ", end="", flush=True)
            elif time.monotonic() - last >= 1:
                print(line)
                last = time.monotonic()
            time.sleep(LEVEL_STEP)
    except KeyboardInterrupt:
        pass
    if interactive:
        print()
    summary = [f"{key}: {loudest[key]}%" for key, row in (("out", speakers), ("in", microphone)) if row]
    print("loudest: " + ", ".join(summary))
    if microphone and not listening and loudest["in"] == 0:
        print("The microphone read 0% the whole time. Windows only measures a microphone while a program is using it; "
              "'snd level listen' opens it for the measurement.")
    return 0


def _test(words, options):
    if words:
        raise SoundError("usage: snd test", 2)
    row = _default_row("playback", _devices())
    if row is None:
        raise SoundError("there is no default playback device. 'snd' lists the devices.", 1)
    if row["muted"]:
        _say(options, f"{row['name']} is muted, so you will not hear the tone: 'snd {row['id']} unmute'.")
    elif row["volume"] is not None and row["volume"] >= LOUD:
        if not _confirm(f"{row['name']} is at {row['volume']}%, so the tone may be loud. Play it anyway? [y/N]: ", options):
            print("cancelled")
            return 0
    try:
        import winsound
    except ImportError:
        raise SoundError("this needs Windows' winsound module")
    _say(options, f"playing a short tone through {row['name']}...")
    try:
        for hertz in TONES:
            winsound.Beep(hertz, 250)
    except RuntimeError:
        raise SoundError("Windows could not play the tone")
    if options["json"]:
        _core.print_json({"played": True, **_brief(row)})
    else:
        print("did you hear it? If not: 'snd why', or 'snd default <id>' to pick another device.")
    return 0


# ======================================================================
# WHY — the usual causes of no sound, or a silent microphone
# ======================================================================
def _check(key, status, title, detail=None, fix=None):
    return {"check": key, "status": status, "title": title, "detail": detail, "fix": fix}


def _service_check(name, label):
    state = _net.service_state(name)
    if state == "RUNNING":
        return _check(name.lower(), "ok", f"{label} is running")
    if state == "UNKNOWN":
        return _check(name.lower(), "note", f"could not read the state of {label}", fix=f"svc {name}")
    return _check(name.lower(), "problem", f"{label} is {state.lower()}",
                  "Windows plays and records sound through it.", f"svc {name} on   (administrator)")


def _microphone_privacy_checks():
    """Windows can switch every app's microphone access off in three places; any of them gives a silent microphone."""
    checks = []
    policy = _net.reg_read(MIC_POLICY[0], MIC_POLICY[1], None)
    if policy == 2:
        checks.append(_check("microphone_policy", "problem", "an organisation's policy blocks apps from the microphone",
                             "It is set by Group Policy or device management, so it cannot be changed here.",
                             "ask the person who manages this PC"))
    for hive, label in ((_win.HKCU, "your account"), (_win.HKLM, "this PC")):
        if _net.reg_read(MIC_CONSENT, "Value", None, hive=hive) == "Deny":
            checks.append(_check("microphone_access", "problem", f"microphone access is off for {label}",
                                 "Apps cannot hear the microphone while it is off.",
                                 "turn on Microphone access in Settings > Privacy & security > Microphone"))
    if not checks:
        checks.append(_check("microphone_access", "ok", "Windows lets apps use the microphone"))
    return checks


def _device_checks(rows, kind):
    """Checks for the default playback or recording device."""
    noun = "speakers" if kind == "playback" else "microphone"
    checks = []
    active = _active_in_kind(rows, kind)
    row = _default_row(kind, rows)
    if not active:
        others = [r for r in rows if r["kind"] == kind]
        if others:
            checks.append(_check("device", "problem", f"no {kind} device is active",
                                 "; ".join(f"{r['id']} {r['name']} is {r['state']}" for r in others),
                                 f"snd enable {others[0]['id']}   (says how to turn it on)"))
        else:
            checks.append(_check("device", "problem", f"Windows lists no {kind} devices",
                                 "The sound hardware or its driver may be missing or turned off.", "dvc audio   then dvc errors"))
        return checks
    if row is None:
        checks.append(_check("default", "problem", f"there is no default {noun}",
                             "Windows has devices but none is chosen.", f"snd default {active[0]['id']}"))
        return checks
    checks.append(_check("default", "ok", f"the default {noun} is {row['name']}"))
    if row["volume"] is None:
        checks.append(_check("volume", "note", "this device has no volume control Windows can read"))
    elif row["muted"]:
        checks.append(_check("muted", "problem", f"the default {noun} is muted", f"{row['name']} is muted.",
                             f"snd {row['id']} unmute"))
    elif row["volume"] <= QUIET:
        checks.append(_check("volume", "problem", f"the default {noun} volume is {row['volume']}%",
                             "It is too low to hear.", f"snd {row['id']} volume 50"))
    else:
        checks.append(_check("volume", "ok", f"the default {noun} is not muted and is at {row['volume']}%"))
    calls = next((r for r in rows if r["kind"] == kind and "communications" in r["roles"]), None)
    if calls is not None and calls["endpoint_id"] != row["endpoint_id"]:
        checks.append(_check("calls", "note", f"calls use {calls['name']}, other sound uses {row['name']}",
                             "Apps like Teams and Zoom can pick the calls device and seem silent.",
                             f"snd default {row['id']} calls"))
    return checks


def _why(words, options):
    scope = "playback"
    if words:
        scope = {"out": "playback", "playback": "playback", "speakers": "playback", "sound": "playback",
                 "in": "recording", "recording": "recording", "mic": "recording", "microphone": "recording"}.get(
            words[0].lower() if len(words) == 1 else "")
        if scope is None:
            raise SoundError("usage: snd why [out|in]", 2)
    rows = _devices()
    checks = [_service_check("Audiosrv", "the Windows Audio service"),
              _service_check("AudioEndpointBuilder", "the Windows Audio Endpoint Builder service")]
    checks += _device_checks(rows, scope)
    row = _default_row(scope, rows)
    if scope == "recording":
        checks += _microphone_privacy_checks()
    if row is not None and row["state"] == "active" and row["volume"] is not None and not row["muted"]:
        peak = _sample(_audio(), row)
        if peak:
            checks.append(_check("level", "ok", f"sound is moving through the {row['name']} meter ({peak}%)"))
        elif scope == "playback":
            checks.append(_check("level", "note", "nothing is playing through the default speakers right now",
                                 "If something should be: its own volume may be 0 (run vm ls), or it plays through another device.",
                                 "vm ls"))
        else:
            checks.append(_check("level", "note", "the microphone level reads 0%",
                                 "Windows only measures a microphone while a program uses it.", "snd level listen"))
    problems = sum(1 for c in checks if c["status"] == "problem")
    if options["json"]:
        _core.print_json({"scope": scope, "ok": problems == 0, "problems": problems, "checks": checks})
        return 0
    colors = {"ok": _net.GREEN, "problem": _net.RED, "note": _net.YELLOW}
    print("no sound? checking the usual causes for playback." if scope == "playback"
          else "microphone silent? checking the usual causes.")
    print()
    for item in checks:
        print(colors[item["status"]] + f"  {item['status']:<9}{item['title']}" + _net.RESET)
        if item["detail"]:
            print(colors[item["status"]] + f"            {item['detail']}" + _net.RESET)
        if item["fix"] and item["status"] != "ok":
            print(colors[item["status"]] + f"            fix: {item['fix']}" + _net.RESET)
    print()
    if problems:
        print(f"{problems} problem{'' if problems == 1 else 's'} found. Fix them in order, then run 'snd why"
              f"{' in' if scope == 'recording' else ''}' again.")
    else:
        print("nothing obviously wrong. If only one app is silent, its own volume may be 0: 'vm ls'. "
              "'snd test' plays a tone.")
    return 0


# ======================================================================
# SETTINGS WE ONLY READ, OR OPEN — where Windows has no way for a program to change them (fashion.txt, rule 13)
# ======================================================================
def _settings(uri, message):
    print(message)
    _win.open_settings(uri)
    return 0


def _mono(words, options):
    value = _net.reg_read(MONO_KEY, MONO_VALUE, None, hive=_win.HKCU)
    on = value == 1
    if words:
        if len(words) != 1 or words[0].lower() not in _net.ON_WORDS + _net.OFF_WORDS:
            raise SoundError("usage: snd mono [on|off]", 2)
        return _settings(SETTINGS_MONO, f"Mono audio is {'on' if on else 'off'}. Windows has no documented way for a "
                         f"program to change it, so choose Mono audio on the page that is opening: Settings > "
                         f"Accessibility > Audio.")
    if options["json"]:
        _core.print_json({"mono_audio": on, "read_from": f"HKCU\\{MONO_KEY}\\{MONO_VALUE}"})
        return 0
    print(f"Mono audio is {'on' if on else 'off'}"
          + ("." if value is not None else " (nothing is set, which Windows treats as off)."))
    print(f"Read from the value Settings keeps ({MONO_VALUE}). To change it: 'snd mono on' opens the page in Settings.")
    return 0


def _startup_state():
    value = _net.reg_read(STARTUP_KEY, STARTUP_VALUE, None)
    return {0: "on", 1: "off"}.get(value, "not set") if isinstance(value, int) else "not set"


def _startup(words, options):
    if len(words) > 1 or (words and words[0].lower() not in ("on", "off", "default", "enable", "disable")):
        raise SoundError("usage: snd startup [on|off|default]", 2)
    if not words:
        state = _startup_state()
        if options["json"]:
            _core.print_json({"startup_sound_policy": state})
            return 0
        meaning = {"on": "forced on by the policy 'Turn off Windows Startup sound' (set to disabled)",
                   "off": "forced off by the policy 'Turn off Windows Startup sound'",
                   "not set": "no policy: each person chooses in Settings > Personalization > Themes > Sounds"}[state]
        print(f"Windows startup sound: {meaning}.")
        print("'snd startup off' or 'snd startup on' sets the policy (administrator); 'snd startup default' removes it.")
        return 0
    word = {"enable": "on", "disable": "off"}.get(words[0].lower(), words[0].lower())
    _net.need_admin()
    _say(options, "this sets the Group Policy 'Turn off Windows Startup sound'. It takes effect at the next start, and "
                  "while it is set, the Sounds choice in Settings is locked." if word != "default"
                  else "removing the Group Policy value, so each person chooses again.")
    if word == "default":
        _win.reg_delete(_win.HKLM, STARTUP_KEY, STARTUP_VALUE)
    else:
        _win.reg_write(_win.HKLM, STARTUP_KEY, STARTUP_VALUE, 0 if word == "on" else 1)
    state = _startup_state()
    if options["json"]:
        _core.print_json({"startup_sound_policy": state})
    else:
        print(f"startup sound policy is now: {state}.")
    return 0


def _classic(words, options):
    if len(words) > 1 or (words and words[0].lower() not in CLASSIC_TABS):
        raise SoundError("usage: snd classic [playback|recording|sounds|communications]", 2)
    tab = CLASSIC_TABS[words[0].lower()] if words else 0
    print("opening the classic Sound dialog (Properties > Enhancements, Spatial sound and Advanced hold the formats).")
    try:
        subprocess.Popen(["control.exe", f"mmsys.cpl,,{tab}"])
    except OSError as e:
        raise SoundError(f"could not open the Sound dialog: {e}")
    return 0


def _enable_disable(word, words, options):
    if len(words) != 1:
        raise SoundError(f"usage: snd {word} <id>", 2)
    row = _find(words[0], _devices(levels=False))
    return _settings(SETTINGS_DEVICES,
                     f"Windows has no documented way for a program to turn {row['name']} {'on' if word == 'enable' else 'off'}. "
                     f"In the page that is opening (Settings > System > Sound > All sound devices), choose the device "
                     f"and use Allow or Don't allow. To turn the hardware itself off, 'dvc audio' then 'dvc <id> disable' "
                     "(administrator).")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "sound"/"snd"
# ======================================================================
def _dispatch(args, options):
    if not args:
        return _list([], options)
    word, rest = args[0].lower(), args[1:]
    if word in _net.LIST_WORDS:
        return _list(rest, options)
    if word == "default":
        return _default_cmd(rest, options)
    if word in ("out", "in"):
        return _default_device_cmd("playback" if word == "out" else "recording", rest, options)
    if word == "level":
        return _level(rest, options)
    if word == "test":
        return _test(rest, options)
    if word == "why":
        return _why(rest, options)
    if word == "mono":
        return _mono(rest, options)
    if word == "startup":
        return _startup(rest, options)
    if word == "classic":
        return _classic(rest, options)
    if word == "apps":
        return _settings(SETTINGS_MIXER, "Windows has no documented way for a program to choose which device an app plays "
                         "through, so choose it in the page that is opening (Settings > System > Sound > Volume mixer). "
                         "One app's volume is 'vm ls'.")
    if word in ("enable", "disable"):
        return _enable_disable(word, rest, options)
    if word == "open":
        return _settings(SETTINGS_SOUND, "opening Settings > System > Sound.")
    return _device_cmd(_find(args[0], _devices()), rest, options)


def run(args):
    """Run one sound command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if args and args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        return _dispatch(args, options)
    except (SoundError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

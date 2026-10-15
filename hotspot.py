"""
hotspot: share this PC's internet as a Wi-Fi hotspot, the same as Settings > Network & internet >
Mobile hotspot. Routed from app.py ("hotspot", "hs" or "mobilehotspot"), and from 'wifi hotspot'.

    hs on                  turn it on, then show the name, password and band to connect with
    hs on <id>             share connection <id> from 'hs from' instead of the usual one
    hs off                 turn it off
    hs status              name, password, band, security, what it shares, and who is connected
    hs name <name>         rename it
    hs password [<new>]    change the password (asks hidden, twice, when left out)
    hs band 2.4|5|6|any    pick the Wi-Fi band
    hs security wpa2|wpa3|wpa3-transition
    hs devices             the devices connected now
    hs from                the connections that can be shared, with ids
    hs sleep on|off        turn the hotspot off when nothing is connected (power saving)
    hs over wifi|bluetooth how other devices connect (opens Settings, see below)

The hotspot is driven through Windows' tethering API (WinRT), the one Settings uses, so it
needs no administrator rights. Passwords are shown, as Settings shows them.

Windows has no API for 'Share over' (Wi-Fi or Bluetooth), so 'hs over' opens the Mobile
hotspot page in Settings at the right place rather than guessing at hidden settings.
"""

import asyncio
import getpass
import os
import sys
import uuid

import _core
import _net

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "hotspot"
ALIASES = ["hs", "mobilehotspot"]
SUMMARY = "Share this PC's internet as a Wi-Fi hotspot"
USAGE = ("hs on|off | hs status | hs name <name> | hs password [<new>] | hs band 2.4|5|any | "
         "hs devices | hs from | hs on <id> | hs security <kind> | hs sleep on|off | hs over wifi|bluetooth")
HELP = [
    ("hs on", "turn the hotspot on, then show its name, password and band"),
    ("hs off", "turn it off"),
    ("hs status", "name, password, band, security and who is connected"),
    ("hs name <name>", 'rename it, e.g. hs name "Study Room"'),
    ("hs password [<new>]", "change the password (8-63 characters; asks hidden if left out)"),
    ("hs band 2.4 | 5 | any", "2.4 GHz reaches further, 5 GHz is faster, any lets Windows pick"),
    ("", "more"),
    ("hs devices", "the devices connected now"),
    ("hs from   then   hs on <id>", "see which connections can be shared, and share one of them"),
    ("hs security wpa2 | wpa3", "the security type, where this PC supports more than one"),
    ("hs sleep on | off", "turn the hotspot off by itself when nothing is connected"),
    ("hs over wifi | bluetooth", "how other devices connect (opens the setting in Settings)"),
]
TIP = ("Changes made while the hotspot is on apply the next time it starts. "
       "Agents: 'hs status --json' gives the name, password and band as data.")

SETTINGS_PAGE = "ms-settings:network-mobilehotspot"
ICSSVC_KEY = r"SYSTEM\CurrentControlSet\Services\icssvc\Settings"  # PreferredPublicInterface: the shared connection
INTERNET = 3  # NetworkConnectivityLevel.INTERNET_ACCESS

STATE_WORDS = {"ON": "on", "OFF": "off", "IN_TRANSITION": "turning on or off", "UNKNOWN": "unknown"}
BAND_WORDS = {"2.4": "TWO_POINT_FOUR_GIGAHERTZ", "2.4ghz": "TWO_POINT_FOUR_GIGAHERTZ", "5": "FIVE_GIGAHERTZ",
              "5ghz": "FIVE_GIGAHERTZ", "6": "SIX_GIGAHERTZ", "6ghz": "SIX_GIGAHERTZ", "any": "AUTO", "auto": "AUTO"}
BAND_NAMES = {"AUTO": "any available (Windows picks)", "TWO_POINT_FOUR_GIGAHERTZ": "2.4 GHz",
              "FIVE_GIGAHERTZ": "5 GHz", "SIX_GIGAHERTZ": "6 GHz"}
BAND_SHORT = {"AUTO": "any", "TWO_POINT_FOUR_GIGAHERTZ": "2.4", "FIVE_GIGAHERTZ": "5", "SIX_GIGAHERTZ": "6"}
SECURITY_WORDS = {"wpa2": "WPA2", "wpa3": "WPA3", "wpa3-transition": "WPA3_TRANSITION_MODE",
                  "transition": "WPA3_TRANSITION_MODE"}
SECURITY_NAMES = {"WPA2": "WPA2-Personal", "WPA3": "WPA3-Personal",
                  "WPA3_TRANSITION_MODE": "WPA2/WPA3-Personal (transition)"}
START_PROBLEMS = {
    "WI_FI_DEVICE_OFF": "Wi-Fi is turned off. Turn it on in quick settings, then try again.",
    "BLUETOOTH_DEVICE_OFF": "the hotspot is set to share over Bluetooth, and Bluetooth is off. Turn Bluetooth "
                            "on, or switch to Wi-Fi with 'hs over wifi'.",
    "OPERATION_IN_PROGRESS": "Windows is already turning the hotspot on or off. Wait a moment and try again.",
    "NETWORK_LIMITED_CONNECTIVITY": "the connection being shared has no internet right now.",
    "RADIO_RESTRICTION": "the Wi-Fi adapter can't host a hotspot right now (airplane mode or a radio limit).",
    "BAND_INTERFERENCE": "that band clashes with the Wi-Fi network you are on. Try 'hs band any'.",
    "ENTITLEMENT_CHECK_TIMEOUT": "your mobile operator did not answer the tethering check in time.",
    "ENTITLEMENT_CHECK_FAILURE": "your mobile operator does not allow tethering on this plan.",
    "MOBILE_BROADBAND_DEVICE_OFF": "the mobile broadband device is off.",
}
CAPABILITY_PROBLEMS = {
    "DISABLED_BY_GROUP_POLICY": "your organisation has turned off the mobile hotspot with a policy.",
    "DISABLED_BY_HARDWARE_LIMITATION": "this PC's Wi-Fi adapter can't host a hotspot.",
    "DISABLED_BY_OPERATOR": "the mobile operator has turned off tethering for this connection.",
    "DISABLED_BY_SKU": "this edition of Windows does not include the mobile hotspot.",
    "DISABLED_BY_REQUIRED_APP_NOT_INSTALLED": "the mobile operator's app must be installed first.",
    "DISABLED_BY_SYSTEM_CAPABILITY": "Windows has turned off the mobile hotspot on this PC.",
    "DISABLED_DUE_TO_UNKNOWN_CAUSE": "Windows can't share this connection, for a reason it does not give.",
}


class HotspotError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# WINDOWS — the tethering API, loaded only when a command needs it
# ======================================================================
_rt = None


def _winrt():
    global _rt
    if _rt is None:
        try:
            from winrt.windows.networking.connectivity import NetworkInformation
            from winrt.windows.networking.networkoperators import (
                NetworkOperatorTetheringManager,
                TetheringCapability,
                TetheringOperationalState,
                TetheringOperationStatus,
                TetheringWiFiAuthenticationKind,
                TetheringWiFiBand,
            )
        except ImportError:
            raise HotspotError("the hotspot needs the winrt packages. Run: py -m pip install -r requirements.txt")
        _rt = {
            "info": NetworkInformation, "manager": NetworkOperatorTetheringManager,
            "capability": TetheringCapability, "state": TetheringOperationalState,
            "status": TetheringOperationStatus, "security": TetheringWiFiAuthenticationKind, "band": TetheringWiFiBand,
        }
    return _rt


def _wait(make):
    """Run one WinRT async call to the end and return its result."""
    async def runner():
        return await make()
    try:
        return asyncio.run(runner())
    except OSError as e:
        raise HotspotError(f"Windows refused: {e}")


def _adapter_names():
    """{adapter GUID: name, such as Wi-Fi or Ethernet}."""
    return {adapter["guid"]: adapter["name"] for adapter in _net._read_adapters()}


def _profile_guid(profile):
    adapter = profile.network_adapter
    return "{" + str(adapter.network_adapter_id).upper() + "}" if adapter else None


def _connections():
    """The connections with internet that could be shared, by name, numbered from 1: the
    'Share my internet connection from' list. The list and the ids both come from here."""
    rt = _winrt()
    names = _adapter_names()
    found = []
    for profile in rt["info"].get_connection_profiles():
        guid = _profile_guid(profile)
        if guid is None or profile.get_network_connectivity_level() < INTERNET:
            continue
        capability = rt["capability"](rt["manager"].get_tethering_capability_from_connection_profile(profile)).name
        found.append({"name": names.get(guid, profile.profile_name), "network": profile.profile_name,
                      "guid": guid, "can_share": capability == "ENABLED", "capability": capability,
                      "_profile": profile})
    found.sort(key=lambda item: item["name"].lower())
    for number, item in enumerate(found, start=1):
        item["id"] = number
    return found


def _manager(profile=None):
    """The tethering manager for a connection: the one given, or the one Windows uses for internet."""
    rt = _winrt()
    if profile is None:
        profile = rt["info"].get_internet_connection_profile()
    if profile is None:
        profiles = [p for p in rt["info"].get_connection_profiles() if p.network_adapter]
        if not profiles:
            raise HotspotError("this PC has no network connection to share. Connect to Wi-Fi or Ethernet first.")
        profile = profiles[0]  # the settings can still be read and changed without internet
    try:
        return rt["manager"].create_from_connection_profile(profile), profile
    except OSError as e:
        raise HotspotError(f"Windows would not open the mobile hotspot: {e}")


def _shared_from():
    """The connection the hotspot shares, from the hotspot service's own setting."""
    raw = _net.reg_read(ICSSVC_KEY, "PreferredPublicInterface")
    if not isinstance(raw, bytes) or len(raw) != 16:
        return None
    guid = "{" + str(uuid.UUID(bytes_le=raw)).upper() + "}"
    return _adapter_names().get(guid)


def _has_bluetooth():
    """Whether this PC has Bluetooth networking, which the hotspot needs to share over Bluetooth."""
    return any("bluetooth" in (adapter["description"] or "").lower() for adapter in _net._read_adapters())


def _band_name(config):
    return _winrt()["band"](config.band).name


def _security_name(config):
    return _winrt()["security"](config.authentication_kind).name


# ======================================================================
# STATUS — one dict for people and agents, drawn as coloured sections
# ======================================================================
def _clients(manager):
    clients = []
    try:
        for client in manager.get_tethering_clients():
            names = [host.display_name for host in client.host_names]
            clients.append({"name": names[0] if names else "(no name)", "mac": client.mac_address})
    except OSError:
        pass  # Windows only lists clients while the hotspot is on
    return sorted(clients, key=lambda client: client["name"].lower())


def _status_data():
    rt = _winrt()
    manager, _ = _manager()
    config = manager.get_current_access_point_configuration()
    state = rt["state"](manager.tethering_operational_state).name
    on = state == "ON"
    band = _band_name(config)
    security = _security_name(config)
    return {
        "state": STATE_WORDS.get(state, state.lower()),
        "name": config.ssid,
        "password": config.passphrase,
        "band": BAND_NAMES.get(band, band),
        "band_setting": BAND_SHORT.get(band, band),
        "bands_supported": [BAND_SHORT[b.name] for b in rt["band"] if config.is_band_supported(b)],
        "security": SECURITY_NAMES.get(security, security),
        "security_supported": [w for w, kind in SECURITY_WORDS.items() if w != "transition"
                               and config.is_authentication_kind_supported(rt["security"][kind])],
        "sharing_from": _shared_from(),
        "devices_connected": manager.client_count if on else 0,
        "max_devices": manager.max_client_count,
        "devices": _clients(manager) if on else [],
        "turn_off_when_idle": rt["manager"].is_no_connections_timeout_enabled(),
        "share_over": None,  # Windows does not expose it; 'hs over' opens Settings
        "bluetooth_available": _has_bluetooth(),
    }


def _show_status(data, options):
    if options["json"]:
        _core.print_json(data)
        return
    _net.render(f"mobile hotspot: {data['state']}", [
        ("connect with", [
            ("name", data["name"]),
            ("password", data["password"]),
            ("band", data["band"]),
            ("security", data["security"]),
        ]),
        ("sharing", [
            ("sharing from", data["sharing_from"]),
            ("devices connected", f"{data['devices_connected']} of {data['max_devices']}"),
            ("share over", "shown in Settings only ('hs over' opens it)"
             + ("" if data["bluetooth_available"] else "; no Bluetooth, so Wi-Fi")),
        ]),
        ("power saving", [("turn off when idle", data["turn_off_when_idle"])]),
        ("change it with", [
            ("hs on | hs off", "turn it on or off"),
            ("hs name <name>", "rename it"),
            ("hs password", "change the password"),
            ("hs band " + " | ".join(data["bands_supported"]), "pick the band"),
        ]),
    ])


# ======================================================================
# ON / OFF
# ======================================================================
def _on(rest, options):
    rt = _winrt()
    profile = None
    if rest:
        if len(rest) != 1:
            raise HotspotError("usage: hs on | hs on <id>   (ids from 'hs from')", 2)
        choice = next((c for c in _connections() if str(c["id"]) == rest[0] or c["name"].lower() == rest[0].lower()), None)
        if choice is None:
            raise HotspotError(f"no connection {rest[0]}. Run 'hs from' to see them.", 2)
        profile = choice["_profile"]
    manager, profile = _manager(profile)
    capability = rt["capability"](rt["manager"].get_tethering_capability_from_connection_profile(profile)).name
    if capability != "ENABLED":
        raise HotspotError(CAPABILITY_PROBLEMS.get(capability, f"Windows can't share this connection ({capability})"))
    if profile.get_network_connectivity_level() < INTERNET:
        raise HotspotError("this connection has no internet to share. Connect to Wi-Fi or Ethernet first.")
    if rt["state"](manager.tethering_operational_state).name == "ON" and not rest:
        print("the mobile hotspot is already on")
        _show_status(_status_data(), options)
        return
    config = manager.get_current_access_point_configuration()
    if rt["state"](manager.tethering_operational_state).name == "ON":
        _wait(lambda: manager.stop_tethering_async())  # switching to another connection
    print(f"turning the mobile hotspot on... expect a network called {config.ssid} to appear within a few seconds.")
    result = _wait(lambda: manager.start_tethering_async())
    status = rt["status"](result.status).name
    if status not in ("SUCCESS", "ALREADY_ON"):
        extra = f" ({result.additional_error_message})" if result.additional_error_message else ""
        raise HotspotError(START_PROBLEMS.get(status, f"Windows could not start it: {status.lower()}") + extra)
    print("mobile hotspot on")
    _show_status(_status_data(), options)


def _off(options):
    rt = _winrt()
    manager, _ = _manager()
    if rt["state"](manager.tethering_operational_state).name == "OFF":
        print("the mobile hotspot is already off")
        return
    print(f"turning the mobile hotspot off... connected devices ({manager.client_count}) will lose the connection.")
    result = _wait(lambda: manager.stop_tethering_async())
    status = rt["status"](result.status).name
    if status != "SUCCESS":
        raise HotspotError(START_PROBLEMS.get(status, f"Windows could not stop it: {status.lower()}"))
    print("mobile hotspot off")
    if options["json"]:
        _core.print_json({"state": "off"})


# ======================================================================
# PROPERTIES — name, password, band and security, saved the way Settings' Edit button saves them
# ======================================================================
def _configure(change):
    """Apply one change to the hotspot's settings and return them read back from Windows."""
    rt = _winrt()
    manager, _ = _manager()
    config = manager.get_current_access_point_configuration()
    change(config)
    _wait(lambda: manager.configure_access_point_async(config))
    if rt["state"](manager.tethering_operational_state).name == "ON":
        print("note: the hotspot is on, so this applies the next time it starts. "
              "Run 'hs off' then 'hs on' to apply it now (connected devices will drop).")
    return manager.get_current_access_point_configuration()


def _name(rest, options):
    if len(rest) != 1:
        raise HotspotError('usage: hs name <name>   (use quotes for spaces, e.g. hs name "Study Room")', 2)
    new = rest[0]
    if not 1 <= len(new.encode("utf-8")) <= 32:
        raise HotspotError("a hotspot name is 1 to 32 characters", 2)

    def change(config):
        config.ssid = new
    saved = _configure(change)
    print(f"hotspot name: {saved.ssid}")
    if options["json"]:
        _core.print_json({"name": saved.ssid})


def _ask_password():
    try:
        first = getpass.getpass("new hotspot password (8-63 characters, blank to cancel): ")
        if not first:
            return ""
        second = getpass.getpass("type it again: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    if first != second:
        raise HotspotError("the two passwords did not match, so nothing changed")
    return first


def _password(rest, options):
    if len(rest) > 1:
        raise HotspotError("usage: hs password [<new password>]", 2)
    new = rest[0] if rest else _ask_password()
    if not new:
        print("cancelled")
        return
    if not 8 <= len(new) <= 63 or not new.isascii() or not new.isprintable():
        raise HotspotError("a hotspot password is 8 to 63 plain characters (letters, numbers and symbols)", 2)
    old = _manager()[0].get_current_access_point_configuration().passphrase

    def change(config):
        config.passphrase = new
    saved = _configure(change)
    if saved.passphrase != new:
        raise HotspotError("Windows did not keep the new password")
    if new == old:
        print("hotspot password unchanged (it was already that)")
    else:
        print("hotspot password changed. Devices that knew the old one will need the new one.")
    if options["json"]:
        _core.print_json({"password": saved.passphrase})


def _band(rest, options):
    rt = _winrt()
    if len(rest) != 1 or rest[0].lower() not in BAND_WORDS:
        raise HotspotError("usage: hs band 2.4 | 5 | 6 | any", 2)
    band = rt["band"][BAND_WORDS[rest[0].lower()]]
    manager, _ = _manager()
    if not manager.get_current_access_point_configuration().is_band_supported(band):
        raise HotspotError(f"this PC's Wi-Fi can't host a hotspot on {BAND_NAMES[band.name]}. "
                           "Run 'hs status' for the bands it can use.")

    def change(config):
        config.band = band
    saved = _configure(change)
    print(f"hotspot band: {BAND_NAMES.get(_band_name(saved))}")
    if options["json"]:
        _core.print_json({"band": BAND_SHORT.get(_band_name(saved))})


def _security(rest, options):
    rt = _winrt()
    if len(rest) != 1 or rest[0].lower() not in SECURITY_WORDS:
        raise HotspotError("usage: hs security wpa2 | wpa3 | wpa3-transition", 2)
    kind = rt["security"][SECURITY_WORDS[rest[0].lower()]]
    manager, _ = _manager()
    if not manager.get_current_access_point_configuration().is_authentication_kind_supported(kind):
        raise HotspotError(f"this PC's Wi-Fi can't host a {SECURITY_NAMES[kind.name]} hotspot. "
                           "Run 'hs status' to see what it supports.")

    def change(config):
        config.authentication_kind = kind
    saved = _configure(change)
    print(f"hotspot security: {SECURITY_NAMES.get(_security_name(saved))}")


# ======================================================================
# THE REST — devices, the shared connection, power saving and 'share over'
# ======================================================================
def _devices(options):
    data = _status_data()
    if options["json"]:
        _core.print_json({"state": data["state"], "devices": data["devices"]})
        return
    if data["state"] != "on":
        print("the mobile hotspot is off, so nothing is connected. Turn it on with 'hs on'.")
        return
    if not data["devices"]:
        print(f"no devices connected yet. They join {data['name']} with the password {data['password']}.")
        return
    os.system("")  # enables ANSI colour codes in the Windows console
    lines = [f"  {'DEVICE':<34}PHYSICAL ADDRESS"]
    for number, device in enumerate(data["devices"]):
        color = _net.SECTION_COLORS[number % len(_net.SECTION_COLORS)]
        lines.append(color + f"  {device['name'][:32]:<34}{device['mac']}" + _net.RESET)
    print("\n".join(lines))


def _from(options):
    connections = _connections()
    shared = _shared_from()
    if options["json"]:
        _core.print_json([dict(_net.public(c), shared=c["name"] == shared) for c in connections])
        return
    if not connections:
        print("no connection has internet right now, so there is nothing to share")
        return
    os.system("")  # enables ANSI colour codes in the Windows console
    lines = [f"  {'ID':<4}{'CONNECTION':<24}{'NETWORK':<24}SHARE IT?"]
    for item in connections:
        can = "yes" + (" (shared now)" if item["name"] == shared else "") if item["can_share"] else "no"
        color = _net.GREEN if item["name"] == shared else _core.BLUE
        lines.append(color + f"  {item['id']:<4}{item['name'][:22]:<24}{item['network'][:22]:<24}{can}" + _net.RESET)
    lines += ["", "Share one with 'hs on <id>'."]
    print("\n".join(lines))


def _sleep(rest, options):
    rt = _winrt()
    manager_class = rt["manager"]
    if not rest:
        print(f"turn off when no devices are connected: {'on' if manager_class.is_no_connections_timeout_enabled() else 'off'}")
        return
    if len(rest) != 1:
        raise HotspotError("usage: hs sleep on | hs sleep off", 2)
    on = rest[0].lower() in _net.ON_WORDS
    if not on and rest[0].lower() not in _net.OFF_WORDS:
        raise HotspotError("use on or off, e.g. hs sleep off", 2)
    try:
        if on:
            manager_class.enable_no_connections_timeout()
        else:
            manager_class.disable_no_connections_timeout()
    except OSError as e:
        raise HotspotError(f"Windows would not change it: {e}")
    now = manager_class.is_no_connections_timeout_enabled()
    print(f"turn off when no devices are connected: {'on' if now else 'off'}")
    if options["json"]:
        _core.print_json({"turn_off_when_idle": now})


def _over(rest, options):
    bluetooth = _has_bluetooth()
    if not rest:
        print("Windows keeps 'Share over' (Wi-Fi or Bluetooth) to itself, so programs can't read or change it.\n"
              "Choose it in Settings with 'hs over wifi' or 'hs over bluetooth', which opens the right page."
              + ("" if bluetooth else "\nThis PC has no Bluetooth, so the hotspot shares over Wi-Fi."))
        return
    word = rest[0].lower()
    if len(rest) != 1 or word not in ("wifi", "wi-fi", "bluetooth", "bt"):
        raise HotspotError("usage: hs over wifi | hs over bluetooth", 2)
    medium = "Wi-Fi" if word in ("wifi", "wi-fi") else "Bluetooth"
    if medium == "Bluetooth" and not bluetooth:
        raise HotspotError("this PC has no Bluetooth, so the hotspot can only share over Wi-Fi")
    print(f"opening Settings > Mobile hotspot. Under 'Share over', choose {medium}."
          + (" Devices must be paired with this PC first." if medium == "Bluetooth" else ""))
    try:
        os.startfile(SETTINGS_PAGE)
    except OSError as e:
        raise HotspotError(f"could not open Settings: {e}")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "hotspot"/"hs"
# ======================================================================
def _dispatch(args, options):
    word = args[0].lower()
    rest = args[1:]
    if word in _net.ON_WORDS:
        _on(rest, options)
    elif word in _net.OFF_WORDS and not rest:
        _off(options)
    elif word in ("status", "info", "show") and not rest:
        _show_status(_status_data(), options)
    elif word in ("name", "ssid", "rename"):
        _name(rest, options)
    elif word in ("password", "pass", "key"):
        _password(rest, options)
    elif word == "band":
        _band(rest, options)
    elif word == "security":
        _security(rest, options)
    elif word in ("devices", "clients") and not rest:
        _devices(options)
    elif word == "from" and not rest:
        _from(options)
    elif word in ("sleep", "timeout", "powersaving"):
        _sleep(rest, options)
    elif word in ("over", "share"):
        _over(rest, options)
    else:
        raise HotspotError(f"unknown hotspot command: {args[0]}\nusage: {USAGE}", 2)


def run(args):
    """Run one hotspot command; returns an exit code."""
    args, options = _core.split_flags(args)
    if not args:
        if options["json"]:
            args = ["status"]
        else:
            print(_core.page_help(_core.registry()[NAME]))
            return 0
    if args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        _dispatch(args, options)
        return 0
    except (HotspotError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

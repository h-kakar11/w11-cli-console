"""
wifi: connect to Wi-Fi, and every Wi-Fi setting, on Windows 11. Routed from app.py
("wifi", "internet" or "wf").

    wifi ls            list Wi-Fi networks in range, with ids
    wifi status        show the network you are connected to
    wifi info          everything about the connection, like ipconfig but readable
    wifi on            join the strongest saved network in range
    wifi off           disconnect from Wi-Fi
    wifi <id>          show one network
    wifi <id> on       join it (asks for the password if it is new)
    wifi <id> off      disconnect, if you are connected to it
    wifi rm <id>       forget a saved network in range (asks you to confirm first)

    wifi known                         saved networks, in range or not, with ids
    wifi known <id>                    one saved network's settings
    wifi known rm <id>                 forget it (asks first)
    wifi known <id> auto on|off        connect automatically when in range
    wifi known <id> metered on|off     metered connection
    wifi known <id> random on|off|daily   random hardware address for that network

    wifi metered on|off                metered connection, for the network you are on
    wifi random on|off                 random hardware addresses, for every network
    wifi auth [...]                    802.1X sign-in, for work and school networks
    wifi ip | dns | share | features   shared with ethernet (see _net.py)
    wifi hotspot ...                   the mobile hotspot page (same as 'hs')

Ids are numbered by name, so they can shift when networks come and go.
Run 'wifi ls' first.

Wi-Fi is read and changed with netsh, the command-line tool that ships with
Windows. Windows only shows network names to apps when Location is on, so
if a command says so, turn Location on and try again.
"""

import getpass
import os
import re
import subprocess
import sys
import tempfile
import time
from xml.sax.saxutils import escape

import _core
import _net

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "wifi"
ALIASES = ["internet", "wf"]
SUMMARY = "Connect to Wi-Fi, and every Wi-Fi setting"
USAGE = ("wifi ls | wifi status | wifi info | wifi on|off | wifi <id> [on|off] | wifi rm <id> | "
         "wifi known [...] | wifi metered on|off | wifi random on|off | wifi auth | wifi ip | wifi dns | "
         "wifi share | wifi features | wifi hotspot   (e.g. wifi 3 on)")
HELP = [
    ("wifi on", "join the strongest saved network in range"),
    ("wifi ls", "list Wi-Fi networks in range, with ids and signal"),
    ("wifi <id> on", "join a network (asks for the password if it is new)"),
    ("wifi off", "disconnect from Wi-Fi"),
    ("wifi info", "everything about your connection, like ipconfig but readable"),
    ("", "known networks"),
    ("wifi known", "every saved network, with ids"),
    ("wifi known rm <id>", "forget one (asks you to confirm first)"),
    ("wifi known <id> auto on | off", "connect to it automatically when it is in range"),
    ("", "settings"),
    ("wifi ip auto | manual <ip>/<prefix>", "how this PC gets its address (auto is DHCP)"),
    ("wifi dns auto | <server> ...", "which DNS servers it uses, e.g. wifi dns 1.1.1.1 8.8.8.8"),
    ("wifi metered on | off", "metered connection, for the network you are on"),
    ("wifi random on | off", "random hardware addresses, for privacy"),
    ("wifi auth", "802.1X sign-in, for work and school networks"),
    ("wifi share", "let devices on another connection use this one"),
    ("wifi features", "IPv4, IPv6, File and Printer Sharing and more: on, off, install, remove"),
    ("wifi hotspot", "share this PC's internet as a hotspot (same as 'hs')"),
]
TIP = ("Run 'wifi ls' first, since ids follow the list; Windows needs Location on to show network names. "
       "Agents: add --json for data, and --yes to confirm a change the person has agreed to.")
REMOVE_WORDS = ("rm", "remove", "delete", "uninstall", "del")
PREFIX = "wifi"

CONNECT_WAIT = 20  # seconds to wait for a new connection to come up
LOCATION_HINT = (
    "Windows needs Location turned on to show Wi-Fi network names. Turn it on at "
    "Settings > Privacy & security > Location, and click 'let apps have access to your location', then try again. if that doesnt work, use 'lc/location' settings by typing 'lc' or 'location'"
)
GREEN = "\033[32m"  # connected
BLUE = "\033[34m"  # saved, not connected
RESET = "\033[0m"

# netsh's security name -> (XML authentication, XML encryption, needs a password)
SECURITY = {
    "open": ("open", "none", False),
    "wpa2-personal": ("WPA2PSK", "AES", True),
    "wpa3-personal": ("WPA3SAE", "AES", True),
    "wpa-personal": ("WPAPSK", "TKIP", True),
}
ENTERPRISE = ("WPA", "WPA2", "WPA3ENT", "WPA3ENT192")  # profile authentications that sign in with 802.1X
RANDOM_WORDS = {"on": "yes", "enable": "yes", "yes": "yes", "off": "no", "disable": "no", "no": "no",
                "daily": "daily"}

PROFILE_XML = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{name}</name>
    <SSIDConfig>
        <SSID>
            <name>{name}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{authentication}</authentication>
                <encryption>{encryption}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>{shared_key}
        </security>
    </MSM>
</WLANProfile>
"""

SHARED_KEY_XML = """
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>"""


class WifiError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# NETSH — every read and change goes through these two helpers
# ======================================================================
def _netsh(*args):
    """Run 'netsh wlan' with these arguments; returns (succeeded, output)."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", *args], capture_output=True, text=True, encoding="oem", errors="replace"
        )
    except OSError as e:
        raise WifiError(f"could not run netsh: {e}")
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def _explain(text):
    """A short reason from netsh's output, with the fix when we know it."""
    lowered = text.lower()
    if "location permission" in lowered:
        return LOCATION_HINT
    if "elevation" in lowered:
        return "Windows wants administrator rights for this. Run the terminal as administrator."
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[0] if lines else "netsh failed with no message"


def _netsh_ok(*args):
    """Run netsh and return its output, or raise a WifiError if it failed."""
    ok, text = _netsh(*args)
    if not ok:
        raise WifiError(_explain(text))
    return text


def _fields(text):
    """'key : value' lines as (key, value) pairs, with the spaces stripped."""
    pairs = []
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            pairs.append((key.strip(), value.strip()))
    return pairs


def _first_fields(text):
    """'key : value' lines as a dict, keeping the first value when a key repeats."""
    values = {}
    for key, value in _fields(text):
        values.setdefault(key, value)
    return values


def _percent(value):
    match = re.match(r"\s*(\d+)\s*%", value or "")
    return int(match.group(1)) if match else 0


# ======================================================================
# SOURCES — the networks in range and the ones saved on this computer
# ======================================================================
def _interface():
    """What 'netsh wlan show interfaces' says about the Wi-Fi adapter, as a dict."""
    return dict(_fields(_netsh_ok("show", "interfaces")))


def _current():
    """(SSID, signal) of the network the adapter is joined to, or (None, None)."""
    values = _interface()
    if values.get("State", "").lower() != "connected":
        return None, None
    return values.get("SSID") or None, _percent(values.get("Signal"))


def _current_profile():
    """The saved profile behind the current connection, or None when not connected."""
    values = _interface()
    if values.get("State", "").lower() != "connected":
        return None
    return values.get("Profile") or values.get("SSID") or None


def _saved_names():
    """Names of the Wi-Fi profiles saved on this computer."""
    names = set()
    for key, value in _fields(_netsh_ok("show", "profiles")):
        if "user profile" in key.lower():
            names.add(value)
    return names


def _visible():
    """{SSID: {ssid, signal, auth}} for every named network in range, strongest signal kept."""
    networks = {}
    name = None
    for key, value in _fields(_netsh_ok("show", "networks", "mode=bssid")):
        if re.fullmatch(r"SSID \d+", key):
            name = value or None  # hidden networks have no name, so they are skipped
            if name and name not in networks:
                networks[name] = {"ssid": name, "signal": 0, "auth": "unknown"}
        elif name is None:
            continue
        elif key == "Authentication":
            networks[name]["auth"] = value
        elif key == "Signal":
            networks[name]["signal"] = max(networks[name]["signal"], _percent(value))
    return networks


def _networks():
    """Every network in range with its id, sorted by name and numbered from 1."""
    visible = _visible()
    saved = _saved_names()
    connected, _ = _current()
    found = sorted(visible.values(), key=lambda n: n["ssid"].lower())
    for index, net in enumerate(found, start=1):
        net["id"] = index
        net["saved"] = net["ssid"] in saved
        net["connected"] = net["ssid"] == connected
    return found


def _get_network(network_id):
    for net in _networks():
        if net["id"] == network_id:
            return net
    raise WifiError(f"no Wi-Fi network with id {network_id}. Run 'wifi ls' to see them.", 2)


def _parse_id(word, listing="wifi ls"):
    try:
        return int(word)
    except ValueError:
        raise WifiError(f"expected an id from '{listing}', got: {word}", 2)


def _adapter():
    found = _net.adapters("wifi")
    if not found:
        raise WifiError("this PC has no Wi-Fi adapter, or it is turned off in Device Manager")
    return found[0]


# ======================================================================
# JOIN / LEAVE — a new network gets a saved profile, then netsh connects to it
# ======================================================================
def _security(auth):
    try:
        return SECURITY[auth.lower()]
    except KeyError:
        raise WifiError(f"this network uses {auth}, which this page can't join. Connect to it in Windows Settings.")


def _ask_password(ssid):
    """The password for a new network, or '' if the user gave none."""
    try:
        password = getpass.getpass(f"password for {ssid} (blank to cancel): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    if password and not 8 <= len(password) <= 63:
        raise WifiError("Wi-Fi passwords are 8 to 63 characters")
    return password


def _add_profile(net, password):
    """Save a profile for a new network, so Windows can join it and remember the password."""
    authentication, encryption, needs_key = _security(net["auth"])
    shared_key = SHARED_KEY_XML.format(password=escape(password)) if needs_key else ""
    xml = PROFILE_XML.format(
        name=escape(net["ssid"]), authentication=authentication, encryption=encryption, shared_key=shared_key
    )
    fd, path = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(xml)
        _netsh_ok("add", "profile", f"filename={path}", "user=current")
    finally:
        os.remove(path)  # the file holds the password in plain text, so it goes at once


def _wait_for(ssid):
    deadline = time.monotonic() + CONNECT_WAIT
    while True:
        connected, _ = _current()
        if connected == ssid:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def _join(net):
    """Join a network in range. Returns False if the user cancelled the password prompt."""
    if net["connected"]:
        print(f"already connected to {net['ssid']}")
        return True
    if not net["saved"]:
        needs_key = _security(net["auth"])[2]  # rejects unsupported networks before asking for a password
        password = ""
        if needs_key:
            password = _ask_password(net["ssid"])
            if not password:
                print("cancelled")
                return False
        _add_profile(net, password)
    print(f"connecting to {net['ssid']}... expect the Wi-Fi icon to change within {CONNECT_WAIT} seconds.")
    _netsh_ok("connect", f"name={net['ssid']}")
    if not _wait_for(net["ssid"]):
        raise WifiError(
            f"not connected to {net['ssid']} after {CONNECT_WAIT} seconds. Check the password, "
            f"or forget the saved network with 'wifi rm {net['id']}'."
        )
    print(f"connected to {net['ssid']}")
    return True


def _join_best(options):
    """Join the strongest saved network in range."""
    networks = _networks()
    if any(net["connected"] for net in networks):
        _status(options)
        return
    saved = [net for net in networks if net["saved"]]
    if not saved:
        raise WifiError("no saved network is in range. Run 'wifi ls', then join one with 'wifi <id> on'.")
    _join(max(saved, key=lambda net: net["signal"]))


def _disconnect(net=None):
    ssid, _ = _current()
    if net is not None and not net["connected"]:
        print(f"not connected to {net['ssid']}")
        return
    if ssid is None:
        print("not connected to Wi-Fi")
        return
    _netsh_ok("disconnect")
    print(f"disconnected from {ssid}")


# ======================================================================
# FORGET — deletes the saved profile, so the password is lost
# ======================================================================
def _forget_profile(name, connected, options):
    drop = " You are connected to it, so the connection will drop." if connected else ""
    if not _core.confirm(
        f"Forget the saved Wi-Fi network {name}?{drop} You will need its password to join "
        "again. This can't be undone. [y/N]: ", options["yes"]
    ):
        print("cancelled")
        return
    print(f"forgetting {name}... expect it to vanish from 'wifi known' at once.")
    _netsh_ok("delete", "profile", f"name={name}")
    print(f"forgot {name}")


def _forget(args, options):
    if len(args) != 2:
        raise WifiError("usage: wifi rm <id>   (or 'wifi known rm <id>' for networks out of range)", 2)
    net = _get_network(_parse_id(args[1]))
    if not net["saved"]:
        raise WifiError(f"{net['ssid']} has no saved password to forget")
    _forget_profile(net["ssid"], net["connected"], options)


# ======================================================================
# KNOWN NETWORKS — every saved profile, in range or not ("Manage known networks")
# ======================================================================
def _known():
    """Every saved Wi-Fi network, by name, numbered from 1. The list and the ids both come from here."""
    current = _current_profile()
    try:
        in_range = set(_visible())
    except WifiError:
        in_range = None  # Location is off, so Windows won't say which are in range
    found = []
    for number, name in enumerate(sorted(_saved_names(), key=str.lower), start=1):
        found.append({"id": number, "name": name, "connected": name == current,
                      "in_range": None if in_range is None else name in in_range})
    return found


def _get_known(word):
    known_id = _parse_id(word, "wifi known")
    for item in _known():
        if item["id"] == known_id:
            return item
    raise WifiError(f"no saved network with id {known_id}. Run 'wifi known' to see them.", 2)


def _profile_details(name):
    """One saved network's settings, from 'netsh wlan show profile'."""
    text = _netsh_ok("show", "profile", f"name={name}")
    values = _first_fields(text)
    security = []
    for key, value in _fields(text):
        if key == "Authentication" and value not in security:
            security.append(value)  # a profile can allow several, e.g. WPA3 and WPA2
    cost = values.get("Cost", "Unrestricted")
    return {
        "name": name,
        "connect_automatically": values.get("Connection mode", "").lower().startswith("connect automatically"),
        "security": " or ".join(security) or None,
        "password_saved": values.get("Security key", "").lower() == "present",
        "metered": cost.lower() in ("fixed", "variable"),
        "cost": cost,
        "random_hardware_address": values.get("MAC Randomization", "Disabled").lower(),
    }


def _show_known(options):
    known = _known()
    if options["json"]:
        _core.print_json(known)
        return
    if not known:
        print("(no saved Wi-Fi networks)")
        return
    os.system("")  # enables ANSI colour codes in the Windows console
    print(f"{'ID':<4}{'NETWORK':<34}STATE")
    for item in known:
        if item["connected"]:
            state, color = "connected", GREEN
        elif item["in_range"]:
            state, color = "in range", BLUE
        else:
            state, color = ("" if item["in_range"] is None else "not in range"), ""
        print(color + f"{item['id']:<4}{item['name'][:32]:<34}{state}" + (RESET if color else ""))
    print(f"\n'wifi known <id>' shows one; 'wifi known rm <id>' forgets it.")


def _show_profile(item, options):
    details = _profile_details(item["name"])
    details["connected"] = item["connected"]
    if options["json"]:
        _core.print_json(details)
        return
    _net.render(f"{item['name']}: saved network {item['id']}", [
        ("settings", [
            ("connected now", "yes" if details["connected"] else "no"),
            ("connect automatically", details["connect_automatically"]),
            ("security", details["security"]),
            ("password saved", "yes" if details["password_saved"] else "no"),
            ("metered connection", details["metered"]),
            ("random hardware address", details["random_hardware_address"]),
        ]),
        ("change it with", [
            (f"wifi known {item['id']} auto on | off", "connect automatically when in range"),
            (f"wifi known {item['id']} metered on | off", "limit background data on this network"),
            (f"wifi known {item['id']} random on | off | daily", "a different hardware address for this network"),
            (f"wifi known rm {item['id']}", "forget it"),
        ]),
    ])


def _set_profile(name, setting, value):
    _netsh_ok("set", "profileparameter", f"name={name}", f"{setting}={value}")


def _known_command(rest, options):
    if not rest or rest[0].lower() in ("ls", "list"):
        _show_known(options)
        return
    if rest[0].lower() in REMOVE_WORDS:
        if len(rest) != 2:
            raise WifiError("usage: wifi known rm <id>", 2)
        item = _get_known(rest[1])
        _forget_profile(item["name"], item["connected"], options)
        return
    item = _get_known(rest[0])
    if len(rest) == 1:
        _show_profile(item, options)
        return
    if len(rest) != 3:
        raise WifiError("usage: wifi known <id> auto|metered on|off  or  wifi known <id> random on|off|daily", 2)
    setting, word = rest[1].lower(), rest[2].lower()
    name = item["name"]
    if setting in ("auto", "autoconnect"):
        on = _net.on_off(word, f"wifi known {item['id']} auto on")
        _set_profile(name, "connectionmode", "auto" if on else "manual")
    elif setting == "metered":
        on = _net.on_off(word, f"wifi known {item['id']} metered on")
        _set_profile(name, "cost", "fixed" if on else "unrestricted")
    elif setting in ("random", "randomization"):
        if word not in RANDOM_WORDS:
            raise WifiError(f"use on, off or daily, e.g. wifi known {item['id']} random daily", 2)
        _set_profile(name, "randomization", RANDOM_WORDS[word])
    else:
        raise WifiError("use auto, metered or random, e.g. wifi known 1 metered on", 2)
    _show_profile(item, options)


# ======================================================================
# THIS CONNECTION'S SETTINGS — metered, random hardware addresses, 802.1X
# ======================================================================
def _need_profile():
    name = _current_profile()
    if name is None:
        raise WifiError("not connected to Wi-Fi. Join a network first, or use 'wifi known <id> ...' for a saved one.")
    return name


def _metered_command(rest, options):
    name = _need_profile()
    if rest:
        if len(rest) != 1:
            raise WifiError("usage: wifi metered on | wifi metered off", 2)
        on = _net.on_off(rest[0], "wifi metered on")
        _set_profile(name, "cost", "fixed" if on else "unrestricted")
    metered = _profile_details(name)["metered"]
    if options["json"]:
        _core.print_json({"network": name, "metered": metered})
        return
    print(f"metered connection for {name}: {'on' if metered else 'off'}")
    if metered and rest:
        print("Windows now holds back updates and background data on this network.")


def _random_state(adapter):
    """Whether Windows gives this adapter a random hardware address on every network (the global switch)."""
    text = _netsh_ok("show", "randomization")
    for line in text.splitlines():
        if f"interface {adapter['name']}".lower() in line.lower():
            return "enabled" in line.lower()
    return None  # this adapter does not support it


def _random_command(rest, options):
    adapter = _adapter()
    if rest:
        if len(rest) != 1:
            raise WifiError("usage: wifi random on | wifi random off", 2)
        on = _net.on_off(rest[0], "wifi random on")
        if _random_state(adapter) != on:
            print(f"turning random hardware addresses {'on' if on else 'off'}... "
                  "expect a short drop, as Wi-Fi reconnects with the new address.")
            _netsh_ok("set", "randomization", f"enabled={'yes' if on else 'no'}", f"interface={adapter['name']}")
    state = _random_state(adapter)
    if options["json"]:
        _core.print_json({"adapter": adapter["name"], "random_hardware_addresses": state})
        return
    if state is None:
        print(f"{adapter['name']} does not support random hardware addresses")
        return
    print(f"random hardware addresses: {'on' if state else 'off'}")
    if not rest:
        print("Change it with 'wifi random on|off', or per network with 'wifi known <id> random on|off|daily'.")


def _profile_xml(name):
    return _net.export_xml(lambda folder: ["netsh", "wlan", "export", "profile", f"name={name}", f"folder={folder}"])


def _auth_state(name):
    xml = _profile_xml(name)
    if xml is None:
        raise WifiError(f"Windows would not export the profile for {name}")
    state = _net.onex_summary(xml)
    state["network"] = name
    if not state["enabled"] or state["authentication"] not in ENTERPRISE:
        state["enabled"] = False
        security = _profile_details(name)["security"] or "no password"
        state["note"] = (f"{name} signs in with a password ({security}), so 802.1X does not apply. "
                         "It is for work and school networks that sign in with an account or certificate.")
    return state, xml


def _auth_command(rest, options):
    name = _need_profile()
    state, xml = _auth_state(name)
    if rest:
        if not state["enabled"]:
            raise WifiError(state["note"])
        if len(rest) != 2:
            raise WifiError("usage: wifi auth method|mode|remember|sso <value>", 2)
        setting, word = rest[0].lower(), rest[1]
        if setting == "method":
            method = _net.method_word(word, PREFIX)
            print(f"changing how {name} signs in... expect Windows to ask for your sign-in details on the next connect.")
            new = _net.with_method(xml, method)
            _net.add_xml(new, lambda path: ["netsh", "wlan", "add", "profile", f"filename={path}"])
        elif setting == "mode":
            _set_profile(name, "authMode", _net.mode_word(word, PREFIX))
        elif setting == "remember":
            _set_profile(name, "cacheUserData", "yes" if _net.on_off(word, "wifi auth remember off") else "no")
        elif setting == "sso":
            _set_profile(name, "ssoMode", _net.sso_word(word, PREFIX))
        else:
            raise WifiError("use method, mode, remember or sso, e.g. wifi auth mode user", 2)
        state, _ = _auth_state(name)
    if options["json"]:
        _core.print_json(state)
        return
    sections = [("802.1X for " + name, _net.auth_rows(state))]
    if state["enabled"]:
        sections.append(("change it with", [
            ("wifi auth method peap | certificate | ttls", "how you prove who you are"),
            ("wifi auth mode user | computer | both | guest", "whose credentials are used"),
            ("wifi auth remember on | off", "remember my credentials"),
            ("wifi auth sso before | after | off", "sign in to Wi-Fi before or after Windows sign-in"),
        ]))
    _net.render(f"{name}: 802.1X sign-in", sections)


# ======================================================================
# DETAILS — 'wifi info': the radio, then the same address details as ethernet
# ======================================================================
def _info_data():
    adapter = _adapter()
    values = _interface()
    connected = values.get("State", "").lower() == "connected"
    data = {"wireless": {
        "state": values.get("State"),
        "network": values.get("SSID") if connected else None,
        "profile": values.get("Profile") if connected else None,
        "band": values.get("Band") if connected else None,
        "channel": values.get("Channel") if connected else None,
        "radio_type": values.get("Radio type") if connected else None,
        "security": values.get("Authentication") if connected else None,
        "cipher": values.get("Cipher") if connected else None,
        "signal": values.get("Signal") if connected else None,
        "rssi_dbm": values.get("Rssi") if connected else None,
        "receive_mbps": values.get("Receive rate (Mbps)") if connected else None,
        "transmit_mbps": values.get("Transmit rate (Mbps)") if connected else None,
        "access_point": values.get("AP BSSID") if connected else None,
        "random_hardware_addresses": _random_state(adapter),
        "metered": _profile_details(values["Profile"])["metered"] if connected and values.get("Profile") else None,
    }}
    data.update(_net.info_data(adapter))
    return data


def _info(options):
    data = _info_data()
    if options["json"]:
        _core.print_json(data)
        return
    radio = data["wireless"]
    band = f"{radio['band']}, channel {radio['channel']}" if radio["band"] else None
    signal = f"{radio['signal']} ({radio['rssi_dbm']} dBm)" if radio["signal"] else None
    rates = f"{radio['receive_mbps']} down / {radio['transmit_mbps']} up (Mbps)" if radio["receive_mbps"] else None
    wireless = [
        ("network", radio["network"]),
        ("signal", signal),
        ("band", band),
        ("Wi-Fi standard", radio["radio_type"]),
        ("security", f"{radio['security']} ({radio['cipher']})" if radio["security"] else None),
        ("link speed", rates),
        ("access point", radio["access_point"]),
    ]
    switches = [
        ("metered connection", radio["metered"]),
        ("random hardware addresses", radio["random_hardware_addresses"]),
    ]
    sections = [("wi-fi", wireless)] + _net.info_sections(data) + [("wi-fi settings", switches)]
    state = "connected to " + radio["network"] if radio["network"] else "not connected"
    _net.render(f"Wi-Fi: {state}", sections)


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "wifi"
# ======================================================================
def _describe(net):
    state = "connected" if net["connected"] else "not connected"
    saved = "saved" if net["saved"] else "not saved"
    return f"{state}, signal {net['signal']}%, {net['auth']}, {saved}"


def _list(options):
    networks = _networks()
    if options["json"]:
        _core.print_json(networks)
        return
    os.system("")  # enables ANSI colour codes in the Windows console
    if not networks:
        print("(no Wi-Fi networks in range)")
        return
    print(f"{'ID':<4}{'NETWORK':<34}{'SIGNAL':<8}{'SECURITY':<18}STATE")
    for net in networks:
        state = "connected" if net["connected"] else ("saved" if net["saved"] else "")
        row = f"{net['id']:<4}{net['ssid'][:32]:<34}{str(net['signal']) + '%':<8}{net['auth'][:16]:<18}{state}"
        if net["connected"]:
            print(GREEN + row + RESET)
        elif net["saved"]:
            print(BLUE + row + RESET)
        else:
            print(row)


def _status(options):
    ssid, signal = _current()
    if options["json"]:
        _core.print_json({"connected": ssid is not None, "network": ssid, "signal": signal})
        return
    if ssid is None:
        print("not connected to Wi-Fi")
        return
    print(f"connected to {ssid}: {signal}%")


def _dispatch(args, options):
    word = args[0].lower()
    rest = args[1:]
    if word in ("ls", "list"):
        if rest:
            raise WifiError("usage: wifi ls", 2)
        _list(options)
        return
    if word == "status":
        if rest:
            raise WifiError("usage: wifi status", 2)
        _status(options)
        return
    if word in ("info", "details", "ipconfig"):
        if rest:
            raise WifiError("usage: wifi info", 2)
        _info(options)
        return
    if word in ("on", "enable") and not rest:
        _join_best(options)
        return
    if word in ("off", "disable") and not rest:
        _disconnect()
        return
    if word in REMOVE_WORDS:
        _forget(args, options)
        return
    if word in ("known", "saved"):
        _known_command(rest, options)
        return
    if word == "metered":
        _metered_command(rest, options)
        return
    if word in ("random", "randomization"):
        _random_command(rest, options)
        return
    if word in ("auth", "8021x", "802.1x"):
        _auth_command(rest, options)
        return
    if word in _net.ADAPTER_WORDS:
        _net.adapter_command(word, rest, _adapter(), options, PREFIX)
        return

    net = _get_network(_parse_id(args[0]))

    if len(args) == 1:
        if options["json"]:
            _core.print_json(net)
        else:
            print(f"{net['ssid']}: {_describe(net)}")
        return

    action = args[1].lower()
    if action in ("on", "enable"):
        _join(net)
    elif action in ("off", "disable"):
        _disconnect(net)
    else:
        raise WifiError("use on or off, e.g. wifi 3 on", 2)


def run(args):
    """Run one Wi-Fi command; returns an exit code."""
    if args and args[0].lower() in ("hotspot", "hs"):
        return _core.registry()["hotspot"].run(args[1:])  # the hotspot page reads its own flags
    args, options = _core.split_flags(args)
    if not args:
        print(f"usage: {USAGE}")
        return 0
    if args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        _dispatch(args, options)
        return 0
    except (WifiError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

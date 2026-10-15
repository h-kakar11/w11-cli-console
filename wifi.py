"""
wifi: connect to and disconnect from Wi-Fi networks on Windows 11. Routed from app.py
("wifi", "net", "internet" or "wf").

    wifi ls            list Wi-Fi networks in range, with ids
    wifi status        show the network you are connected to
    wifi on            join the strongest saved network in range
    wifi off           disconnect from Wi-Fi
    wifi <id>          show one network
    wifi <id> on       join it (asks for the password if it is new)
    wifi <id> off      disconnect, if you are connected to it
    wifi rm <id>       forget a saved network (asks you to confirm first)

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

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "wifi"
ALIASES = ["net", "internet", "wf"]
SUMMARY = "Connect to and disconnect from Wi-Fi networks"
USAGE = "wifi ls | wifi status | wifi on|off | wifi <id> [on|off] | wifi rm <id>   (e.g. wifi 3 on)"
HELP = [
    ("wifi ls", "list Wi-Fi networks in range, with ids and signal"),
    ("wifi status", "show the network you are connected to"),
    ("wifi on", "join the strongest saved network in range"),
    ("wifi off", "disconnect from Wi-Fi"),
    ("wifi <id> on", "join a network (asks for the password if it is new)"),
    ("wifi rm <id>", "forget a saved network's password (asks you to confirm first)"),
]
TIP = "Run 'wifi ls' first, since ids follow the list. Passwords are typed hidden."
REMOVE_WORDS = ("rm", "remove", "delete", "uninstall", "del")

CONNECT_WAIT = 20  # seconds to wait for a new connection to come up
LOCATION_HINT = (
    "Windows needs Location turned on to show Wi-Fi network names. Turn it on at "
    "Settings > Privacy & security > Location (ms-settings:privacy-location), then try again."
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


def _percent(value):
    match = re.match(r"\s*(\d+)\s*%", value or "")
    return int(match.group(1)) if match else 0


# ======================================================================
# SOURCES — the networks in range and the ones saved on this computer
# ======================================================================
def _current():
    """(SSID, signal) of the network the adapter is joined to, or (None, None)."""
    values = dict(_fields(_netsh_ok("show", "interfaces")))
    if values.get("State", "").lower() != "connected":
        return None, None
    return values.get("SSID") or None, _percent(values.get("Signal"))


def _saved_names():
    """Names of the Wi-Fi profiles saved on this computer."""
    names = set()
    for key, value in _fields(_netsh_ok("show", "profiles")):
        if "all user profile" in key.lower():
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


def _parse_id(word):
    try:
        return int(word)
    except ValueError:
        raise WifiError(f"expected a network id from 'wifi ls', got: {word}", 2)


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


def _join_best():
    """Join the strongest saved network in range."""
    networks = _networks()
    if any(net["connected"] for net in networks):
        _status()
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
def _confirm(question):
    try:
        return input(question).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _forget(args):
    if len(args) != 2:
        raise WifiError("usage: wifi rm <id>", 2)
    net = _get_network(_parse_id(args[1]))
    if not net["saved"]:
        raise WifiError(f"{net['ssid']} has no saved password to forget")
    drop = " You are connected to it, so the connection will drop." if net["connected"] else ""
    if not _confirm(
        f"Forget the saved Wi-Fi network {net['ssid']}?{drop} You will need its password to join "
        "again. This can't be undone. [y/N]: "
    ):
        print("cancelled")
        return
    print(f"forgetting {net['ssid']}... expect it to vanish from 'wifi ls' at once.")
    _netsh_ok("delete", "profile", f"name={net['ssid']}")
    print(f"forgot {net['ssid']}")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "wifi"/"net"
# ======================================================================
def _describe(net):
    state = "connected" if net["connected"] else "not connected"
    saved = "saved" if net["saved"] else "not saved"
    return f"{state}, signal {net['signal']}%, {net['auth']}, {saved}"


def _list():
    os.system("")  # enables ANSI colour codes in the Windows console
    networks = _networks()
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


def _status():
    ssid, signal = _current()
    if ssid is None:
        print("not connected to Wi-Fi")
        return
    print(f"connected to {ssid}: {signal}%")


def _dispatch(args):
    word = args[0].lower()
    if word in ("ls", "list"):
        if len(args) > 1:
            raise WifiError("usage: wifi ls", 2)
        _list()
        return
    if word == "status":
        if len(args) > 1:
            raise WifiError("usage: wifi status", 2)
        _status()
        return
    if word in ("on", "enable") and len(args) == 1:
        _join_best()
        return
    if word in ("off", "disable") and len(args) == 1:
        _disconnect()
        return
    if word in REMOVE_WORDS:
        _forget(args)
        return

    net = _get_network(_parse_id(args[0]))

    if len(args) == 1:
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
    if not args:
        print(f"usage: {USAGE}")
        return 0
    if args[0].lower() in ("help", "-h", "--help", "?"):
        print(f"usage: {USAGE}")
        return 0
    try:
        _dispatch(args)
        return 0
    except WifiError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

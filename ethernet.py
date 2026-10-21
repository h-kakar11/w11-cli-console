"""
ethernet: the wired connection on Windows 11, the same as Settings > Network & internet > Ethernet
and the adapter's Properties. Routed from app.py ("ethernet", "eth", "lan" or "wired").

    eth info                     everything about the wired connection, like ipconfig but readable
    eth ip | eth ip auto | eth ip manual <ip>/<prefix> [<gateway>]
    eth dns | eth dns auto | eth dns <server> [<server>...]
    eth metered on|off           metered connection
    eth auth                     802.1X sign-in, and what it is set to
    eth auth on|off              turn 802.1X on (starts Wired AutoConfig) or off
    eth auth method peap|certificate|ttls
    eth auth mode user|computer|both|guest
    eth auth remember on|off     remember my credentials
    eth auth fallback on|off     fall back to unauthorised network access
    eth auth sso before|after|off
    eth share                    Internet Connection Sharing
    eth features                 IPv4, IPv6, File and Printer Sharing and more (see _net.py)
    eth ls                       wired adapters, if there is more than one
    eth <id> <command>           run a command on adapter <id> from 'eth ls'

Without an id, commands use the first wired adapter, connected ones first. Reading needs no
administrator rights; every change here does, and says so before doing anything.
"""

import sys

import _core
import _net

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "ethernet"
ALIASES = ["eth", "lan", "wired"]
SUMMARY = "Wired network: details, IP, DNS, 802.1X and metered"
# extra words people use, for 'settings search'
KEYWORDS = ["wired", "cable", "lan", "ip address", "dns", "802.1x", "network", "no internet"]
USAGE = ("eth info | eth ip [auto|manual <ip>/<prefix> [<gateway>]] | eth dns [auto|<server>...] | "
         "eth metered on|off | eth auth [on|off|method|mode|remember|fallback|sso ...] | eth share | "
         "eth features | eth ls | eth <id> <command>")
HELP = [
    ("eth info", "everything about the wired connection, like ipconfig but readable"),
    ("eth ip auto | manual <ip>/<prefix>", "how this PC gets its address (auto is DHCP)"),
    ("eth dns auto | <server> ...", "which DNS servers it uses, e.g. eth dns 1.1.1.1 8.8.8.8"),
    ("eth metered on | off", "metered connection: Windows holds back updates and background data"),
    ("eth auth", "802.1X sign-in: on or off, method, who signs in, fallback"),
    ("eth share", "let devices on another connection use this one"),
    ("eth features", "IPv4, IPv6, File and Printer Sharing and more: on, off, install, remove"),
    ("eth ls", "wired adapters with ids, when there is more than one (then: eth <id> info)"),
]
TIP = ("Changes need an administrator terminal; reading does not. "
       "Agents: add --json for data, and --yes to confirm a change the person has agreed to.")
PREFIX = "eth"
LAN_SERVICE = "dot3svc"  # Wired AutoConfig: 802.1X on Ethernet needs it running


class EthernetError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# ADAPTERS — the wired ones only (not Wi-Fi, Bluetooth or virtual switches)
# ======================================================================
def _adapters():
    found = _net.adapters("ethernet")
    if not found:
        raise EthernetError("this PC has no wired network adapter")
    return found


def _pick(word):
    for adapter in _adapters():
        if str(adapter["id"]) == word:
            return adapter
    raise EthernetError(f"no wired adapter with id {word}. Run 'eth ls' to see them.", 2)


def _list(options):
    found = _adapters()
    if options["json"]:
        _core.print_json([{key: a[key] for key in ("id", "name", "description", "connected", "mac", "speed_mbps")}
                          for a in found])
        return
    lines = [f"  {'ID':<4}{'ADAPTER':<22}{'STATE':<16}HARDWARE"]
    for adapter in found:
        color = _net.GREEN if adapter["connected"] else _net.GREY
        state = "connected" if adapter["connected"] else "not connected"
        lines.append(color + f"  {adapter['id']:<4}{adapter['name'][:20]:<22}{state:<16}{adapter['description']}"
                     + _net.RESET)
    lines += ["", "Commands use adapter 1 unless you give an id, e.g. eth 2 info."]
    print("\n".join(lines))


# ======================================================================
# METERED
# ======================================================================
def _metered(adapter, rest, options):
    if rest:
        if len(rest) != 1:
            raise EthernetError("usage: eth metered on | eth metered off", 2)
        on = _net.on_off(rest[0], "eth metered on")
        _net.need_admin()
        print(f"turning metered connection {'on' if on else 'off'} for {adapter['name']}... "
              "expect the Data Usage service to restart, which takes a few seconds.")
        if not _net.set_ethernet_metered(adapter, on):
            print("note: the Data Usage service did not restart by itself. Sign out and in for it to apply.")
    metered = _net.ethernet_metered(adapter)
    if options["json"]:
        _core.print_json({"adapter": adapter["name"], "metered": metered})
        return
    print(f"metered connection for {adapter['name']}: {'on' if metered else 'off'}")
    if metered and rest:
        print("Windows now holds back updates and background data on this connection.")


# ======================================================================
# 802.1X — needs Wired AutoConfig (dot3svc) running and a LAN profile on the adapter
# ======================================================================
def _export(adapter):
    return _net.export_xml(lambda folder: ["netsh", "lan", "export", "profile", f"folder={folder}",
                                           f"interface={adapter['name']}"])


def _auth_state(adapter):
    """(802.1X settings in plain words, the profile XML or None)."""
    service = _net.service_state(LAN_SERVICE)
    state = {"adapter": adapter["name"], "wired_autoconfig": service.lower(), "enabled": False}
    if service != "RUNNING":
        state["note"] = ("802.1X needs the Wired AutoConfig service, which is not running. "
                         "'eth auth on' starts it and turns 802.1X on.")
        return state, None
    try:
        xml = _export(adapter)
    except _net.NetError as e:
        xml = None
        state["note"] = f"no 802.1X profile on {adapter['name']} yet ({e}). 'eth auth on' makes one."
    if xml is None:
        state.setdefault("note", f"no 802.1X profile on {adapter['name']} yet. 'eth auth on' makes one.")
        return state, None
    state.update(_net.onex_summary(xml))
    state.pop("authentication", None)
    return state, xml


def _start_wired_autoconfig():
    """Start Wired AutoConfig, and set it to start with Windows so 802.1X keeps working after a restart."""
    if _net.service_state(LAN_SERVICE) == "RUNNING":
        return
    _net.tool_ok(["sc", "config", LAN_SERVICE, "start=", "auto"])
    _net.run_tool(["sc", "start", LAN_SERVICE])
    if not _net._wait_for_service(LAN_SERVICE, "RUNNING", 15):
        raise EthernetError("Wired AutoConfig did not start. Check it in services.msc.")


def _add_profile(adapter, xml):
    _net.add_xml(xml, lambda path: ["netsh", "lan", "add", "profile", f"filename={path}",
                                    f"interface={adapter['name']}"])


def _set_profile(adapter, setting, value):
    _net.tool_ok(["netsh", "lan", "set", "profileparameter", f"interface={adapter['name']}", f"{setting}={value}"])


def _auth_change(adapter, rest, xml):
    setting = rest[0].lower()
    name = adapter["name"]
    if setting in _net.ON_WORDS and len(rest) == 1:
        _net.need_admin()
        print(f"turning on 802.1X for {name}... expect Windows to ask you to sign in the next time the network "
              "asks for it. Wired AutoConfig will start with Windows from now on.")
        _start_wired_autoconfig()
        xml = xml or _export_or_none(adapter)
        if xml is None:
            _add_profile(adapter, _net.LAN_PROFILE.format(eap=_net.EAP_CONFIGS["peap"]))  # Windows' default: PEAP
        else:
            _set_profile(adapter, "oneXEnabled", "yes")
        return
    if setting in _net.OFF_WORDS and len(rest) == 1:
        _net.need_admin()
        if xml is None:
            print(f"802.1X is already off for {name}")
            return
        print(f"turning off 802.1X for {name}...")
        _set_profile(adapter, "oneXEnabled", "no")
        return
    if len(rest) != 2:
        raise EthernetError("usage: eth auth on|off | eth auth method|mode|remember|fallback|sso <value>", 2)
    word = rest[1]
    if setting == "method":
        value = _net.method_word(word, PREFIX)
    elif setting == "mode":
        value = _net.mode_word(word, PREFIX)
    elif setting in ("remember", "fallback"):
        value = _net.on_off(word, f"eth auth {setting} on")
    elif setting == "sso":
        value = _net.sso_word(word, PREFIX)
    else:
        raise EthernetError("use on, off, method, mode, remember, fallback or sso, e.g. eth auth mode user", 2)
    if xml is None:
        raise EthernetError(f"802.1X is off for {name}. Turn it on first: eth auth on")
    _net.need_admin()
    if setting == "method":
        print(f"changing how {name} signs in... expect Windows to ask for your sign-in details on the next connect.")
        _add_profile(adapter, _net.with_method(xml, value))
    elif setting == "mode":
        _set_profile(adapter, "authMode", value)
    elif setting == "remember":
        _add_profile(adapter, _net.with_cache(xml, value))
    elif setting == "fallback":
        _set_profile(adapter, "oneXEnforced", "no" if value else "yes")  # fallback allowed = 802.1X not enforced
    else:
        _set_profile(adapter, "ssoMode", value)


def _export_or_none(adapter):
    try:
        return _export(adapter)
    except _net.NetError:
        return None


def _auth(adapter, rest, options):
    state, xml = _auth_state(adapter)
    if rest:
        _auth_change(adapter, rest, xml)
        state, _ = _auth_state(adapter)
    if options["json"]:
        _core.print_json(state)
        return
    change = [("eth auth on | off", "802.1X sign-in for this connection")]
    if state["enabled"]:
        change += [
            ("eth auth method peap | certificate | ttls", "how you prove who you are"),
            ("eth auth mode user | computer | both | guest", "whose credentials are used"),
            ("eth auth remember on | off", "remember my credentials"),
            ("eth auth fallback on | off", "fall back to unauthorised access if sign-in fails"),
            ("eth auth sso before | after | off", "sign in to the network before or after Windows sign-in"),
        ]
    _net.render(f"{adapter['name']}: 802.1X sign-in", [
        ("now", _net.auth_rows(state) + [("Wired AutoConfig", state["wired_autoconfig"])]),
        ("change it with", change),
    ])


# ======================================================================
# DETAILS
# ======================================================================
def _info(adapter, options):
    data = _net.info_data(adapter)
    auth, _ = _auth_state(adapter)
    data["metered"] = _net.ethernet_metered(adapter)
    data["ieee_8021x"] = auth["enabled"]
    if options["json"]:
        _core.print_json(data)
        return
    sections = _net.info_sections(data) + [("ethernet settings", [
        ("metered connection", data["metered"]),
        ("802.1X sign-in", data["ieee_8021x"]),
    ])]
    state = "connected" if adapter["connected"] else "not connected (is the cable plugged in?)"
    _net.render(f"{adapter['name']}: {state}", sections)


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "ethernet"/"eth"
# ======================================================================
def _dispatch(args, options):
    if args[0].isdigit():
        adapter = _pick(args[0])
        args = args[1:] or ["info"]
    else:
        adapter = None
    word = args[0].lower()
    rest = args[1:]
    if word in _net.LIST_WORDS and not rest:
        _list(options)
        return
    adapter = adapter or _adapters()[0]
    if word in ("info", "details", "status", "ipconfig") and not rest:
        _info(adapter, options)
    elif word == "metered":
        _metered(adapter, rest, options)
    elif word in ("auth", "8021x", "802.1x"):
        _auth(adapter, rest, options)
    elif word in _net.ADAPTER_WORDS:
        _net.adapter_command(word, rest, adapter, options, PREFIX)
    else:
        raise EthernetError(f"unknown ethernet command: {args[0]}\nusage: {USAGE}", 2)


def run(args):
    """Run one Ethernet command; returns an exit code."""
    args, options = _core.split_flags(args)
    if not args:
        if options["json"]:
            args = ["info"]
        else:
            print(_core.page_help(_core.registry()[NAME]))
            return 0
    if args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        _dispatch(args, options)
        return 0
    except (EthernetError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

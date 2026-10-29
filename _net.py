"""
Shared network code for the wifi and ethernet pages: adapter details, IP and DNS assignment,
metered Ethernet, connection sharing, 802.1X sign-in, and the features (bindings) on each adapter.
The name starts with an underscore, so app.py does not load it as a page.

Reading needs no administrator rights. Changing IP, DNS, 802.1X on Ethernet, sharing, metered
Ethernet or features does, and each change checks that first, so nothing is announced that will
not happen. After every change the setting is read back, and the page reports what Windows says now.
"""

import ctypes
import datetime
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import time
import winreg
import xml.etree.ElementTree as ET
from ctypes import POINTER, Structure, c_char_p, c_int, c_ubyte, c_ulong, c_ulonglong, c_void_p, c_wchar_p

import _core

# ======================================================================
# CONSTANTS
# ======================================================================
CYAN, GREEN, YELLOW, MAGENTA, BLUE = "\033[96m", "\033[92m", "\033[93m", "\033[95m", "\033[94m"
RED, GREY, RESET = "\033[91m", "\033[90m", "\033[0m"
SECTION_COLORS = [CYAN, GREEN, YELLOW, MAGENTA, BLUE]  # the same palette as process.py's rows

ADMIN_HINT = "this needs administrator rights. Run the terminal as administrator."
ON_WORDS = ("on", "enable", "yes")
OFF_WORDS = ("off", "disable", "no")
AUTO_WORDS = ("auto", "automatic", "dhcp")
REMOVE_WORDS = ("rm", "remove", "delete", "uninstall", "del")
LIST_WORDS = ("ls", "list")

HKLM = winreg.HKEY_LOCAL_MACHINE
NETWORK_CLASS = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
TCPIP = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
TCPIP6 = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"
DUSM = r"SOFTWARE\Microsoft\DusmSvc\Profiles"  # metered Ethernet: {adapter GUID}\*\UserCost
METERED, NOT_METERED = 2, 0
PHYSICAL_BUSES = ("PCI\\", "USB\\", "SD\\")  # real hardware; virtual adapters sit on ROOT\, SWD\ or BTH\

ICS_PUBLIC, ICS_PRIVATE = 0, 1  # the shared connection, and the home network it is shared with
ICS_ADDRESS = "192.168.137.1"  # what Windows gives the home network when sharing starts
SELF_ASSIGNED = "169.254."  # the address Windows picks itself when no DHCP server answers

# The eight features Windows lists on an adapter's Properties, in that order. Their ids (1-8)
# never change, so agents can rely on them; anything else bound to the adapter comes after.
# (component id, short name, Windows' name, netcfg class, what it does)
FEATURES = [
    ("ms_msclient", "client", "Client for Microsoft Networks", "c",
     "lets this PC open shared folders and printers on other PCs"),
    ("ms_server", "sharing", "File and Printer Sharing for Microsoft Networks", "s",
     "lets other PCs open this PC's shared folders and printers"),
    ("ms_pacer", "qos", "QoS Packet Scheduler", "s",
     "lets apps ask for priority, for calls and games"),
    ("ms_tcpip", "ipv4", "Internet Protocol Version 4 (TCP/IPv4)", "p",
     "the main internet protocol. Turning it off cuts most connections"),
    ("ms_lldp", "lldp", "Microsoft LLDP Protocol Driver", "p",
     "tells network switches what this PC is"),
    ("ms_tcpip6", "ipv6", "Internet Protocol Version 6 (TCP/IPv6)", "p",
     "the newer internet protocol, used alongside IPv4"),
    ("ms_lltdio", "mapper", "Link-Layer Topology Discovery Mapper I/O Driver", "p",
     "lets this PC map the devices on the network"),
    ("ms_rspndr", "responder", "Link-Layer Topology Discovery Responder", "p",
     "lets this PC show up on other PCs' network maps"),
]
BUILT_IN = {"ms_tcpip", "ms_tcpip6"}  # part of Windows' TCP/IP, so they can be turned off but not uninstalled
NETCFG_CLASSES = {"client": "c", "service": "s", "protocol": "p"}


class NetError(_core.CommandError):
    """An error with an exit code: 1 for system errors, 2 for bad usage.
    A CommandError, so the shared engine and --json error reporting handle it too."""

    def __init__(self, message, code=1, error=None):
        super().__init__(message, code, error)


# ======================================================================
# TOOLS — netsh, sc and netcfg, the Windows tools for what Python cannot reach
# ======================================================================
def run_tool(args, timeout=60):
    """Run a Windows tool; returns (succeeded, output)."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, encoding="oem", errors="replace", timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise NetError(f"could not run {args[0]}: {e}")
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def explain(text):
    """A short reason from a tool's output, with the fix when we know it."""
    lowered = text.lower()
    if "elevation" in lowered or "access is denied" in lowered or "run as administrator" in lowered:
        return ADMIN_HINT
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[0] if lines else "the command failed with no message"


def tool_ok(args, timeout=60):
    """Run a tool and return its output, or raise a NetError if it failed."""
    ok, text = run_tool(args, timeout)
    if not ok:
        raise NetError(explain(text))
    return text


def need_admin():
    if not _core.is_admin():
        raise NetError(ADMIN_HINT)


def on_off(word, example):
    word = word.lower()
    if word in ON_WORDS:
        return True
    if word in OFF_WORDS:
        return False
    raise NetError(f"use on or off, e.g. {example}", 2)


def reg_read(path, name, default=None, hive=HKLM):
    try:
        with winreg.OpenKey(hive, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return default


def service_state(name):
    """A Windows service's state, such as RUNNING or STOPPED (UNKNOWN if sc cannot say)."""
    _, text = run_tool(["sc", "query", name])
    match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", text)
    return match.group(1).upper() if match else "UNKNOWN"


def _wait_for_service(name, state, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if service_state(name) == state:
            return True
        time.sleep(0.5)
    return False


def restart_service(name, seconds=15):
    """Stop and start a service so it rereads its settings. Returns False if it did not come back."""
    run_tool(["sc", "stop", name])
    _wait_for_service(name, "STOPPED", seconds)
    run_tool(["sc", "start", name])
    return _wait_for_service(name, "RUNNING", seconds)


def _com():
    """comtypes, for WMI and connection sharing. pycaw already installs it."""
    try:
        import comtypes
        import comtypes.client
    except ImportError:
        raise NetError("this needs the comtypes package. Run: py -m pip install -r requirements.txt")
    comtypes.CoInitialize()
    return comtypes


def _wmi(namespace):
    comtypes = _com()
    try:
        return comtypes.client.CoGetObject(f"winmgmts:{namespace}")
    except (OSError, comtypes.COMError) as e:
        raise NetError(f"Windows would not open {namespace}: {e}")


def _prop(row, name):
    return row.Properties_(name).Value


def _wql(text):
    return text.replace("\\", "\\\\").replace("'", "\\'")


# ======================================================================
# ADAPTERS — read with GetAdaptersAddresses, the same call ipconfig uses
# ======================================================================
class _SocketAddress(Structure):
    _fields_ = [("sockaddr", c_void_p), ("length", c_int)]


class _Address(Structure):
    """The shape shared by DNS server, gateway, anycast and multicast entries."""


_Address._fields_ = [
    ("Length", c_ulong), ("Flags", c_ulong), ("Next", POINTER(_Address)), ("Address", _SocketAddress),
]


class _Unicast(Structure):
    """One address on an adapter."""


_Unicast._fields_ = [
    ("Length", c_ulong), ("Flags", c_ulong), ("Next", POINTER(_Unicast)), ("Address", _SocketAddress),
    ("PrefixOrigin", c_int), ("SuffixOrigin", c_int), ("DadState", c_int),
    ("ValidLifetime", c_ulong), ("PreferredLifetime", c_ulong), ("LeaseLifetime", c_ulong),
    ("OnLinkPrefixLength", c_ubyte),
]


class _Adapter(Structure):
    """IP_ADAPTER_ADDRESSES_LH, field for field."""


_Adapter._fields_ = [
    ("Length", c_ulong), ("IfIndex", c_ulong), ("Next", POINTER(_Adapter)), ("AdapterName", c_char_p),
    ("FirstUnicastAddress", POINTER(_Unicast)), ("FirstAnycastAddress", POINTER(_Address)),
    ("FirstMulticastAddress", POINTER(_Address)), ("FirstDnsServerAddress", POINTER(_Address)),
    ("DnsSuffix", c_wchar_p), ("Description", c_wchar_p), ("FriendlyName", c_wchar_p),
    ("PhysicalAddress", c_ubyte * 8), ("PhysicalAddressLength", c_ulong), ("Flags", c_ulong),
    ("Mtu", c_ulong), ("IfType", c_ulong), ("OperStatus", c_int), ("Ipv6IfIndex", c_ulong),
    ("ZoneIndices", c_ulong * 16), ("FirstPrefix", c_void_p),
    ("TransmitLinkSpeed", c_ulonglong), ("ReceiveLinkSpeed", c_ulonglong),
    ("FirstWinsServerAddress", POINTER(_Address)), ("FirstGatewayAddress", POINTER(_Address)),
    ("Ipv4Metric", c_ulong), ("Ipv6Metric", c_ulong), ("Luid", c_ulonglong),
    ("Dhcpv4Server", _SocketAddress), ("CompartmentId", c_ulong), ("NetworkGuid", c_ubyte * 16),
    ("ConnectionType", c_int), ("TunnelType", c_int), ("Dhcpv6Server", _SocketAddress),
    ("Dhcpv6ClientDuid", c_ubyte * 130), ("Dhcpv6ClientDuidLength", c_ulong), ("Dhcpv6Iaid", c_ulong),
    ("FirstDnsSuffix", c_void_p),
]

GAA_FLAGS = 0x10 | 0x80  # include prefixes and gateways
ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA = 111, 232
IF_ETHERNET, IF_WIFI = 6, 71
IF_OPER_UP = 1
DHCP_ENABLED = 0x4
ORIGIN_DHCP = 3
SUFFIX_RANDOM = 5  # IpSuffixOriginRandom: what ipconfig calls a temporary IPv6 address
NO_SPEED = 0xFFFFFFFFFFFFFFFF


def _ip(address):
    if not address.sockaddr:
        return None
    raw = ctypes.string_at(address.sockaddr, address.length)
    family = int.from_bytes(raw[0:2], "little")
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[4:8])
    if family == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, raw[8:24])
    return None


def _chain(first):
    node = first
    while node:
        yield node.contents
        node = node.contents.Next


def _addresses(first):
    """The addresses in a chain, each once, in Windows' order."""
    found = []
    for entry in _chain(first):
        address = _ip(entry.Address)
        if address and address not in found:
            found.append(address)
    return found


def _physical(guid):
    pnp = reg_read(f"{NETWORK_CLASS}\\{guid}\\Connection", "PnPInstanceId", "") or ""
    return pnp.upper().startswith(PHYSICAL_BUSES)


def _adapter_dict(raw):
    guid = raw.AdapterName.decode().upper()
    ipv4, ipv6 = [], []
    for entry in _chain(raw.FirstUnicastAddress):
        address = _ip(entry.Address)
        if address is None:
            continue
        item = {"address": address, "prefix": entry.OnLinkPrefixLength, "dhcp": entry.PrefixOrigin == ORIGIN_DHCP}
        if ":" in address:
            if address.lower().startswith("fe80"):
                item["kind"] = "link-local"
            else:
                item["kind"] = "temporary" if entry.SuffixOrigin == SUFFIX_RANDOM else "global"
            ipv6.append(item)
        else:
            ipv4.append(item)
    kind = "other"
    if raw.IfType in (IF_ETHERNET, IF_WIFI) and _physical(guid):
        kind = "wifi" if raw.IfType == IF_WIFI else "ethernet"
    speed = raw.TransmitLinkSpeed
    return {
        "name": raw.FriendlyName,
        "description": raw.Description,
        "guid": guid,
        "kind": kind,
        "if_type": raw.IfType,
        "connected": raw.OperStatus == IF_OPER_UP,
        "mac": "-".join(f"{b:02X}" for b in raw.PhysicalAddress[:raw.PhysicalAddressLength]),
        "speed_mbps": None if speed in (0, NO_SPEED) else round(speed / 1_000_000, 1),
        "dhcp_enabled": bool(raw.Flags & DHCP_ENABLED),
        "ipv4": ipv4,
        "ipv6": ipv6,
        "gateways": _addresses(raw.FirstGatewayAddress),
        "dns_servers": _addresses(raw.FirstDnsServerAddress),
        "dns_suffix": raw.DnsSuffix or None,
        "mtu": raw.Mtu,
    }


def _read_adapters():
    """Every network adapter Windows knows about, as plain dicts."""
    size = c_ulong(16 * 1024)
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size.value)
        code = ctypes.windll.iphlpapi.GetAdaptersAddresses(0, GAA_FLAGS, None, buffer, ctypes.byref(size))
        if code == ERROR_NO_DATA:
            return []
        if code == 0:
            return [_adapter_dict(raw) for raw in _chain(ctypes.cast(buffer, POINTER(_Adapter)))]
        if code != ERROR_BUFFER_OVERFLOW:  # on overflow, size now holds what is needed
            break
    raise NetError("Windows could not list the network adapters")


def adapters(kind):
    """Physical adapters of one kind ("wifi" or "ethernet"): connected first, then by name, numbered from 1.
    The list and the numbers both come from here."""
    found = [a for a in _read_adapters() if a["kind"] == kind]
    found.sort(key=lambda a: (not a["connected"], a["name"].lower()))
    for number, adapter in enumerate(found, start=1):
        adapter["id"] = number
    return found


def refresh(adapter):
    """The same adapter, read again after a change."""
    for fresh in _read_adapters():
        if fresh["guid"] == adapter["guid"]:
            fresh["id"] = adapter.get("id")
            return fresh
    raise NetError(f"{adapter['name']} has gone. Run the command again.")


# ======================================================================
# IP SETTINGS — what DHCP gave, or what was typed in, from the TCP/IP registry keys
# ======================================================================
def mask(prefix):
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)


def _servers(text):
    return [server for server in re.split(r"[,\s]+", text or "") if server]


def _unix(seconds):
    return datetime.datetime.fromtimestamp(seconds) if seconds else None


def tcpip(adapter):
    """How this adapter's IP and DNS are assigned, with the DHCP lease, as Windows stores them."""
    key = f"{TCPIP}\\{adapter['guid']}"
    manual_dns = _servers(reg_read(key, "NameServer")) + _servers(reg_read(f"{TCPIP6}\\{adapter['guid']}", "NameServer"))
    automatic = bool(reg_read(key, "EnableDHCP", 1))
    return {
        "ip_assignment": "automatic" if automatic else "manual",
        "dns_assignment": "manual" if manual_dns else "automatic",
        "manual_dns": manual_dns,
        "dhcp_server": reg_read(key, "DhcpServer") if automatic else None,
        "lease_obtained": _unix(reg_read(key, "LeaseObtainedTime")) if automatic else None,
        "lease_expires": _unix(reg_read(key, "LeaseTerminatesTime")) if automatic else None,
        "domain": reg_read(key, "DhcpDomain") or reg_read(key, "Domain") or None,
    }


def info_data(adapter):
    """Everything ipconfig /all says about one adapter, with plain names."""
    tcp = tcpip(adapter)
    return {
        "adapter": adapter["name"],
        "hardware": adapter["description"],
        "connected": adapter["connected"],
        "physical_address": adapter["mac"],
        "speed_mbps": adapter["speed_mbps"],
        "ipv4": [f"{a['address']}/{a['prefix']}" for a in adapter["ipv4"]],
        "subnet_mask": [mask(a["prefix"]) for a in adapter["ipv4"]],
        "ipv6": [{"address": a["address"], "prefix": a["prefix"], "kind": a["kind"]} for a in adapter["ipv6"]],
        "gateways": adapter["gateways"],
        "dns_servers": adapter["dns_servers"],
        "ip_assignment": tcp["ip_assignment"],
        "dns_assignment": tcp["dns_assignment"],
        "dhcp_server": tcp["dhcp_server"],
        "lease_obtained": tcp["lease_obtained"],
        "lease_expires": tcp["lease_expires"],
        "dns_suffix": adapter["dns_suffix"] or tcp["domain"],
        "mtu": adapter["mtu"],
    }


def info_sections(data):
    """The sections 'info' shows for any adapter. Pages add their own (wireless, metered, 802.1X)."""
    speed = f"{data['speed_mbps']:g} Mbps" if data["speed_mbps"] else None
    adapter_rows = [
        ("name", data["adapter"]),
        ("hardware", data["hardware"]),
        ("state", "connected" if data["connected"] else "not connected"),
        ("speed", speed),
        ("physical address", data["physical_address"]),
    ]
    address_rows = []
    for address, net_mask in zip(data["ipv4"], data["subnet_mask"]):
        hint = "   self-assigned: no DHCP server answered" if address.startswith(SELF_ASSIGNED) else ""
        address_rows.append(("IPv4 address", f"{address}   (mask {net_mask}){hint}"))
    for item in data["ipv6"]:
        address_rows.append((f"IPv6 {item['kind']}", f"{item['address']}/{item['prefix']}"))
    address_rows += [("gateway", data["gateways"]), ("DNS servers", data["dns_servers"])]
    setting_rows = [
        ("IP assignment", "automatic (DHCP)" if data["ip_assignment"] == "automatic" else "manual"),
        ("DNS assignment", data["dns_assignment"]),
        ("DHCP server", data["dhcp_server"]),
        ("lease obtained", data["lease_obtained"]),
        ("lease expires", data["lease_expires"]),
        ("DNS suffix", data["dns_suffix"]),
        ("MTU", data["mtu"]),
    ]
    if data["ip_assignment"] != "automatic" or not data["connected"]:
        setting_rows = [row for row in setting_rows if not row[0].startswith(("DHCP", "lease"))]  # stale when unplugged
    return [("adapter", adapter_rows), ("addresses", address_rows), ("ip settings", setting_rows)]


# ======================================================================
# OUTPUT — sections in different colours, so long details stay readable
# ======================================================================
def show(value):
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) if value else "none"
    return str(value)


def render(title, sections):
    """A title, then each (heading, [(label, value), ...]) section in its own colour."""
    os.system("")  # enables ANSI colour codes in the Windows console
    labels = [label for _, rows in sections for label, _ in rows]
    width = max([len(label) for label in labels], default=0) + 3
    lines = [title]
    for number, (heading, rows) in enumerate(sections):
        color = SECTION_COLORS[number % len(SECTION_COLORS)]
        lines += ["", color + f" {heading.upper()}" + RESET]
        lines += [color + f"   {label:<{width}}{show(value)}" + RESET for label, value in rows]
    print("\n".join(lines))


def public(item):
    """A dict without its private keys (the ones starting with _), for JSON."""
    return {key: value for key, value in item.items() if not key.startswith("_")}


# ======================================================================
# IP AND DNS — changed with netsh, the same as the Edit buttons in Settings
# ======================================================================
def _ip_state(adapter):
    tcp = tcpip(adapter)
    return {
        "adapter": adapter["name"],
        "ip_assignment": tcp["ip_assignment"],
        "ipv4": [f"{a['address']}/{a['prefix']}" for a in adapter["ipv4"]],
        "gateways": adapter["gateways"],
        "ipv6": [f"{a['address']}/{a['prefix']}" for a in adapter["ipv6"] if a["kind"] != "link-local"],
    }


def _show_ip(adapter, options, prefix):
    state = _ip_state(adapter)
    if options["json"]:
        _core.print_json(state)
        return
    automatic = state["ip_assignment"] == "automatic"
    render(f"{adapter['name']}: IP settings", [
        ("now", [
            ("IP assignment", "automatic (DHCP)" if automatic else "manual"),
            ("IPv4 address", state["ipv4"]),
            ("gateway", state["gateways"]),
            ("IPv6 address", state["ipv6"]),
        ]),
        ("change it with", [
            (f"{prefix} ip auto", "get an address from the router (DHCP), the usual choice"),
            (f"{prefix} ip manual <ip>/<prefix> [gateway]", f"e.g. {prefix} ip manual 192.168.1.50/24 192.168.1.1"),
        ]),
    ])


def _parse_manual(words, prefix):
    usage = (f"usage: {prefix} ip manual <ip>/<prefix> [<gateway>], "
             f"e.g. {prefix} ip manual 192.168.1.50/24 192.168.1.1")
    words = list(words)
    if words and "/" not in words[0] and len(words) > 1 and words[1].count(".") == 3:
        words[0:2] = [f"{words[0]}/{words[1]}"]  # 192.168.1.50 255.255.255.0 -> 192.168.1.50/255.255.255.0
    if not words or "/" not in words[0] or len(words) > 2:
        raise NetError(usage, 2)
    try:
        interface = ipaddress.IPv4Interface(words[0])
    except ValueError:
        raise NetError(f"not an IPv4 address with a prefix: {words[0]}. {usage}", 2)
    network = interface.network
    if network.prefixlen < 31 and interface.ip in (network.network_address, network.broadcast_address):
        raise NetError(f"{interface.ip} is the network's own address, not one a device can use", 2)
    gateway = None
    if len(words) == 2:
        try:
            gateway = ipaddress.IPv4Address(words[1])
        except ValueError:
            raise NetError(f"not an IPv4 gateway: {words[1]}", 2)
        if gateway not in network or gateway == interface.ip:
            raise NetError(f"the gateway {gateway} must be another address in {network}", 2)
    return interface, gateway


def _ip_command(adapter, rest, options, prefix):
    if not rest:
        _show_ip(adapter, options, prefix)
        return
    word = rest[0].lower()
    name = adapter["name"]
    if word in AUTO_WORDS and len(rest) == 1:
        need_admin()
        print(f"setting {name} to get its address automatically... expect a short drop while it asks the router.")
        tool_ok(["netsh", "interface", "ipv4", "set", "address", f"name={name}", "source=dhcp"])
    elif word in ("manual", "static"):
        interface, gateway = _parse_manual(rest[1:], prefix)
        need_admin()
        gateway_text = f", gateway {gateway}" if gateway else ", no gateway (no internet through it)"
        if not _core.confirm(
            f"Set {name} to the manual address {interface.with_prefixlen}{gateway_text}? If it does not suit "
            f"this network, you lose the connection until you run '{prefix} ip auto'. [y/N]: ", options["yes"]
        ):
            print("cancelled")
            return
        tool_ok(["netsh", "interface", "ipv4", "set", "address", f"name={name}", "source=static",
                 f"address={interface.ip}", f"mask={interface.netmask}", f"gateway={gateway or 'none'}"])
        if tcpip(adapter)["dns_assignment"] == "automatic":
            print(f"note: DNS is still automatic, which needs DHCP. Set DNS servers with '{prefix} dns 1.1.1.1 8.8.8.8'.")
    else:
        raise NetError(f"usage: {prefix} ip | {prefix} ip auto | {prefix} ip manual <ip>/<prefix> [<gateway>]", 2)
    time.sleep(1)  # give Windows a moment to apply the address before reading it back
    _show_ip(refresh(adapter), options, prefix)


def _dns_state(adapter):
    tcp = tcpip(adapter)
    return {
        "adapter": adapter["name"],
        "dns_assignment": tcp["dns_assignment"],
        "dns_servers": adapter["dns_servers"],
        "manual_dns": tcp["manual_dns"],
    }


def _show_dns(adapter, options, prefix):
    state = _dns_state(adapter)
    if options["json"]:
        _core.print_json(state)
        return
    render(f"{adapter['name']}: DNS settings", [
        ("now", [
            ("DNS assignment", state["dns_assignment"]),
            ("DNS servers in use", state["dns_servers"]),
        ]),
        ("change it with", [
            (f"{prefix} dns auto", "use the servers the router hands out, the usual choice"),
            (f"{prefix} dns <server> [<server>...]", f"e.g. {prefix} dns 1.1.1.1 8.8.8.8 (IPv6 servers work too)"),
        ]),
    ])


def _dns_command(adapter, rest, options, prefix):
    if not rest:
        _show_dns(adapter, options, prefix)
        return
    name = adapter["name"]
    if rest[0].lower() in AUTO_WORDS and len(rest) == 1:
        need_admin()
        print(f"setting {name} to get DNS servers automatically...")
        for family in ("ipv4", "ipv6"):
            tool_ok(["netsh", "interface", family, "set", "dnsservers", f"name={name}", "source=dhcp"])
    else:
        try:
            servers = [ipaddress.ip_address(word) for word in rest]
        except ValueError as e:
            raise NetError(f"{e}. usage: {prefix} dns auto | {prefix} dns <server> [<server>...]", 2)
        need_admin()
        print(f"setting {name}'s DNS servers to {', '.join(str(s) for s in servers)}...")
        for family, version in (("ipv4", 4), ("ipv6", 6)):
            group = [str(server) for server in servers if server.version == version]
            if not group:
                continue  # a family not typed keeps its current servers
            tool_ok(["netsh", "interface", family, "set", "dnsservers", f"name={name}", "source=static",
                     f"address={group[0]}", "register=primary", "validate=no"])
            for index, server in enumerate(group[1:], start=2):
                tool_ok(["netsh", "interface", family, "add", "dnsservers", f"name={name}",
                         f"address={server}", f"index={index}", "validate=no"])
    time.sleep(1)
    _show_dns(refresh(adapter), options, prefix)


# ======================================================================
# METERED ETHERNET — the switch Settings keeps under DusmSvc (Data Usage service)
# ======================================================================
def ethernet_metered(adapter):
    return reg_read(f"{DUSM}\\{adapter['guid']}\\*", "UserCost", NOT_METERED) == METERED


def set_ethernet_metered(adapter, on):
    """Set the metered switch, then restart the Data Usage service so Windows picks it up.
    Returns False if the service did not come back on its own."""
    try:
        with winreg.CreateKeyEx(HKLM, f"{DUSM}\\{adapter['guid']}\\*", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "UserCost", 0, winreg.REG_DWORD, METERED if on else NOT_METERED)
    except PermissionError:
        raise NetError(ADMIN_HINT)
    restarted = restart_service("DusmSvc")
    if ethernet_metered(adapter) != on:
        raise NetError("Windows did not keep the change. Check that the terminal is an administrator.")
    return restarted


# ======================================================================
# CONNECTION SHARING — "Allow other network users to connect through this computer's
# Internet connection", and the "Home networking connection" dropdown under it
# ======================================================================
def sharing_state():
    """{adapter GUID: "public" or "private"} for every connection Windows is sharing.
    Read from Windows' HomeNet records, which need no administrator rights."""
    wmi = _wmi("root\\Microsoft\\HomeNet")
    state = {}
    for row in wmi.ExecQuery("SELECT * FROM HNet_ConnectionProperties"):
        match = re.search(r"\{[0-9A-Fa-f-]+\}", _prop(row, "Connection") or "")
        if not match:
            continue
        if _prop(row, "IsIcsPublic"):
            state[match.group(0).upper()] = "public"
        elif _prop(row, "IsIcsPrivate"):
            state[match.group(0).upper()] = "private"
    return state


def home_choices(adapter):
    """The connections that can be the home network, by name, numbered from 1: the same list as the
    'Home networking connection' dropdown, which offers every other wired or wireless connection."""
    found = [a for a in _read_adapters() if a["if_type"] in (IF_ETHERNET, IF_WIFI) and a["guid"] != adapter["guid"]]
    found.sort(key=lambda a: a["name"].lower())
    for number, choice in enumerate(found, start=1):
        choice["id"] = number
    return found


def _share_configs():
    """{adapter GUID: sharing configuration} from Windows' connection sharing manager (administrator only)."""
    comtypes = _com()
    try:
        manager = comtypes.client.CreateObject("HNetCfg.HNetShare", dynamic=True)
        configs = {}
        for connection in manager.EnumEveryConnection:
            props = manager.NetConnectionProps(connection)
            configs[props.Guid.upper()] = manager.INetSharingConfigurationForINetConnection(connection)
        return configs
    except (OSError, comtypes.COMError) as e:
        raise NetError(f"Windows would not open connection sharing: {e}")


def _share_data(adapter):
    state = sharing_state()
    choices = home_choices(adapter)
    home = next((c for c in choices if state.get(c["guid"]) == "private"), None)
    return {
        "adapter": adapter["name"],
        "shared": state.get(adapter["guid"]) == "public",
        "home_network": home["name"] if home else None,
        "home_choices": [{"id": c["id"], "name": c["name"], "hardware": c["description"]} for c in choices],
        "shared_elsewhere": [a["name"] for a in _read_adapters() if state.get(a["guid"]) == "public"
                             and a["guid"] != adapter["guid"]],
    }


def _show_share(adapter, options, prefix):
    data = _share_data(adapter)
    if options["json"]:
        _core.print_json(data)
        return
    now = [
        ("allow other devices to use this connection", data["shared"]),
        ("home networking connection", data["home_network"]),
    ]
    if data["shared_elsewhere"]:
        now.append(("note", f"already sharing {', '.join(data['shared_elsewhere'])}; Windows shares one at a time"))
    render(f"{adapter['name']}: Internet Connection Sharing", [
        ("now", now),
        ("home networking connection (pick one)", [(str(c["id"]), f"{c['name']}  ({c['hardware']})")
                                                   for c in data["home_choices"]]),
        ("change it with", [
            (f"{prefix} share on <id>", f"share {adapter['name']}'s internet with that connection"),
            (f"{prefix} share off", "stop sharing"),
        ]),
    ])


def _share_command(adapter, rest, options, prefix):
    if not rest:
        _show_share(adapter, options, prefix)
        return
    word = rest[0].lower()
    if word in ON_WORDS and len(rest) == 2:
        choices = home_choices(adapter)
        home = next((c for c in choices if str(c["id"]) == rest[1] or c["name"].lower() == rest[1].lower()), None)
        if home is None:
            raise NetError(f"no home networking connection {rest[1]}. Run '{prefix} share' to see them.", 2)
        need_admin()
        if not _core.confirm(
            f"Share {adapter['name']}'s internet with {home['name']}? Windows gives {home['name']} the address "
            f"{ICS_ADDRESS} and hands out addresses to devices plugged into it, replacing its own IP settings. "
            f"Any other sharing stops. [y/N]: ", options["yes"]
        ):
            print("cancelled")
            return
        configs = _share_configs()
        if adapter["guid"] not in configs or home["guid"] not in configs:
            raise NetError("Windows' sharing manager does not list one of these connections")
        print(f"sharing {adapter['name']} with {home['name']}... expect devices on {home['name']} to get "
              "addresses within a minute.")
        comtypes = _com()
        try:
            for guid, config in configs.items():
                if config.SharingEnabled and guid not in (adapter["guid"], home["guid"]):
                    config.DisableSharing()  # Windows shares one connection at a time
            configs[adapter["guid"]].EnableSharing(ICS_PUBLIC)
            configs[home["guid"]].EnableSharing(ICS_PRIVATE)
        except (OSError, comtypes.COMError) as e:
            raise NetError(f"Windows would not turn sharing on: {e}")
    elif word in OFF_WORDS and len(rest) == 1:
        need_admin()
        configs = _share_configs()
        print("stopping Internet Connection Sharing...")
        comtypes = _com()
        try:
            for config in configs.values():
                if config.SharingEnabled:
                    config.DisableSharing()
        except (OSError, comtypes.COMError) as e:
            raise NetError(f"Windows would not turn sharing off: {e}")
    elif word in ON_WORDS:
        raise NetError(f"pick the home network: {prefix} share on <id>. Run '{prefix} share' to see the ids.", 2)
    else:
        raise NetError(f"usage: {prefix} share | {prefix} share on <id> | {prefix} share off", 2)
    _show_share(adapter, options, prefix)


# ======================================================================
# FEATURES — the checkboxes on an adapter's Properties (bindings), and installing or
# uninstalling them, which affects every adapter on the PC
# ======================================================================
def installed_components():
    """Component ids installed on this PC, from 'netcfg -s n' (needs no administrator rights)."""
    text = tool_ok(["netcfg", "-s", "n"])
    return {line.split()[0].lower() for line in text.splitlines() if re.match(r"^[a-z][\w.-]*\s{2,}\S", line, re.I)}


def _binding_rows(adapter):
    """{component id: (WMI row, Windows' name, enabled)} for everything bound to this adapter."""
    wmi = _wmi("root\\StandardCimv2")
    query = f"SELECT * FROM MSFT_NetAdapterBindingSettingData WHERE Name = '{_wql(adapter['name'])}'"
    rows = {}
    for row in wmi.ExecQuery(query):
        rows[_prop(row, "ComponentID").lower()] = (row, _prop(row, "DisplayName"), bool(_prop(row, "Enabled")))
    return rows


def features(adapter):
    """The features on this adapter: Windows' eight first (ids 1-8, always the same), then anything else
    bound to it, by name. The list and the ids both come from here."""
    rows = _binding_rows(adapter)
    installed = installed_components()
    listed = []
    for number, (component, key, name, kind, purpose) in enumerate(FEATURES, start=1):
        bound = rows.pop(component, None)
        listed.append({
            "id": number, "key": key, "component": component, "name": name, "class": kind, "purpose": purpose,
            "installed": bound is not None or component in installed,
            "enabled": bool(bound and bound[2]),
            "_row": bound[0] if bound else None,
        })
    others = sorted(rows.items(), key=lambda item: item[1][1].lower())
    for number, (component, (row, name, enabled)) in enumerate(others, start=len(FEATURES) + 1):
        listed.append({"id": number, "key": component, "component": component, "name": name, "class": None,
                       "purpose": "", "installed": True, "enabled": enabled, "_row": row})
    return listed


def _find_feature(word, listed, prefix):
    lowered = word.lower()
    for feature in listed:
        if lowered in (str(feature["id"]), feature["key"], feature["component"]):
            return feature
    raise NetError(f"no feature {word}. Run '{prefix} features' to see them.", 2)


def _feature_state(feature):
    if not feature["installed"]:
        return "not installed"
    return "on" if feature["enabled"] else "off"


def _show_features(adapter, options, prefix):
    listed = features(adapter)
    if options["json"]:
        _core.print_json({"adapter": adapter["name"], "features": [public(f) for f in listed]})
        return
    os.system("")  # enables ANSI colour codes in the Windows console
    short = max(len(feature["key"]) for feature in listed) + 2
    lines = [f"{adapter['name']}: features (the checkboxes on the adapter's Properties)", "",
             f"  {'ID':<4}{'SHORT':<{short}}{'STATE':<15}FEATURE"]
    for feature in listed:
        color = GREEN if feature["enabled"] else (RED if not feature["installed"] else GREY)
        lines.append(color + f"  {feature['id']:<4}{feature['key']:<{short}}{_feature_state(feature):<15}"
                     f"{feature['name']}" + RESET)
    lines += ["", f"green = on, grey = off, red = not installed. '{prefix} features <id>' explains one.",
              f"Change one with '{prefix} features <id or short name> on|off', e.g. {prefix} features ipv6 off."]
    print("\n".join(lines))


def _set_feature(adapter, feature, on, options, prefix):
    if feature["_row"] is None:
        raise NetError(f"{feature['name']} is not installed. Install it with '{prefix} features install {feature['key']}'.")
    need_admin()
    if not on and feature["component"] == "ms_tcpip" and adapter["connected"]:
        if not _core.confirm(f"Turn off IPv4 on {adapter['name']}? Most connections stop until you turn it back "
                             f"on with '{prefix} features ipv4 on'. [y/N]: ", options["yes"]):
            print("cancelled")
            return
    print(f"turning {feature['name']} {'on' if on else 'off'} for {adapter['name']}...")
    comtypes = _com()
    try:
        result = feature["_row"].ExecMethod_("Enable" if on else "Disable")
        code = _prop(result, "ReturnValue")
    except (OSError, comtypes.COMError) as e:
        raise NetError(f"Windows would not change it: {e}. {ADMIN_HINT}")
    if code:
        raise NetError(f"Windows would not change it (code {code})")
    now = _find_feature(feature["key"], features(adapter), prefix)
    print(f"{now['name']}: {_feature_state(now)}")


def _netcfg(args, done_word):
    """Run netcfg to install or uninstall; returns its message. netcfg can return a non-zero code
    when it succeeded but wants a restart, so its words decide."""
    ok, text = run_tool(["netcfg", *args], timeout=300)
    lowered = text.lower()
    if not ok and done_word not in lowered:
        raise NetError(explain(text))
    if "reboot" in lowered or "restart" in lowered:
        print("note: Windows needs a restart to finish this.")
    return text


def _install_command(rest, options, prefix):
    catalog = installed_components()
    if not rest:
        missing = [(n, f) for n, f in enumerate(FEATURES, start=1) if f[0] not in catalog]
        lines = [f"features you can install (they apply to every adapter on this PC):", ""]
        lines += [f"  {number:<4}{key:<11}{name}" for number, (component, key, name, kind, purpose) in missing]
        if not missing:
            lines.append("  (all of Windows' features are installed)")
        lines += ["", f"  {prefix} features install <id or short name>",
                  f"  {prefix} features install file <path.inf> client|service|protocol <component id>"
                  "   (from a driver's file, like 'Have Disk')"]
        if options["json"]:
            _core.print_json([{"id": n, "key": f[1], "component": f[0], "name": f[2]} for n, f in missing])
        else:
            print(_core.BLUE + "\n".join(lines) + _core.RESET)
        return
    if rest[0].lower() == "file":
        if len(rest) != 4 or rest[2].lower() not in NETCFG_CLASSES:
            raise NetError(f"usage: {prefix} features install file <path.inf> client|service|protocol <component id>", 2)
        inf, kind, component = os.path.abspath(rest[1]), NETCFG_CLASSES[rest[2].lower()], rest[3]
        if not os.path.isfile(inf):
            raise NetError(f"no such file: {inf}", 2)
        need_admin()
        print(f"installing {component} from {inf}... expect a short pause while Windows binds it to every adapter.")
        _netcfg(["-l", inf, "-c", kind, "-i", component], "success")
        print(f"installed {component}")
        return
    if len(rest) != 1:
        raise NetError(f"usage: {prefix} features install <id or short name>", 2)
    match = [f for n, f in enumerate(FEATURES, start=1) if rest[0].lower() in (str(n), f[1], f[0])]
    if not match:
        raise NetError(f"no feature {rest[0]}. Run '{prefix} features install' to see them.", 2)
    component, key, name, kind, _ = match[0]
    if component in catalog:
        print(f"{name} is already installed")
        return
    need_admin()
    print(f"installing {name}... expect a short pause while Windows binds it to every adapter.")
    _netcfg(["-c", kind, "-i", component], "success")
    print(f"installed {name}" if component in installed_components() else f"netcfg finished; check '{prefix} features'")


def _uninstall_command(adapter, rest, options, prefix):
    if len(rest) != 1:
        raise NetError(f"usage: {prefix} features rm <id or short name>", 2)
    feature = _find_feature(rest[0], features(adapter), prefix)
    if feature["component"] in BUILT_IN:
        raise NetError(f"{feature['name']} is part of Windows and can't be uninstalled. "
                       f"Turn it off instead: {prefix} features {feature['key']} off")
    if not feature["installed"]:
        print(f"{feature['name']} is not installed")
        return
    need_admin()
    again = f" Put it back with '{prefix} features install {feature['key']}'." if feature["class"] else ""
    if not _core.confirm(f"Uninstall {feature['name']} from this PC? It goes from every adapter, not just "
                         f"{adapter['name']}.{again} [y/N]: ", options["yes"]):
        print("cancelled")
        return
    print(f"uninstalling {feature['name']}... expect a short pause.")
    _netcfg(["-u", feature["component"]], "success")
    print(f"uninstalled {feature['name']}" if feature["component"] not in installed_components()
          else f"netcfg finished; check '{prefix} features'")


def _features_command(adapter, rest, options, prefix):
    if not rest or rest[0].lower() in LIST_WORDS:
        _show_features(adapter, options, prefix)
        return
    word = rest[0].lower()
    if word == "install":
        _install_command(rest[1:], options, prefix)
        return
    if word in REMOVE_WORDS:
        _uninstall_command(adapter, rest[1:], options, prefix)
        return
    feature = _find_feature(rest[0], features(adapter), prefix)
    if len(rest) == 1:
        if options["json"]:
            _core.print_json(public(feature))
            return
        print(_core.BLUE + f"{feature['name']} ({feature['component']}): {_feature_state(feature)}\n"
              f"  {feature['purpose'] or 'added by another program or driver'}" + _core.RESET)
        return
    if len(rest) != 2:
        raise NetError(f"usage: {prefix} features <id> on|off", 2)
    _set_feature(adapter, feature, on_off(rest[1], f"{prefix} features ipv6 off"), options, prefix)


ADAPTER_WORDS = ("ip", "dns", "share", "sharing", "ics", "features", "feature", "properties")


def adapter_command(word, rest, adapter, options, prefix):
    """The commands wifi and ethernet share (the words in ADAPTER_WORDS). Returns False for any other word."""
    if word == "ip":
        _ip_command(adapter, rest, options, prefix)
    elif word == "dns":
        _dns_command(adapter, rest, options, prefix)
    elif word in ("share", "sharing", "ics"):
        _share_command(adapter, rest, options, prefix)
    elif word in ("features", "feature", "properties"):
        _features_command(adapter, rest, options, prefix)
    else:
        return False
    return True


# ======================================================================
# 802.1X — sign-in for work and school networks. Simple switches go through netsh; the
# method and "remember my credentials" are edits to the exported profile XML
# ======================================================================
EAP_METHODS = {
    13: "smart card or other certificate (EAP-TLS)", 21: "EAP-TTLS", 25: "Protected EAP (PEAP)",
    26: "EAP-MSCHAPv2", 18: "EAP-SIM", 23: "EAP-AKA", 50: "EAP-AKA'",
}
METHOD_WORDS = {"peap": "peap", "certificate": "tls", "cert": "tls", "tls": "tls", "smartcard": "tls", "ttls": "ttls"}
AUTH_MODES = {"user": "userOnly", "computer": "machineOnly", "machine": "machineOnly",
              "both": "machineOrUser", "guest": "guest"}
AUTH_MODE_NAMES = {"userOnly": "user", "machineOnly": "computer", "machineOrUser": "user or computer",
                   "guest": "guest"}
SSO_MODES = {"before": "preLogon", "after": "postLogon", "off": "none"}
SSO_NAMES = {"preLogon": "before sign-in", "postLogon": "after sign-in", "none": "off"}

_EAP_COMMON = ('<Type xmlns="http://www.microsoft.com/provisioning/EapCommon">{type}</Type>'
               '<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>'
               '<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>'
               '<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">{author}</AuthorId>')
_EAP_WRAP = ('<EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">'
             '<EapMethod>{method}</EapMethod>'
             '<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">{config}</Config>'
             '</EapHostConfig></EAPConfig>')
# Windows' defaults for each method in the Authentication tab's dropdown
EAP_CONFIGS = {
    "peap": _EAP_WRAP.format(method=_EAP_COMMON.format(type=25, author=0), config=(
        '<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type>'
        '<EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">'
        '<ServerValidation><DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>'
        '<ServerNames></ServerNames></ServerValidation><FastReconnect>true</FastReconnect>'
        '<InnerEapOptional>false</InnerEapOptional>'
        '<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type>'
        '<EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">'
        '<UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap>'
        '<EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>false</RequireCryptoBinding>'
        '<PeapExtensions><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">'
        'true</PerformServerValidation><AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">'
        'false</AcceptServerName></PeapExtensions></EapType></Eap>')),
    "tls": _EAP_WRAP.format(method=_EAP_COMMON.format(type=13, author=0), config=(
        '<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>13</Type>'
        '<EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">'
        '<CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore>'
        '</CredentialsSource><ServerValidation><DisableUserPromptForServerValidation>false'
        '</DisableUserPromptForServerValidation><ServerNames></ServerNames></ServerValidation>'
        '<DifferentUsername>false</DifferentUsername>'
        '<PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true'
        '</PerformServerValidation><AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">'
        'false</AcceptServerName></EapType></Eap>')),
    "ttls": _EAP_WRAP.format(method=_EAP_COMMON.format(type=21, author=311), config=(
        '<EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1">'
        '<ServerValidation><ServerNames></ServerNames><DisablePrompt>false</DisablePrompt></ServerValidation>'
        '<Phase2Authentication><MSCHAPv2Authentication><UseWinlogonCredentials>false</UseWinlogonCredentials>'
        '</MSCHAPv2Authentication></Phase2Authentication>'
        '<Phase1Identity><IdentityPrivacy>false</IdentityPrivacy></Phase1Identity></EapTtls>')),
}

LAN_PROFILE = """<?xml version="1.0"?>
<LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1">
    <MSM>
        <security>
            <OneXEnforced>false</OneXEnforced>
            <OneXEnabled>true</OneXEnabled>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <cacheUserData>true</cacheUserData>
                <authMode>machineOrUser</authMode>
                {eap}
            </OneX>
        </security>
    </MSM>
</LANProfile>
"""


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _true(text, default):
    if text is None:
        return default
    return text.strip().lower() == "true"


def onex_summary(xml_text):
    """The 802.1X settings in a LAN or Wi-Fi profile, in plain words."""
    root = ET.fromstring(xml_text)
    found = {}
    method = None
    for element in root.iter():
        name = _local(element.tag)
        if name == "EapMethod":
            for child in element:
                if _local(child.tag) == "Type" and method is None:
                    method = int(child.text)
        elif name not in found:
            found[name] = element.text
    sso = None
    for element in root.iter():
        if _local(element.tag) == "singleSignOn":
            sso = next((c.text for c in element if _local(c.tag) == "type"), None)
    wired = _local(root.tag) == "LANProfile"
    enabled = _true(found.get("OneXEnabled"), False) if wired else _true(found.get("useOneX"), False)
    return {
        "enabled": enabled,
        "method": EAP_METHODS.get(method, f"EAP type {method}") if method else None,
        "mode": AUTH_MODE_NAMES.get(found.get("authMode") or "machineOrUser", found.get("authMode")),
        "remember_credentials": _true(found.get("cacheUserData"), True),
        "fallback_to_unauthorized": (not _true(found.get("OneXEnforced"), False)) if wired else None,
        "single_sign_on": SSO_NAMES.get(sso or "none", sso),
        "authentication": found.get("authentication"),
    }


def export_xml(build_args):
    """Run a netsh export into a temporary folder and return the XML it wrote, or None.
    build_args gets the folder and returns netsh's arguments. The folder is deleted afterwards."""
    with tempfile.TemporaryDirectory() as folder:
        tool_ok(build_args(folder))
        files = [name for name in os.listdir(folder) if name.lower().endswith(".xml")]
        if not files:
            return None
        with open(os.path.join(folder, files[0]), encoding="utf-8-sig") as file:
            return file.read()


def add_xml(xml_text, build_args):
    """Write XML to a temporary file, run netsh's add profile on it, and delete the file."""
    fd, path = tempfile.mkstemp(suffix=".xml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(xml_text)
        tool_ok(build_args(path))
    finally:
        os.remove(path)


def with_cache(xml_text, on):
    """The profile with 'remember my credentials' set. It is the first setting inside OneX, so it goes there."""
    value = "true" if on else "false"
    pattern = r"<cacheUserData>\s*\w*\s*</cacheUserData>"
    if re.search(pattern, xml_text):
        return re.sub(pattern, f"<cacheUserData>{value}</cacheUserData>", xml_text, count=1)
    return re.sub(r"(<OneX\b[^>]*>)", rf"\1<cacheUserData>{value}</cacheUserData>", xml_text, count=1)


def with_method(xml_text, method):
    """The profile with its sign-in method swapped for Windows' default settings for that method."""
    if not re.search(r"<EAPConfig>.*?</EAPConfig>", xml_text, re.S):
        raise NetError("this profile has no sign-in method to change")
    return re.sub(r"<EAPConfig>.*?</EAPConfig>", lambda _: EAP_CONFIGS[method], xml_text, count=1, flags=re.S)


def method_word(word, prefix):
    try:
        return METHOD_WORDS[word.lower()]
    except KeyError:
        raise NetError(f"use peap, certificate or ttls, e.g. {prefix} auth method peap", 2)


def mode_word(word, prefix):
    try:
        return AUTH_MODES[word.lower()]
    except KeyError:
        raise NetError(f"use user, computer, both or guest, e.g. {prefix} auth mode user", 2)


def sso_word(word, prefix):
    try:
        return SSO_MODES[word.lower()]
    except KeyError:
        raise NetError(f"use before, after or off, e.g. {prefix} auth sso before", 2)


def auth_rows(state):
    """The rows 'auth' and 'info' show for 802.1X."""
    rows = [("802.1X sign-in", state.get("enabled"))]
    if state.get("enabled"):
        rows += [
            ("method", state.get("method")),
            ("sign in as", state.get("mode")),
            ("remember my credentials", state.get("remember_credentials")),
            ("single sign-on", state.get("single_sign_on")),
        ]
        if state.get("fallback_to_unauthorized") is not None:
            rows.append(("fallback to unauthorised access", state["fallback_to_unauthorized"]))
    if state.get("note"):
        rows.append(("note", state["note"]))
    return rows

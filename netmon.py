"""
netmon: a live view of this PC's network connections. Routed from app.py
("netmon", "net", "nm" or "traffic").

    net                        overview: interfaces, connections, busiest programs, findings
    net live [seconds]         live view, redrawn every 2 s (Ctrl+C stops and saves a sample)
    net ls [options]           every connection, one row each, sorted and filtered
    net <id>                   one connection in full: its program, why it exists, what you can do
    net procs                  traffic by program: connections, peers, and what each one is
    net bytes [seconds]        bytes per program, address and protocol, measured for a few seconds (administrator)
    net bytes last | clear     show the last measurement without measuring, or delete it
    net iface                  Wi-Fi and Ethernet: speed, bytes since Windows started, rate now
    net history [days]         totals and busiest programs from earlier net live sessions
    net history clear          delete the saved samples (asks first)
    net kill <id>              end the program that owns a connection (asks first)
    net block [ls]             list the addresses blocked by this page
    net block <id|ip>          block all traffic to and from an address (administrator; asks first)
    net unblock <ip>           remove the blocks this page made for an address

net ls options: --sort program|remote|port|state|seen|domain|proto (seen puts the longest open
first), --reverse, --state listen|established|..., --proto tcp|udp, --process <name>, --ip <address>,
--loopback (also shows connections that stay on this PC), --bytes (adds the bytes net bytes last saw).
net bytes options: --sort total|in|out|program, --reverse, --loopback.

Byte counts per adapter come from net iface and need no administrator rights. Windows gives ordinary users
no byte counts per connection or per program, so net bytes measures them for a short window: as administrator
it runs a Windows trace session (the Microsoft-Windows-Kernel-Network provider, started and stopped with
logman), reads the trace back with Get-WinEvent, adds the bytes up and deletes the trace. The session is always
stopped, even on Ctrl+C. The last measurement is kept in a small file, and net procs and net <id> show it
(with how long ago it was taken). "open for" is the time since net first saw a connection; net keeps that in
a small file, so it survives between runs.

Needs psutil (see requirements.txt). Blocking uses netsh and Windows Firewall, and needs administrator rights.
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil

import _core
import _net
import _win
import process as process_page  # the same rule prc uses for system programs

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "netmon"
ALIASES = ["net", "nm", "traffic"]
SUMMARY = "Network monitor: connections, programs, bytes, blocks"
# extra words people use, for 'settings search'
KEYWORDS = ["bandwidth", "traffic", "connections", "ports", "netstat", "who is using the network",
            "data usage", "bytes"]
USAGE = ("net | net live [sec] | net ls [options] | net <id> | net procs | net bytes [sec] | net iface | net history | "
         "net kill <id> | net block <id|ip>")
HELP = [
    ("net", "overview: interfaces, connections, and what is using the network"),
    ("net live", "live view, refreshed every 2 s (Ctrl+C to stop)"),
    ("net ls", "every connection, with its program, domain and how long it has been open"),
    ("net <id>", "one connection in full, with why it exists and what you can do"),
    ("net procs", "connections by program, and what each one is"),
    ("net bytes [seconds]", "bytes in and out per program, measured for a few seconds (administrator)"),
    ("net iface", "Wi-Fi and Ethernet: speed, bytes, and the rate now"),
    ("net history", "totals from earlier net live sessions"),
    ("net kill <id>", "end the program that owns a connection (asks first)"),
    ("net block <id|ip>", "block all traffic to and from an address (administrator; asks first)"),
]
TIP = ("Bytes per program need an administrator terminal: 'net bytes' measures them for 10 seconds. "
       "Without it, byte counts are per adapter ('net iface').")
RUN_ALONE = True  # typing 'net' on its own shows the overview, which changes nothing; 'net help' shows this intro

CYAN, GREEN, YELLOW, MAGENTA, BLUE = "\033[96m", "\033[92m", "\033[93m", "\033[95m", "\033[94m"
RED, GREY, RESET = "\033[91m", "\033[90m", "\033[0m"
SECTION_COLORS = [CYAN, GREEN, YELLOW, MAGENTA, BLUE]  # the palette the other pages use
CELL_MAX = 40  # a table cell longer than this is cut with "..."
MIB = 1024 * 1024
RATE_SECONDS = 1.0  # how long the overview and net iface watch the counters for a rate
LIVE_DEFAULT = 2
LIVE_MAX = 60
LOOKUP_BUDGET = 2.0  # seconds one command waits for name lookups
LIVE_LOOKUP_BUDGET = 0.3  # live refreshes do not wait for names; they fill in on later refreshes
MAX_LOOKUPS = 64  # reverse lookups started per refresh
BUSY_PEERS = 50  # a program talking to this many addresses is listed as busy
ANY_ADDRESS = ("0.0.0.0", "::")  # listening here means "any address", so other devices can reach it
TEMP_MARKS = ("\\temp\\", "\\tmp\\", "\\downloads\\")
LIST_WORDS = ("ls", "list")
CLEAR_WORDS = ("clear", "rm", "delete")
SAMPLE_EVERY = 60  # seconds between history samples while net live runs
HISTORY_KEEP_DAYS = 30
HISTORY_MAX_BYTES = 2 * MIB
BLOCK_PREFIX = "w11-cli-console-block-"  # every firewall rule this page makes starts with this

DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "w11-cli-console"
SEEN_FILE = DATA_DIR / "net-seen.json"
HISTORY_FILE = DATA_DIR / "net-history.jsonl"

# What a program usually is, for the 'why' text. Keys are lower case.
PROGRAM_NOTES = {
    "chrome.exe": "a web browser: web pages, and its own updates and sync",
    "msedge.exe": "Microsoft Edge: web pages, and its own updates and sync",
    "firefox.exe": "a web browser: web pages and its own updates",
    "brave.exe": "a web browser: web pages and its own updates",
    "opera.exe": "a web browser: web pages and its own updates",
    "onedrive.exe": "OneDrive, syncing your files with Microsoft's cloud",
    "teams.exe": "Microsoft Teams: calls, chat and meetings",
    "ms-teams.exe": "Microsoft Teams: calls, chat and meetings",
    "outlook.exe": "Outlook: email and calendar",
    "olk.exe": "the new Outlook: email and calendar",
    "discord.exe": "Discord: voice and text chat",
    "spotify.exe": "Spotify: music streaming",
    "steam.exe": "Steam: the store, downloads and game servers",
    "steamwebhelper.exe": "Steam's built-in web pages",
    "zoom.exe": "Zoom: meetings and calls",
    "dropbox.exe": "Dropbox: syncing your files",
    "googledrivefs.exe": "Google Drive: syncing your files",
    "code.exe": "VS Code: extensions, updates and remote tools",
    "python.exe": "a Python program, possibly one you run yourself",
    "py.exe": "the Python launcher, running a Python program",
    "git.exe": "Git: fetching or pushing code",
    "svchost.exe": "a Windows service (several share this program; 'svc' lists them)",
    "system": "the Windows kernel: file sharing and other system traffic",
    "searchhost.exe": "Windows Search",
    "wslhost.exe": "WSL, Linux running on Windows",
    "vmmem": "a virtual machine (WSL or Hyper-V)",
}

# What a port is usually used for. Only a hint: a program can use any port.
PORT_MEANINGS = {
    20: "FTP data", 21: "FTP control", 22: "SSH (remote shell)",
    25: "email sending (SMTP)", 465: "email sending (SMTP)", 587: "email sending (SMTP)",
    53: "DNS (looking up names)", 67: "DHCP (getting an address)", 68: "DHCP (getting an address)",
    80: "unencrypted web (HTTP)", 8080: "alternate web (HTTP)",
    443: "encrypted web (HTTPS)", 8443: "alternate encrypted web (HTTPS)",
    110: "email reading (POP3)", 995: "email reading (POP3)",
    143: "email reading (IMAP)", 993: "email reading (IMAP)",
    123: "time sync (NTP)", 135: "Windows RPC (Windows services)",
    137: "NetBIOS (old Windows sharing)", 138: "NetBIOS (old Windows sharing)", 139: "NetBIOS (old Windows sharing)",
    445: "Windows file sharing (SMB)", 500: "VPN (IPsec)", 4500: "VPN (IPsec)", 1194: "VPN (OpenVPN)",
    51820: "VPN (WireGuard)", 1900: "device discovery (SSDP)", 5353: "local device discovery (mDNS)",
    5355: "local name lookup (LLMNR)", 3389: "Remote Desktop", 5985: "Windows remote management",
    5986: "Windows remote management", 3478: "calls and video (STUN/TURN)", 5222: "chat (XMPP)",
}

DOMAIN_STATUS = {  # shown in net <id> when there is no name, by why there is none
    "no name": "none found",
    "still looking up": "still looking up",
    "": "not looked up (not an internet address, or the lookup ran out of time)",
}

SORT_KEYS = {
    "program": lambda c: (c["program"].lower(), c["id"]),
    "remote": lambda c: (c["raddr"] or c["laddr"] or "", c["rport"] or c["lport"] or 0),
    "port": lambda c: (c["rport"] or c["lport"] or 0, c["id"]),
    "state": lambda c: (c["state"], c["id"]),
    "seen": lambda c: (c["first_seen"], c["id"]),
    "domain": lambda c: (c["domain"] or "~", c["id"]),
    "proto": lambda c: (c["proto"], c["id"]),
}


class NetmonError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# NAMES — the DNS cache Windows keeps, then reverse lookups for what it does not know
# ======================================================================
_DNS = {"at": 0.0, "names": {}}
DNS_CACHE_SECONDS = 60
_REVERSE = {}  # ip -> host name, or "" when there is none
_PENDING = set()  # ips with a lookup running
_LOCK = threading.Lock()


def _dns_names():
    """ip -> name, from the names this PC looked up recently (Get-DnsClientCache). Kept for a minute."""
    if time.time() - _DNS["at"] < DNS_CACHE_SECONDS:
        return _DNS["names"]
    names = {}
    script = "Get-DnsClientCache | Select-Object Entry,Data | ConvertTo-Json -Compress"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15,
        )
        rows = json.loads(result.stdout or "[]")
    except (OSError, subprocess.SubprocessError, ValueError):
        rows = []  # no names is better than a failed page
    if isinstance(rows, dict):
        rows = [rows]
    for row in rows:
        ip, name = _norm(row.get("Data") or ""), (row.get("Entry") or "").rstrip(".")
        if ip and name and ip not in names:
            names[ip] = name
    _DNS.update(at=time.time(), names=names)
    return names


def _lookup(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        name = ""
    with _LOCK:
        _REVERSE[ip] = name.rstrip(".")
        _PENDING.discard(ip)


def _resolve(ips, budget):
    """Starts a reverse lookup for each unknown address and waits up to budget seconds for them."""
    with _LOCK:
        todo = [ip for ip in ips if ip not in _REVERSE and ip not in _PENDING][:MAX_LOOKUPS]
        _PENDING.update(todo)
    threads = [threading.Thread(target=_lookup, args=(ip,), daemon=True) for ip in todo]
    for thread in threads:
        thread.start()
    deadline = time.time() + budget
    for thread in threads:
        thread.join(max(0.0, deadline - time.time()))


def _domain(ip, dns):
    """(name, where it came from) for a remote address. Empty when no name is known."""
    if ip in dns:
        return dns[ip], "Windows DNS cache"
    if ip in _REVERSE:
        return (_REVERSE[ip], "reverse lookup") if _REVERSE[ip] else ("", "no name")
    if ip in _PENDING:
        return "", "still looking up"
    return "", "not looked up"


# ======================================================================
# CONNECTIONS — one list, numbered the same way for every command
# ======================================================================
def _norm(text):
    """An IP address as text, without its zone (%1), or None if it is not an address."""
    try:
        return ipaddress.ip_address(str(text).split("%")[0]).compressed
    except ValueError:
        return None


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except (ValueError, AttributeError):
        return False


def _scope(ip):
    """Where an address is: this PC, the local network, the internet, or something else."""
    if ip is None:
        return ""
    try:
        address = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "other"
    if address.is_loopback:
        return "this PC"
    if address.is_private and not address.is_link_local:
        return "local network"
    if address.is_global:
        return "internet"
    return "other"


def _safe(getter):
    try:
        return getter()
    except psutil.Error:
        return None


def _program(pid, cache):
    """The program behind a pid: name, file, account, and whether it is part of Windows."""
    if pid in cache:
        return cache[pid]
    info = {"pid": pid, "program": "unknown", "exe": None, "username": None, "protected": False}
    if pid is not None:
        info["program"] = f"pid {pid}"
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            info["program"] = "(ended)"
        except psutil.Error:
            pass
        else:
            info["program"] = _safe(proc.name) or "(access denied)"
            info["exe"] = _safe(proc.exe)
            info["username"] = _safe(proc.username)
            info["protected"] = process_page._is_protected(pid, info["program"], info["exe"], info["username"])
    cache[pid] = info
    return info


def _address_owners():
    """ip -> adapter name, from the addresses Windows gives each adapter."""
    owners = {}
    try:
        found = _net._read_adapters()  # the same reading wifi and ethernet use
    except _net.NetError:
        return owners
    for adapter in found:
        for entry in adapter["ipv4"] + adapter["ipv6"]:
            owners[_norm(entry["address"])] = adapter["name"]
    return owners


def _remember(keys):
    """When net first saw each connection. Connections that are gone are forgotten."""
    now = time.time()
    previous = _read_json(SEEN_FILE, {})
    current = {key: previous.get(key, now) for key in keys}
    _write_json(SEEN_FILE, current)
    return current


def _read_json(path, default):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
    return data if isinstance(data, type(default)) else default


def _write_json(path, data):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass  # the page still works without the file; "open for" just restarts


def _gather(budget=LOOKUP_BUDGET):
    """Every connection on this PC, numbered from 1 in name order. Ids are for this one reading."""
    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.Error as e:
        raise NetmonError(f"Windows would not list the connections: {e}")
    owners = _address_owners()
    cache = {}
    conns = []
    for c in raw:
        if not c.laddr:
            continue
        laddr, lport = _norm(c.laddr.ip), c.laddr.port
        raddr = _norm(c.raddr.ip) if c.raddr else None
        rport = c.raddr.port if c.raddr else None
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        state = c.status if c.status not in (None, "", psutil.CONN_NONE) else "-"
        listening = state == psutil.CONN_LISTEN or (proto == "udp" and raddr is None)
        prog = _program(c.pid, cache)
        if laddr in ANY_ADDRESS:
            via = "all interfaces"
        else:
            via = owners.get(laddr, "")
        conns.append({
            "pid": c.pid,
            "program": prog["program"],
            "exe": prog["exe"],
            "username": prog["username"],
            "protected": prog["protected"],
            "proto": proto,
            "state": state,
            "listening": listening,
            "laddr": laddr,
            "lport": lport,
            "raddr": raddr,
            "rport": rport,
            "scope": _scope(raddr),
            "local_only": _is_loopback(laddr) and (raddr is None or _is_loopback(raddr)),
            "via": via,
            "domain": "",
            "domain_source": "",
        })
    dns = _dns_names()
    internet = sorted({c["raddr"] for c in conns if c["scope"] == "internet"})
    _resolve(internet, budget)
    for c in conns:
        if c["scope"] == "internet":
            c["domain"], c["domain_source"] = _domain(c["raddr"], dns)
    conns.sort(key=lambda c: (c["program"].lower(), c["pid"] or 0, c["proto"], c["lport"], c["raddr"] or "", c["rport"] or 0))
    for number, c in enumerate(conns, start=1):
        c["id"] = number
    seen = _remember([_key(c) for c in conns])
    for c in conns:
        c["key"] = _key(c)
        c["first_seen"] = seen[c["key"]]
    return conns


def _key(c):
    return f"{c['proto']}|{c['laddr']}:{c['lport']}|{c['raddr']}:{c['rport']}|{c['pid']}"


def _find(conns, number):
    for c in conns:
        if c["id"] == number:
            return c
    raise NetmonError(f"no connection with id {number}. Run 'net ls' to see them.", 2)


def _endpoint(ip, port):
    if ip is None:
        return "-"
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _from_temp(exe):
    return bool(exe) and any(mark in exe.lower() for mark in TEMP_MARKS)


def _programs(conns):
    """One row per program: connections, peers and the names they reach. Busiest first."""
    groups = {}
    for c in conns:
        key = c["program"].lower()
        group = groups.setdefault(key, {
            "program": c["program"], "pids": set(), "connections": 0, "established": 0,
            "listening": 0, "peers": set(), "domains": {}, "protected": False,
        })
        group["pids"].add(c["pid"])
        group["connections"] += 1
        group["established"] += c["state"] == psutil.CONN_ESTABLISHED
        group["listening"] += c["listening"]
        if c["raddr"] and not c["local_only"]:
            group["peers"].add(c["raddr"])
        if c["domain"]:
            group["domains"][c["domain"]] = group["domains"].get(c["domain"], 0) + 1
        group["protected"] = group["protected"] or c["protected"]
    rows = []
    for key, group in groups.items():
        domains = sorted(group["domains"], key=lambda d: (-group["domains"][d], d))
        note = PROGRAM_NOTES.get(key, "part of Windows" if group["protected"] else "")
        rows.append({
            "program": group["program"],
            "pids": sorted(p for p in group["pids"] if p is not None),
            "connections": group["connections"],
            "established": group["established"],
            "listening": group["listening"],
            "peers": len(group["peers"]),
            "domains": domains[:5],
            "protected": group["protected"],
            "note": note,
        })
    rows.sort(key=lambda g: (-g["connections"], g["program"].lower()))
    return rows


def _counts(conns):
    remote = {c["raddr"] for c in conns if c["raddr"] and not c["local_only"]}
    return {
        "connections": len(conns),
        "established": sum(1 for c in conns if c["state"] == psutil.CONN_ESTABLISHED),
        "listening": sum(1 for c in conns if c["listening"] and c["proto"] == "tcp"),
        "udp": sum(1 for c in conns if c["proto"] == "udp"),
        "programs": len({c["program"].lower() for c in conns}),
        "remote_addresses": len(remote),
    }


# ======================================================================
# ADAPTERS — bytes per Wi-Fi and Ethernet adapter, and the rate between two readings
# ======================================================================
IFACE_KINDS = ("wifi", "ethernet")


def _counters():
    return {name: c._asdict() for name, c in psutil.net_io_counters(pernic=True).items()}


def _match(adapter, counters):
    """The psutil name for an adapter: its friendly name or its description, ignoring case."""
    for key in (adapter["name"], adapter["description"]):
        for name in counters:
            if name.lower() == key.lower():
                return name
    return None


def _interfaces(now, before=None, elapsed=0.0):
    """Wi-Fi and Ethernet adapters with totals since Windows started, and the rate since 'before'."""
    rows = []
    for adapter in _net._read_adapters():
        if adapter["kind"] not in IFACE_KINDS:
            continue
        key = _match(adapter, now)
        counts = now.get(key) if key else None
        old = before.get(key) if (before and key) else None
        row = {
            "name": adapter["name"],
            "kind": adapter["kind"],
            "connected": adapter["connected"],
            "speed_mbps": adapter["speed_mbps"],
            "addresses": [a["address"] for a in adapter["ipv4"]],
            "down_rate": None,
            "up_rate": None,
            "total_in": None,
            "total_out": None,
            "errors": None,
            "drops": None,
        }
        if counts:
            row.update(
                total_in=counts["bytes_recv"], total_out=counts["bytes_sent"],
                errors=counts["errin"] + counts["errout"], drops=counts["dropin"] + counts["dropout"],
            )
            if old and elapsed > 0:
                row["down_rate"] = max(0, counts["bytes_recv"] - old["bytes_recv"]) / elapsed
                row["up_rate"] = max(0, counts["bytes_sent"] - old["bytes_sent"]) / elapsed
        rows.append(row)
    return rows


def _rates(seconds=RATE_SECONDS):
    before = _counters()
    time.sleep(seconds)
    return _interfaces(_counters(), before, seconds)


def _size(num_bytes):
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def _rate(bytes_per_second):
    return "-" if bytes_per_second is None else f"{_size(bytes_per_second)}/s"


def _bar(fraction, width=10):
    if fraction is None:
        return " " * width
    filled = round(max(0.0, min(1.0, fraction)) * width)
    return "#" * filled + "." * (width - filled)


def _capacity_fraction(rate, speed_mbps):
    """How full the link is: against its link speed, or against 1 MB/s when Windows does not say."""
    if rate is None:
        return None
    capacity = speed_mbps * 125000 if speed_mbps else MIB  # megabits per second in bytes per second
    return rate / capacity


def _iface_line(row):
    name = f"  {row['name']:<14}"
    if not row["connected"]:
        return f"{name} not connected"
    down = _capacity_fraction(row["down_rate"], row["speed_mbps"])
    up = _capacity_fraction(row["up_rate"], row["speed_mbps"])
    return (f"{name} down {_bar(down)} {_rate(row['down_rate']):>11}   "
            f"up {_bar(up)} {_rate(row['up_rate']):>11}")


def _address_of(conns, row):
    return sum(1 for c in conns if c["via"] == row["name"])


# ======================================================================
# FINDINGS AND WHY — plain-English reasons, from the port, the program and the address
# ======================================================================
def _why(conn):
    """The reasons a connection is there, as plain sentences."""
    lines = []
    name, proto = conn["program"], conn["proto"].upper()
    if conn["listening"]:
        lines.append(f"{name} is waiting for incoming {proto} traffic on port {conn['lport']}.")
        if conn["laddr"] in ANY_ADDRESS:
            lines.append("It accepts traffic from any address, so other devices on the network can reach it if Windows Firewall allows.")
        elif _is_loopback(conn["laddr"]):
            lines.append("It only accepts traffic from this PC.")
        else:
            lines.append(f"It accepts traffic on {conn['laddr']} only.")
        meaning = PORT_MEANINGS.get(conn["lport"])
        if meaning:
            lines.append(f"Port {conn['lport']} is usually {meaning}.")
    else:
        where = _endpoint(conn["raddr"], conn["rport"])
        if conn["scope"] == "this PC":
            lines.append(f"It talks to another program on this PC ({where}).")
        elif conn["scope"] == "local network":
            lines.append(f"It talks to a device on your local network ({where}).")
        elif conn["scope"] == "internet":
            target = conn["domain"] or conn["raddr"]
            lines.append(f"It talks to {target} on the internet ({where}).")
        else:
            lines.append(f"It talks to {where}.")
        meaning = PORT_MEANINGS.get(conn["rport"])
        if meaning:
            lines.append(f"Port {conn['rport']} is usually {meaning}.")
    note = PROGRAM_NOTES.get(name.lower())
    if conn["protected"]:
        lines.append(f"{name} is part of Windows. Do not end it.")
    elif note:
        lines.append(f"{name} is {note}.")
    else:
        lines.append(f"No description for {name}. Check where its file is, and whether you installed it.")
    if _from_temp(conn["exe"]):
        lines.append("It runs from a temporary or download folder. Installed programs normally do not, so check where it came from.")
    if conn["exe"] is None and not conn["protected"] and conn["pid"] is not None:
        lines.append("Windows did not show its file, so this program could not be checked.")
    return lines


def _findings(conns, rows):
    """Things worth a look. Each one is unusual, not proof of a problem."""
    found = []
    open_to_all = sorted({c["program"] for c in conns
                          if c["listening"] and c["laddr"] in ANY_ADDRESS and not c["protected"]}, key=str.lower)
    if open_to_all:
        found.append(f"{len(open_to_all)} program(s) accept traffic from any address: {', '.join(open_to_all[:8])}. "
                     "Check each one with 'net ls --state listen'.")
    temp = sorted({c["program"] for c in conns if _from_temp(c["exe"])}, key=str.lower)
    if temp:
        found.append(f"{', '.join(temp[:8])} run from a temporary or download folder. Check where they came from.")
    for group in _programs(conns):
        if group["peers"] >= BUSY_PEERS and not group["protected"]:
            found.append(f"{group['program']} talks to {group['peers']} different addresses. "
                         "Browsers and sync apps often do; check whether that is expected.")
    for row in rows:
        if row["connected"] and (row["errors"] or row["drops"]):
            found.append(f"{row['name']} reports {row['errors']} error(s) and {row['drops']} dropped packet(s) "
                         "since Windows started. A few are normal on Wi-Fi.")
    return found or ["nothing unusual found."]


# ======================================================================
# OUTPUT — the same look as the other pages: coloured sections, and tables with one colour per row
# ======================================================================
def _pairs(rows, color=""):
    width = max([len(label) for label, _ in rows] + [0]) + 3
    return [color + f"  {label:<{width}}{value}" + RESET for label, value in rows]


def _section(number, heading, body):
    """A heading in its own colour, then body lines that are already indented and coloured."""
    color = SECTION_COLORS[number % len(SECTION_COLORS)]
    return ["", color + f" {heading.upper()}" + RESET] + body


def _table(headers, rows, colors):
    """Indented lines of a table. Columns are as wide as their longest cell, up to CELL_MAX."""
    widths = [min(max([len(head)] + [len(row[i]) for row in rows]), CELL_MAX) for i, head in enumerate(headers)]

    def fit(text, width):
        return text if len(text) <= width else text[: width - 3] + "..."

    lines = ["  " + GREY + "  ".join(fit(h, w).ljust(w) for h, w in zip(headers, widths)).rstrip() + RESET]
    for row, color in zip(rows, colors):
        lines.append("  " + color + "  ".join(fit(cell, w).ljust(w) for cell, w in zip(row, widths)).rstrip() + RESET)
    return lines


def _row_color(conn):
    if conn["protected"]:
        return RED
    if conn["listening"]:
        return YELLOW
    if conn["state"] == psutil.CONN_ESTABLISHED:
        return GREEN
    return GREY


def _elapsed(seconds):
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds} s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min"
    return f"{hours // 24} d {hours % 24} h"


def _open_for(conn, now):
    return _elapsed(now - conn["first_seen"])


def _local_time(epoch):
    return time.strftime("%H:%M:%S %d %b", time.localtime(epoch))


def _say(lines):
    os.system("")  # enables ANSI colour codes in the Windows console
    print("\n".join(lines))


# ======================================================================
# OVERVIEW AND LISTS
# ======================================================================
def _overview(options):
    rows = _rates()
    conns = _gather()
    counts = _counts(conns)
    programs = _programs(conns)
    findings = _findings(conns, rows)
    if options["json"]:
        _core.print_json({"interfaces": rows, "counts": counts, "programs": programs[:10], "findings": findings})
        return 0
    lines = [CYAN + "netmon: what this PC is connected to" + RESET]
    lines += _section(0, "interfaces", [_iface_line(r) for r in rows] or ["no Wi-Fi or Ethernet adapter found"])
    lines += _section(1, "connections", _pairs([
        ("total", str(counts["connections"])),
        ("established", str(counts["established"])),
        ("listening (TCP)", str(counts["listening"])),
        ("udp", str(counts["udp"])),
        ("programs", str(counts["programs"])),
        ("remote addresses", str(counts["remote_addresses"])),
    ], GREEN))
    top = programs[:5]
    table = _table(
        ["program", "conns", "est", "listen", "peers", "talks to"],
        [[g["program"], str(g["connections"]), str(g["established"]), str(g["listening"]), str(g["peers"]),
          ", ".join(g["domains"]) or "-"] for g in top],
        [_group_color(g) for g in top],
    )
    lines += _section(2, "busiest programs", table)
    lines += _section(3, "findings", [f"  {text}" for text in findings])
    lines += _section(4, "next", _pairs([
        ("net live", "watch it change, every 2 s"),
        ("net ls", "every connection, with domains and how long it has been open"),
        ("net procs", "connections by program, with what each one is"),
        ("net bytes", "bytes in and out per program, measured for 10 seconds (administrator)"),
        ("net iface", "Wi-Fi and Ethernet bytes and speed"),
    ], BLUE))
    lines += ["", GREY + "  'net help' lists everything this page can do." + RESET]
    _say(lines)
    return 0


def _group_color(group):
    if group["protected"]:
        return RED
    return GREEN if group["established"] else GREY


def _select(conns, options):
    rows = conns
    if not options["loopback"]:
        rows = [c for c in rows if not c["local_only"]]
    if options.get("state"):
        rows = [c for c in rows if c["state"].lower().startswith(options["state"])]
    if options.get("proto"):
        rows = [c for c in rows if c["proto"] == options["proto"]]
    if options.get("process"):
        rows = [c for c in rows if c["program"].lower() == options["process"]]
    if options.get("ip"):
        rows = [c for c in rows if options["ip"] in (c["laddr"], c["raddr"])]
    sort = options.get("sort", "program")
    if sort not in SORT_KEYS:
        raise NetmonError(f"--sort must be one of: {', '.join(SORT_KEYS)}", 2)
    return sorted(rows, key=SORT_KEYS[sort], reverse=options.get("reverse", False))


def _list(rest, options):
    if rest:
        raise NetmonError("usage: net ls [--sort program|remote|port|state|seen|domain|proto] [--reverse] "
                          "[--state listen|established] [--proto tcp|udp] [--process <name>] [--ip <address>] [--loopback]", 2)
    conns = _gather()
    rows = _select(conns, options)
    measured = _fresh_measurement()
    if options["json"]:
        _core.print_json([dict(c, bytes=_connection_bytes(measured, c)) for c in rows])
        return 0
    if not rows:
        _say([CYAN + "no connections match. 'net ls --loopback' also shows the ones that stay on this PC." + RESET])
        return 0
    now = time.time()
    headers = ["id", "program", "proto", "state", "address", "domain", "open for"]
    cells = [[str(c["id"]), c["program"], c["proto"], c["state"],
              _endpoint(*((c["laddr"], c["lport"]) if c["listening"] else (c["raddr"], c["rport"]))),
              c["domain"] or "-", _open_for(c, now)] for c in rows]
    notes = []
    if options.get("bytes"):
        headers.append("bytes")
        for cell, c in zip(cells, rows):
            cell.append(_connection_bytes_text(measured, c))
        notes = ["", GREY + _measured_note(measured, "bytes") + RESET]
    table = _table(headers, cells, [_row_color(c) for c in rows])
    _say([f"{len(rows)} of {len(conns)} connections. 'net <id>' explains one. Ids follow the list, so they can shift.", ""]
         + table + notes)
    return 0


def _procs(options):
    conns = _gather()
    programs = _programs(conns)
    measured = _fresh_measurement()
    by_name = _bytes_by_program(measured)
    if options["json"]:
        for g in programs:
            g["bytes"] = by_name.get(g["program"].lower())
        _core.print_json(programs)
        return 0
    headers = ["program", "pids", "conns", "est", "listen", "peers", "talks to", "what it is"]
    cells = [[g["program"], str(len(g["pids"])), str(g["connections"]), str(g["established"]), str(g["listening"]),
              str(g["peers"]), ", ".join(g["domains"]) or "-", g["note"] or "-"] for g in programs]
    if measured:
        headers.insert(6, "bytes")
        for cell, g in zip(cells, programs):
            seen = by_name.get(g["program"].lower())
            cell.insert(6, _size(seen["total"]) if seen else "0 B")
        footnote = _measured_note(measured, "bytes") + " 'net iface' shows bytes per adapter."
    else:
        footnote = ("Bytes are not counted per program here. 'net iface' shows bytes per adapter, "
                    "and 'net bytes' measures them per program (administrator).")
    table = _table(headers, cells, [_group_color(g) for g in programs])
    _say([CYAN + f"{len(programs)} programs. Red is part of Windows; green has connections open now." + RESET, ""]
         + table + ["", GREY + footnote + RESET])
    return 0


# ======================================================================
# LIVE — redrawn in place; a history sample every minute
# ======================================================================
def _seconds(rest):
    if not rest:
        return LIVE_DEFAULT
    try:
        value = int(rest[0])
    except ValueError:
        raise NetmonError("usage: net live [seconds], e.g. net live 5", 2)
    if not 1 <= value <= LIVE_MAX:
        raise NetmonError(f"seconds must be from 1 to {LIVE_MAX}", 2)
    return value


def _frame(seconds, ifaces, conns, counts, programs, recent, since_start, now):
    lines = [CYAN + f"netmon live: every {seconds} s, {time.strftime('%H:%M:%S', time.localtime(now))}, Ctrl+C to stop" + RESET]
    lines += _section(0, "interfaces", [_iface_line(r) for r in ifaces] or ["no Wi-Fi or Ethernet adapter found"])
    lines += _section(1, "connections", _pairs([
        ("total", str(counts["connections"])),
        ("established", str(counts["established"])),
        ("listening (TCP)", str(counts["listening"])),
        ("new since start", str(since_start["new"])),
        ("closed since start", str(since_start["closed"])),
    ], GREEN))
    top = programs[:10]
    table = _table(
        ["program", "conns", "est", "listen", "peers", "talks to"],
        [[g["program"], str(g["connections"]), str(g["established"]), str(g["listening"]), str(g["peers"]),
          ", ".join(g["domains"]) or "-"] for g in top],
        [_group_color(g) for g in top],
    )
    lines += _section(2, "busiest programs", table)
    lines += _section(3, "newest connections", [
        f"  {_local_time(when)[:8]}  {program:<20} -> {target}" for when, program, target in recent
    ] or ["  none yet"])
    return "\033[2J\033[H" + "\n".join(lines) + "\n"


def _save_sample(ifaces, conns):
    sample = {
        "t": round(time.time(), 1),
        "ifaces": {row["name"]: [row["total_out"], row["total_in"]] for row in ifaces if row["total_in"] is not None},
        "programs": {},
    }
    for c in conns:
        sample["programs"][c["program"]] = sample["programs"].get(c["program"], 0) + 1
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > HISTORY_MAX_BYTES:
            cutoff = time.time() - HISTORY_KEEP_DAYS * 86400
            kept = [line for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines()
                    if _sample_time(line) >= cutoff]
            HISTORY_FILE.write_text("\n".join(kept) + "\n", encoding="utf-8")
        with HISTORY_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(sample) + "\n")
    except OSError as e:
        print(f"warning: could not save the sample: {e}", file=sys.stderr)


def _sample_time(line):
    try:
        return float(json.loads(line)["t"])
    except (ValueError, KeyError, TypeError):
        return 0.0


def _live(rest, options):
    seconds = _seconds(rest)
    os.system("")
    since_start = {"new": 0, "closed": 0}
    recent = []  # (time, program, target) of the newest new connections, up to 5
    known = None
    previous_counters, previous_time = None, None
    last_sample = None
    samples = 0
    try:
        while True:
            started = time.time()
            counters = _counters()
            ifaces = _interfaces(counters, previous_counters, started - previous_time if previous_time else 0.0)
            conns = _gather(budget=LIVE_LOOKUP_BUDGET)
            keys = {c["key"] for c in conns}
            if known is not None:
                for c in conns:
                    if c["key"] not in known:
                        since_start["new"] += 1
                        if c["raddr"]:
                            target = c["domain"] or _endpoint(c["raddr"], c["rport"])
                        else:
                            target = _endpoint(c["laddr"], c["lport"]) + " (listening)"
                        recent = [(started, c["program"], target)] + recent[:4]
                since_start["closed"] += len(known - keys)
            known = keys
            counts = _counts(conns)
            programs = _programs(conns)
            sys.stdout.write(_frame(seconds, ifaces, conns, counts, programs, recent, since_start, started))
            sys.stdout.flush()
            if last_sample is None or started - last_sample >= SAMPLE_EVERY:
                _save_sample(ifaces, conns)
                last_sample = started
                samples += 1
            previous_counters, previous_time = counters, started
            time.sleep(max(0.0, seconds - (time.time() - started)))
    except KeyboardInterrupt:
        print()
        if samples:
            print(f"stopped. Samples are saved to {HISTORY_FILE}. 'net history' shows them.")
        else:
            print("stopped.")
        return 0


# ======================================================================
# ONE CONNECTION — why it exists, and what can be done about it
# ======================================================================
def _started(pid):
    if pid is None:
        return "not known"
    try:
        return time.strftime("%d %b %Y %H:%M", time.localtime(psutil.Process(pid).create_time()))
    except (psutil.Error, OSError, ValueError, TypeError):
        return "not known"


def _inspect(number, options):
    conns = _gather()
    conn = _find(conns, number)
    why = _why(conn)
    measured = _fresh_measurement()
    if options["json"]:
        _core.print_json(dict(conn, why=why, bytes=_connection_bytes(measured, conn)))
        return 0
    now = time.time()
    actions = []
    if conn["protected"]:
        actions.append(("nothing", "this is part of Windows; netmon will not end it"))
    elif conn["pid"] is not None:
        actions.append((f"net kill {number}", f"end {conn['program']}; its unsaved work is lost (asks first)"))
    if conn["raddr"] and not conn["local_only"]:
        actions.append((f"net block {number}", "block this address for every program (administrator; asks first)"))
    actions.append((f"net ls --process {conn['program'].lower()}", "every connection this program has"))
    if not measured and conn["raddr"] and not conn["local_only"]:
        actions.append(("net bytes", "measure bytes per program for 10 seconds (administrator)"))
    domain = conn["domain"] or DOMAIN_STATUS.get(conn["domain_source"], DOMAIN_STATUS[""])
    if conn["domain"]:
        domain = f"{conn['domain']} (from {conn['domain_source']})"
    sections = [
        ("program", [
            ("name", conn["program"]),
            ("pid", "-" if conn["pid"] is None else str(conn["pid"])),
            ("file", conn["exe"] or "not shown by Windows"),
            ("account", conn["username"] or "not shown by Windows"),
            ("started", _started(conn["pid"])),
            ("part of Windows", "yes" if conn["protected"] else "no"),
        ]),
        ("connection", [
            ("protocol", conn["proto"].upper()),
            ("state", conn["state"] if conn["state"] != "-" else "(UDP has no state)"),
            ("local", _endpoint(conn["laddr"], conn["lport"])),
            ("remote", _endpoint(conn["raddr"], conn["rport"]) if conn["raddr"] else "none"),
            ("domain", domain),
            ("place", conn["scope"] or "-"),
            ("uses adapter", conn["via"] or "-"),
            ("open for", f"{_open_for(conn, now)}, since net first saw it at {_local_time(conn['first_seen'])}"),
        ] + ([("bytes seen", _connection_bytes_sentence(measured, conn))] if measured and not conn["listening"] else [])),
        ("why it exists", [(str(i), text) for i, text in enumerate(why, start=1)]),
        ("what you can do", actions),
    ]
    lines = [CYAN + f"connection {number}: {conn['program']} ({conn['proto'].upper()})" + RESET]
    for index, (heading, rows) in enumerate(sections):
        if heading == "why it exists":
            body = [f"  {label}. {text}" for label, text in rows]
        else:
            body = _pairs(rows)
        lines += _section(index, heading, body)
    _say(lines)
    return 0


# ======================================================================
# ACTIONS — end a program, block an address; both ask first
# ======================================================================
def _terminate(pid):
    """Ends one process. Returns an error message, or None if it ended (or was already gone)."""
    try:
        target = psutil.Process(pid)
        target.terminate()  # on Windows this ends the process at once; nothing is saved
        target.wait(timeout=3)
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return f"Windows will not let this terminal end pid {pid}. Run the terminal as administrator."
    except psutil.TimeoutExpired:
        return f"pid {pid} did not close. Try again, or end it from Task Manager."
    return None


def _one_id(rest, usage):
    if len(rest) != 1 or not rest[0].isdecimal():
        raise NetmonError(usage, 2)
    return int(rest[0])


def _kill(rest, options):
    conns = _gather()
    conn = _find(conns, _one_id(rest, "usage: net kill <id>"))
    if conn["pid"] is None:
        raise NetmonError("Windows did not give a program for this connection, so there is nothing to end.", 1)
    if conn["pid"] == os.getpid():
        raise NetmonError("that connection belongs to this console. Type 'exit' to close it.", 2)
    if conn["protected"]:
        raise NetmonError(f"{conn['program']} is part of Windows, so netmon will not end it.", 1)
    if conn["exe"] is None and conn["username"] is None:
        raise NetmonError(f"Windows shows nothing about {conn['program']} (no file, no account), so netmon cannot tell "
                          "whether it is part of Windows and will not end it. Use Task Manager.", 1)
    owned = sum(1 for c in conns if c["pid"] == conn["pid"])
    question = (f"End {conn['program']} (pid {conn['pid']})? It has {owned} connection(s), "
                "and unsaved work in it will be lost. [y/N]: ")
    if not _core.confirm(question, options["yes"]):
        print("cancelled")
        return 0
    error = _terminate(conn["pid"])
    if error:
        raise NetmonError(error, 1)
    print(f"ended {conn['program']} (pid {conn['pid']}). Its connections close with it.")
    return 0


def _block_target(word):
    """(ip, domain) from a connection id or an address."""
    if word.isdigit():
        conn = _find(_gather(), int(word))
        if not conn["raddr"]:
            raise NetmonError(f"connection {word} has no remote address. Block an address with 'net block <ip>'.", 2)
        return conn["raddr"], conn["domain"]
    ip = _norm(word)
    if ip is None:
        raise NetmonError(f"not a connection id or an IP address: {word}", 2)
    return ip, ""


def _check_blockable(ip):
    """Refuses the addresses that would cut this PC off: itself, its router and its DNS servers."""
    address = ipaddress.ip_address(ip)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise NetmonError(f"{ip} is not a remote address that can be blocked.", 2)
    own = set()
    for adapter in _net._read_adapters():
        own |= {_norm(entry["address"]) for entry in adapter["ipv4"] + adapter["ipv6"]}
        own |= {_norm(a) for a in adapter["gateways"] + adapter["dns_servers"]}
    if ip in own:
        raise NetmonError(f"{ip} is this PC, its router or its DNS server. Blocking it would cut this PC off.", 2)


def _rule(ip, direction):
    return f"{BLOCK_PREFIX}{ip}-{direction}"


def _block_rules():
    """The blocks this page made, read back from Windows Firewall: {ip: {"out": enabled, "in": enabled}}."""
    script = (f"Get-NetFirewallRule -DisplayName '{BLOCK_PREFIX}*' -ErrorAction SilentlyContinue | "
              "Select-Object DisplayName,Enabled | ConvertTo-Json -Compress")
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise NetmonError("could not read the Windows Firewall rules")
    if result.returncode != 0:
        raise NetmonError(f"could not read the Windows Firewall rules: {_net.explain(result.stderr + result.stdout)}")
    text = result.stdout.strip()
    try:
        rows = json.loads(text) if text else []
    except ValueError:
        raise NetmonError("could not read the Windows Firewall rules")
    if isinstance(rows, dict):
        rows = [rows]
    blocks = {}
    for row in rows:
        name = row.get("DisplayName") or ""
        if not name.startswith(BLOCK_PREFIX):
            continue
        ip, _, direction = name[len(BLOCK_PREFIX):].rpartition("-")
        blocks.setdefault(ip, {})[direction] = str(row.get("Enabled")).lower() in ("true", "1")
    return blocks


def _netsh(words):
    _net.tool_ok(["netsh", "advfirewall", "firewall", *words])


def _list_blocks(options):
    blocks = _block_rules()
    if options["json"]:
        _core.print_json(blocks)
        return 0
    if not blocks:
        _say([CYAN + "no addresses are blocked by netmon." + RESET])
        return 0
    lines = [CYAN + "addresses blocked by netmon" + RESET]
    lines += _pairs([(ip, "outbound and inbound" if len(d) == 2 else ", ".join(sorted(d))) for ip, d in sorted(blocks.items())], GREEN)
    lines += ["", GREY + "'net unblock <ip>' removes a block." + RESET]
    _say(lines)
    return 0


def _block(rest, options):
    if not rest or rest[0].lower() in LIST_WORDS:
        return _list_blocks(options)
    if len(rest) != 1:
        raise NetmonError("usage: net block <id|ip>, or net block ls", 2)
    ip, domain = _block_target(rest[0])
    _check_blockable(ip)
    _net.need_admin()
    existing = _block_rules().get(ip, {})
    if existing.get("out") and existing.get("in"):
        print(f"{ip} is already blocked. 'net unblock {ip}' removes the block.")
        return 0
    label = f"{ip} ({domain})" if domain else ip
    question = (f"Block all traffic to and from {label}? Every program on this PC loses access to it "
                f"until you run 'net unblock {ip}'. [y/N]: ")
    if not _core.confirm(question, options["yes"]):
        print("cancelled")
        return 0
    print(f"blocking {ip}...")
    try:
        for direction in ("out", "in"):
            _netsh(["add", "rule", f"name={_rule(ip, direction)}", f"dir={direction}", "action=block",
                    f"remoteip={ip}", "profile=any", "enable=yes"])
    except _net.NetError as e:
        raise NetmonError(f"{e} Part of the block may be in place; 'net unblock {ip}' removes it.", 1)
    now = _block_rules().get(ip, {})
    if now.get("out") and now.get("in"):
        print(f"blocked {label}: outbound and inbound. 'net unblock {ip}' undoes it.")
        return 0
    raise NetmonError(f"Windows does not show the block for {ip} yet. Check 'net block ls'.", 1)


def _unblock(rest, options):
    if len(rest) != 1:
        raise NetmonError("usage: net unblock <ip>", 2)
    ip = _norm(rest[0])
    if ip is None:
        raise NetmonError(f"not an IP address: {rest[0]}", 2)
    _net.need_admin()
    existing = _block_rules().get(ip)
    if not existing:
        print(f"{ip} is not blocked by netmon.")
        return 0
    try:
        for direction in existing:
            _netsh(["delete", "rule", f"name={_rule(ip, direction)}"])
    except _net.NetError as e:
        raise NetmonError(str(e), 1)
    if _block_rules().get(ip):
        raise NetmonError(f"{ip} is still blocked. Check 'net block ls'.", 1)
    print(f"unblocked {ip}. Its traffic is allowed again.")
    return 0


# ======================================================================
# INTERFACES AND HISTORY
# ======================================================================
def _iface(options):
    rows = _rates()
    conns = _gather()
    if options["json"]:
        _core.print_json([dict(row, connections=_address_of(conns, row)) for row in rows])
        return 0
    if not rows:
        _say([CYAN + "no Wi-Fi or Ethernet adapter found." + RESET])
        return 0
    lines = []
    for number, row in enumerate(rows):
        status = f"connected, {row['speed_mbps']:g} Mbps" if row["connected"] and row["speed_mbps"] else (
            "connected" if row["connected"] else "not connected")
        totals = "-" if row["total_in"] is None else f"{_size(row['total_in'])} in, {_size(row['total_out'])} out"
        errors = "-" if row["errors"] is None else f"{row['errors']} errors, {row['drops']} dropped"
        lines += _section(number, row["name"], _pairs([
            ("status", status),
            ("address", ", ".join(row["addresses"]) or "-"),
            ("download now", _rate(row["down_rate"])),
            ("upload now", _rate(row["up_rate"])),
            ("since Windows started", totals),
            ("errors", errors),
            ("connections", str(_address_of(conns, row))),
        ]))
    lines += ["", GREY + "The rate is measured over one second. Totals count from the last Windows start." + RESET]
    _say(lines)
    return 0


def _days(rest):
    if not rest:
        return 7
    try:
        value = int(rest[0])
    except ValueError:
        raise NetmonError("usage: net history [days], e.g. net history 3", 2)
    if not 1 <= value <= HISTORY_KEEP_DAYS:
        raise NetmonError(f"days must be from 1 to {HISTORY_KEEP_DAYS}", 2)
    return value


def _read_samples(days):
    cutoff = time.time() - days * 86400
    try:
        text = HISTORY_FILE.read_text(encoding="utf-8")
    except OSError:
        return []
    samples = []
    for line in text.splitlines():
        try:
            sample = json.loads(line)
        except ValueError:
            continue
        if isinstance(sample, dict) and sample.get("t", 0) >= cutoff:
            samples.append(sample)
    samples.sort(key=lambda s: s["t"])
    return samples


def _history(rest, options):
    if rest and rest[0].lower() in CLEAR_WORDS:
        return _clear_history(options)
    days = _days(rest)
    samples = _read_samples(days)
    if len(samples) < 2:
        message = (f"not enough samples in the last {days} day(s). 'net live' saves one sample a minute while it runs, "
                   "so run it for a couple of minutes first.")
        if options["json"]:
            _core.print_json({"samples": len(samples)})
        else:
            _say([CYAN + message + RESET])
        return 0
    totals = {}
    for before, after in zip(samples, samples[1:]):
        for name, (sent, received) in after["ifaces"].items():
            if name not in before["ifaces"]:
                continue
            old_sent, old_received = before["ifaces"][name]
            total = totals.setdefault(name, {"out": 0, "in": 0})
            # a counter that went down means Windows restarted: count what it has reached since then
            total["out"] += sent - old_sent if sent >= old_sent else sent
            total["in"] += received - old_received if received >= old_received else received
    connections = {}
    presence = {}
    for sample in samples:
        for program, count in sample["programs"].items():
            connections[program] = connections.get(program, 0) + count
            presence[program] = presence.get(program, 0) + 1
    span = samples[-1]["t"] - samples[0]["t"]
    count = len(samples)
    programs = sorted(connections, key=lambda p: (-connections[p], p.lower()))[:10]
    if options["json"]:
        _core.print_json({
            "samples": count, "from": samples[0]["t"], "to": samples[-1]["t"],
            "interfaces": totals,
            "programs": {p: {"average_connections": round(connections[p] / count, 1), "samples_seen": presence[p]} for p in programs},
        })
        return 0
    lines = [CYAN + f"{count} samples over {_elapsed(span)}, from {_local_time(samples[0]['t'])} "
             f"to {_local_time(samples[-1]['t'])}" + RESET,
             GREY + "  Only the time that net live was running is covered." + RESET]
    lines += _section(0, "bytes per adapter", _pairs([
        (name, f"{_size(t['in'])} in, {_size(t['out'])} out") for name, t in sorted(totals.items())
    ]) or ["  no adapter counts in these samples"])
    table = _table(
        ["program", "avg conns", "seen in"],
        [[p, f"{connections[p] / count:.1f}", f"{presence[p]} of {count} samples"] for p in programs],
        [GREEN] * len(programs),
    )
    lines += _section(1, "busiest programs", table)
    _say(lines)
    return 0


def _clear_history(options):
    if not HISTORY_FILE.exists():
        _say([CYAN + "no samples saved yet." + RESET])
        return 0
    if not _core.confirm("Delete all saved netmon samples? [y/N]: ", options["yes"]):
        print("cancelled")
        return 0
    try:
        HISTORY_FILE.unlink()
    except OSError as e:
        raise NetmonError(f"could not delete the samples: {e}", 1)
    print("deleted the saved samples.")
    return 0


# ======================================================================
# BYTES — a Windows trace for a few seconds: bytes per program, remote address and protocol.
# Windows gives ordinary users no byte counts per connection or program. The only source is the kernel's network
# events (ETW, the Microsoft-Windows-Kernel-Network provider), which need administrator rights and a trace session.
# logman starts and stops the session and writes an .etl file; Get-WinEvent reads it back and adds the bytes up;
# the file is deleted. Nothing here calls the ETW API itself: a wrong structure in ctypes would crash Python,
# while a wrong logman or Get-WinEvent line only fails with a message.
# ======================================================================
BYTES_FILE = "net-bytes.json"  # the last measurement, kept in the data folder
BYTES_SESSION = "w11-cli-console-net"  # the name of the Windows trace session
BYTES_DEFAULT, BYTES_MIN, BYTES_MAX = 10, 3, 120  # seconds one measurement runs
BYTES_FRESH = 3600  # a measurement older than this (seconds) is not shown next to the live lists
BYTES_SORTS = ("total", "in", "out", "program")
BYTES_ROWS = 25  # programs shown in the table (--json has all of them)
BYTES_REMOTES = 10  # remote addresses shown
BYTES_KEEP = 300  # connections saved with a measurement, busiest first
READ_TIMEOUT = 900  # seconds Get-WinEvent may take to read a trace
KERNEL_NETWORK = "{7dd42a49-5329-4832-8dfd-43d979153a88}"  # Microsoft-Windows-Kernel-Network, by id so no name lookup is needed
KERNEL_NETWORK_NAME = "Microsoft-Windows-Kernel-Network"
# The trace events that carry data: id -> (protocol, direction, IP version). 10, 11, 42 and 43 are the ones Microsoft
# publishes for this provider. The IPv6 ids follow the same pattern but were not confirmed, so every id is checked
# against the provider's own event list before it is counted (see _data_events).
DATA_EVENTS = {
    10: ("tcp", "out", 4), 11: ("tcp", "in", 4), 26: ("tcp", "out", 6), 27: ("tcp", "in", 6),
    42: ("udp", "out", 4), 43: ("udp", "in", 4), 58: ("udp", "out", 6), 59: ("udp", "in", 6),
}
BYTES_SORT_KEYS = {
    "total": lambda g: (-g["total"], g["program"].lower()),
    "in": lambda g: (-g["in"], g["program"].lower()),
    "out": lambda g: (-g["out"], g["program"].lower()),
    "program": lambda g: (g["program"].lower(),),
}

# What the provider says about its own events. Used to check DATA_EVENTS before anything is counted.
META_SCRIPT = r"""
$provider = Get-WinEvent -ListProvider 'Microsoft-Windows-Kernel-Network'
foreach ($e in $provider.Events) {
    [pscustomobject]@{ id = [int]$e.Id; description = [string]$e.Description; template = [string]$e.Template }
}
"""

# Reads the trace and adds the data events up per event id, process, source and destination, so a busy network
# does not produce a huge reply. The path and the ids arrive in the environment, never in the script text. Fields
# are taken by name from the event's XML, which Windows formats (dotted addresses, ports as numbers).
READ_SCRIPT = r"""
$etl = $env:W11_ETL
$want = @{}
foreach ($part in ($env:W11_IDS -split ',')) { if ($part) { $want[[int]$part] = $true } }
$agg = @{}
$census = @{}
$total = 0
$unparsed = 0
Get-WinEvent -Path $etl -Oldest -ErrorAction SilentlyContinue -ErrorVariable readErr | ForEach-Object {
    $total++
    $eventId = [int]$_.Id
    $census[[string]$eventId] = 1 + [int]$census[[string]$eventId]
    if (-not $want.ContainsKey($eventId)) { return }
    try {
        $fields = @{}
        foreach ($m in [regex]::Matches($_.ToXml(), "<Data Name='([^']+)'>([^<]*)</Data>")) {
            $fields[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        $size = [int64]0
        if (-not ($fields.ContainsKey('PID') -and $fields.ContainsKey('daddr') -and $fields.ContainsKey('saddr') -and
                  [int64]::TryParse([string]$fields['size'], [ref]$size))) { $unparsed++; return }
        $key = '{0}|{1}|{2}|{3}|{4}|{5}' -f $eventId, $fields['PID'], $fields['daddr'], $fields['dport'], $fields['saddr'], $fields['sport']
        $row = $agg[$key]
        if ($null -eq $row) {
            $row = [pscustomobject]@{ kind = 'row'; id = $eventId; pid = [string]$fields['PID']
                                      daddr = [string]$fields['daddr']; dport = [string]$fields['dport']
                                      saddr = [string]$fields['saddr']; sport = [string]$fields['sport']
                                      bytes = [int64]0; events = 0 }
            $agg[$key] = $row
        }
        $row.bytes += $size
        $row.events++
    } catch { $unparsed++ }
}
$problems = @($readErr | Where-Object { $_ -and $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' } |
    ForEach-Object { $_.Exception.Message })
$agg.Values
[pscustomobject]@{ kind = 'summary'; total = $total; unparsed = $unparsed; problems = ($problems -join '; ')
                   census = @($census.GetEnumerator() | ForEach-Object { [pscustomobject]@{ id = [string]$_.Key; count = [int]$_.Value } }) }
"""


def _note(options, text):
    """A progress line. With --json it goes to stderr, so stdout stays pure data."""
    print(text, file=sys.stderr if options["json"] else sys.stdout, flush=True)


# -- the trace session ------------------------------------------------------------------------------------------
def _logman(*words, timeout=30):
    return _net.run_tool(["logman", *words], timeout=timeout)


def _stop_session():
    """Stops the trace session if it is running. False only when it is running and Windows would not stop it."""
    ok, text = _logman("query", BYTES_SESSION, "-ets")
    if not ok or "not found" in text.lower():
        return True
    ok, _ = _logman("stop", BYTES_SESSION, "-ets")
    return ok


def _start_session(etl):
    ok, text = _logman("start", BYTES_SESSION, "-p", KERNEL_NETWORK, "0xFFFFFFFFFFFFFFFF", "0xFF", "-o", etl,
                       "-ets", "-bs", "1024", "-nb", "4", "16", "-max", "256")
    if not ok:
        reason = _net.explain(text)
        raise NetmonError(reason if reason == _net.ADMIN_HINT else f"Windows would not start the trace: {reason}")


def _wait(seconds):
    """Waits for the window to pass. Ctrl+C ends it early; returns True if it did."""
    end = time.time() + seconds
    try:
        while time.time() < end:
            time.sleep(min(0.25, max(0.0, end - time.time())))
    except KeyboardInterrupt:
        return True
    return False


def _remove(folder):
    """Deletes the temporary folder the trace was written to. A file Windows still holds is tried again."""
    for _ in range(3):
        shutil.rmtree(folder, ignore_errors=True)
        if not os.path.exists(folder):
            return
        time.sleep(0.5)


# -- what the provider says, and what the trace holds ---------------------------------------------------------------
def _provider_events():
    """The provider's own list of events [{id, description, template}], or None when Windows will not give it."""
    try:
        return _win.powershell_json(META_SCRIPT, timeout=60)
    except _net.NetError:
        return None


def _data_events(listed):
    """(the events to count, a note or None): DATA_EVENTS checked against the provider's own list. An id the provider
    does not have, one without the fields a data event has, or one whose description says the opposite direction or
    protocol is left out, so a wrong id can never add bytes that are not there."""
    if listed is None:
        return dict(DATA_EVENTS), "the provider's event list could not be read, so the built-in event ids were used unchecked"
    by_id = {}
    for row in listed:
        try:
            by_id[int(row["id"])] = row
        except (KeyError, TypeError, ValueError):
            continue
    use, left_out = {}, []
    for event_id, (proto, direction, version) in DATA_EVENTS.items():
        row = by_id.get(event_id)
        if row is None:
            left_out.append(event_id)
            continue
        fields = {name.lower() for name in re.findall(r'name="([^"]+)"', row.get("template") or "")}
        text = (row.get("description") or "").lower()
        says_out = bool(re.search(r"\b(sent|send|transmitted)\b", text))
        says_in = bool(re.search(r"\brecei", text))
        says_udp, says_tcp = "udp" in text, "tcp" in text
        wrong_way = (direction == "out" and says_in and not says_out) or (direction == "in" and says_out and not says_in)
        wrong_protocol = (proto == "tcp" and says_udp and not says_tcp) or (proto == "udp" and says_tcp and not says_udp)
        no_fields = bool(fields) and not {"pid", "size", "daddr", "saddr"} <= fields
        if wrong_way or wrong_protocol or no_fields:
            left_out.append(event_id)
        else:
            use[event_id] = (proto, direction, version)
    note = None
    if left_out:
        note = ("event id(s) " + ", ".join(str(i) for i in sorted(left_out)) +
                " were not counted: the provider's own list does not describe them as data events")
    return use, note


def _read_trace(etl, ids):
    """(rows, summary) from the .etl file: the data events added up per event id, process, source and destination."""
    data = _win.powershell_json(READ_SCRIPT, timeout=READ_TIMEOUT,
                                env={"W11_ETL": etl, "W11_IDS": ",".join(str(i) for i in sorted(ids))})
    rows = [item for item in data if item.get("kind") == "row"]
    summary = next((item for item in data if item.get("kind") == "summary"), {})
    if summary.get("problems"):
        raise NetmonError(f"Windows could not read the trace: {summary['problems']}")
    return rows, summary


def _event_address(text):
    """An IP address from a trace field: dotted or colon text as Windows formats it, or the raw number an IPv4
    field holds (the four bytes in network order, read as a little-endian number)."""
    text = str(text or "").strip()
    if not text:
        return None
    ip = _norm(text)
    if ip:
        return ip
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None
    if 0 <= number <= 0xFFFFFFFF:
        return str(ipaddress.IPv4Address(number.to_bytes(4, "little")))
    return None


def _event_port(text):
    try:
        port = int(str(text).strip())
    except ValueError:
        return None
    return port if 0 <= port <= 65535 else None


def _local_addresses():
    """The addresses that belong to this PC: its adapters', loopback, and every local address of a connection."""
    local = {ip for ip in _address_owners() if ip} | {"127.0.0.1", "::1"}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.laddr:
                ip = _norm(c.laddr.ip)
                if ip and ip not in ANY_ADDRESS:
                    local.add(ip)
    except psutil.Error:
        pass
    return local


def _process_names():
    """pid -> (name, file, account) for every process running now, to name the pids in a trace."""
    found = {}
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            info = proc.info
            found[info["pid"]] = (info.get("name") or f"pid {info['pid']}", info.get("exe"), info.get("username"))
    except psutil.Error:
        pass
    return found


def _name_pid(pid, before, after, cache):
    """{"program", "protected", "ended"} for a process id: looked up among the processes running when the window
    ended, then among those running when it began (it has ended since if it is only there)."""
    if pid in cache:
        return cache[pid]
    if pid in (0, 4):
        who = {"program": "System", "protected": True, "ended": False}
    elif pid in after or pid in before:
        name, exe, user = after.get(pid) or before.get(pid)
        who = {"program": name, "ended": pid not in after,
               "protected": process_page._is_protected(pid, name, exe, user)}
    else:
        who = {"program": f"pid {pid} (ended)", "protected": False, "ended": True}
    cache[pid] = who
    return who


def _orient(saddr, sport, daddr, dport, direction, local):
    """(local address, local port, remote address, remote port, stays on this PC) for one traced event.
    An event names a source and a destination. Which of them is this PC depends on the direction and on how Windows
    fills the fields in for a receive, so it is decided by which address belongs to this PC. The direction only
    decides when neither is known (a VPN or tunnel address)."""
    source_here, destination_here = saddr in local, daddr in local
    if source_here and destination_here:
        return saddr, sport, daddr, dport, True
    if source_here:
        return saddr, sport, daddr, dport, _is_loopback(daddr)
    if destination_here:
        return daddr, dport, saddr, sport, _is_loopback(saddr)
    if direction == "out":
        return saddr, sport, daddr, dport, False
    return daddr, dport, saddr, sport, False


def _summarize(rows, classes, local, before, after, loopback):
    """Adds the trace's rows up. Returns programs, remote addresses, protocols, connections and totals as plain data."""
    cache = {}
    programs, remotes, connections = {}, {}, {}
    protocols = {"tcp": {"in": 0, "out": 0}, "udp": {"in": 0, "out": 0}}
    totals = {"in": 0, "out": 0, "events": 0, "counted": 0, "stayed_on_pc_bytes": 0, "unreadable": 0}
    for row in rows:
        kind = classes.get(row.get("id"))
        if kind is None:
            continue
        proto, direction, _version = kind
        size, events = int(row["bytes"]), int(row["events"])
        saddr, daddr = _event_address(row.get("saddr")), _event_address(row.get("daddr"))
        try:
            pid = int(str(row.get("pid", "")).strip())
        except ValueError:
            pid = None
        if saddr is None or daddr is None or pid is None:
            totals["unreadable"] += events
            continue
        totals["events"] += events
        laddr, lport, raddr, rport, here = _orient(saddr, _event_port(row.get("sport")), daddr,
                                                   _event_port(row.get("dport")), direction, local)
        if here and not loopback:
            totals["stayed_on_pc_bytes"] += size
            continue
        totals["counted"] += events
        totals[direction] += size
        protocols[proto][direction] += size
        who = _name_pid(pid, before, after, cache)
        group = programs.setdefault(who["program"].lower(), {
            "program": who["program"], "pids": set(), "protected": False, "ended": True, "in": 0, "out": 0,
            "connections": set(), "peers": set()})
        group[direction] += size
        group["pids"].add(pid)
        group["protected"] = group["protected"] or who["protected"]
        group["ended"] = group["ended"] and who["ended"]
        group["connections"].add((proto, lport, raddr, rport))
        group["peers"].add(raddr)
        remote = remotes.setdefault(raddr, {"address": raddr, "in": 0, "out": 0, "by_program": {}})
        remote[direction] += size
        remote["by_program"][who["program"]] = remote["by_program"].get(who["program"], 0) + size
        conn = connections.setdefault((pid, proto, laddr, lport, raddr, rport), {
            "pid": pid, "program": who["program"], "proto": proto, "laddr": laddr, "lport": lport,
            "raddr": raddr, "rport": rport, "in": 0, "out": 0})
        conn[direction] += size
    grand = totals["in"] + totals["out"]
    program_rows = []
    for key, group in programs.items():
        total = group["in"] + group["out"]
        program_rows.append({
            "program": group["program"], "pids": sorted(group["pids"]), "protected": group["protected"],
            "ended": group["ended"], "in": group["in"], "out": group["out"], "total": total,
            "share": round(total / grand, 4) if grand else 0.0,
            "connections": len(group["connections"]), "peers": len(group["peers"]),
            "note": PROGRAM_NOTES.get(key, "part of Windows" if group["protected"] else ""),
        })
    program_rows.sort(key=BYTES_SORT_KEYS["total"])
    remote_rows = []
    for remote in remotes.values():
        by_program = sorted(remote["by_program"].items(), key=lambda item: (-item[1], item[0].lower()))
        remote_rows.append({
            "address": remote["address"], "scope": _scope(remote["address"]), "domain": "", "domain_source": "",
            "in": remote["in"], "out": remote["out"], "total": remote["in"] + remote["out"],
            "programs": [name for name, _ in by_program[:5]],
        })
    remote_rows.sort(key=lambda r: (-r["total"], r["address"]))
    connection_rows = sorted(connections.values(), key=lambda c: (-(c["in"] + c["out"]), c["pid"], c["rport"] or 0))
    return {"totals": totals, "programs": program_rows, "remotes": remote_rows, "protocols": protocols,
            "connections": connection_rows[:BYTES_KEEP], "connections_total": len(connection_rows)}


def _name_remotes(remotes):
    """Fills in domain names for the internet addresses: the DNS cache first, then reverse lookups."""
    internet = sorted(r["address"] for r in remotes if r["scope"] == "internet")
    dns = _dns_names()
    _resolve(internet, LOOKUP_BUDGET)
    for remote in remotes:
        if remote["scope"] == "internet":
            remote["domain"], remote["domain_source"] = _domain(remote["address"], dns)


def _measure(seconds, options):
    """Runs the trace for `seconds` and returns the measurement. The session is stopped and the trace deleted
    whatever happens."""
    _note(options, f"measuring for {seconds} s with a Windows trace session ({KERNEL_NETWORK_NAME}). "
                   "It is stopped and its file deleted when this is done; Ctrl+C ends it early.")
    classes, check_note = _data_events(_provider_events())
    if not classes:
        raise NetmonError("Windows' list of events for the network trace provider does not match what this page counts, "
                          "so it cannot measure bytes on this PC. " + (check_note or ""))
    if not _stop_session():  # a session an earlier run left behind
        raise NetmonError(f"a trace session called {BYTES_SESSION} is running and Windows would not stop it. "
                          f"Stop it yourself with: logman stop {BYTES_SESSION} -ets")
    folder = tempfile.mkdtemp(prefix="w11-net-")
    etl = os.path.join(folder, "net.etl")
    running = False
    try:
        running = True  # set first: Ctrl+C during the logman call may still have started it, and stopping a missing one is harmless
        _start_session(etl)
        began = time.time()
        before = _process_names()
        interrupted = _wait(seconds)
        after = _process_names()
        elapsed = time.time() - began
        local = _local_addresses()
        running = not _stop_session()
        if running:
            raise NetmonError(f"Windows would not stop the trace session. Stop it yourself with: "
                              f"logman stop {BYTES_SESSION} -ets")
        _note(options, "reading the trace (this can take about as long as the measurement)...")
        rows, summary = _read_trace(etl, classes)
    finally:
        if running:
            _stop_session()
        _remove(folder)
    result = _summarize(rows, classes, local, before, after, options["loopback"])
    result["totals"]["unreadable"] += int(summary.get("unparsed") or 0)
    _name_remotes(result["remotes"])
    return {
        "window": {"started": round(began, 1), "seconds": round(elapsed, 1), "requested": seconds,
                   "interrupted": interrupted, "loopback": options["loopback"]},
        **result,
        "events": {"read": int(summary.get("total") or 0),
                   "seen": {item["id"]: item["count"] for item in summary.get("census") or []},
                   "counted_ids": sorted(classes), "note": check_note},
    }


# -- showing a measurement ----------------------------------------------------------------------------------------
def _bytes_notes(result):
    """What the numbers mean, in plain sentences."""
    window, totals = result["window"], result["totals"]
    total = totals["in"] + totals["out"]
    notes = []
    if window["interrupted"]:
        notes.append(f"stopped early, after {_elapsed(window['seconds'])}.")
    if not totals["counted"]:
        seen = result["events"]["seen"]
        if seen:
            notes.append(f"the trace held {result['events']['read']} events (ids {', '.join(sorted(seen, key=int))}) but "
                         "none were data events this page counts. 'net bytes --json' lists them under events.")
        else:
            notes.append("no traffic events were captured. The PC may have been idle, or Windows produced no events "
                         "for this provider. Nothing here is a guess: try again while something is downloading.")
    else:
        top = max(result["programs"], key=lambda g: g["total"])
        if total >= MIB and top["total"] / total >= 0.6:
            what = f" ({top['note']})" if top["note"] else ""
            notes.append(f"{top['program']} accounts for {top['total'] / total:.0%} of the traffic{what}.")
        uploading = [g for g in result["programs"] if g["out"] >= MIB and g["out"] > 2 * g["in"] and not g["protected"]]
        for g in sorted(uploading, key=lambda g: -g["out"])[:3]:
            notes.append(f"{g['program']} sent {_size(g['out'])} and received {_size(g['in'])}: mostly uploading. "
                         "A backup, a sync, a call or a file share usually does this; check it is expected.")
    if totals["stayed_on_pc_bytes"]:
        notes.append(f"{_size(totals['stayed_on_pc_bytes'])} stayed on this PC and is not counted "
                     "('net bytes --loopback' includes it).")
    if totals["unreadable"]:
        notes.append(f"{totals['unreadable']} event(s) could not be read and are not counted.")
    if result["events"].get("note"):
        notes.append(result["events"]["note"] + ".")
    return notes


def _show_bytes(result, options, when):
    if options["json"]:
        _core.print_json(result)
        return
    window, totals = result["window"], result["totals"]
    total = totals["in"] + totals["out"]
    rate = total / window["seconds"] if window["seconds"] else 0
    lines = [CYAN + f"net bytes: {_size(total)} over {_elapsed(window['seconds'])} ({_size(totals['in'])} in, "
             f"{_size(totals['out'])} out), {when}, about {_rate(rate)}" + RESET]
    shown = result["programs"][:BYTES_ROWS]
    colors = [RED if g["protected"] else GREY if g["ended"] else GREEN for g in shown]
    table = _table(
        ["program", "in", "out", "total", "share", "conns"],
        [[g["program"] + (" (ended)" if g["ended"] and not g["program"].endswith("(ended)") else ""),
          _size(g["in"]), _size(g["out"]), _size(g["total"]), f"{g['share']:.1%}", str(g["connections"])] for g in shown],
        colors) if shown else ["  none"]
    if len(result["programs"]) > len(shown):
        table.append(GREY + f"  ... and {len(result['programs']) - len(shown)} more (--json has all of them)" + RESET)
    lines += _section(0, "programs", table)
    remotes = result["remotes"][:BYTES_REMOTES]
    lines += _section(1, "top remote addresses", _table(
        ["address", "name", "program", "in", "out", "total"],
        [[r["address"], r["domain"] or ("local network" if r["scope"] == "local network" else "-"),
          (r["programs"][0] + (f" +{len(r['programs']) - 1}" if len(r["programs"]) > 1 else "")) if r["programs"] else "-",
          _size(r["in"]), _size(r["out"]), _size(r["total"])] for r in remotes],
        [GREEN if r["scope"] == "internet" else YELLOW if r["scope"] == "local network" else GREY for r in remotes],
    ) if remotes else ["  none"])
    lines += _section(2, "protocols", _pairs([
        (name, f"{_size(counts['in'])} in, {_size(counts['out'])} out") for name, counts in result["protocols"].items()
    ], YELLOW))
    lines += _section(3, "what this means", [f"  {text}" for text in _bytes_notes(result)] or ["  nothing unusual."])
    lines += ["", GREY + "Counts are the data bytes Windows' network trace reported for this window; packet headers are "
              "not included. 'net iface' shows totals per adapter." + RESET]
    _say(lines)


def _sorted_view(result, options, sort):
    return dict(result, programs=sorted(result["programs"], key=BYTES_SORT_KEYS[sort], reverse=options["reverse"]))


# -- the saved measurement, as the live lists use it ----------------------------------------------------------------
def _last_measurement():
    """The measurement net bytes saved last, or None."""
    data = _win.load_json(BYTES_FILE)
    if isinstance(data, dict) and isinstance(data.get("window"), dict) and isinstance(data.get("programs"), list):
        return data
    return None


def _fresh_measurement():
    """The saved measurement if it is recent enough to show next to the live lists, else None."""
    data = _last_measurement()
    if data and -1 <= time.time() - data["window"]["started"] <= BYTES_FRESH:  # started is rounded, so it can lead by 0.05 s
        return data
    return None


def _measured_note(measured, noun):
    if not measured:
        return f"No {noun} yet: 'net bytes' measures them (administrator)."
    window = measured["window"]
    return (f"The {noun} come from 'net bytes', measured {_elapsed(time.time() - window['started'])} ago over "
            f"{_elapsed(window['seconds'])} (run it again for a fresh count).")


def _bytes_by_program(measured):
    """program name in lower case -> {"in", "out", "total", "measured_at", "seconds"}; {} when there is no measurement."""
    if not measured:
        return {}
    when, seconds = measured["window"]["started"], measured["window"]["seconds"]
    return {g["program"].lower(): {"in": g["in"], "out": g["out"], "total": g["total"],
                                   "measured_at": when, "seconds": seconds} for g in measured["programs"]}


def _connection_bytes(measured, conn):
    """What a measurement saw for one connection: {"in", "out", "match", "truncated", "measured_at", "seconds"}.
    match is 'connection' (same program, protocol and ports), 'address' (same program and remote address, other
    ports) or 'none'. None when there is no measurement or the connection has no remote end."""
    if not measured or not conn["raddr"]:
        return None
    rows = measured.get("connections") or []
    same = [m for m in rows if (m["pid"], m["proto"], m["lport"], m["raddr"], m["rport"]) ==
            (conn["pid"], conn["proto"], conn["lport"], conn["raddr"], conn["rport"])]
    near = [m for m in rows if m["pid"] == conn["pid"] and m["raddr"] == conn["raddr"]]
    found, match = (same, "connection") if same else (near, "address") if near else ([], "none")
    return {"in": sum(m["in"] for m in found), "out": sum(m["out"] for m in found), "match": match,
            "truncated": measured.get("connections_total", len(rows)) > len(rows),
            "measured_at": measured["window"]["started"], "seconds": measured["window"]["seconds"]}


def _connection_bytes_text(measured, conn):
    seen = _connection_bytes(measured, conn)
    if seen is None:
        return "-"
    if seen["match"] == "none":
        return "-" if seen["truncated"] else "0 B"
    return _size(seen["in"] + seen["out"])


def _connection_bytes_sentence(measured, conn):
    seen = _connection_bytes(measured, conn)
    if seen is None:
        return "-"
    when = f"net bytes, {_elapsed(time.time() - seen['measured_at'])} ago, over {_elapsed(seen['seconds'])}"
    if seen["match"] == "none":
        if seen["truncated"]:
            return f"not among the busiest connections in the measurement ({when})"
        return f"none seen ({when})"
    where = "" if seen["match"] == "connection" else " to this address, on any port"
    return f"{_size(seen['in'])} in, {_size(seen['out'])} out{where} ({when})"


# -- the command ----------------------------------------------------------------------------------------------------
BYTES_USAGE = "usage: net bytes [seconds] | net bytes last | net bytes clear   (seconds from 3 to 120; default 10)"


def _bytes_seconds(word):
    try:
        value = int(word)
    except ValueError:
        raise NetmonError(BYTES_USAGE, 2)
    if not BYTES_MIN <= value <= BYTES_MAX:
        raise NetmonError(f"seconds must be from {BYTES_MIN} to {BYTES_MAX}", 2)
    return value


def _bytes_last(options, sort):
    measured = _last_measurement()
    if options["json"]:
        _core.print_json(measured or {"window": None})
        return 0
    if not measured:
        _say([CYAN + "no measurement saved yet. 'net bytes' makes one (administrator)." + RESET])
        return 0
    when = f"measured {_elapsed(time.time() - measured['window']['started'])} ago"
    _show_bytes(_sorted_view(measured, options, sort), options, when)
    return 0


def _bytes_clear(options):
    path = _win.data_dir() / BYTES_FILE
    if not path.exists():
        _say([CYAN + "no measurement saved." + RESET])
        return 0
    if not _core.confirm("Delete the saved net bytes measurement? [y/N]: ", options["yes"]):
        print("cancelled")
        return 0
    try:
        path.unlink()
    except OSError as e:
        raise NetmonError(f"could not delete the measurement: {e}", 1)
    print("deleted the saved measurement.")
    return 0


def _bytes(rest, options):
    sort = options.get("sort", "total")
    if sort not in BYTES_SORTS:
        raise NetmonError(f"--sort must be one of: {', '.join(BYTES_SORTS)}", 2)
    word = rest[0].lower() if rest else ""
    if word == "last" and len(rest) == 1:
        return _bytes_last(options, sort)
    if word in CLEAR_WORDS and len(rest) == 1:
        return _bytes_clear(options)
    if len(rest) > 1:
        raise NetmonError(BYTES_USAGE, 2)
    seconds = _bytes_seconds(rest[0]) if rest else BYTES_DEFAULT
    _net.need_admin()
    try:
        result = _measure(seconds, options)
    except KeyboardInterrupt:  # the session is already stopped and the trace deleted (see _measure)
        raise NetmonError("cancelled. The trace session was stopped and its file deleted.", 1)
    try:
        _win.save_json(BYTES_FILE, result)
    except _net.NetError as e:
        _note(options, f"warning: {e}. 'net procs' will not show this measurement.")
    _show_bytes(_sorted_view(result, options, sort), options,
                f"measured at {time.strftime('%H:%M:%S', time.localtime(result['window']['started']))}")
    return 0


# ======================================================================
# OPTIONS AND ROUTING
# ======================================================================
VALUE_FLAGS ={"--sort": "sort", "--state": "state", "--proto": "proto", "--process": "process", "--ip": "ip"}
BOOL_FLAGS = {"--json": "json", "--yes": "yes", "--loopback": "loopback", "--reverse": "reverse", "--bytes": "bytes"}


def _parse(args):
    """(words, options) from the words after the name. Flags with a value take the next word."""
    options = {"json": False, "yes": False, "loopback": False, "reverse": False, "bytes": False}
    words = []
    index = 0
    while index < len(args):
        word = args[index]
        lowered = word.lower()
        if lowered in BOOL_FLAGS:
            options[BOOL_FLAGS[lowered]] = True
        elif lowered in VALUE_FLAGS:
            if index + 1 >= len(args):
                raise NetmonError(f"{lowered} needs a value", 2)
            index += 1
            options[VALUE_FLAGS[lowered]] = args[index].lower()
        else:
            words.append(word)
        index += 1
    if options.get("proto") not in (None, "tcp", "udp"):
        raise NetmonError("--proto must be tcp or udp", 2)
    if "ip" in options:
        options["ip"] = _norm(options["ip"])
        if options["ip"] is None:
            raise NetmonError("--ip needs an IP address", 2)
    return words, options


def _dispatch(args):
    words, options = _parse(args)
    if not words:
        return _overview(options)
    word, rest = words[0].lower(), words[1:]
    if word in ("live", "watch"):
        return _live(rest, options)
    if word in LIST_WORDS:
        return _list(rest, options)
    if word in ("procs", "program", "programs", "prog"):
        return _procs(options)
    if word == "bytes":
        return _bytes(rest, options)
    if word in ("iface", "interface", "interfaces", "adapters", "usage"):
        return _iface(options)
    if word in ("history", "hist"):
        return _history(rest, options)
    if word == "kill":
        return _kill(rest, options)
    if word == "block":
        return _block(rest, options)
    if word == "unblock":
        return _unblock(rest, options)
    if word.isdecimal():
        return _inspect(int(word), options)
    raise NetmonError(f"unknown netmon command: {words[0]}. Type 'net' for the overview, or 'net help' for the commands.", 2)


def run(args):
    try:
        return _dispatch(args)
    except (NetmonError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return getattr(e, "code", 1)

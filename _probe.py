"""
Readings shared by the hardware and system pages. Everything here is read-only and needs no administrator rights.
A reading Windows refuses comes back as a reason rather than an error:
  - PowerShell, one call per group of readings, for WMI/CIM, performance counters and the storage cmdlets
  - the Windows processor API, for cores, caches, NUMA nodes and processor groups
  - powercfg and the power-status call, for power plans and battery state
"""

import base64
import ctypes
import json
import re
import subprocess
from datetime import datetime

import _core
import _net

# Every reading script starts with this: each named reading runs in its own try, so one refusal does not stop the rest
PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$data = [ordered]@{}
$errors = [ordered]@{}
function Get-Part([string]$name, [scriptblock]$block) {
    try { $script:data[$name] = @(& $block) } catch { $script:errors[$name] = $_.Exception.Message }
}
"""
TAIL = "[ordered]@{ data = $data; errors = $errors } | ConvertTo-Json -Depth 8 -Compress"
TIMEOUT = 120
ADMIN_WORDS = ("access to a cim resource", "access is denied", "access denied", "not authorized", "unauthorized",
               "administrator")
MISSING_WORDS = ("not supported", "does not exist", "invalid class", "invalid namespace", "not found",
                 "cannot find", "could not be found", "not recognized", "no matching")
DATE = re.compile(r"/Date\((-?\d+)[+-]?\d*\)/")
CACHE_TYPES = {0: "unified", 1: "instruction", 2: "data", 3: "trace"}
ARCHITECTURES = {0: "x86", 5: "ARM", 9: "x64", 12: "ARM64"}
# IsProcessorFeaturePresent codes (the PF_ values in the Windows SDK) and the names people look for
FEATURES = [("MMX", 3), ("SSE", 6), ("SSE2", 10), ("SSE3", 13), ("SSSE3", 36), ("SSE4.1", 37), ("SSE4.2", 38),
            ("AVX", 39), ("AVX2", 40), ("AVX-512 foundation", 41), ("no-execute (NX)", 12), ("XSAVE", 17),
            ("second-level address translation", 20), ("virtualisation enabled in firmware", 21)]


def _powershell(script, timeout):
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise _net.NetError(f"could not run PowerShell: {e}")
    if result.returncode != 0 or not result.stdout.strip():
        raise _net.NetError(reason(result.stderr or result.stdout or "PowerShell gave no output"))
    return result.stdout


def reason(message):
    """Why a reading is missing, in a few words: an administrator matter, a sensor this PC does not have,
    or the first line of whatever Windows said."""
    lowered = (message or "").lower()
    if any(word in lowered for word in ADMIN_WORDS):
        return "needs administrator rights"
    if any(word in lowered for word in MISSING_WORDS):
        return "not exposed on this PC"
    lines = [line.strip() for line in (message or "").splitlines() if line.strip()]
    return lines[0] if lines else "not readable"


def _dates(value):
    """PowerShell writes dates as /Date(milliseconds)/; turn them into local time text."""
    if isinstance(value, dict):
        return {key: _dates(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_dates(item) for item in value]
    if isinstance(value, str):
        match = DATE.fullmatch(value)
        if match:
            return datetime.fromtimestamp(int(match.group(1)) / 1000).isoformat(timespec="seconds")
    return value


def probe(body, timeout=TIMEOUT):
    """Run readings in one PowerShell call. Returns (data, errors): data maps each name to its list of results
    (empty if nothing came back), errors maps a name to why it could not be read."""
    reply = json.loads(_powershell(PRELUDE + body + "\n" + TAIL, timeout))
    data = _dates(reply.get("data") or {})
    errors = {name: reason(message) for name, message in (reply.get("errors") or {}).items()}
    return data, errors


def sample(paths, seconds):
    """Performance counters, read once a second for `seconds`: [{"time": ..., "samples": [{"path", "value"}]}]."""
    names = ", ".join("'" + path + "'" for path in paths)
    body = (f"Get-Part 'samples' {{ Get-Counter -Counter @({names}) -SampleInterval 1 -MaxSamples {int(seconds)} | "
            "ForEach-Object { [pscustomobject]@{ time = $_.Timestamp.ToString('o'); "
            "samples = @($_.CounterSamples | Select-Object Path, CookedValue) } } }")
    data, errors = probe(body, timeout=int(seconds) + 60)
    if "samples" in errors:
        raise _net.NetError(errors["samples"])
    readings = []
    for moment in data.get("samples", []):
        readings.append({"time": moment["time"], "samples": [
            {"path": item["Path"], "value": item["CookedValue"]} for item in moment["samples"]]})
    return readings


def instance_of(path):
    """The instance name inside a counter path: \\\\host\\process(chrome)\\% processor time gives chrome."""
    match = re.search(r"\((.+?)\)\\", path)
    return match.group(1) if match else ""


def counter_name(path):
    """The counter name at the end of a counter path, in lower case."""
    return path.rsplit("\\", 1)[-1].lower()


def average(values):
    values = [value for value in values if value is not None]
    return round(sum(values) / len(values), 2) if values else None


def peak(values):
    values = [value for value in values if value is not None]
    return round(max(values), 2) if values else None


def power_status():
    """Battery and AC state from the same call the taskbar uses: {"ac": True/False/None, "percent": n/None,
    "battery": True/False}."""
    class Status(ctypes.Structure):
        _fields_ = [("ac", ctypes.c_ubyte), ("flag", ctypes.c_ubyte), ("percent", ctypes.c_ubyte),
                    ("saver", ctypes.c_ubyte), ("life", ctypes.c_long), ("full", ctypes.c_long)]

    status = Status()
    if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
        return {"ac": None, "percent": None, "battery": None}
    return {
        "ac": {0: False, 1: True}.get(status.ac),
        "percent": status.percent if status.percent != 255 else None,
        "battery": not (status.flag & 128) if status.flag != 255 else None,  # 128: no system battery
    }


class _Info(ctypes.Structure):
    """SYSTEM_LOGICAL_PROCESSOR_INFORMATION (32 bytes on 64-bit Windows): a mask of logical processors, the kind of
    entry, then 16 bytes of detail that start at offset 16 (the union is 8-byte aligned)."""
    _fields_ = [("mask", ctypes.c_size_t), ("relation", ctypes.c_int), ("_pad", ctypes.c_ubyte * 4),
                ("detail", ctypes.c_ubyte * 16)]


def _ids(mask):
    return [bit for bit in range(64) if mask >> bit & 1]


def ranges(ids):
    """[0, 1, 2, 5] as '0-2, 5' for display."""
    if not ids:
        return "-"
    parts, start, last = [], ids[0], ids[0]
    for number in ids[1:]:
        if number == last + 1:
            last = number
            continue
        parts.append(str(start) if start == last else f"{start}-{last}")
        start = last = number
    parts.append(str(start) if start == last else f"{start}-{last}")
    return ", ".join(parts)


def processor_layout():
    """Cores, caches and NUMA nodes from the processor API, each with the logical processors that share it.
    Returns None if Windows will not say."""
    kernel = ctypes.windll.kernel32
    length = ctypes.c_ulong(0)
    kernel.GetLogicalProcessorInformation(None, ctypes.byref(length))
    if length.value < ctypes.sizeof(_Info):
        return None
    buffer = (_Info * (length.value // ctypes.sizeof(_Info)))()
    if not kernel.GetLogicalProcessorInformation(ctypes.cast(buffer, ctypes.c_void_p), ctypes.byref(length)):
        return None
    cores, caches, nodes, packages = [], [], [], 0
    for info in buffer:
        raw = bytes(info.detail)
        ids = _ids(info.mask)
        if info.relation == 0:  # RelationProcessorCore
            cores.append({"logical": ids, "hyperthreaded": bool(raw[0] & 1)})
        elif info.relation == 1:  # RelationNumaNode
            nodes.append({"node": int.from_bytes(raw[0:4], "little"), "logical": ids})
        elif info.relation == 2:  # RelationCache
            kind = int.from_bytes(raw[8:12], "little")
            caches.append({"level": raw[0], "associativity": raw[1], "line_size": int.from_bytes(raw[2:4], "little"),
                           "size_kb": int.from_bytes(raw[4:8], "little") // 1024,
                           "type": CACHE_TYPES.get(kind, "other"), "shared_by": ids})
        elif info.relation == 3:  # RelationProcessorPackage
            packages += 1
    groups = []
    for group in range(kernel.GetActiveProcessorGroupCount()):
        groups.append({"group": group, "logical": kernel.GetActiveProcessorCount(group)})
    return {"packages": packages, "cores": cores, "caches": caches, "numa_nodes": nodes, "groups": groups}


def feature_flags():
    """{name: True/False} for the instruction sets and features in FEATURES, from the processor API."""
    kernel = ctypes.windll.kernel32
    return {name: bool(kernel.IsProcessorFeaturePresent(code)) for name, code in FEATURES}


def powercfg(args):
    """powercfg's text for these arguments, or None if it fails."""
    ok, text = _net.run_tool(["powercfg", *args], timeout=30)
    return text if ok else None


def power_settings(text):
    """The settings in a powercfg /query listing: [{"name", "ac", "dc"}], with values as the scheme stores them."""
    settings, current = [], None
    for line in (text or "").splitlines():
        match = re.search(r"Power Setting GUID: \S+\s+\((.+)\)", line)
        if match:
            current = {"name": match.group(1), "ac": None, "dc": None}
            settings.append(current)
            continue
        match = re.search(r"Current (AC|DC) Power Setting Index: 0x([0-9a-fA-F]+)", line)
        if match and current is not None:
            current["ac" if match.group(1) == "AC" else "dc"] = int(match.group(2), 16)
    return settings


def table(headers, rows, width=44):
    """Rows as aligned text columns. Cells longer than width are cut, so one long name cannot spread the table."""
    if not rows:
        return "  (none)"
    cells = [[_net.show(cell) for cell in row] for row in rows]
    cells = [[(text if len(text) <= width else text[:width - 1] + "…") for text in row] for row in cells]
    widths = [max([len(header)] + [len(row[i]) for row in cells]) + 2 for i, header in enumerate(headers)]
    lines = ["".join(f"{header:<{widths[i]}}" for i, header in enumerate(headers)).rstrip()]
    for row in cells:
        lines.append("".join(f"{text:<{widths[i]}}" for i, text in enumerate(row)).rstrip())
    return "\n".join(lines)


def emit(options, title, data, sections=None, rows=None, headers=None, notes=()):
    """One reading: data as JSON with --json; otherwise a titled list of sections, or a table, then the notes.
    notes is a list of lines (missing readings and what they need), shown in text only."""
    if options["json"]:
        _core.print_json(data)
        return
    if sections is not None:
        _net.render(title, sections)
    else:
        print(title)
    if rows is not None:
        print(table(headers, rows))
    for note in notes:
        print(note)


def missing_notes(errors):
    """One line per reading that could not be read, with the reason (text output only)."""
    return [f"not available: {name.replace('_', ' ')} ({why})" for name, why in errors.items()]

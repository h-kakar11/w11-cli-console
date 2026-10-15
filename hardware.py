"""
hardware: the parts of the PC, what they are, what they are doing now, and what has gone wrong with them.
Routed from app.py ("hardware" or "hw").

    hw cpu | hw gpu | hw ram | hw storage | hw board      the summary of each area
    hw cpu usage|frequency|cache|features|topology|power|report
    hw gpu list|inspect|usage|memory|display|drivers|processes|errors|report
    hw ram modules|slots|usage|processes|paging|pressure|test|report
    hw storage list|inspect|partitions|volumes|health|temperature|performance|errors|firmware|trim|bitlocker|space|report
    hw bios|firmware|pci|usb|battery|fans|sensors|report

Nothing here changes the PC. Live readings sample for a few seconds (usage, frequency, performance, pressure
take an optional number of seconds). Readings Windows keeps from ordinary users say "needs administrator rights";
sensors this PC does not have say "not exposed on this PC". Nothing is guessed or filled in with zeros.
"""

import os
import re
import sys
import time
from collections import defaultdict

import _core
import _net
import _probe

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "hardware"
ALIASES = ["hw"]
SUMMARY = "Processor, graphics, memory, drives, board and sensors"
USAGE = "hw cpu | hw gpu | hw ram | hw storage | hw board | hw report"
HELP = [
    ("hw cpu", "the processor: model, cores, clock speed and features"),
    ("hw gpu", "the graphics cards: memory, driver and displays"),
    ("hw ram", "memory: installed, in use, paging and pressure"),
    ("hw storage", "drives and volumes: health, space and errors"),
    ("hw board", "motherboard, BIOS and everything plugged in"),
    ("hw report", "the whole inventory as JSON, for scripts and agents"),
    ("", "processor"),
    ("hw cpu usage [sec]", "busy time for each logical processor, sampled"),
    ("hw cpu frequency [sec]", "current clock speed, and how it changed"),
    ("hw cpu cache", "L1, L2 and L3 caches, and which processors share them"),
    ("hw cpu features", "instruction sets, virtualisation and security features"),
    ("hw cpu topology", "cores, NUMA nodes and processor groups"),
    ("hw cpu power", "the power plan's processor settings"),
    ("", "graphics"),
    ("hw gpu usage [sec]", "engine busy time: 3D, compute, copy and video"),
    ("hw gpu memory", "video memory in use: dedicated and shared"),
    ("hw gpu display", "monitors, screen positions and refresh rates"),
    ("hw gpu drivers", "driver version, date and signature"),
    ("hw gpu processes", "processes using the GPU and their video memory"),
    ("hw gpu errors [days]", "driver resets and GPU errors in the event logs"),
    ("hw gpu inspect [n]", "one graphics card in full"),
    ("", "memory"),
    ("hw ram modules", "each memory stick: size, speed, part number, slot"),
    ("hw ram slots", "slots used and slots free"),
    ("hw ram usage", "in use, cached, standby, paged and non-paged memory"),
    ("hw ram processes [n]", "the processes using the most memory"),
    ("hw ram paging", "page file size, use and paging rate"),
    ("hw ram pressure [sec]", "is memory short, or paging heavily"),
    ("hw ram test", "how to run Windows' memory test (not started here)"),
    ("", "storage"),
    ("hw storage inspect <n>", "one drive in full: model, serial, firmware, bus"),
    ("hw storage partitions", "partitions on each drive"),
    ("hw storage volumes", "drive letters: space used and free, file system"),
    ("hw storage health", "drive health, and SMART details when run as administrator"),
    ("hw storage temperature", "drive temperature where Windows exposes it"),
    ("hw storage performance [sec]", "read and write speed, queue and latency"),
    ("hw storage errors [days]", "disk and file-system errors in the event logs"),
    ("hw storage firmware", "firmware version of each drive"),
    ("hw storage trim", "whether TRIM is on for the drives"),
    ("hw storage bitlocker", "encryption of each volume (recovery keys are never shown)"),
    ("hw storage space [path]", "low space, largest folders, temp folders that can be reviewed"),
    ("", "motherboard and devices"),
    ("hw bios", "BIOS version, date and boot mode"),
    ("hw firmware", "every firmware version this page can read"),
    ("hw pci", "PCI devices, with vendor and device IDs"),
    ("hw usb", "USB devices, with vendor and product IDs"),
    ("hw battery", "battery presence, charge and wear"),
    ("hw fans", "fan sensors Windows can see"),
    ("hw sensors", "temperature, voltage and fan readings Windows can see"),
]
TIP = (
    "'hw gpu' and 'hw storage' list the devices, and 'hw gpu inspect 1' shows one. The live readings sample for "
    "a few seconds: hw cpu usage 10. Nothing here changes the PC."
)

# ======================================================================
# CONSTANTS
# ======================================================================
GPU_VENDORS = {"10DE": "NVIDIA", "1002": "AMD", "8086": "Intel", "1414": "Microsoft"}
DISPLAY_CLASS = r"HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
SMBIOS_MEMORY = {20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 34: "DDR5"}
FORM_FACTORS = {8: "DIMM", 12: "SO-DIMM"}
DISK_BUS_KINDS = {"File Backed Virtual": "virtual disk", "Virtual": "virtual disk", "USB": "external (USB)"}
ENCRYPTION = {0: "none", 1: "AES 128 with diffuser", 2: "AES 256 with diffuser", 3: "AES 128", 4: "AES 256",
              5: "hardware encryption", 6: "XTS-AES 128", 7: "XTS-AES 256"}
CONVERSION = {0: "fully decrypted", 1: "fully encrypted", 2: "encrypting", 3: "decrypting",
              4: "encryption paused", 5: "decryption paused"}
PROTECTION = {0: "off", 1: "on", 2: "unknown"}
VBS = {0: "not enabled", 1: "enabled, not running", 2: "running"}
SECURITY_SERVICES = {1: "Credential Guard", 2: "memory integrity (HVCI)", 3: "System Guard secure launch",
                     4: "SMM firmware measurement"}
GPU_PROVIDERS = ["nvlddmkm", "display", "dxgkrnl", "dxgmms", "igfx", "amdkmdag", "amdlog", "gpu"]
STORAGE_PROVIDERS = ["disk", "storahci", "stornvme", "ntfs", "volmgr", "volsnap", "partmgr", "storport",
                     "iastor", "nvraid", "usbstor"]
CLEANUP_FOLDERS = [
    ("user temp files", "%TEMP%"), ("Windows temp files", "%SystemRoot%\\Temp"),
    ("crash dumps", "%LOCALAPPDATA%\\CrashDumps"), ("memory dumps", "%SystemRoot%\\Minidump"),
    ("Windows Update downloads", "%SystemRoot%\\SoftwareDistribution\\Download"),
]
SCAN_SECONDS = 20  # how long the folder sizes may take before the rest are left out
DEFAULT_COUNT = 15
PAGE_RATE_HIGH = 1000  # pages per second that counts as heavy paging when it is sustained
COMMIT_HIGH = 0.9  # committed memory as a share of the commit limit
PAGE_FILE_HIGH = 80  # percent of the page file in use


class HardwareError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# FORMATTING — sizes, seconds and small helpers
# ======================================================================
def _size(number):
    if number is None:
        return None
    value = float(number)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _mb(number):
    return None if number is None else round(number / 1048576, 1)


def _pct(part, whole):
    return None if not whole or part is None else round(100.0 * part / whole, 1)


def _name(text):
    return " ".join(str(text or "").split()) or None


def _seconds(args, default, limit=600):
    """The optional number of seconds a live reading samples for: (remaining words, seconds)."""
    if args and args[0].isdigit():
        seconds = int(args[0])
        if not 1 <= seconds <= limit:
            raise HardwareError(f"seconds must be between 1 and {limit}", 2)
        return args[1:], seconds
    return args, default


def _count(args, default=DEFAULT_COUNT):
    if args and args[0].isdigit() and int(args[0]) >= 1:
        return args[1:], int(args[0])
    return args, default


def _vendor(pnp):
    match = re.search(r"VEN_([0-9A-F]{4})", (pnp or "").upper())
    return GPU_VENDORS.get(match.group(1), "unknown") if match else "unknown"


def _ids(pnp):
    """Vendor and device IDs from a PCI or USB device ID: 1022:1444 for PCI, 1532:0099 for USB."""
    match = re.search(r"(?:VEN|VID)_([0-9A-F]{4})&(?:DEV|PID)_([0-9A-F]{4})", (pnp or "").upper())
    return f"{match.group(1)}:{match.group(2)}" if match else None


def _sorted_ids(keys):
    """Processor instance names (0, 1, ..., _total): numbers in order, the total first."""
    return sorted(keys, key=lambda key: (key != "_total", int(key) if key.isdigit() else -1))


def _unavailable(data, errors):
    """Add the readings that could not be made to the data, so --json says what is missing and why."""
    if errors:
        data["unavailable"] = errors
    return data


def _notes(errors):
    return _probe.missing_notes(errors)


def _dispatch(area, subs, default, rest, options):
    """Route 'hw <area> <word>' to its function; no word runs the area's default."""
    if not rest:
        return default([], options)
    word = rest[0].lower()
    if word not in subs:
        raise HardwareError(f"usage: hw {area} [{'|'.join(subs)}]", 2)
    return subs[word](rest[1:], options)


def _pick(args, rows, what):
    """A device from a list by its number (1 is the first row), or raise with the usage."""
    if len(args) != 1 or not args[0].isdigit():
        raise HardwareError(f"usage: hw {what} <n>, where n is the number in the list", 2)
    number = int(args[0])
    if not 1 <= number <= len(rows):
        raise HardwareError(f"there is no {what} number {number}. Run 'hw {what}' to see the list.", 2)
    return rows[number - 1]


# ======================================================================
# CPU — hw cpu
# ======================================================================
CPU_BODY = r"""
Get-Part 'processors' { Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, Architecture, SocketDesignation, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, CurrentClockSpeed, DataWidth, L2CacheSize, L3CacheSize, VirtualizationFirmwareEnabled, VMMonitorModeExtensions, SecondLevelAddressTranslationExtensions }
Get-Part 'device_guard' { Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard | Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning }
Get-Part 'tpm' { Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerIdTxt, ManufacturerVersion }
"""


def _cpu_chips():
    data, errors = _probe.probe(CPU_BODY)
    return data, errors


def _cpu_data():
    data, errors = _cpu_chips()
    chips = data.get("processors") or []
    first = chips[0] if chips else {}
    layout = _probe.processor_layout() or {}
    cores = layout.get("cores", [])
    logical = sum(chip.get("NumberOfLogicalProcessors") or 0 for chip in chips) or os.cpu_count()
    physical = sum(chip.get("NumberOfCores") or 0 for chip in chips) or len(cores)
    return _unavailable({
        "model": _name(first.get("Name")),
        "manufacturer": first.get("Manufacturer"),
        "architecture": _probe.ARCHITECTURES.get(first.get("Architecture"), "unknown"),
        "socket": first.get("SocketDesignation"),
        "sockets": len(chips) or layout.get("packages"),
        "physical_cores": physical,
        "logical_processors": logical,
        "rated_mhz": first.get("MaxClockSpeed"),
        "current_mhz": first.get("CurrentClockSpeed"),
        "l2_cache_kb": first.get("L2CacheSize"),
        "l3_cache_kb": first.get("L3CacheSize"),
        "data_width": first.get("DataWidth"),
    }, errors)


def _cpu_summary(args, options):
    data = _cpu_data()
    sections = [
        ("processor", [("model", data["model"]), ("manufacturer", data["manufacturer"]),
                       ("architecture", data["architecture"]), ("socket", data["socket"])]),
        ("cores", [("sockets", data["sockets"]), ("physical cores", data["physical_cores"]),
                   ("logical processors", data["logical_processors"])]),
        ("speed", [("rated (advertised) speed", _mhz(data["rated_mhz"])),
                   ("current speed", _mhz(data["current_mhz"]))]),
        ("cache", [("L2, total", _size_kb(data["l2_cache_kb"])), ("L3, total", _size_kb(data["l3_cache_kb"]))]),
    ]
    _probe.emit(options, "processor", data, sections, notes=_notes(data.get("unavailable", {})))


def _mhz(value):
    return None if value is None else f"{value} MHz"


def _size_kb(value):
    return None if value is None else _size(value * 1024)


def _cpu_cache(args, options):
    layout = _probe.processor_layout()
    if layout is None:
        raise HardwareError("Windows would not describe the processor's caches", 1)
    caches = sorted(layout["caches"], key=lambda c: (c["level"], c["type"]))
    data = {"caches": caches}
    rows = [(f"L{c['level']}", c["type"], _size(c["size_kb"] * 1024), _probe.ranges(c["shared_by"]))
            for c in caches]
    _probe.emit(options, "cache", data, rows=rows, headers=["LEVEL", "TYPE", "SIZE", "SHARED BY (logical processors)"])


def _cpu_features(args, options):
    data, errors = _cpu_chips()
    chip = (data.get("processors") or [{}])[0]
    guard = (data.get("device_guard") or [{}])[0]
    tpm = (data.get("tpm") or [{}])[0]
    if all(value in (None, "") for value in tpm.values()):
        errors["tpm"] = "needs administrator rights"  # Windows returns the TPM fields blank to ordinary users
        tpm = {}
    running = [SECURITY_SERVICES.get(code, f"service {code}") for code in guard.get("SecurityServicesRunning") or []]
    out = {
        "instruction_sets": _probe.feature_flags(),
        "virtualisation": {
            "enabled_in_firmware": chip.get("VirtualizationFirmwareEnabled"),
            "hyper_v_monitor_mode": chip.get("VMMonitorModeExtensions"),
            "second_level_address_translation": chip.get("SecondLevelAddressTranslationExtensions"),
        },
        "security": {
            "virtualisation_based_security": VBS.get(guard.get("VirtualizationBasedSecurityStatus"), "unknown"),
            "security_services_running": running,
            "tpm_present": tpm.get("TpmPresent"),
            "tpm_ready": tpm.get("TpmReady"),
            "tpm_manufacturer": tpm.get("ManufacturerIdTxt"),
            "tpm_firmware_version": tpm.get("ManufacturerVersion"),
        },
    }
    out = _unavailable(out, errors)
    sections = [
        ("instruction sets", [(name, "yes" if on else "no") for name, on in out["instruction_sets"].items()]),
        ("virtualisation", [(label, value) for label, value in [
            ("enabled in firmware", chip.get("VirtualizationFirmwareEnabled")),
            ("Hyper-V monitor mode", chip.get("VMMonitorModeExtensions")),
            ("address translation", chip.get("SecondLevelAddressTranslationExtensions"))]]),
        ("security", [
            ("virtualisation-based security", out["security"]["virtualisation_based_security"]),
            ("services running", running), ("TPM present", tpm.get("TpmPresent")),
            ("TPM ready", tpm.get("TpmReady")), ("TPM version", tpm.get("ManufacturerVersion")),
        ]),
    ]
    _probe.emit(options, "processor features", out, sections, notes=_notes(errors))


def _cpu_usage(args, options):
    args, seconds = _seconds(args, 5)
    readings = _probe.sample([r"\Processor(*)\% Processor Time"], seconds)
    per = defaultdict(list)
    for moment in readings:
        for item in moment["samples"]:
            per[_probe.instance_of(item["path"])].append(item["value"])
    processors = [{"processor": key if key != "_total" else "all", "average_percent": _probe.average(per[key]),
                   "peak_percent": _probe.peak(per[key])} for key in _sorted_ids(per)]
    data = {"seconds": seconds, "processors": processors}
    rows = [(item["processor"], item["average_percent"], item["peak_percent"]) for item in processors]
    _probe.emit(options, f"processor busy time over {seconds} s", data, rows=rows,
                headers=["PROCESSOR", "AVERAGE %", "PEAK %"])


def _cpu_frequency(args, options):
    args, seconds = _seconds(args, 5)
    readings = _probe.sample([r"\Processor Information(_Total)\Processor Frequency",
                              r"\Processor Information(_Total)\% Processor Performance"], seconds)
    freq, perf = [], []
    for moment in readings:
        for item in moment["samples"]:
            name = _probe.counter_name(item["path"])
            if name == "processor frequency":
                freq.append(item["value"])
            elif name == "% processor performance":
                perf.append(item["value"])
    changes = sum(1 for a, b in zip(freq, freq[1:]) if round(a) != round(b))
    rated = _cpu_data()["rated_mhz"]
    data = {
        "seconds": seconds, "rated_mhz": rated,
        "reported_mhz": round(freq[-1]) if freq else None,
        "estimated_now_mhz": round(rated * _probe.average(perf) / 100) if rated and perf else None,
        "average_mhz": round(_probe.average(freq) or 0) or None,
        "lowest_mhz": round(min(freq)) if freq else None,
        "highest_mhz": round(max(freq)) if freq else None,
        "performance_percent": _probe.average(perf),
        "changes_seen": changes,
        "minimum_speed": "not exposed: Windows reports only the rated speed",
    }
    sections = [("clock speed", [("rated (advertised)", _mhz(rated)),
                                 ("reported now", _mhz(data["reported_mhz"])),
                                 ("estimated now (rated x performance)", _mhz(data["estimated_now_mhz"])),
                                 ("average reported", _mhz(data["average_mhz"])),
                                 ("lowest reported", _mhz(data["lowest_mhz"])),
                                 ("highest reported", _mhz(data["highest_mhz"]))]),
                ("behaviour", [("performance (of rated)", f"{data['performance_percent']}%"),
                               (f"changes in {seconds} s", changes),
                               ("minimum speed", data["minimum_speed"])])]
    _probe.emit(options, "processor clock speed", data, sections)


def _cpu_topology(args, options):
    layout = _probe.processor_layout()
    if layout is None:
        raise HardwareError("Windows would not describe the processor's layout", 1)
    data = {
        "packages": layout["packages"], "physical_cores": len(layout["cores"]),
        "numa_nodes": layout["numa_nodes"], "groups": layout["groups"],
        "cores": [{"core": n, "logical": c["logical"], "hyperthreaded": c["hyperthreaded"]}
                  for n, c in enumerate(layout["cores"])],
    }
    sections = [("layout", [("sockets (packages)", layout["packages"]),
                            ("physical cores", len(layout["cores"])),
                            ("NUMA nodes", len(layout["numa_nodes"])),
                            ("processor groups", len(layout["groups"]))])]
    rows = [(c["core"], _probe.ranges(c["logical"]), "yes" if c["hyperthreaded"] else "no") for c in data["cores"]]
    _probe.emit(options, "processor topology", data, sections, rows=rows,
                headers=["CORE", "LOGICAL PROCESSORS", "HYPER-THREADED"])


def _cpu_power(args, options):
    scheme_text = _probe.powercfg(["/getactivescheme"]) or ""
    match = re.search(r"Power Scheme GUID:\s*\S+\s+\((.+)\)", scheme_text)
    settings = _probe.power_settings(_probe.powercfg(["/query", "SCHEME_CURRENT", "SUB_PROCESSOR"]))
    data = {"plan": match.group(1) if match else None, "settings": settings}
    rows = [(s["name"], s["ac"], s["dc"]) for s in settings]
    _probe.emit(options, f"processor power, plan: {data['plan'] or 'not readable'}", data, rows=rows,
                headers=["SETTING", "ON AC", "ON BATTERY"],
                notes=["values are the plan's own numbers (a percentage for the maximum state)."])


def _cpu_report(args, options):
    layout = _probe.processor_layout() or {}
    _core.print_json({"summary": _cpu_data(), "features": _probe.feature_flags(),
                      "caches": layout.get("caches", []), "topology": {
                          "cores": len(layout.get("cores", [])), "numa_nodes": len(layout.get("numa_nodes", []))}})


CPU_SUBS = {"usage": _cpu_usage, "frequency": _cpu_frequency, "cache": _cpu_cache, "features": _cpu_features,
            "topology": _cpu_topology, "power": _cpu_power, "report": _cpu_report}


def _cpu(rest, options):
    _dispatch("cpu", CPU_SUBS, _cpu_summary, rest, options)


# ======================================================================
# GRAPHICS — hw gpu
# ======================================================================
GPU_BODY = r"""
Get-Part 'adapters' { Get-CimInstance Win32_VideoController | Select-Object Name, AdapterCompatibility, DriverVersion, DriverDate, AdapterRAM, PNPDeviceID, VideoProcessor, VideoModeDescription, CurrentRefreshRate, CurrentHorizontalResolution, CurrentVerticalResolution, Status, CapabilityDescriptions }
Get-Part 'registry' { Get-ChildItem '""" + DISPLAY_CLASS + r"""' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DriverDesc } | Select-Object DriverDesc, DriverVersion, MatchingDeviceId, @{ n = 'memory'; e = { $_.'HardwareInformation.qwMemorySize' } } }
"""


def _kind(name, vendor):
    """A guess from the vendor and the name: Windows does not say whether a card is built in."""
    lowered = name.lower()
    if vendor == "Microsoft" or "basic display" in lowered:
        return "basic display (no vendor driver)"
    if vendor == "Intel":
        return "discrete" if re.search(r"\bArc\b", name) else "integrated"
    if vendor == "AMD":
        return "integrated" if "graphics" in lowered and " rx " not in lowered else "discrete"
    if vendor == "NVIDIA":
        return "discrete"
    return "unknown"


def _gpus():
    data, errors = _probe.probe(GPU_BODY)
    memory = {row.get("DriverDesc"): row for row in data.get("registry") or []}
    gpus = []
    for number, row in enumerate(data.get("adapters") or [], start=1):
        name = _name(row.get("Name")) or "unknown"
        vendor = _vendor(row.get("PNPDeviceID"))
        found = memory.get(row.get("Name")) or {}
        vram = found.get("memory")
        source = "registry (the driver's own figure)"
        if vram is None and row.get("AdapterRAM") is not None:
            vram, source = row["AdapterRAM"], "AdapterRAM (32-bit: capped at 4 GB)"
        width, height = row.get("CurrentHorizontalResolution"), row.get("CurrentVerticalResolution")
        gpus.append({
            "id": number, "name": name, "vendor": vendor, "kind": _kind(name, vendor),
            "device_id": _ids(row.get("PNPDeviceID")), "driver_version": row.get("DriverVersion"),
            "driver_date": (row.get("DriverDate") or "")[:10] or None,
            "video_memory_bytes": vram, "video_memory": _size(vram), "video_memory_source": source,
            "resolution": f"{width}x{height}" if width and height else None,
            "refresh_hz": row.get("CurrentRefreshRate"), "processor": _name(row.get("VideoProcessor")),
            "capabilities": row.get("CapabilityDescriptions") or [], "status": row.get("Status"),
            "pnp_id": row.get("PNPDeviceID"),
        })
    return gpus, errors


def _gpu_list(args, options):
    gpus, errors = _gpus()
    rows = [(g["id"], g["name"], g["kind"], g["video_memory"], g["driver_version"], g["driver_date"]) for g in gpus]
    data = _unavailable({"gpus": gpus}, errors)
    _probe.emit(options, "graphics", data, rows=rows,
                headers=["ID", "NAME", "KIND (a guess)", "VIDEO MEMORY", "DRIVER", "DATE"],
                notes=_notes(errors) + ["'hw gpu inspect <n>' shows one card in full."])


def _gpu_inspect(args, options):
    gpus, errors = _gpus()
    gpu = _pick(args, gpus, "gpu")
    sections = [
        ("card", [("name", gpu["name"]), ("vendor", gpu["vendor"]), ("kind", gpu["kind"] + " (a guess)"),
                  ("device ID", gpu["device_id"]), ("processor", gpu["processor"])]),
        ("memory", [("video memory", gpu["video_memory"]), ("where it came from", gpu["video_memory_source"])]),
        ("driver", [("version", gpu["driver_version"]), ("date", gpu["driver_date"])]),
        ("display", [("resolution", gpu["resolution"]), ("refresh rate", f"{gpu['refresh_hz']} Hz"
                                                          if gpu["refresh_hz"] else None)]),
        ("capabilities", [("reported", gpu["capabilities"] or None)]),
        ("status", [("Windows status", gpu["status"])]),
    ]
    _probe.emit(options, gpu["name"], gpu, sections, notes=_notes(errors))


USAGE_NAMES = {"3d": "3D", "compute": "compute", "copy": "copy", "videodecode": "video decode",
               "videoencode": "video encode", "videoprocessing": "video processing"}


def _gpu_usage(args, options):
    args, seconds = _seconds(args, 5)
    readings = _probe.sample([r"\GPU Engine(*)\Utilization Percentage"], seconds)
    per_moment = []
    for moment in readings:
        engines = defaultdict(float)
        for item in moment["samples"]:
            match = re.search(r"phys_(\d+)_eng_(\d+)_engtype_(\w+)", item["path"].lower())
            if match:
                engines[(match.group(1), match.group(2), match.group(3))] += item["value"] or 0
        kinds = defaultdict(float)
        for (phys, eng, kind), value in engines.items():
            kinds[kind] = max(kinds[kind], min(value, 100))
        per_moment.append(kinds)
    kinds = sorted({kind for moment in per_moment for kind in moment})
    rows, data = [], {"seconds": seconds, "engines": {}}
    for kind in kinds:
        values = [moment.get(kind, 0.0) for moment in per_moment]
        label = USAGE_NAMES.get(kind, kind)
        data["engines"][kind] = {"average_percent": _probe.average(values), "peak_percent": _probe.peak(values)}
        rows.append((label, _probe.average(values), _probe.peak(values)))
    _probe.emit(options, f"graphics engines over {seconds} s (busiest engine of each kind)", data, rows=rows,
                headers=["ENGINE", "AVERAGE %", "PEAK %"],
                notes=[] if rows else ["no GPU engine counters were reported."])


def _gpu_memory(args, options):
    gpus, errors = _gpus()
    readings = _probe.sample([r"\GPU Adapter Memory(*)\Dedicated Usage", r"\GPU Adapter Memory(*)\Shared Usage"], 1)
    used = defaultdict(lambda: {"dedicated": None, "shared": None})
    for item in readings[-1]["samples"] if readings else []:
        kind = "dedicated" if "dedicated" in item["path"].lower() else "shared"
        used[_probe.instance_of(item["path"])][kind] = item["value"]
    total = sum(g["video_memory_bytes"] or 0 for g in gpus)
    adapters = [{"adapter": key, "dedicated_used": _size(value["dedicated"]), "shared_used": _size(value["shared"])}
                for key, value in used.items()]
    data = _unavailable({"video_memory_total": _size(total) if total else None, "adapters": adapters,
                         "budget": "not exposed: Windows does not report the budget without a graphics API call"},
                        errors)
    sections = [("dedicated (on the card)", [("total", data["video_memory_total"])]),
                ("in use", [(a["adapter"], f"{a['dedicated_used']} dedicated, {a['shared_used']} shared")
                            for a in adapters] or [("adapters", None)])]
    _probe.emit(options, "graphics memory", data, sections, notes=_notes(errors))


def _gpu_display(args, options):
    gpus, errors = _gpus()
    data, more = _probe.probe(r"""
Add-Type -AssemblyName System.Windows.Forms
Get-Part 'screens' { [System.Windows.Forms.Screen]::AllScreens | Select-Object DeviceName, Primary, Bounds }
Get-Part 'monitors' { Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorID | Select-Object ManufacturerName, UserFriendlyName, ProductCodeID }
""")
    screens = [{"device": s.get("DeviceName"), "primary": s.get("Primary"),
                "resolution": f"{s['Bounds']['Width']}x{s['Bounds']['Height']}",
                "position": f"{s['Bounds']['X']},{s['Bounds']['Y']}"} for s in data.get("screens") or []]
    monitors = [{"name": _text(m.get("UserFriendlyName")), "maker": _text(m.get("ManufacturerName")),
                 "product_code": _text(m.get("ProductCodeID"))} for m in data.get("monitors") or []]
    refresh = gpus[0]["refresh_hz"] if gpus else None
    out = _unavailable({"screens": screens, "monitors": monitors, "refresh_hz": refresh,
                        "outputs": "not exposed: Windows does not report which port (HDMI, DisplayPort) each screen uses"},
                       {**errors, **more})
    rows = [(s["device"], "yes" if s["primary"] else "no", s["resolution"], s["position"]) for s in screens]
    sections = [("monitors", [(m["name"] or "unnamed", m["maker"]) for m in monitors] or [("found", None)]),
                ("refresh", [("adapter's current rate", f"{refresh} Hz" if refresh else None)])]
    _probe.emit(options, "displays", out, sections, rows=rows,
                headers=["SCREEN", "PRIMARY", "RESOLUTION", "POSITION"],
                notes=_notes({**errors, **more}))


def _text(values):
    """A WMI character array (a list of numbers) as text."""
    if isinstance(values, list):
        return bytes(v for v in values if v).decode("ascii", errors="replace") or None
    return values


def _gpu_drivers(args, options):
    data, errors = _probe.probe(r"""
Get-Part 'drivers' { Get-CimInstance Win32_PnPSignedDriver -Filter "DeviceClass='DISPLAY'" | Select-Object DeviceName, DriverProviderName, DriverVersion, DriverDate, InfName, IsSigned, Signer, Manufacturer }
""")
    drivers = [{"device": d.get("DeviceName"), "provider": d.get("DriverProviderName"),
                "version": d.get("DriverVersion"), "date": (d.get("DriverDate") or "")[:10] or None,
                "inf": d.get("InfName"), "signed": d.get("IsSigned"), "signer": d.get("Signer")}
               for d in data.get("drivers") or []]
    rows = [(d["device"], d["provider"], d["version"], d["date"], "yes" if d["signed"] else "no") for d in drivers]
    _probe.emit(options, "graphics drivers", _unavailable({"drivers": drivers}, errors), rows=rows,
                headers=["DEVICE", "PROVIDER", "VERSION", "DATE", "SIGNED"], notes=_notes(errors))


def _gpu_processes(args, options):
    args, seconds = _seconds(args, 3)
    readings = _probe.sample([r"\GPU Engine(*)\Utilization Percentage", r"\GPU Process Memory(*)\Dedicated Usage",
                              r"\GPU Process Memory(*)\Shared Usage"], seconds)
    engine_by_moment, last = [], {}
    for moment in readings:
        busy = defaultdict(float)
        for item in moment["samples"]:
            name = item["path"].lower()
            pid = re.search(r"pid_(\d+)", name)
            if not pid:
                continue
            if "engine" in name:
                busy[pid.group(1)] += item["value"] or 0
            elif "dedicated" in name:
                last.setdefault(pid.group(1), {})["dedicated"] = item["value"]
            elif "shared" in name:
                last.setdefault(pid.group(1), {})["shared"] = item["value"]
        engine_by_moment.append(busy)
    names, _ = _probe.probe(r"Get-Part 'processes' { Get-Process | Select-Object Id, ProcessName }")
    label = {str(p["Id"]): p["ProcessName"] for p in names.get("processes") or []}
    pids = set(last) | {pid for busy in engine_by_moment for pid in busy}
    rows = []
    for pid in pids:
        busy = [moment.get(pid, 0.0) for moment in engine_by_moment]
        mem = last.get(pid, {})
        rows.append({"pid": int(pid), "name": label.get(pid), "gpu_average_percent": _probe.average(busy),
                     "dedicated_memory": _size(mem.get("dedicated")), "shared_memory": _size(mem.get("shared")),
                     "_dedicated": mem.get("dedicated") or 0})
    rows.sort(key=lambda r: (r["gpu_average_percent"] or 0, r["_dedicated"]), reverse=True)
    for row in rows:
        del row["_dedicated"]
    shown = rows[:DEFAULT_COUNT]
    data = {"seconds": seconds, "processes": rows}
    _probe.emit(options, f"processes using the GPU (sampled over {seconds} s)", data,
                rows=[(r["pid"], r["name"], r["gpu_average_percent"], r["dedicated_memory"], r["shared_memory"])
                      for r in shown],
                headers=["PID", "NAME", "GPU %", "DEDICATED", "SHARED"],
                notes=[] if rows else ["no processes are using the GPU right now."])


GPU_ERROR_NOTE = "driver resets and GPU faults that Windows logged"


def _gpu_errors(args, options):
    import events
    args, days = _days_arg(args, 7)
    rows = events._fetch(["System", "Application"], events._query(levels=[1, 2, 3], since=events._when(f"{days}d")),
                         limit=200, providers=GPU_PROVIDERS)
    if not options["json"]:
        print(f"{GPU_ERROR_NOTE}, the last {days} day(s)")
    events._print_events(rows, options, empty=f"no GPU errors in the last {days} day(s)")


def _days_arg(args, default):
    if args and args[0].isdigit() and int(args[0]) >= 1:
        return args[1:], int(args[0])
    return args, default


GPU_SUBS = {"list": _gpu_list, "inspect": _gpu_inspect, "usage": _gpu_usage, "memory": _gpu_memory,
            "display": _gpu_display, "drivers": _gpu_drivers, "processes": _gpu_processes, "errors": _gpu_errors}


def _gpu_report(args, options):
    gpus, errors = _gpus()
    _core.print_json(_unavailable({"gpus": gpus, "drivers_and_memory": "see hw gpu drivers and hw gpu memory"}, errors))


def _gpu(rest, options):
    if rest and rest[0].lower() == "report":
        return _gpu_report(rest[1:], options)
    _dispatch("gpu", GPU_SUBS, _gpu_list, rest, options)


# ======================================================================
# MEMORY — hw ram
# ======================================================================
RAM_BODY = r"""
Get-Part 'os' { Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory }
Get-Part 'modules' { Get-CimInstance Win32_PhysicalMemory | Select-Object Capacity, Manufacturer, PartNumber, SerialNumber, Speed, ConfiguredClockSpeed, DeviceLocator, BankLabel, FormFactor, SMBIOSMemoryType, TypeDetail }
Get-Part 'arrays' { Get-CimInstance Win32_PhysicalMemoryArray | Select-Object MemoryDevices, MaxCapacity }
Get-Part 'perf' { Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | Select-Object AvailableBytes, CommittedBytes, CommitLimit, CacheBytes, StandbyCacheCoreBytes, StandbyCacheNormalPriorityBytes, StandbyCacheReserveBytes, ModifiedPageListBytes, FreeAndZeroPageListBytes, PoolPagedBytes, PoolNonpagedBytes, PagesPerSec, PageFaultsPerSec, PagesInputPerSec, PagesOutputPerSec }
"""


def _ram_data():
    data, errors = _probe.probe(RAM_BODY)
    os_row = (data.get("os") or [{}])[0]
    perf = (data.get("perf") or [{}])[0]
    modules = data.get("modules") or []
    installed = sum(m.get("Capacity") or 0 for m in modules) or None
    usable = (os_row.get("TotalVisibleMemorySize") or 0) * 1024 or None
    available = perf.get("AvailableBytes")
    if available is None and os_row.get("FreePhysicalMemory") is not None:
        available = os_row["FreePhysicalMemory"] * 1024
    committed, limit = perf.get("CommittedBytes"), perf.get("CommitLimit")
    standby = sum(perf.get(k) or 0 for k in ("StandbyCacheCoreBytes", "StandbyCacheNormalPriorityBytes",
                                             "StandbyCacheReserveBytes"))
    out = {
        "installed": _size(installed), "installed_bytes": installed,
        "usable": _size(usable), "usable_bytes": usable,
        "reserved_by_hardware": _size(installed - usable) if installed and usable and installed > usable else None,
        "in_use": _size(usable - available) if usable and available is not None else None,
        "in_use_percent": _pct(usable - available, usable) if usable and available is not None else None,
        "available": _size(available), "available_bytes": available,
        "available_percent": _pct(available, usable),
        "cached": _size(perf.get("CacheBytes")), "standby": _size(standby or None),
        "modified": _size(perf.get("ModifiedPageListBytes")),
        "free": _size(perf.get("FreeAndZeroPageListBytes")),
        "paged_pool": _size(perf.get("PoolPagedBytes")), "non_paged_pool": _size(perf.get("PoolNonpagedBytes")),
        "committed": _size(committed), "commit_limit": _size(limit),
        "commit_percent": _pct(committed, limit),
        "pages_per_second": perf.get("PagesPerSec"), "page_faults_per_second": perf.get("PageFaultsPerSec"),
    }
    return _unavailable(out, errors), modules


def _ram_summary(args, options):
    data, modules = _ram_data()
    sections = [
        ("installed", [("installed", data["installed"]), ("usable by Windows", data["usable"]),
                       ("reserved by hardware", data["reserved_by_hardware"]), ("modules", len(modules))]),
        ("now", [("in use", f"{data['in_use']} ({data['in_use_percent']}%)" if data["in_use"] else None),
                 ("available", f"{data['available']} ({data['available_percent']}%)" if data["available"] else None),
                 ("committed", f"{data['committed']} of {data['commit_limit']} ({data['commit_percent']}%)"
                  if data["committed"] else None)]),
        ("paging", [("pages per second", data["pages_per_second"]),
                    ("page faults per second", data["page_faults_per_second"])]),
    ]
    _probe.emit(options, "memory", data, sections, notes=_notes(data.get("unavailable", {})))


def _ram_modules(args, options):
    data, errors = _probe.probe(RAM_BODY)
    rows = []
    modules = []
    for number, m in enumerate(data.get("modules") or [], start=1):
        item = {"id": number, "slot": m.get("DeviceLocator"), "bank": m.get("BankLabel"),
                "size": _size(m.get("Capacity")), "size_bytes": m.get("Capacity"),
                "type": SMBIOS_MEMORY.get(m.get("SMBIOSMemoryType"), "unknown"),
                "form_factor": FORM_FACTORS.get(m.get("FormFactor"), "unknown"),
                "manufacturer": _name(m.get("Manufacturer")), "part_number": _name(m.get("PartNumber")),
                "rated_mhz": m.get("Speed"), "running_mhz": m.get("ConfiguredClockSpeed")}
        modules.append(item)
        rows.append((number, item["slot"], item["size"], item["type"], item["manufacturer"], item["part_number"],
                     f"{item['running_mhz']} MHz" if item["running_mhz"] else None))
    _probe.emit(options, "memory modules", _unavailable({"modules": modules}, errors), rows=rows,
                headers=["ID", "SLOT", "SIZE", "TYPE", "MAKER", "PART NUMBER", "RUNNING"], notes=_notes(errors))


def _ram_slots(args, options):
    data, errors = _probe.probe(RAM_BODY)
    arrays = data.get("arrays") or []
    total_slots = sum(a.get("MemoryDevices") or 0 for a in arrays) or None
    modules = data.get("modules") or []
    slots = [{"slot": m.get("DeviceLocator"), "bank": m.get("BankLabel"), "populated": True} for m in modules]
    out = _unavailable({"total_slots": total_slots, "populated": len(modules),
                        "free": (total_slots - len(modules)) if total_slots else None,
                        "max_capacity": _size(sum((a.get("MaxCapacity") or 0) * 1024 for a in arrays) or None),
                        "slots": slots,
                        "channels": "not exposed: Windows does not say which slots form a channel; bank labels are shown"},
                       errors)
    rows = [(s["slot"], s["bank"]) for s in slots]
    sections = [("slots", [("total reported", total_slots), ("populated", len(modules)),
                           ("free", out["free"]), ("maximum supported", out["max_capacity"])])]
    _probe.emit(options, "memory slots", out, sections, rows=rows, headers=["SLOT", "BANK"],
                notes=[out["channels"]] + _notes(errors))


def _ram_usage(args, options):
    data, _ = _ram_data()
    sections = [("memory", [("in use", data["in_use"]), ("available", data["available"]), ("cached", data["cached"]),
                            ("standby", data["standby"]), ("modified", data["modified"]), ("free", data["free"])]),
                ("kernel", [("paged pool", data["paged_pool"]), ("non-paged pool", data["non_paged_pool"])])]
    _probe.emit(options, "memory use", data, sections, notes=_notes(data.get("unavailable", {})))


def _ram_processes(args, options):
    args, count = _count(args)
    data, errors = _probe.probe(
        f"Get-Part 'processes' {{ Get-Process | Sort-Object PrivateMemorySize64 -Descending | Select-Object -First {count} Id, ProcessName, WorkingSet64, PrivateMemorySize64, PagedMemorySize64 }}")
    rows = [{"pid": p.get("Id"), "name": p.get("ProcessName"), "working_set": _size(p.get("WorkingSet64")),
             "working_set_bytes": p.get("WorkingSet64"), "private_committed": _size(p.get("PrivateMemorySize64")),
             "private_committed_bytes": p.get("PrivateMemorySize64")} for p in data.get("processes") or []]
    _probe.emit(options, f"the {count} processes using the most committed memory",
                _unavailable({"processes": rows}, errors),
                rows=[(r["pid"], r["name"], r["working_set"], r["private_committed"]) for r in rows],
                headers=["PID", "NAME", "WORKING SET", "COMMITTED"], notes=_notes(errors))


def _ram_paging(args, options):
    data, errors = _probe.probe(r"""
Get-Part 'files' { Get-CimInstance Win32_PageFileUsage | Select-Object Name, AllocatedBaseSize, CurrentUsage, PeakUsage }
Get-Part 'settings' { Get-CimInstance Win32_PageFileSetting | Select-Object Name, InitialSize, MaximumSize }
Get-Part 'system' { Get-CimInstance Win32_ComputerSystem | Select-Object AutomaticManagedPagefile }
""")
    readings = _probe.sample([r"\Memory\Pages/sec", r"\Memory\Pages Input/sec", r"\Memory\Pages Output/sec",
                              r"\Paging File(_Total)\% Usage", r"\Memory\Commit Limit"], 3)
    per = defaultdict(list)
    for moment in readings:
        for item in moment["samples"]:
            per[_probe.counter_name(item["path"])].append(item["value"])
    files = [{"file": f.get("Name"), "size": _size((f.get("AllocatedBaseSize") or 0) * 1048576),
              "in_use": _size((f.get("CurrentUsage") or 0) * 1048576),
              "peak_in_use": _size((f.get("PeakUsage") or 0) * 1048576)} for f in data.get("files") or []]
    out = _unavailable({
        "files": files, "automatic_management": (data.get("system") or [{}])[0].get("AutomaticManagedPagefile"),
        "pages_per_second": _probe.average(per["pages/sec"]), "pages_input_per_second": _probe.average(per["pages input/sec"]),
        "pages_output_per_second": _probe.average(per["pages output/sec"]),
        "page_file_percent": _probe.average(per["% usage"]),
        "peak_pages_per_second": _probe.peak(per["pages/sec"]),
    }, errors)
    rows = [(f["file"], f["size"], f["in_use"], f["peak_in_use"]) for f in files]
    sections = [("paging file", [("automatic management", out["automatic_management"]),
                                 ("average in use (3 s)", f"{out['page_file_percent']}%"
                                  if out["page_file_percent"] is not None else None)]),
                ("paging rate (3 s)", [("average pages per second", out["pages_per_second"]),
                                       ("peak pages per second", out["peak_pages_per_second"])])]
    _probe.emit(options, "paging", out, sections, rows=rows, headers=["FILE", "SIZE", "IN USE", "PEAK"],
                notes=_notes(errors))


def _ram_pressure(args, options):
    args, seconds = _seconds(args, 5)
    data, _ = _ram_data()
    readings = _probe.sample([r"\Memory\Available MBytes", r"\Memory\Committed Bytes", r"\Memory\Commit Limit",
                              r"\Memory\Pages/sec", r"\Paging File(_Total)\% Usage"], seconds)
    per = defaultdict(list)
    for moment in readings:
        for item in moment["samples"]:
            per[_probe.counter_name(item["path"])].append(item["value"])
    available = _probe.average(per["available mbytes"])
    usable_mb = (data["usable_bytes"] or 0) / 1048576 or None
    avail_pct = _pct(available, usable_mb) if usable_mb else None
    commit = [c / l for c, l in zip(per["committed bytes"], per["commit limit"]) if l]
    paging = per["pages/sec"]
    heavy_share = (sum(1 for p in paging if p > PAGE_RATE_HIGH) / len(paging)) if paging else 0
    findings = []
    if avail_pct is not None and avail_pct < 10:
        findings.append(("warn" if avail_pct >= 5 else "bad", f"only {avail_pct}% of memory is available"))
    if heavy_share >= 0.6:
        findings.append(("warn", f"paging above {PAGE_RATE_HIGH} pages per second for most of the {seconds} s "
                                 f"(average {round(_probe.average(paging) or 0)})"))
    if commit and sum(commit) / len(commit) > COMMIT_HIGH:
        findings.append(("warn", "committed memory is close to the commit limit: programs may fail to allocate"))
    if per["% usage"] and (_probe.average(per["% usage"]) or 0) > PAGE_FILE_HIGH:
        findings.append(("warn", f"the page file is more than {PAGE_FILE_HIGH}% in use"))
    out = {
        "seconds": seconds, "available_percent": avail_pct, "available_mb_average": available,
        "paging_average": _probe.average(paging), "paging_peak": _probe.peak(paging),
        "commit_ratio_average": round(sum(commit) / len(commit), 3) if commit else None,
        "verdict": "memory pressure" if any(level != "info" for level, _ in findings) else "no sustained pressure",
        "findings": [{"level": level, "text": text} for level, text in findings],
    }
    lines = [f"{'[' + level + ']':<7}{text}" for level, text in findings] or ["ok: no sustained memory pressure seen"]
    sections = [("reading", [("verdict", out["verdict"]), ("available", f"{avail_pct}%" if avail_pct is not None else None),
                             ("paging (average)", out["paging_average"]), ("paging (peak)", out["paging_peak"]),
                             ("committed vs limit", out["commit_ratio_average"])])]
    _probe.emit(options, f"memory pressure over {seconds} s", out, sections, notes=lines)


def _ram_test(args, options):
    text = ("Windows' memory test is started from Windows Tools, not from this page: it reboots the PC and checks "
            "memory before Windows loads. Run 'mdsched.exe' and choose the restart option. A live reading cannot "
            "test all of the memory, so this page does not start it.")
    if options["json"]:
        _core.print_json({"action": "guidance only", "tool": "mdsched.exe", "text": text})
        return
    print(text)


def _ram_report(args, options):
    data, modules = _ram_data()
    _core.print_json({"memory": data, "modules": modules})


RAM_SUBS = {"modules": _ram_modules, "slots": _ram_slots, "usage": _ram_usage, "processes": _ram_processes,
            "paging": _ram_paging, "pressure": _ram_pressure, "test": _ram_test, "report": _ram_report}


def _ram(rest, options):
    _dispatch("ram", RAM_SUBS, _ram_summary, rest, options)


# ======================================================================
# STORAGE — hw storage
# ======================================================================
STORAGE_BODY = r"""
Get-Part 'drives' { Get-CimInstance Win32_DiskDrive | Select-Object Index, Model, Size, InterfaceType, MediaType, SerialNumber, FirmwareRevision, PNPDeviceID, Partitions }
Get-Part 'physical' { Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size }
Get-Part 'volumes' { Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, Size, SizeRemaining, UniqueId }
Get-Part 'partitions' { Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type, IsBoot, IsSystem }
"""


def _disk_kind(bus, media, removable):
    if bus in DISK_BUS_KINDS:
        return DISK_BUS_KINDS[bus]
    if removable or bus == "USB":
        return "removable or external"
    if bus == "NVMe":
        return "NVMe SSD"
    return {"SSD": "SSD", "HDD": "hard disk"}.get(media, "unknown")


def _disks():
    data, errors = _probe.probe(STORAGE_BODY)
    physical = {str(p.get("DeviceId")): p for p in data.get("physical") or []}
    disks = []
    for drive in data.get("drives") or []:
        index = str(drive.get("Index"))
        phys = physical.get(index, {})
        removable = "removable" in (drive.get("MediaType") or "").lower()
        disks.append({
            "id": int(index) if index.isdigit() else index,
            "model": _name(drive.get("Model") or phys.get("FriendlyName")),
            "kind": _disk_kind(phys.get("BusType") or drive.get("InterfaceType"), phys.get("MediaType"), removable),
            "size": _size(drive.get("Size")), "size_bytes": drive.get("Size"),
            "bus": phys.get("BusType") or drive.get("InterfaceType"),
            "serial": _name(drive.get("SerialNumber")), "firmware": _name(drive.get("FirmwareRevision")),
            "partitions": drive.get("Partitions"), "health": phys.get("HealthStatus"),
            "operational": phys.get("OperationalStatus"), "pnp_id": drive.get("PNPDeviceID"),
        })
    return disks, data, errors


def _storage_list(args, options):
    disks, data, errors = _disks()
    rows = [(d["id"], d["model"], d["kind"], d["size"], d["bus"], d["health"]) for d in disks]
    _probe.emit(options, "drives", _unavailable({"drives": disks}, errors), rows=rows,
                headers=["ID", "MODEL", "KIND", "SIZE", "BUS", "HEALTH"],
                notes=_notes(errors) + ["'hw storage inspect <n>' shows one drive in full."])


def _storage_inspect(args, options):
    disks, data, errors = _disks()
    disk = _pick(args, disks, "storage")
    sections = [
        ("drive", [("model", disk["model"]), ("kind", disk["kind"]), ("size", disk["size"]),
                   ("bus", disk["bus"]), ("serial", disk["serial"]), ("firmware", disk["firmware"])]),
        ("health", [("health", disk["health"]), ("operational status", disk["operational"])]),
        ("layout", [("partitions", disk["partitions"]), ("device ID", disk["pnp_id"])]),
    ]
    _probe.emit(options, disk["model"] or "drive", disk, sections, notes=_notes(errors))


def _storage_partitions(args, options):
    data, errors = _probe.probe(STORAGE_BODY)
    parts = [{"disk": p.get("DiskNumber"), "partition": p.get("PartitionNumber"),
              "drive_letter": p.get("DriveLetter"), "size": _size(p.get("Size")), "type": p.get("Type"),
              "boot": p.get("IsBoot"), "system": p.get("IsSystem")} for p in data.get("partitions") or []]
    rows = [(p["disk"], p["partition"], p["drive_letter"] or "-", p["size"], p["type"]) for p in parts]
    _probe.emit(options, "partitions", _unavailable({"partitions": parts}, errors), rows=rows,
                headers=["DISK", "PART", "LETTER", "SIZE", "TYPE"], notes=_notes(errors))


def _storage_volumes(args, options):
    data, errors = _probe.probe(STORAGE_BODY)
    volumes = []
    for v in data.get("volumes") or []:
        size, free = v.get("Size") or 0, v.get("SizeRemaining")
        volumes.append({"letter": v.get("DriveLetter"), "label": v.get("FileSystemLabel") or None,
                        "file_system": v.get("FileSystem"), "type": v.get("DriveType"),
                        "size": _size(size), "free": _size(free), "free_percent": _pct(free, size) if size else None,
                        "health": v.get("HealthStatus"), "id": v.get("UniqueId")})
    rows = [(v["letter"] or "-", v["label"] or "-", v["file_system"] or "-", v["size"], v["free"],
             f"{v['free_percent']}%" if v["free_percent"] is not None else "-", v["health"]) for v in volumes]
    _probe.emit(options, "volumes", _unavailable({"volumes": volumes}, errors), rows=rows,
                headers=["LETTER", "LABEL", "FILE SYSTEM", "SIZE", "FREE", "FREE %", "HEALTH"], notes=_notes(errors))


def _storage_health(args, options):
    disks, _, errors = _disks()
    health, more_errors = _probe.probe(r"""
Get-Part 'reliability' { Get-PhysicalDisk | ForEach-Object { $disk = $_; try { $c = $disk | Get-StorageReliabilityCounter; [pscustomobject]@{ disk = $disk.DeviceId; temperature = $c.Temperature; wear = $c.Wear; read_errors = $c.ReadErrorsTotal; power_on_hours = $c.PowerOnHours } } catch { [pscustomobject]@{ disk = $disk.DeviceId; error = $_.Exception.Message } } } }
Get-Part 'prediction' { Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus | Select-Object InstanceName, PredictFailure, Reason }
""")
    by_disk = {str(r.get("disk")): r for r in health.get("reliability") or []}
    rows, out_disks = [], []
    for disk in disks:
        counters = by_disk.get(str(disk["id"]), {})
        smart = {k: counters.get(k) for k in ("temperature", "wear", "read_errors", "power_on_hours")}
        if counters.get("error"):
            smart["note"] = _probe.reason(counters["error"])
        out_disks.append({"id": disk["id"], "model": disk["model"], "health": disk["health"],
                          "operational": disk["operational"], **smart})
        wear = smart["wear"] if smart["wear"] is not None else smart.get("note", "-")
        rows.append((disk["id"], disk["model"], disk["health"] or "-", disk["operational"] or "-", wear))
    predicted = [p for p in health.get("prediction") or [] if p.get("PredictFailure")]
    out = _unavailable({"disks": out_disks, "failure_predicted": bool(predicted)}, {**errors, **more_errors})
    notes = []
    if predicted:
        notes.append("[bad] Windows reports that a drive is predicted to fail. Back it up now.")
    unhealthy = [d for d in disks if (d["health"] or "Healthy") != "Healthy"]
    if unhealthy:
        notes.append(f"[warn] {len(unhealthy)} drive(s) not reporting Healthy")
    if "prediction" in more_errors and not _core.is_admin():
        notes.append("the failure prediction and SMART details need an administrator terminal")
    _probe.emit(options, "drive health", out, rows=rows, headers=["ID", "MODEL", "HEALTH", "STATUS", "WEAR %"],
                notes=notes + _notes({**errors, **more_errors}))


def _storage_temperature(args, options):
    reliability, errors = _probe.probe(r"""
Get-Part 'reliability' { Get-PhysicalDisk | ForEach-Object { $disk = $_; try { $c = $disk | Get-StorageReliabilityCounter; [pscustomobject]@{ disk = $disk.DeviceId; temperature = $c.Temperature } } catch { [pscustomobject]@{ disk = $disk.DeviceId; error = $_.Exception.Message } } } }
""")
    disks, _, _ = _disks()
    names = {str(d["id"]): d["model"] for d in disks}
    rows, found = [], []
    for item in reliability.get("reliability") or []:
        disk = str(item.get("disk"))
        value = item.get("temperature")
        if item.get("error"):
            value = _probe.reason(item["error"])
        found.append({"id": disk, "model": names.get(disk), "celsius": value if isinstance(value, int) else None})
        rows.append((disk, names.get(disk), f"{value} °C" if isinstance(value, int) else value))
    notes = ["temperature needs an administrator terminal, and only where the drive reports one."] if not _core.is_admin() else []
    _probe.emit(options, "drive temperature", _unavailable({"drives": found}, errors), rows=rows,
                headers=["ID", "MODEL", "TEMPERATURE"], notes=notes + _notes(errors))


def _storage_performance(args, options):
    args, seconds = _seconds(args, 5)
    readings = _probe.sample([r"\PhysicalDisk(*)\Disk Read Bytes/sec", r"\PhysicalDisk(*)\Disk Write Bytes/sec",
                              r"\PhysicalDisk(*)\Avg. Disk Queue Length", r"\PhysicalDisk(*)\% Disk Time",
                              r"\PhysicalDisk(*)\Avg. Disk sec/Read", r"\PhysicalDisk(*)\Avg. Disk sec/Write"], seconds)
    per = defaultdict(lambda: defaultdict(list))
    for moment in readings:
        for item in moment["samples"]:
            instance = _probe.instance_of(item["path"])
            if instance and instance != "_total":
                per[instance][_probe.counter_name(item["path"])].append(item["value"])
    rows, out = [], []
    for instance in sorted(per):
        c = per[instance]
        read, write = c["disk read bytes/sec"], c["disk write bytes/sec"]
        item = {"disk": instance, "read_mb_per_second": _probe.average([v / 1048576 for v in read]),
                "read_peak_mb_per_second": _probe.peak([v / 1048576 for v in read]),
                "write_mb_per_second": _probe.average([v / 1048576 for v in write]),
                "write_peak_mb_per_second": _probe.peak([v / 1048576 for v in write]),
                "queue": _probe.average(c["avg. disk queue length"]), "busy_percent": _probe.average(c["% disk time"]),
                "read_latency_ms": _ms(c["avg. disk sec/read"]), "write_latency_ms": _ms(c["avg. disk sec/write"])}
        out.append(item)
        rows.append((instance, item["read_mb_per_second"], item["write_mb_per_second"], item["queue"],
                     item["busy_percent"], item["read_latency_ms"], item["write_latency_ms"]))
    _probe.emit(options, f"drive performance over {seconds} s", {"seconds": seconds, "drives": out}, rows=rows,
                headers=["DISK", "READ MB/S", "WRITE MB/S", "QUEUE", "BUSY %", "READ MS", "WRITE MS"])


def _ms(values):
    average = _probe.average(values)
    return None if average is None else round(average * 1000, 2)


def _storage_errors(args, options):
    import events
    args, days = _days_arg(args, 7)
    rows = events._fetch(["System", "Application"], events._query(levels=[1, 2, 3], since=events._when(f"{days}d")),
                         limit=200, providers=STORAGE_PROVIDERS)
    if not options["json"]:
        print(f"disk and file-system errors, the last {days} day(s)")
    events._print_events(rows, options, empty=f"no disk or file-system errors in the last {days} day(s)")


def _storage_firmware(args, options):
    disks, _, errors = _disks()
    bios = _bios_data()[0]
    rows = [(d["id"], d["model"], d["firmware"] or "-") for d in disks]
    data = _unavailable({"drives": [{"id": d["id"], "model": d["model"], "firmware": d["firmware"]} for d in disks],
                         "bios": bios.get("version")}, errors)
    _probe.emit(options, "drive firmware", data, rows=rows, headers=["ID", "MODEL", "FIRMWARE"],
                notes=["compare with the drive maker's support page. This page downloads nothing and changes nothing."]
                + _notes(errors))


def _storage_trim(args, options):
    ok, output = _net.run_tool(["fsutil", "behavior", "query", "DisableDeleteNotify"], timeout=30)
    if not ok:
        raise HardwareError(_net.explain(output), 1)
    states = {}
    for match in re.finditer(r"(NTFS|ReFS) DisableDeleteNotify = (\d)", output):
        states[match.group(1)] = "on" if match.group(2) == "0" else "off"
    disks, _, _ = _disks()
    kinds = [d["kind"] for d in disks]
    data = {"file_systems": states, "solid_state_drives": sum(1 for k in kinds if "SSD" in k or "NVMe" in k)}
    sections = [("TRIM (lets the drive reclaim deleted space)",
                 [(name, value) for name, value in states.items()] or [("reported", None)])]
    _probe.emit(options, "TRIM", data, sections,
                notes=["changing TRIM needs an administrator terminal, and this page does not change it."])


def _storage_bitlocker(args, options):
    data, errors = _probe.probe(r"""
Get-Part 'volumes' { Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | Select-Object DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod }
""")
    volumes = [{"letter": v.get("DriveLetter"), "protection": PROTECTION.get(v.get("ProtectionStatus"), "unknown"),
                "conversion": CONVERSION.get(v.get("ConversionStatus"), "unknown"),
                "method": ENCRYPTION.get(v.get("EncryptionMethod"), "unknown")} for v in data.get("volumes") or []]
    rows = [(v["letter"], v["protection"], v["conversion"], v["method"]) for v in volumes]
    _probe.emit(options, "encryption", _unavailable({"volumes": volumes}, errors), rows=rows,
                headers=["DRIVE", "PROTECTION", "STATE", "METHOD"],
                notes=["recovery keys are never read or shown by this page."] + _notes(errors))


def _folder_size(path, deadline):
    """Bytes under a folder, and whether the scan ran out of time before it finished."""
    total = 0
    for root, _, files in os.walk(path, onerror=lambda error: None):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
        if time.monotonic() > deadline:
            return total, True
    return total, False


def _storage_space(args, options):
    path = " ".join(args) or os.environ.get("USERPROFILE", "C:\\")
    if not os.path.isdir(path):
        raise HardwareError(f"there is no folder called {path}", 2)
    volumes = _storage_volumes_data()
    warnings = []
    for v in volumes:
        if v["letter"] and v["free_percent"] is not None and v["free_percent"] < 20:
            warnings.append({"level": "bad" if v["free_percent"] < 10 else "warn", "volume": v["letter"],
                             "text": f"{v['free']} free ({v['free_percent']}%)"})
    deadline = time.monotonic() + SCAN_SECONDS
    folders, partial = [], False
    try:
        children = sorted(os.scandir(path), key=lambda e: e.name.lower())
    except OSError as e:
        raise HardwareError(f"could not open {path}: {e.strerror}", 1)
    for entry in children:
        if entry.is_dir(follow_symlinks=False):
            if time.monotonic() > deadline:
                partial = True
                break
            size, cut = _folder_size(entry.path, deadline)
            partial = partial or cut
            folders.append({"folder": entry.name, "size": _size(size), "size_bytes": size})
        elif entry.is_file(follow_symlinks=False):
            folders.append({"folder": entry.name, "size": _size(entry.stat().st_size), "size_bytes": entry.stat().st_size})
    folders.sort(key=lambda f: f["size_bytes"], reverse=True)
    candidates = []
    for label, template in CLEANUP_FOLDERS:
        folder = os.path.expandvars(template)
        if os.path.isdir(folder):
            size, _ = _folder_size(folder, time.monotonic() + 5)
            candidates.append({"label": label, "folder": folder, "size": _size(size), "size_bytes": size})
    data = {"path": path, "volumes": volumes, "warnings": warnings, "largest": folders[:DEFAULT_COUNT],
            "scan_complete": not partial, "temp_folders": candidates,
            "note": "temp folders are listed for review only: this page deletes nothing"}
    rows = [(f["folder"], f["size"]) for f in folders[:DEFAULT_COUNT]]
    notes = [f"[{w['level']}] volume {w['volume']}: {w['text']}" for w in warnings]
    notes += [f"temp: {c['label']} ({c['folder']}): {c['size']}" for c in candidates]
    notes.append("the folder sizes stopped early (scan time limit), so they may be incomplete." if partial else "")
    notes = [n for n in notes if n]
    _probe.emit(options, f"space under {path}", data, rows=rows, headers=["FOLDER OR FILE", "SIZE"], notes=notes)


def _storage_volumes_data():
    data, _ = _probe.probe(STORAGE_BODY)
    volumes = []
    for v in data.get("volumes") or []:
        size, free = v.get("Size") or 0, v.get("SizeRemaining")
        volumes.append({"letter": v.get("DriveLetter"), "free": _size(free),
                        "free_percent": _pct(free, size) if size else None})
    return volumes


def _storage_report(args, options):
    disks, _, errors = _disks()
    _core.print_json(_unavailable({"drives": disks, "volumes": _storage_volumes_data()}, errors))


STORAGE_SUBS = {"list": _storage_list, "inspect": _storage_inspect, "partitions": _storage_partitions,
                "volumes": _storage_volumes, "health": _storage_health, "temperature": _storage_temperature,
                "performance": _storage_performance, "errors": _storage_errors, "firmware": _storage_firmware,
                "trim": _storage_trim, "bitlocker": _storage_bitlocker, "space": _storage_space,
                "report": _storage_report}


def _storage(rest, options):
    _dispatch("storage", STORAGE_SUBS, _storage_list, rest, options)


# ======================================================================
# BOARD, FIRMWARE AND DEVICES — hw board, bios, firmware, pci, usb, battery, fans, sensors
# ======================================================================
def _bios_data():
    data, errors = _probe.probe(r"""
Get-Part 'bios' { Get-CimInstance Win32_BIOS | Select-Object Manufacturer, Name, SMBIOSBIOSVersion, Version, ReleaseDate, SMBIOSMajorVersion, SMBIOSMinorVersion }
Get-Part 'boot' { $uefi = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'; $secure = $null; if ($uefi) { $secure = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled }; [pscustomobject]@{ uefi = $uefi; secure_boot = $secure } }
""")
    bios = (data.get("bios") or [{}])[0]
    boot = (data.get("boot") or [{}])[0]
    out = {
        "manufacturer": bios.get("Manufacturer"), "version": bios.get("SMBIOSBIOSVersion"),
        "release_date": (bios.get("ReleaseDate") or "")[:10] or None,
        "smbios": f"{bios.get('SMBIOSMajorVersion')}.{bios.get('SMBIOSMinorVersion')}"
        if bios.get("SMBIOSMajorVersion") else None,
        "boot_mode": "UEFI" if boot.get("uefi") else "legacy BIOS" if boot else None,
        "secure_boot": {1: "on", 0: "off"}.get(boot.get("secure_boot"), None) if boot.get("uefi") else None,
    }
    return out, errors


def _board_data():
    data, errors = _probe.probe(r"""
Get-Part 'board' { Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, Version, SerialNumber }
Get-Part 'system' { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemType }
""")
    board = (data.get("board") or [{}])[0]
    system = (data.get("system") or [{}])[0]
    return {"manufacturer": board.get("Manufacturer"), "product": board.get("Product"),
            "version": board.get("Version"), "serial": board.get("SerialNumber"),
            "system_model": system.get("Model"), "system_type": system.get("SystemType")}, errors


def _board(rest, options):
    board, errors = _board_data()
    sections = [("board", [("maker", board["manufacturer"]), ("model", board["product"]),
                           ("revision", board["version"]), ("serial", board["serial"])]),
                ("computer", [("model", board["system_model"]), ("type", board["system_type"])])]
    _probe.emit(options, "motherboard", _unavailable(board, errors), sections, notes=_notes(errors))


def _bios(rest, options):
    out, errors = _bios_data()
    sections = [("BIOS", [("maker", out["manufacturer"]), ("version", out["version"]),
                          ("release date", out["release_date"]), ("SMBIOS", out["smbios"])]),
                ("boot", [("mode", out["boot_mode"]), ("secure boot", out["secure_boot"])])]
    _probe.emit(options, "BIOS", _unavailable(out, errors), sections, notes=_notes(errors))


def _firmware(rest, options):
    bios, bios_errors = _bios_data()
    board, _ = _board_data()
    disks, _, _ = _disks()
    tpm, tpm_errors = _probe.probe("Get-Part 'tpm' { Get-Tpm | Select-Object TpmPresent, ManufacturerVersion }")
    tpm_row = (tpm.get("tpm") or [{}])[0]
    if all(value in (None, "") for value in tpm_row.values()):
        tpm_errors["tpm"] = "needs administrator rights"
        tpm_row = {}
    out = {"bios": bios.get("version"), "motherboard_revision": board.get("version"),
           "drives": [{"id": d["id"], "model": d["model"], "firmware": d["firmware"]} for d in disks],
           "tpm_firmware": tpm_row.get("ManufacturerVersion"),
           "not_exposed": "graphics cards (video BIOS), network cards and most peripherals: Windows does not report them"}
    rows = [("BIOS", bios.get("version")), ("motherboard", board.get("version")),
            ("TPM", tpm_row.get("ManufacturerVersion"))] + [(f"drive {d['id']}", d["firmware"]) for d in disks]
    _probe.emit(options, "firmware", _unavailable(out, {**bios_errors, **tpm_errors}),
                rows=rows, headers=["PART", "VERSION"], notes=["the video BIOS and peripherals are not exposed by Windows."]
                + _notes({**bios_errors, **tpm_errors}))


def _pci(rest, options):
    data, errors = _probe.probe(r"""
Get-Part 'devices' { Get-CimInstance Win32_PnPEntity -Filter "PNPDeviceID like 'PCI%'" | Select-Object Name, Manufacturer, PNPDeviceID, ConfigManagerErrorCode, Service }
""")
    devices = [{"name": d.get("Name"), "maker": d.get("Manufacturer"), "ids": _ids(d.get("PNPDeviceID")),
                "status": "ok" if not d.get("ConfigManagerErrorCode") else f"error code {d['ConfigManagerErrorCode']}",
                "service": d.get("Service"), "pnp_id": d.get("PNPDeviceID")} for d in data.get("devices") or []]
    rows = [(d["name"], d["ids"] or "-", d["status"]) for d in devices]
    _probe.emit(options, f"PCI devices ({len(devices)})", _unavailable({"devices": devices}, errors), rows=rows,
                headers=["NAME", "VENDOR:DEVICE", "STATUS"], notes=_notes(errors))


def _usb(rest, options):
    data, errors = _probe.probe(r"""
Get-Part 'devices' { Get-CimInstance Win32_PnPEntity -Filter "PNPDeviceID like 'USB%'" | Select-Object Name, Manufacturer, PNPDeviceID, ConfigManagerErrorCode }
""")
    devices = [{"name": d.get("Name"), "maker": d.get("Manufacturer"), "ids": _ids(d.get("PNPDeviceID")),
                "status": "ok" if not d.get("ConfigManagerErrorCode") else f"error code {d['ConfigManagerErrorCode']}",
                "pnp_id": d.get("PNPDeviceID")}
               for d in data.get("devices") or [] if "ROOT_HUB" not in (d.get("PNPDeviceID") or "").upper()]
    rows = [(d["name"], d["ids"] or "-", d["status"]) for d in devices]
    _probe.emit(options, f"USB devices ({len(devices)})", _unavailable({"devices": devices}, errors), rows=rows,
                headers=["NAME", "VENDOR:PRODUCT", "STATUS"],
                notes=["connection speed and power draw are not exposed by Windows."] + _notes(errors))


def _battery(rest, options):
    status = _probe.power_status()
    data, errors = _probe.probe(r"""
Get-Part 'battery' { Get-CimInstance Win32_Battery | Select-Object Name, EstimatedChargeRemaining, BatteryStatus, DesignCapacity, FullChargeCapacity }
Get-Part 'design' { Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData | Select-Object DesignedCapacity }
Get-Part 'full' { Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity | Select-Object FullChargedCapacity }
Get-Part 'cycles' { Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount | Select-Object CycleCount }
""")
    batteries = data.get("battery") or []
    design = (data.get("design") or [{}])[0].get("DesignedCapacity")
    full = (data.get("full") or [{}])[0].get("FullChargedCapacity")
    out = _unavailable({
        "present": bool(batteries) if batteries else status["battery"] if status["battery"] is not None else False,
        "on_ac_power": status["ac"], "charge_percent": status["percent"],
        "design_capacity_mwh": design, "full_charge_capacity_mwh": full,
        "health_percent": _pct(full, design) if design and full else None,
        "cycle_count": (data.get("cycles") or [{}])[0].get("CycleCount"),
    }, errors)
    if not out["present"]:
        sections = [("battery", [("present", "no battery in this PC")]),
                    ("power", [("on AC power", status["ac"])])]
    else:
        sections = [("battery", [("charge", f"{status['percent']}%" if status["percent"] is not None else None),
                                 ("on AC power", status["ac"]), ("health", f"{out['health_percent']}%"
                                                                  if out["health_percent"] is not None else None),
                                 ("cycles", out["cycle_count"])])]
    _probe.emit(options, "battery", out, sections, notes=_notes(errors))


def _fans(rest, options):
    data, errors = _probe.probe(r"""
Get-Part 'fans' { Get-CimInstance Win32_Fan | Select-Object Name, DesiredSpeed, ActiveCooling, Status }
""")
    fans = [{"name": f.get("Name"), "desired_rpm": f.get("DesiredSpeed"), "status": f.get("Status")}
            for f in data.get("fans") or []]
    notes = [] if fans else ["no fan sensors are reported to Windows. Motherboard fan readings usually need the vendor's own tool."]
    _probe.emit(options, "fans", _unavailable({"fans": fans}, errors),
                rows=[(f["name"] or "fan", f["desired_rpm"], f["status"]) for f in fans] or None,
                headers=["NAME", "DESIRED RPM", "STATUS"], notes=notes + _notes(errors))


def _sensors(rest, options):
    data, errors = _probe.probe(r"""
Get-Part 'thermal_zones' { Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | Select-Object InstanceName, CurrentTemperature }
Get-Part 'thermal_counters' { Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | Select-Object Name, Temperature }
Get-Part 'temperature_probes' { Get-CimInstance Win32_TemperatureProbe | Select-Object Name, CurrentReading }
Get-Part 'voltage_probes' { Get-CimInstance Win32_VoltageProbe | Select-Object Name, CurrentReading }
Get-Part 'fans' { Get-CimInstance Win32_Fan | Select-Object Name, DesiredSpeed }
""")
    readings = []
    for z in data.get("thermal_zones") or []:
        kelvin_tenths = z.get("CurrentTemperature")
        if kelvin_tenths:
            readings.append({"source": "ACPI thermal zone", "name": z.get("InstanceName"),
                             "reading": round(kelvin_tenths / 10 - 273.15, 1), "unit": "°C"})
    for z in data.get("thermal_counters") or []:
        if z.get("Temperature"):
            readings.append({"source": "thermal counter", "name": z.get("Name"),
                             "reading": round(z["Temperature"] - 273.15, 1), "unit": "°C"})
    for z in data.get("temperature_probes") or []:
        readings.append({"source": "temperature probe", "name": z.get("Name"), "reading": z.get("CurrentReading"),
                         "unit": "°C"})
    for v in data.get("voltage_probes") or []:
        readings.append({"source": "voltage probe", "name": v.get("Name"), "reading": v.get("CurrentReading"),
                         "unit": "mV"})
    for f in data.get("fans") or []:
        readings.append({"source": "fan", "name": f.get("Name"), "reading": f.get("DesiredSpeed"), "unit": "rpm"})
    rows = [(r["source"], r["name"] or "-", f"{r['reading']} {r['unit']}") for r in readings]
    notes = ["CPU and motherboard temperatures usually need a vendor tool: Windows does not expose them here."]
    if not readings:
        notes.insert(0, "no temperature, voltage or fan sensors are reported to Windows on this PC.")
    _probe.emit(options, "sensors", _unavailable({"sensors": readings}, errors), rows=rows,
                headers=["SOURCE", "NAME", "READING"], notes=notes + _notes(errors))


def _hardware_report(args, options):
    """Everything above, as JSON: the static parts and the current values, without the timed samples."""
    cpu = _cpu_data()
    gpus, gpu_errors = _gpus()
    ram, modules = _ram_data()
    disks, _, storage_errors = _disks()
    board, board_errors = _board_data()
    bios, bios_errors = _bios_data()
    battery_status = _probe.power_status()
    layout = _probe.processor_layout() or {}
    pci_data, _ = _probe.probe("Get-Part 'devices' { Get-CimInstance Win32_PnPEntity -Filter \"PNPDeviceID like 'PCI%'\" | Select-Object Name }")
    usb_data, _ = _probe.probe("Get-Part 'devices' { Get-CimInstance Win32_PnPEntity -Filter \"PNPDeviceID like 'USB%'\" | Select-Object Name }")
    _core.print_json({
        "processor": {**cpu, "instruction_sets": _probe.feature_flags(),
                      "cores": len(layout.get("cores", [])), "caches": layout.get("caches", []),
                      "numa_nodes": len(layout.get("numa_nodes", []))},
        "graphics": gpus,
        "memory": {**ram, "modules": modules},
        "storage": {"drives": disks, "volumes": _storage_volumes_data()},
        "motherboard": board, "bios": bios,
        "battery": battery_status,
        "pci_devices": len(pci_data.get("devices") or []),
        "usb_devices": len(usb_data.get("devices") or []),
        "unavailable": {**cpu.get("unavailable", {}), **{f"graphics {k}": v for k, v in gpu_errors.items()},
                        **{f"storage {k}": v for k, v in storage_errors.items()},
                        **{f"motherboard {k}": v for k, v in board_errors.items()},
                        **{f"bios {k}": v for k, v in bios_errors.items()}},
    })


AREA_ROUTES = {"cpu": _cpu, "gpu": _gpu, "ram": _ram, "storage": _storage}
SINGLE = {"board": _board, "bios": _bios, "firmware": _firmware, "pci": _pci, "usb": _usb,
          "battery": _battery, "fans": _fans, "sensors": _sensors}


def run(args):
    """Run one hardware command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    word, rest = args[0].lower(), args[1:]
    try:
        if word == "report" and not rest:
            _hardware_report(rest, options)
        elif word in AREA_ROUTES:
            AREA_ROUTES[word](rest, options)
        elif word in SINGLE and not rest:
            SINGLE[word](rest, options)
        else:
            raise HardwareError(f"usage: {USAGE}", 2)
        return 0
    except (HardwareError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

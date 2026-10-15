"""
system: how the PC is running right now, what starts with it, and whether anything looks wrong.
Routed from app.py ("system" or "sys").

    sys uptime                   when Windows last started, and whether fast startup is on
    sys load [sec]               CPU, memory, disk and GPU busy time, sampled
    sys load watch [sec]         sample for longer and list the moments that spiked, with the busiest process
    sys processes [n]            the processes using the most CPU and memory, with their parents
    sys startup                  programs and tasks that start with Windows or at sign-in
    sys battery                  power source and charge
    sys power                    the power plan, sleep and display timers, and the sleep states available
    sys environment              PATH entries that are duplicated, missing or refer to unknown variables
    sys inventory                hardware, Windows, drivers and installed programs in one list
    sys health                   the indicators that matter for a problem, each marked ok, warn or bad

Nothing here changes the PC. The live readings sample for a few seconds, and `sys load watch` for longer.
Readings Windows keeps from ordinary users say "needs administrator rights".
"""

import datetime as dt
import os
import re
import sys
import winreg
from collections import defaultdict

import _core
import _net
import _probe

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "system"
ALIASES = ["sys"]
SUMMARY = "Uptime, load, processes, startup, power and overall health"
USAGE = "sys uptime | sys load | sys processes | sys startup | sys power | sys health"
HELP = [
    ("sys health", "the indicators that matter for a problem: ok, warn or bad"),
    ("sys load", "CPU, memory, disk and GPU busy time right now"),
    ("sys processes", "the processes using the most CPU and memory"),
    ("sys uptime", "when Windows last started, and whether fast startup is on"),
    ("sys startup", "programs and tasks that start with Windows or at sign-in"),
    ("sys power", "the power plan, sleep and display timers"),
    ("sys battery", "power source and charge"),
    ("sys environment", "PATH entries that are duplicated, missing or broken"),
    ("sys inventory", "hardware, Windows, drivers and installed programs"),
    ("sys load watch [sec]", "watch for longer and list the moments that spiked, with the busiest process"),
]
TIP = (
    "The live readings sample for a few seconds: sys load 10, or sys load watch 120 for a longer watch. "
    "Boot history from the event log is in 'evt boot'. Nothing here changes the PC."
)

# ======================================================================
# CONSTANTS
# ======================================================================
SPIKE = 90  # percent: a reading at or above this is a spike in sys load watch
UPTIME_LONG_DAYS = 14  # longer than this without a restart is worth a note
LOAD_SECONDS = 5
WATCH_SECONDS = 60
MAX_WATCH = 600
PROCESS_SECONDS = 2
SERVICE_FAILURE_IDS = [7000, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7032, 7034]
STORAGE_PROVIDERS = ["disk", "storahci", "stornvme", "ntfs", "volmgr", "volsnap", "partmgr", "storport",
                     "iastor", "nvraid", "usbstor"]
GPU_PROVIDERS = ["nvlddmkm", "display", "dxgkrnl", "dxgmms", "igfx", "amdkmdag", "amdlog", "gpu"]
PATH_KEYS = {"machine": (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
             "user": (winreg.HKEY_CURRENT_USER, r"Environment")}
SAFE_VARIABLES = ("TEMP", "TMP", "USERPROFILE", "SystemRoot", "ComSpec", "PROCESSOR_ARCHITECTURE", "OS")
UNINSTALL_KEYS = [r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                  r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                  r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"]
ORDER = {"bad": 0, "warn": 1, "ok": 2, "info": 3}


class SystemError_(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


def _seconds(args, default, limit):
    if args and args[0].isdigit():
        seconds = int(args[0])
        if not 1 <= seconds <= limit:
            raise SystemError_(f"seconds must be between 1 and {limit}", 2)
        return args[1:], seconds
    return args, default


def _object(path):
    """The counter object in a path: \\\\host\\processor(_total)\\% processor time gives processor."""
    match = re.search(r"\\\\[^\\]+\\([^\\(]+)", path)
    return match.group(1).lower() if match else ""


def _size(number):
    if number is None:
        return None
    value = float(number)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _duration(seconds):
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours or days:
        parts.append(f"{hours} h")
    parts.append(f"{minutes} min")
    return " ".join(parts)


def _worst(levels):
    return min(levels, key=lambda level: ORDER[level]) if levels else "ok"


# ======================================================================
# UPTIME — sys uptime
# ======================================================================
def _uptime_data():
    data, errors = _probe.probe(r"""
Get-Part 'os' { Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime, Caption, Version, BuildNumber, InstallDate, OSArchitecture }
""")
    os_row = (data.get("os") or [{}])[0]
    fast = _net.reg_read(r"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled")
    boot = os_row.get("LastBootUpTime")
    started = dt.datetime.fromisoformat(boot) if boot else None
    seconds = (dt.datetime.now() - started).total_seconds() if started else None
    return {
        "last_boot": boot, "uptime": _duration(seconds) if seconds is not None else None,
        "uptime_seconds": int(seconds) if seconds is not None else None,
        "fast_startup": {1: "on", 0: "off"}.get(fast),
        "windows": f"{os_row.get('Caption')} {os_row.get('Version')} (build {os_row.get('BuildNumber')})"
        if os_row.get("Caption") else None,
        "installed": (os_row.get("InstallDate") or "")[:10] or None,
        "architecture": os_row.get("OSArchitecture"),
        "_errors": errors,
    }


def _uptime(args, options):
    data = _uptime_data()
    errors = data.pop("_errors")
    notes = ["with fast startup on, shutting down is a hibernate, so uptime can run on past the last full start. "
             "'evt boot' lists the real boots."] if data["fast_startup"] == "on" else []
    sections = [("start", [("last boot", data["last_boot"].replace("T", " ") if data["last_boot"] else None),
                           ("uptime", data["uptime"]), ("fast startup", data["fast_startup"])]),
                ("windows", [("version", data["windows"]), ("installed", data["installed"]),
                             ("architecture", data["architecture"])])]
    _probe.emit(options, "uptime", data, sections, notes=notes + _probe.missing_notes(errors))


# ======================================================================
# LOAD — sys load and sys load watch
# ======================================================================
LOAD_COUNTERS = [r"\Processor(_Total)\% Processor Time", r"\Memory\Available MBytes",
                 r"\PhysicalDisk(_Total)\% Disk Time", r"\GPU Engine(*)\Utilization Percentage"]


def _gpu_busiest(sample):
    """The busiest GPU engine in one sample: each engine's use summed over processes, then the largest."""
    engines = defaultdict(float)
    for item in sample["samples"]:
        match = re.search(r"phys_(\d+)_eng_(\d+)", item["path"].lower())
        if match:
            engines[(match.group(1), match.group(2))] += item["value"] or 0
    return round(min(max(engines.values(), default=0.0), 100), 1)


def _load_moments(seconds, watch):
    paths = LOAD_COUNTERS + ([r"\Process(*)\ID Process", r"\Process(*)\% Processor Time"] if watch else [])
    readings = _probe.sample(paths, seconds)
    total_mb = _total_memory_mb()
    moments = []
    for moment in readings:
        cpu = disk = available = gpu = None
        top, top_pid = None, None
        pids, busy = {}, {}
        for item in moment["samples"]:
            obj, path = _object(item["path"]), item["path"].lower()
            if obj == "processor" and path.endswith("% processor time"):
                cpu = item["value"]
            elif obj == "physicaldisk":
                disk = item["value"]
            elif obj == "memory" and "available" in path:
                available = item["value"]
            elif obj == "gpu engine":
                gpu = (gpu or []) + [item]
            elif obj == "process" and path.endswith("id process"):
                pids[_probe.instance_of(item["path"])] = item["value"]
            elif obj == "process" and path.endswith("% processor time"):
                busy[_probe.instance_of(item["path"])] = item["value"]
        if busy:
            ranked = sorted(((v or 0, name) for name, v in busy.items()
                             if name not in ("_total", "idle")), reverse=True)
            if ranked:
                top = ranked[0][1].split("#")[0]
                top_pid = int(pids[ranked[0][1]]) if pids.get(ranked[0][1]) is not None else None
        used = round(100 * (1 - available / total_mb), 1) if available is not None and total_mb else None
        moments.append({"time": moment["time"], "cpu": cpu and round(cpu, 1), "memory": used,
                        "disk": disk and round(disk, 1),
                        "gpu": _gpu_busiest({"samples": gpu}) if gpu else None,
                        "top_process": top, "top_pid": top_pid})
    return moments


def _total_memory_mb():
    data, _ = _probe.probe("Get-Part 'os' { Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize }")
    kilobytes = (data.get("os") or [{}])[0].get("TotalVisibleMemorySize")
    return kilobytes / 1024 if kilobytes else None


def _load(args, options):
    if args and args[0].lower() == "watch":
        args, seconds = _seconds(args[1:], WATCH_SECONDS, MAX_WATCH)
        return _load_watch(seconds, options)
    args, seconds = _seconds(args, LOAD_SECONDS, MAX_WATCH)
    moments = _load_moments(seconds, watch=False)
    summary = {key: _summary(moments, key) for key in ("cpu", "memory", "disk", "gpu")}
    data = {"seconds": seconds, **summary}
    sections = [("busy time over {} s".format(seconds), [
        ("CPU", _line(summary["cpu"])), ("memory in use", _line(summary["memory"])),
        ("disk", _line(summary["disk"])), ("GPU (busiest engine)", _line(summary["gpu"]))])]
    _probe.emit(options, "system load", data, sections)


def _summary(moments, key):
    values = [m[key] for m in moments if m[key] is not None]
    if not values:
        return {"average": None, "peak": None}
    return {"average": round(sum(values) / len(values), 1), "peak": round(max(values), 1)}


def _line(item):
    if item["average"] is None:
        return "not readable"
    return f"average {item['average']}%, peak {item['peak']}%"


def _load_watch(seconds, options):
    moments = _load_moments(seconds, watch=True)
    spikes = [m for m in moments if any((m[k] or 0) >= SPIKE for k in ("cpu", "memory", "disk", "gpu"))]
    windows = _windows(moments)
    data = {"seconds": seconds, "samples": moments, "spikes": spikes,
            "summary": {key: _summary(moments, key) for key in ("cpu", "memory", "disk", "gpu")}}
    rows = [(m["time"][11:19], _pct(m["cpu"]), _pct(m["memory"]), _pct(m["disk"]), _pct(m["gpu"]),
             m["top_process"] or "-") for m in spikes]
    notes = []
    if windows:
        notes.append(f"{len(windows)} spike(s) in {seconds} s, first at {windows[0]}")
    else:
        notes.append(f"no reading reached {SPIKE}% in {seconds} s")
    notes.append("columns show the reading at each spike; the process is the busiest CPU user at that second.")
    _probe.emit(options, f"system watch over {seconds} s", data, rows=rows,
                headers=["TIME", "CPU %", "MEMORY %", "DISK %", "GPU %", "BUSIEST PROCESS"], notes=notes)


def _pct(value):
    return "-" if value is None else f"{value}"


def _windows(moments):
    """The times at which a spike started: the first spiking second after one that did not spike."""
    starts, quiet = [], True
    for moment in moments:
        spiking = any((moment[k] or 0) >= SPIKE for k in ("cpu", "memory", "disk", "gpu"))
        if spiking and quiet:
            starts.append(moment["time"][11:19])
        quiet = not spiking
    return starts


# ======================================================================
# PROCESSES — sys processes
# ======================================================================
def _processes(args, options):
    count = int(args[0]) if args and args[0].isdigit() and int(args[0]) >= 1 else 15
    data, errors = _probe.probe(
        "Get-Part 'processes' { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, WorkingSetSize, ThreadCount, HandleCount }")
    readings = _probe.sample([r"\Process(*)\ID Process", r"\Process(*)\% Processor Time"], PROCESS_SECONDS)
    pids, busy = {}, defaultdict(list)
    for moment in readings:
        for item in moment["samples"]:
            instance = _probe.instance_of(item["path"])
            if item["path"].lower().endswith("id process"):
                pids[instance] = int(item["value"] or 0)
            else:
                busy[instance].append(item["value"] or 0)
    # Counters count each logical processor as 100%, so divide by the count to give a share of the whole PC
    # (the same scale Task Manager shows); the idle process (PID 0) is not work and is left out.
    logical = os.cpu_count() or 1
    cpu_by_pid = {pids[name]: round(_probe.average(values) / logical, 2)
                  for name, values in busy.items() if name in pids and pids[name] != 0}
    rows_all = [p for p in data.get("processes") or [] if p.get("ProcessId") != 0]
    names = {p.get("ProcessId"): p.get("Name") for p in rows_all}
    rows = []
    for p in rows_all:
        pid = p.get("ProcessId")
        parent = p.get("ParentProcessId")
        rows.append({"pid": pid, "name": p.get("Name"), "parent": {"pid": parent, "name": names.get(parent)},
                     "cpu_percent": cpu_by_pid.get(pid), "working_set": _size(p.get("WorkingSetSize")),
                     "working_set_bytes": p.get("WorkingSetSize"), "threads": p.get("ThreadCount"),
                     "handles": p.get("HandleCount")})
    rows.sort(key=lambda r: (r["cpu_percent"] or 0, r["working_set_bytes"] or 0), reverse=True)
    shown = rows[:count]
    _probe.emit(options, f"the {count} busiest processes (CPU over {PROCESS_SECONDS} s)",
                _unavailable({"processes": shown}, errors),
                rows=[(r["pid"], r["name"], r["cpu_percent"], r["working_set"],
                       f"{r['parent']['name']} ({r['parent']['pid']})" if r["parent"]["name"] else "-", r["threads"])
                      for r in shown],
                headers=["PID", "NAME", "CPU %", "MEMORY", "PARENT", "THREADS"], notes=_probe.missing_notes(errors))


def _unavailable(data, errors):
    """Adds the readings that could not be made, so --json shows them too."""
    if errors:
        data["unavailable"] = errors
    return data


# ======================================================================
# STARTUP — sys startup
# ======================================================================
def _startup(args, options):
    data, errors = _probe.probe(r"""
Get-Part 'startup' { Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User }
Get-Part 'tasks' { Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { $t = $_; $trig = @($t.Triggers | Where-Object { $_.CimClass.CimClassName -in @('MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger') }); if ($trig.Count -gt 0) { [pscustomobject]@{ name = $t.TaskName; path = $t.TaskPath; when = ($trig | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task|Trigger', '' }) -join ' '; user = $t.Principal.UserId } } } }
""")
    items = [{"name": s.get("Name"), "command": s.get("Command"), "where": s.get("Location"), "user": s.get("User")}
             for s in data.get("startup") or []]
    tasks = [{"name": t.get("name"), "path": t.get("path"), "starts": t.get("when"), "user": t.get("user")}
             for t in data.get("tasks") or []]
    out = _unavailable({"startup_items": items, "scheduled_tasks": tasks}, errors)
    rows = [(i["name"], i["where"], i["user"] or "-") for i in items]
    notes = [f"{len(tasks)} scheduled task(s) start at logon or boot: 'sys startup' with --json lists them. "
             "startup apps can be changed on the 'startup' page."]
    if tasks:
        notes.append("scheduled tasks: " + "; ".join(f"{t['name']} ({t['starts']})" for t in tasks[:8]))
    _probe.emit(options, f"programs that start with Windows ({len(items)})", out, rows=rows,
                headers=["NAME", "WHERE", "USER"], notes=notes + _probe.missing_notes(errors))


# ======================================================================
# BATTERY AND POWER — sys battery, sys power
# ======================================================================
def _battery(args, options):
    status = _probe.power_status()
    data = {"on_ac_power": status["ac"], "charge_percent": status["percent"], "battery_present": status["battery"]}
    if status["battery"] is False:
        sections = [("power", [("source", "AC power (no battery in this PC)")])]
    else:
        source = {True: "AC power", False: "battery", None: "not readable"}[status["ac"]]
        sections = [("power", [("source", source), ("charge", f"{status['percent']}%"
                                                     if status["percent"] is not None else None)])]
    _probe.emit(options, "power source", data, sections,
                notes=["battery health and wear are on 'hw battery'."])


def _power(args, options):
    scheme = _probe.powercfg(["/getactivescheme"]) or ""
    match = re.search(r"Power Scheme GUID:\s*\S+\s+\((.+)\)", scheme)
    sleep_text = _probe.powercfg(["/query", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"])
    display_text = _probe.powercfg(["/query", "SCHEME_CURRENT", "SUB_VIDEO", "VIDEOIDLE"])
    states_text = _probe.powercfg(["/a"]) or ""
    # powercfg /a: a heading, then one indented sleep state per line (reasons are indented too but do not start
    # with a state name, so they are skipped)
    available, unavailable = [], []
    section = None
    for line in states_text.splitlines():
        stripped = line.strip()
        if "not available" in stripped:
            section = unavailable
        elif "available on this system" in stripped:
            section = available
        elif stripped and section is not None and stripped.startswith(("Standby", "Hibernate", "Hybrid", "Fast")):
            section.append(stripped)
    sleep = _probe.power_settings(sleep_text)
    display = _probe.power_settings(display_text)
    if "not been enabled" in states_text:
        hibernation = "not enabled"
    elif any(state.startswith("Hibernate") for state in available):
        hibernation = "enabled"
    else:
        hibernation = None
    fast = _net.reg_read(r"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled")
    data = {
        "plan": match.group(1) if match else None,
        "sleep_after_minutes": _minutes(sleep[0] if sleep else None),
        "display_off_after_minutes": _minutes(display[0] if display else None),
        "hibernation": hibernation, "fast_startup": {1: "on", 0: "off"}.get(fast),
        "states_available": available, "states_unavailable": unavailable,
    }
    sections = [("plan", [("name", data["plan"]), ("sleep after", _mins(data["sleep_after_minutes"])),
                          ("display off after", _mins(data["display_off_after_minutes"]))]),
                ("sleep", [("states available", available or None), ("hibernation", hibernation),
                           ("fast startup", data["fast_startup"])])]
    _probe.emit(options, "power", data, sections,
                notes=[] if scheme else ["the power plan could not be read: powercfg gave no answer."])


def _minutes(setting):
    """A powercfg timer (seconds, per AC and DC) in minutes: {"ac": n, "dc": n}, or None."""
    if not setting:
        return None
    return {"ac": None if setting["ac"] is None else setting["ac"] // 60,
            "dc": None if setting["dc"] is None else setting["dc"] // 60}


def _mins(value):
    if not value:
        return None
    if value["ac"] == 0 and value["dc"] == 0:
        return "never"
    return f"{value['ac']} min on AC, {value['dc']} min on battery"


# ======================================================================
# ENVIRONMENT — sys environment
# ======================================================================
def _path_entries():
    rows = []
    for scope, (hive, key) in PATH_KEYS.items():
        try:
            with winreg.OpenKey(hive, key) as handle:
                raw, _ = winreg.QueryValueEx(handle, "Path")
        except OSError:
            raw = ""
        seen = set()
        for entry in [part for part in raw.split(";")]:
            text = entry.strip().strip('"')
            if not text:
                rows.append({"scope": scope, "entry": entry, "expanded": None, "exists": None,
                             "problem": "empty entry"})
                continue
            expanded = os.path.expandvars(text)
            unknown = [name for name in re.findall(r"%([^%]+)%", text) if name not in os.environ]
            key_text = expanded.rstrip("\\").lower()
            problem = None
            if unknown:
                problem = f"unknown variable %{unknown[0]}%"
            elif key_text in seen:
                problem = "duplicate"
            elif not os.path.isdir(expanded):
                problem = "folder does not exist"
            seen.add(key_text)
            rows.append({"scope": scope, "entry": text, "expanded": expanded,
                         "exists": os.path.isdir(expanded), "problem": problem})
    return rows


def _environment(args, options):
    entries = _path_entries()
    problems = [e for e in entries if e["problem"]]
    variables = sorted(os.environ)
    data = {"path_entries": entries, "problems": len(problems),
            "variables": {name: os.environ[name] for name in SAFE_VARIABLES if name in os.environ},
            "variable_names": variables}
    rows = [(e["scope"], e["entry"][:60], e["problem"]) for e in problems]
    notes = [f"{len(entries)} PATH entries, {len(problems)} with a problem. "
             f"{len(variables)} environment variables (values are shown only for: {', '.join(SAFE_VARIABLES)})."]
    _probe.emit(options, "environment", data, rows=rows or None, headers=["SCOPE", "ENTRY", "PROBLEM"],
                notes=(["no PATH problems found"] if not problems else []) + notes)


# ======================================================================
# INVENTORY — sys inventory
# ======================================================================
def _inventory_data():
    import device
    import hardware
    uptime = _uptime_data()
    uptime.pop("_errors", None)
    cpu = hardware._cpu_data()
    ram, _ = hardware._ram_data()
    gpus, gpu_errors = hardware._gpus()
    disks, _, disk_errors = hardware._disks()
    bios, bios_errors = hardware._bios_data()
    devices = device._devices()
    data, driver_errors = _probe.probe(
        "Get-Part 'drivers' { Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName }")
    programs, program_errors = _programs()
    return {
        "windows": uptime["windows"], "installed": uptime["installed"],
        "processor": cpu["model"], "memory": ram["installed"], "graphics": [g["name"] for g in gpus],
        "drives": [{"model": d["model"], "size": d["size"], "kind": d["kind"]} for d in disks],
        "bios": bios.get("version"), "boot_mode": bios.get("boot_mode"),
        "drivers_installed": len(data.get("drivers") or []),
        "devices_with_problems": sum(1 for d in devices if d["state"] == "problem"),
        "programs": programs,
        "unavailable": {**gpu_errors, **disk_errors, **bios_errors, **driver_errors, **program_errors},
    }


def _programs():
    data, errors = _probe.probe("Get-Part 'programs' { Get-ItemProperty " + ", ".join(
        f"'{k}'" for k in UNINSTALL_KEYS) + " -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate }")
    programs = [{"name": p.get("DisplayName"), "version": p.get("DisplayVersion"), "publisher": p.get("Publisher"),
                 "installed": p.get("InstallDate")} for p in data.get("programs") or []]
    programs.sort(key=lambda p: (p["name"] or "").lower())
    return programs, errors


def _inventory(args, options):
    data = _inventory_data()
    sections = [("computer", [("Windows", data["windows"]), ("installed", data["installed"]),
                              ("processor", data["processor"]), ("memory", data["memory"]),
                              ("BIOS", data["bios"]), ("boot mode", data["boot_mode"])]),
                ("graphics", [(g, None) for g in data["graphics"]] or [("found", None)]),
                ("drivers", [("installed", data["drivers_installed"]),
                             ("devices with problems", data["devices_with_problems"])]),
                ("programs", [("installed", len(data["programs"]))])]
    drives = [(d["model"], d["size"], d["kind"]) for d in data["drives"]]
    notes = ["'sys inventory --json' lists every installed program."] if not options["json"] else []
    notes += _probe.missing_notes(data.get("unavailable", {}))
    _probe.emit(options, "inventory", data, sections, rows=drives or None, headers=["DRIVE", "SIZE", "KIND"],
                notes=notes)


# ======================================================================
# HEALTH — sys health
# ======================================================================
def _health_checks():
    """Each indicator as (level, label, detail): level is ok, warn, bad or info. Readings that cannot be made are
    left out with a reason in the last list."""
    import device
    import events
    import hardware
    checks, missing = [], {}
    now = dt.datetime.now().astimezone()
    since_week = now - dt.timedelta(days=7)
    since_day = now - dt.timedelta(days=1)

    disks, _, disk_errors = hardware._disks()
    bad_disks = [d for d in disks if d["health"] and d["health"] != "Healthy"]
    if disks and not bad_disks:
        checks.append(("ok", "drive health", f"{len(disks)} drive(s) report Healthy"))
    elif bad_disks:
        checks.append(("bad", "drive health", ", ".join(f"{d['model']}: {d['health']}" for d in bad_disks)))
    missing.update(disk_errors)

    volumes = [v for v in hardware._storage_volumes_data() if v["letter"] and v["free_percent"] is not None]
    for volume in volumes:
        level = "bad" if volume["free_percent"] < 10 else "warn" if volume["free_percent"] < 20 else "ok"
        if level != "ok":
            checks.append((level, f"drive {volume['letter']} space", f"{volume['free']} free ({volume['free_percent']}%)"))
    if volumes and all(v["free_percent"] >= 20 for v in volumes):
        checks.append(("ok", "drive space", "every lettered drive has at least 20% free"))

    ram, _ = hardware._ram_data()
    available = ram.get("available_percent")
    if available is not None:
        level = "bad" if available < 5 else "warn" if available < 10 else "ok"
        checks.append((level, "memory available", f"{available}% of memory is free"))
    else:
        missing["memory"] = "not readable"

    load = _load_moments(3, watch=False)
    cpu_avg = _summary(load, "cpu")["average"]
    if cpu_avg is not None:
        checks.append(("warn" if cpu_avg >= 90 else "ok", "processor busy", f"{cpu_avg}% over 3 s"))

    uptime = _uptime_data()
    uptime.pop("_errors", None)
    days = (uptime["uptime_seconds"] or 0) / 86400
    if days > UPTIME_LONG_DAYS:
        checks.append(("info", "uptime", f"{uptime['uptime']}: a restart clears memory that programs have leaked"))
    else:
        checks.append(("ok", "uptime", uptime["uptime"] or "not readable"))

    pending = _pending_restart()
    checks.append(("warn", "restart", "Windows is waiting for a restart to finish updates") if pending
                  else ("ok", "restart", "no restart is pending"))

    devices = device._devices()
    problems = [d for d in devices if d["state"] == "problem"]
    checks.append(("warn", "devices", f"{len(problems)} with problems: {', '.join(d['name'] for d in problems[:4])}")
                   if problems else ("ok", "devices", "no devices with problems"))

    recent = events._fetch(["System", "Application"], events._query(levels=[1, 2], since=since_day), limit=500)
    checks.append(("warn", "errors, last 24 h", f"{len(recent)} critical or error event(s)")
                   if recent else ("ok", "errors, last 24 h", "no critical or error events"))

    storage = events._fetch(["System", "Application"], events._query(levels=[1, 2, 3], since=since_week),
                            limit=500, providers=STORAGE_PROVIDERS)
    checks.append(("warn", "disk errors, last 7 days", f"{len(storage)} event(s)")
                   if storage else ("ok", "disk errors, last 7 days", "none"))

    crashes = events._fetch(["System"], events._query(ids=[1001], since=since_week), limit=200, providers=["BugCheck"])
    checks.append(("bad", "crashes, last 7 days", f"{len(crashes)} blue screen(s) (BugCheck)")
                   if crashes else ("ok", "blue screens, last 7 days", "none"))
    gpu = events._fetch(["System", "Application"], events._query(levels=[1, 2, 3], since=since_week), limit=500,
                        providers=GPU_PROVIDERS)
    checks.append(("warn", "GPU errors, last 7 days", f"{len(gpu)} event(s)") if gpu
                  else ("ok", "GPU errors, last 7 days", "none"))

    services = events._fetch(["System"], events._query(ids=SERVICE_FAILURE_IDS, since=since_week), limit=500,
                             providers=["Service Control Manager"])
    checks.append(("warn", "service failures, last 7 days", f"{len(services)} event(s): svc failures"
                   ) if services else ("ok", "service failures, last 7 days", "none"))
    return checks, missing


def _pending_restart():
    for path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"):
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path))
            return True
        except OSError:
            continue
    return False


def _health(args, options):
    checks, missing = _health_checks()
    checks.sort(key=lambda c: ORDER[c[0]])
    verdict = _worst([c[0] for c in checks])
    data = {"verdict": verdict, "checks": [{"level": c[0], "check": c[1], "detail": c[2]} for c in checks],
            "unavailable": missing}
    lines = [f"[{level}] {label}: {detail}" for level, label, detail in checks]
    _probe.emit(options, f"system health: {verdict}", data, notes=lines + _probe.missing_notes(missing))


def run(args):
    """Run one system command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    word, rest = args[0].lower(), args[1:]
    commands = {"uptime": _uptime, "load": _load, "processes": _processes, "startup": _startup,
                "battery": _battery, "power": _power, "environment": _environment, "inventory": _inventory,
                "health": _health}
    try:
        if word not in commands:
            raise SystemError_(f"usage: {USAGE}", 2)
        commands[word](rest, options)
        return 0
    except (SystemError_, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

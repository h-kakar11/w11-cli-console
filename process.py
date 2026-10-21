"""
process: running processes, and a live look at the system. Routed from app.py
("process" or "prc").

    prc ls                 programs, alphabetical, one id per name, with a count
    prc ls /verbose        live CPU, RAM, GPU, Wi-Fi and disk usage (Ctrl+C to stop),
                           then every process on its own row, under its name's id
    prc kill <id>          end every process with that name (rm, remove, delete also work)

Red rows are Windows system processes: anything under C:\\Windows, plus the
names in PROTECTED_NAMES and anything running as NT AUTHORITY. Ending one
asks twice. Ids follow the list, so they can shift as programs start and
stop. The kill prompt shows the name and how many processes it will end.

Needs psutil (see requirements.txt).
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time

import psutil

import _core

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "process"
ALIASES = ["prc"]
SUMMARY = "List and kill running processes, with live system stats"
# extra words people use, for 'settings search'
KEYWORDS = ["task manager", "kill", "end task", "cpu", "memory", "ram", "frozen", "not responding"]
USAGE = "prc ls [/verbose] | prc show <id> | prc kill <id>   (rm, remove, delete also work)"
HELP = [
    ("prc ls", "programs, alphabetical, one id each, with a process count"),
    ("prc ls /verbose", "live CPU, RAM, GPU, Wi-Fi and disk use, then every process"),
    ("prc show <id>", "details for one program's processes"),
    ("prc kill <id>", "end every process with that program's name (asks first)"),
]
TIP = "Red rows are Windows system programs. Ending one asks twice. Ending a process loses its unsaved work."

LIST_WORDS = ("ls", "list")
KILL_WORDS = ("kill", "rm", "remove", "delete", "del")
SHOW_WORDS = ("show", "info")
VERBOSE_FLAGS = ("/verbose", "verbose", "/v", "-v")
HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")

# ======================================================================
# CONFIG
# ======================================================================
PROTECTED_NAMES = {"system", "system idle process", "registry", "memory compression", "osprivacy.exe"}
WINDOWS_DIR = os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\"
SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:") + "\\"
WIFI_WORDS = ("wi-fi", "wifi", "wireless", "wlan")
MAX_NAME_WIDTH = 26
# colours for normal rows; red is kept for system processes
ROW_COLORS = ["\033[96m", "\033[92m", "\033[93m", "\033[95m", "\033[94m"]
RED = "\033[91m"
RESET = "\033[0m"
# per-engine GPU busy percent, the way Task Manager adds it up
GPU_COUNTER_SCRIPT = (
    r"$s = (Get-Counter '\GPU Engine(*)\Utilization Percentage' -ErrorAction Stop).CounterSamples; "
    r"$s | Group-Object { ($_.InstanceName -split '_')[-1] } | "
    r"ForEach-Object { ($_.Group | Measure-Object CookedValue -Sum).Sum } | "
    r"Measure-Object -Maximum | Select-Object -ExpandProperty Maximum"
)


class ProcessError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# SOURCES — processes with the same name are one id, so 'prc ls' stays short
# ======================================================================
def _is_protected(pid, name, exe, username):
    if pid in (0, 4) or name.lower() in PROTECTED_NAMES:
        return True
    if exe and exe.lower().startswith(WINDOWS_DIR):
        return True
    return bool(username) and username.upper().startswith("NT AUTHORITY\\")


def _processes():
    """Every running process, one per row, sorted by name then pid."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe", "username", "memory_info"]):
        info = p.info
        pid = info["pid"]
        name = info["name"] or f"pid {pid}"
        mem = info["memory_info"]
        procs.append({
            "pid": pid,
            "name": name,
            "memory": mem.rss if mem else 0,
            "protected": _is_protected(pid, name, info["exe"], info["username"]),
        })
    procs.sort(key=lambda p: (p["name"].lower(), p["pid"]))
    return procs


def _groups():
    """Processes grouped by name, sorted by name, with one id per group (starting at 1)."""
    groups = {}
    for proc in _processes():
        key = proc["name"].lower()
        group = groups.setdefault(key, {"name": proc["name"], "procs": [], "memory": 0, "protected": False})
        group["procs"].append(proc)
        group["memory"] += proc["memory"]
        group["protected"] = group["protected"] or proc["protected"]
    result = [groups[key] for key in sorted(groups)]
    for index, group in enumerate(result, start=1):
        group["id"] = index
    return result


def _get_group(group_id):
    for group in _groups():
        if group["id"] == group_id:
            return group
    raise ProcessError(f"no process with id {group_id}. Run 'prc ls' to see them.", 2)


# ======================================================================
# KILL — ends every process with that name; two warnings for system processes
# ======================================================================
def _terminate(proc):
    """Ends one process. Returns an error message, or None if it ended (or was already gone)."""
    try:
        target = psutil.Process(proc["pid"])
        target.terminate()  # on Windows this ends the process at once, nothing is saved
        target.wait(timeout=3)
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return f"windows will not let this terminal end pid {proc['pid']}. Run the terminal as administrator."
    except psutil.TimeoutExpired:
        return f"pid {proc['pid']} did not close. Try again, or end it from Task Manager."
    return None


def _kill(args, options):
    if len(args) != 2:
        raise ProcessError("usage: prc kill <id>", 2)
    try:
        group_id = int(args[1])
    except ValueError:
        raise ProcessError("prc kill needs a process id from 'prc ls'", 2)

    group = _get_group(group_id)
    procs = [p for p in group["procs"] if p["pid"] != os.getpid()]  # never end this console
    if not procs:
        raise ProcessError("that is this console. Type 'exit' to close it.", 2)

    count = len(procs)
    label = group["name"] if count == 1 else f"{group['name']} ({count} processes)"
    if group["protected"]:
        print(f"warning: {label} includes a Windows system process. Ending it can freeze or crash Windows.")
        if not _core.confirm("Are you sure? [y/N]: ", options["yes"]):
            print("cancelled")
            return
        if not _core.confirm("Really end a system process? This is the last warning. [y/N]: ", options["yes"]):
            print("cancelled")
            return
    elif not _core.confirm(f"End {label}? Unsaved work in it will be lost. [y/N]: ", options["yes"]):
        print("cancelled")
        return

    print(f"ending {label}... it closes at once, and unsaved work is lost.")
    errors = [message for message in (_terminate(p) for p in procs) if message]
    if errors:
        print(f"ended {count - len(errors)} of {count} for {group['name']}")
        for message in errors:
            print(f"error: {message}", file=sys.stderr)
        raise ProcessError("some processes could not be ended", 1)
    print(f"ended {label}")


# ======================================================================
# LIST — same column layout as apps ls. Default: one row per name.
# /verbose: one row per process, with the id of its name.
# ======================================================================
def _size(num_bytes):
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def _print_table(header, cell, rows):
    """Prints rows down each column, then the next. rows: (id, protected, values)."""
    gap = 4
    cell_width = len(header) + gap
    terminal_width = shutil.get_terminal_size((120, 30)).columns
    columns = max(1, terminal_width // cell_width)
    count = len(rows)
    height = -(-count // columns)  # ceiling division

    os.system("")  # enables ANSI colour codes in the Windows console
    print("".join([header.ljust(cell_width)] * columns).rstrip())
    for row in range(height):
        line = ""
        for col in range(columns):
            index = col * height + row  # fill each column top to bottom
            if index < count:
                group_id, protected, values = rows[index]
                color = RED if protected else ROW_COLORS[(group_id - 1) % len(ROW_COLORS)]
                line += f"{color}{cell.format(**values).ljust(cell_width)}{RESET}"
        print(line)


def _list_groups(options):
    groups = _groups()
    if options["json"]:
        _core.print_json([{"id": g["id"], "name": g["name"], "count": len(g["procs"]),
                           "memory": g["memory"], "protected": g["protected"]} for g in groups])
        return
    if not groups:
        print("(no processes found)")
        return
    name_width = min(max(len(g["name"]) for g in groups), MAX_NAME_WIDTH)
    cell = f"{{id:>4}}  {{name:<{name_width}}}  {{count:>5}}  {{mem:>9}}"
    header = cell.format(id="ID", name="NAME", count="COUNT", mem="MEMORY")
    print("red is core system processes. be careful when using prc rm [id]")
    rows = [
        (g["id"], g["protected"],
         {"id": g["id"], "name": g["name"][:name_width], "count": len(g["procs"]), "mem": _size(g["memory"])})
        for g in groups
    ]
    _print_table(header, cell, rows)
    system_count = sum(1 for g in groups if g["protected"])
    print(f"{len(groups)} programs, {system_count} Windows system (red). Ids shift as programs start and stop.")


def _list_processes():
    groups = _groups()
    if not groups:
        print("(no processes found)")
        return
    procs = [(g["id"], p) for g in groups for p in g["procs"]]
    name_width = min(max(len(p["name"]) for _, p in procs), MAX_NAME_WIDTH)
    cell = f"{{id:>4}}  {{name:<{name_width}}}  {{pid:>7}}  {{mem:>9}}"
    header = cell.format(id="ID", name="NAME", pid="PID", mem="MEMORY")
    rows = [
        (gid, p["protected"],
         {"id": gid, "name": p["name"][:name_width], "pid": p["pid"], "mem": _size(p["memory"])})
        for gid, p in procs
    ]
    _print_table(header, cell, rows)
    system_count = sum(1 for _, p in procs if p["protected"])
    print(f"{len(procs)} processes, {system_count} Windows system (red). "
          "The id is the program's, so 'prc kill' ends every process with that name.")


# ======================================================================
# LIVE — prc ls /verbose redraws the system stats every second
# ======================================================================
class _GpuSampler(threading.Thread):
    """Polls the GPU in the background, so the live screen never waits for it."""

    def __init__(self):
        super().__init__(daemon=True)
        self.value = None

    def run(self):
        while True:
            self.value = _gpu_percent()
            time.sleep(2)


def _gpu_percent():
    """GPU busy percent: nvidia-smi if it is installed, else Windows GPU counters."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5, creationflags=flags,
        ).stdout
        return float(out.split()[0])
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        pass
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", GPU_COUNTER_SCRIPT],
            capture_output=True, text=True, timeout=15, creationflags=flags,
        ).stdout
        return min(100.0, float(out.strip()))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _counters():
    """Running totals for Wi-Fi and disk, so the live screen can work out rates."""
    counters = {"rx": None, "tx": None, "read": None, "write": None}
    for name, c in psutil.net_io_counters(pernic=True).items():
        if any(word in name.lower() for word in WIFI_WORDS):
            counters["rx"] = (counters["rx"] or 0) + c.bytes_recv
            counters["tx"] = (counters["tx"] or 0) + c.bytes_sent
    disk = psutil.disk_io_counters()
    if disk:
        counters["read"], counters["write"] = disk.read_bytes, disk.write_bytes
    return counters


def _per_second(now, before, key, elapsed):
    if now[key] is None or before[key] is None or elapsed <= 0:
        return None
    return (now[key] - before[key]) / elapsed


def _bar(percent, width=24):
    filled = round(width * max(0, min(100, percent)) / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _stats_text(gpu_value, now, before, elapsed):
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory()
    drive = psutil.disk_usage(SYSTEM_DRIVE)

    lines = [
        f"CPU      {_bar(cpu)} {cpu:5.1f}%   {psutil.cpu_count()} logical cores",
        f"RAM      {_bar(ram.percent)} {ram.percent:5.1f}%   {_size(ram.used)} of {_size(ram.total)}",
    ]
    if gpu_value is None:
        lines.append("GPU      n/a (no NVIDIA tool or GPU counters found)")
    else:
        lines.append(f"GPU      {_bar(gpu_value)} {gpu_value:5.1f}%")

    down = _per_second(now, before, "rx", elapsed)
    up = _per_second(now, before, "tx", elapsed)
    if down is None:
        lines.append("Wi-Fi    no Wi-Fi adapter found")
    else:
        lines.append(f"Wi-Fi    down {down * 8 / 1_000_000:8.2f} Mbps   up {up * 8 / 1_000_000:8.2f} Mbps")

    lines.append(f"Disk {SYSTEM_DRIVE[:2]}  {_bar(drive.percent)} {drive.percent:5.1f}%   "
                 f"{_size(drive.used)} of {_size(drive.total)}")
    read = _per_second(now, before, "read", elapsed)
    write = _per_second(now, before, "write", elapsed)
    if read is not None:
        mb = 1024 * 1024
        lines.append(f"Disk I/O read {read / mb:7.2f} MB/s   write {write / mb:7.2f} MB/s")
    return "\n".join(lines)


def _live():
    """Redraw the stats every second until Ctrl+C."""
    os.system("")  # enables ANSI colour codes and screen clearing in the Windows console
    gpu = _GpuSampler()
    gpu.start()
    psutil.cpu_percent(interval=None)  # the first reading starts the measurement
    before = _counters()
    before_time = time.monotonic()
    try:
        while True:
            time.sleep(1)
            now = _counters()
            now_time = time.monotonic()
            text = _stats_text(gpu.value, now, before, now_time - before_time)
            sys.stdout.write(
                "\033[H\033[2J" + "live system stats (Ctrl+C to stop)\n\n" + text + "\n"
            )
            sys.stdout.flush()
            before, before_time = now, now_time
    except KeyboardInterrupt:
        print()


# ======================================================================
# SHOW — what a program is, where it lives, what it uses, and how long it has run
# ======================================================================
KNOWN_PROGRAMS = {
    "svchost.exe": "hosts Windows background services",
    "explorer.exe": "the Windows desktop, taskbar and file manager",
    "csrss.exe": "Windows core process for console and window handling",
    "lsass.exe": "enforces Windows sign-in and security policy",
    "services.exe": "starts and manages Windows services",
    "wininit.exe": "starts core Windows processes at boot",
    "winlogon.exe": "handles sign-in and sign-out",
    "smss.exe": "Windows session manager, starts sessions at boot",
    "dwm.exe": "Desktop Window Manager, draws windows and effects",
    "audiodg.exe": "Windows audio engine",
    "system": "the Windows kernel",
    "registry": "Windows registry cache",
    "memory compression": "Windows memory compression",
    "osprivacy.exe": "OSPrivacy, a Windows privacy tool",
    "chrome.exe": "Google Chrome browser",
    "msedge.exe": "Microsoft Edge browser",
    "discord.exe": "Discord chat app",
    "code.exe": "Visual Studio Code",
}
SHOW_PROCESSES = 5  # details for this many processes in a group; the rest are counted


BLOCKED = []  # set when Windows hides a fact; drives the 'run as admin' hint


def _safe(getter, default=None):
    """Reads one fact about a process; a process we are not allowed to read gives the default."""
    try:
        return getter()
    except psutil.AccessDenied:
        BLOCKED.append(True)
        return default
    except (psutil.Error, OSError):
        return default


def _file_info(path):
    """Description, company and version from the file's own version info, read by PowerShell."""
    if not path:
        return {}
    quoted = path.replace("'", "''")
    script = (
        f"(Get-Item -LiteralPath '{quoted}').VersionInfo | "
        "Select-Object FileDescription, CompanyName, ProductVersion | ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
        return json.loads(out) if out.strip() else {}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def _elapsed(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        return f"{days} d {hours} h {minutes} min"
    if hours:
        return f"{hours} h {minutes} min"
    if minutes:
        return f"{minutes} min {seconds} s"
    return f"{seconds} s"


def _process_details(pid):
    """What we can read about one process. Anything Windows will not show us is left out."""
    try:
        p = psutil.Process(pid)
    except psutil.Error:
        return None
    exe = _safe(p.exe, "")
    created = _safe(p.create_time)
    cpu = _safe(p.cpu_times)
    mem = _safe(p.memory_info)
    parent = _safe(p.parent)
    return {
        "pid": pid,
        "exe": exe,
        "command": " ".join(_safe(p.cmdline, []) or []),
        "user": _safe(p.username, "(access denied)"),
        "status": _safe(p.status, "unknown"),
        "started": created,
        "running": time.time() - created if created else None,
        "cpu_seconds": (cpu.user + cpu.system) if cpu else None,
        "memory": mem.rss if mem else None,
        "threads": _safe(p.num_threads),
        "parent": _safe(parent.name, "(unknown)") if parent else "(none)",
        "folder": os.path.dirname(exe) if exe else "",
        "file_created": os.path.getctime(exe) if exe and os.path.exists(exe) else None,
    }


def _show(args):
    if len(args) != 2:
        raise ProcessError("usage: prc show <id>", 2)
    try:
        group_id = int(args[1])
    except ValueError:
        raise ProcessError("prc show needs a process id from 'prc ls'", 2)

    group = _get_group(group_id)
    procs = group["procs"]
    name = group["name"]
    BLOCKED.clear()
    details = [d for d in (_process_details(p["pid"]) for p in procs[:SHOW_PROCESSES]) if d]
    first_exe = next((d["exe"] for d in details if d["exe"]), "")
    info = _file_info(first_exe)
    # our plain-English note first, otherwise the vendor's file description
    description = KNOWN_PROGRAMS.get(name.lower()) or info.get("FileDescription") or ""
    count = len(procs)

    # the program, once: its file, its company and what it is
    print(f"{name}  (id {group_id}, {count} process{'es' if count != 1 else ''})")
    print(f"  what it is   {description or '(no description in the file)'}")
    if info.get("CompanyName"):
        print(f"  company      {info['CompanyName']}")
    if info.get("ProductVersion"):
        print(f"  version      {info['ProductVersion']}")
    print(f"  path         {first_exe or '(not readable)'}")
    created = next((d["file_created"] for d in details if d["file_created"]), None)
    if created:
        print(f"  installed    {time.strftime('%Y-%m-%d', time.localtime(created))} (file created; close to the install date)")
    print(f"  system       {'yes, shown in red in prc ls' if group['protected'] else 'no'}")

    # the group's totals, from the processes we could read
    starts = [d["started"] for d in details if d["started"]]
    if starts:
        first = min(starts)
        print(f"  first start  {time.strftime('%Y-%m-%d %H:%M', time.localtime(first))}"
              f"  (running {_elapsed(time.time() - first)})")
    print(f"  memory       {_size(group['memory'])} across all {count}")
    cpu_total = sum(d["cpu_seconds"] for d in details if d["cpu_seconds"] is not None)
    print(f"  cpu time     {cpu_total:.1f} s across the {len(details)} shown")
    users = sorted({d["user"] for d in details if d["user"]})
    if users:
        print(f"  user         {', '.join(users)}")
    parents = sorted({d["parent"] for d in details if d["parent"]})
    if parents:
        print(f"  started by   {', '.join(parents)}")
    command = next((d["command"] for d in details if d["command"]), "")
    if command:
        print(f"  command      {command}")

    # one line per process, not a full block each
    if details:
        print()
        print(f"  {'PID':>7}  {'STARTED':<16}  {'RUNNING':<15}  {'MEMORY':>9}  {'THREADS':>7}")
        for d in details:
            started = time.strftime("%Y-%m-%d %H:%M", time.localtime(d["started"])) if d["started"] else "(hidden)"
            running = _elapsed(d["running"]) if d["running"] is not None else "(hidden)"
            memory = _size(d["memory"]) if d["memory"] is not None else "(hidden)"
            threads = d["threads"] if d["threads"] is not None else "(hidden)"
            print(f"  {d['pid']:>7}  {started:<16}  {running:<15}  {memory:>9}  {threads:>7}")
    if count > SHOW_PROCESSES:
        print(f"  and {count - SHOW_PROCESSES} more (prc ls /verbose lists them all)")
    if BLOCKED:
        print()
        print("run terminal as admin to see more details")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "process"/"prc"
# ======================================================================
def _dispatch(args, options):
    command = args[0].lower()
    if command in LIST_WORDS:
        flags = [a.lower() for a in args[1:]]
        if len(flags) > 1 or (flags and flags[0] not in VERBOSE_FLAGS):
            raise ProcessError("usage: prc ls [/verbose]", 2)
        if flags:
            if options["json"]:
                raise ProcessError("prc ls /verbose is live, so it has no --json. Use 'prc ls --json' for the list.", 2)
            _live()
            _list_processes()
        else:
            _list_groups(options)
    elif command in KILL_WORDS:
        _kill(args, options)
    elif command in SHOW_WORDS:
        _show(args)
    else:
        raise ProcessError(f"unknown process command: {args[0]}\nusage: {USAGE}", 2)

def run(args):
    """Run one process command; returns an exit code."""
    args, options = _core.split_flags(args)
    if not args:
        print(f"usage: {USAGE}")
        return 0
    if args[0].lower() in HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        _dispatch(args, options)
        return 0
    except ProcessError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

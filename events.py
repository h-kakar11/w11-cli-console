"""
events: Windows event logs, searched and explained. Routed from app.py ("events" or "evt").

    evt list                       every log: on or off, how many records, how big
    evt errors                     errors, critical events and warnings (--level, --since, --source)
    evt recent [N]                 the newest events, N at a time (--oldest for the other end)
    evt search <text>              find text in messages, ids, providers, tasks and computer names
    evt inspect <record>           one event in full: its fields and its XML (--log picks the log)
    evt filter                     any mix of --log --since --until --level --provider --id --user --pid --xpath
    evt crashes                    application crashes and hangs, with the faulting module
    evt shutdowns                  clean and unexpected shutdowns, restarts and blue screens
    evt boot                       each boot, how the one before ended, and what went wrong just after
    evt drivers                    driver load failures, device errors and display driver resets
    evt services                   services that failed, timed out or keep stopping
    evt network                    DHCP, DNS, Wi-Fi, TCP/IP and network profile problems
    evt security                   failed sign-ins and lockouts (needs administrator rights)
    evt correlate                  group events by time, provider, id, process or activity
    evt timeline <time>            everything around one moment, 15 minutes either side
    evt frequency                  repeated events, and spikes in them
    evt baseline save | baseline   save how often things happen, then compare with now
    evt export <file>              save matching events as .json, .csv or .evtx
    evt watch                      print new matching events as they arrive (Ctrl+C stops)
    evt clear <log>                clear a log, after its name is typed (needs administrator rights)

Reading goes through PowerShell's Get-WinEvent, one call per query, so the results carry the
rendered message text. Windows writes the messages in the PC's language, and most events are
read without administrator rights. The Security log, and some Operational logs, need them.
"""

import base64
import csv
import json
import os
import re
import statistics
import subprocess
import sys
import time
import xml.dom.minidom
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import _core
import _net

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "events"
ALIASES = ["evt"]
SUMMARY = "Windows event logs: errors, crashes, boots, timelines"
# extra words people use, for 'settings search'
KEYWORDS = ["event viewer", "log", "crash", "error", "bsod", "blue screen", "why did it restart"]
USAGE = "evt errors | evt recent [N] | evt search <text> | evt inspect <record> | evt crashes | evt timeline <time>"
HELP = [
    ("evt errors", "errors, critical events and warnings from the last day"),
    ("evt recent", "the newest events (evt recent 100 for more)"),
    ("evt search <text>", "find text in messages, ids, providers and computers"),
    ("evt inspect <record>", "one event in full, with its fields and XML"),
    ("", "what went wrong"),
    ("evt crashes", "application crashes and hangs, with the faulting module"),
    ("evt shutdowns", "clean and unexpected shutdowns, and blue screens"),
    ("evt boot", "each boot, and the problems in its first 10 minutes"),
    ("evt drivers", "driver failures, device errors and display driver resets"),
    ("evt services", "services that failed, timed out or keep stopping"),
    ("evt network", "DHCP, DNS, Wi-Fi and TCP/IP problems"),
    ("evt security", "failed sign-ins and lockouts (needs administrator rights)"),
    ("", "over time"),
    ("evt timeline <time>", "everything around one moment, 15 minutes either side"),
    ("evt correlate", "events that happened together, grouped"),
    ("evt frequency", "repeated events, and spikes in them"),
    ("evt baseline save", "save how often things happen, on a normal day"),
    ("evt baseline", "compare the last day with that saved baseline"),
    ("", "logs"),
    ("evt list", "every log, whether it is on, and how full it is"),
    ("evt filter", "any mix: --log --since --level --provider --id --user --xpath"),
    ("evt export <file>", "save matching events as .json, .csv or .evtx"),
    ("evt watch", "print new matching events as they happen (Ctrl+C stops)"),
    ("evt clear <log>", "clear a log after you type its name (needs administrator rights)"),
]
TIP = (
    "Times read as 2h (two hours ago), 3d, today, or 2026-10-15 14:30. "
    "Most logs need no administrator rights; the Security log does."
)

DEFAULT_LOGS = ["System", "Application"]
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
LEVELS = {"critical": 1, "error": 2, "warning": 3, "information": 4, "info": 4, "verbose": 5}
LEVEL_NAMES = {0: "Information", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
PROBLEM_LEVELS = [1, 2, 3]  # critical, error and warning
SLOW_BOOT_MS = 60000  # a boot over a minute is reported as slow
BOOT_WINDOW = timedelta(minutes=10)  # problems this long after a boot are blamed on it
SEARCH_SCAN = 2000  # evt search reads the newest this many events before it looks for the text

# Windows' own names for the events each command looks at
ENDINGS = {
    ("EventLog", 6006): "clean shutdown",
    ("EventLog", 6008): "unexpected shutdown",
    ("Microsoft-Windows-Kernel-Power", 41): "restart without a clean shutdown",
    ("User32", 1074): "shutdown or restart requested",
    ("BugCheck", 1001): "blue screen",
}
ENDING_LABELS = {**ENDINGS, ("EventLog", 6005): "Windows started"}
CRASH_EXTRA = (
    "((Provider[@Name='Application Error'] and EventID=1000) or "
    "(Provider[@Name='Application Hang'] and EventID=1002) or "
    "(Provider[@Name='Windows Error Reporting'] and EventID=1001))"
)
SERVICE_PROBLEMS = {
    7000: "failed to start",
    7001: "a service it depends on failed to start",
    7002: "a service it depends on did not start",
    7009: "start timed out",
    7011: "did not answer in time",
    7022: "hung on start",
    7023: "stopped with an error",
    7024: "stopped with its own error",
    7026: "boot driver failed to load",
    7031: "stopped unexpectedly, then restarted",
    7032: "restart action failed",
    7034: "stopped unexpectedly, not restarted",
}
SERVICE_RESTARTS = (7031, 7034)
DRIVER_PROVIDERS = [
    "Kernel-PnP", "Kernel-PlugPlay", "DriverFrameworks", "Display", "nvlddmkm", "amdkmdag", "atikmdag", "igfx",
]
NETWORK_PROVIDERS = ["Dhcp", "DNS-Client", "WLAN", "Wlan", "Tcpip", "NetworkProfile", "NDIS", "Winsock", "Netwtw"]
SECURITY_WHAT = {
    4625: "failed sign-in",
    4740: "account locked out",
    4720: "account created",
    4722: "account enabled",
    4723: "password change tried",
    4724: "password reset",
    4725: "account disabled",
    4726: "account deleted",
}
SECURITY_CHANGES = (4720, 4722, 4723, 4724, 4725, 4726)
RELATIVE = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

VALUE_FLAGS = (
    "log", "since", "until", "level", "provider", "id", "user", "pid", "limit", "xpath",
    "by", "window", "minutes", "bucket", "seconds", "interval", "backup",
)
SWITCH_FLAGS = ("oldest", "all", "failed", "lockouts", "changes", "no-backup")

HEADER = f"{'TIME':<21}{'LEVEL':<12}{'ID':<7}{'LOG':<13}{'PROVIDER':<32}{'RECORD':<10}MESSAGE"


class EventError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# POWERSHELL — one call per query, the script is sent encoded so quoting cannot break it
# ======================================================================
PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$req = $env:EVT_REQUEST | ConvertFrom-Json
$names = @{}
function Who($sid) {
    if ($null -eq $sid) { return $null }
    $key = $sid.Value
    if (-not $names.ContainsKey($key)) {
        try { $names[$key] = $sid.Translate([Security.Principal.NTAccount]).Value } catch { $names[$key] = $key }
    }
    return $names[$key]
}
function Utc($time) {
    if ($null -eq $time) { return $null }
    return $time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff') + 'Z'
}
if ($req.mode -eq 'logs') {
    $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            name = $_.LogName; enabled = [bool]$_.IsEnabled; records = $_.RecordCount; size = $_.FileSize
            max = $_.MaximumSizeInBytes; mode = [string]$_.LogMode; providers = @($_.ProviderNames)
        }
    })
    [pscustomobject]@{ logs = $logs } | ConvertTo-Json -Depth 4 -Compress
} else {
    $events = New-Object System.Collections.ArrayList
    $problems = New-Object System.Collections.ArrayList
    foreach ($log in @($req.logs)) {
        $filter = @{ LogName = $log; FilterXPath = [string]$req.query; ErrorAction = 'Stop' }
        if ($req.limit) { $filter.MaxEvents = [int]$req.limit }
        if ($req.oldest) { $filter.Oldest = $true }
        try { $found = @(Get-WinEvent @filter) }
        catch {
            if ($_.Exception.Message -match 'No events were found') { $found = @() }
            else { [void]$problems.Add([pscustomobject]@{ log = $log; error = $_.Exception.Message }); continue }
        }
        foreach ($e in $found) {
            $text = $null
            if ($req.messages) { $text = $e.Message }
            [void]$events.Add([pscustomobject]@{
                log = $e.LogName; record = $e.RecordId; id = $e.Id; level = $e.Level; levelName = $e.LevelDisplayName
                time = (Utc $e.TimeCreated); provider = $e.ProviderName; process_id = $e.ProcessId; thread_id = $e.ThreadId
                computer = $e.MachineName; user = (Who $e.UserId); task = $e.TaskDisplayName
                keywords = (@($e.KeywordsDisplayNames) -join ', '); message = $text; xml = $e.ToXml()
            })
        }
    }
    [pscustomobject]@{ events = $events; errors = $problems } | ConvertTo-Json -Depth 5 -Compress
}
"""


def _reason(text):
    """A short reason for a failure, with the fix when it is about rights."""
    lowered = (text or "").lower()
    if "unauthorized" in lowered or "access is denied" in lowered or "elevated" in lowered:
        return _net.ADMIN_HINT
    return _net.explain(text)


def _powershell(request):
    """Run the event script with one request; returns its parsed JSON reply."""
    encoded = base64.b64encode(PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ, EVT_REQUEST=json.dumps(request))
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise EventError(f"could not run PowerShell: {e}")
    if result.returncode != 0 or not result.stdout.strip():
        raise EventError(_reason(result.stderr or result.stdout or "no output from PowerShell"))
    return json.loads(result.stdout)


# ======================================================================
# EVENTS — one dict per event, the same keys everywhere
# ======================================================================
def _at(e):
    """The event's time as a local datetime."""
    return datetime.fromisoformat(e["time"])


def _xml_fields(text):
    """The named data fields of an event, and its activity id, read from its XML."""
    if not text:
        return {}, None
    root = ET.fromstring(text)
    data = {}
    for index, node in enumerate(root.findall(f"{NS}EventData/{NS}Data")):
        data[node.get("Name") or f"Data{index}"] = (node.text or "").strip()
    correlation = root.find(f"{NS}System/{NS}Correlation")
    activity = correlation.get("ActivityID") if correlation is not None else None
    return data, activity


def _event(raw):
    data, activity = _xml_fields(raw.get("xml"))
    severity = raw.get("level")
    if severity is None:
        severity = 4
    utc = datetime.strptime(raw["time"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return {
        "log": raw["log"],
        "record": raw["record"],
        "id": raw["id"],
        "level": raw.get("levelName") or LEVEL_NAMES.get(severity, "Information"),
        "severity": severity,
        "time": utc.astimezone().isoformat(timespec="seconds"),
        "provider": raw["provider"],
        "process_id": raw["process_id"],
        "thread_id": raw["thread_id"],
        "computer": raw["computer"],
        "user": raw["user"],
        "task": raw["task"],
        "keywords": raw["keywords"],
        "activity_id": activity,
        "message": raw.get("message"),
        "data": data,
        "xml": raw.get("xml"),
    }


def _public(e):
    """An event as it is printed with --json: the XML is left out except by inspect."""
    return {key: value for key, value in e.items() if key != "xml"}


def _fetch(logs, query, limit=50, oldest=False, messages=True, user=None, providers=None):
    """Events from the given logs, newest first (oldest first with oldest=True), up to limit.
    providers are parts of provider names, not case sensitive. Windows' query language cannot match
    part of a name, so with providers every event in the window is read first, then matched here."""
    reply = _powershell({
        "mode": "events", "logs": logs, "query": query, "limit": None if providers else limit,
        "oldest": oldest, "messages": messages,
    })
    problems = reply.get("errors") or []
    if problems and len(problems) == len(logs):
        raise EventError(_reason(problems[0]["error"]))
    for problem in problems:
        print(f"warning: could not read {problem['log']}: {_reason(problem['error'])}", file=sys.stderr)
    events = [_event(raw) for raw in reply.get("events") or []]
    if user:
        events = [e for e in events if user.lower() in (e["user"] or "").lower()]
    if providers:
        names = [name.lower() for name in providers]
        events = [e for e in events if any(name in e["provider"].lower() for name in names)]
    events.sort(key=_at, reverse=not oldest)
    if limit:
        events = events[:limit]
    return events


def _line(e, prefix=""):
    """One event as a table row, without colour."""
    first = (e["message"] or "").strip().splitlines()
    text = first[0].strip() if first else ""
    if len(text) > 70:
        text = text[:67] + "..."
    return prefix + (
        f"{e['time'][:19].replace('T', ' '):<21}{e['level']:<12}{str(e['id']):<7}{e['log'][:11]:<13}"
        f"{e['provider'][:30]:<32}{str(e['record']):<10}{text}"
    )


def _color(severity):
    if severity in (1, 2):
        return _net.RED
    if severity == 3:
        return _net.YELLOW
    return _net.GREY


def _print_events(events, options, empty="no events match"):
    if options["json"]:
        _core.print_json([_public(e) for e in events])
        return
    if not events:
        print(empty)
        return
    print(HEADER)
    for e in events:
        print(_color(e["severity"]) + _line(e) + _net.RESET)


# ======================================================================
# OPTIONS, TIMES AND QUERIES
# ======================================================================
def _parse(args):
    """Split the words from --options. Returns (words, {option: value or True})."""
    words, opts = [], {}
    rest = iter(args)
    for arg in rest:
        if not arg.startswith("--"):
            words.append(arg)
            continue
        name, equals, value = arg[2:].partition("=")
        name = name.lower()
        if name == "source":
            name = "provider"
        if name in SWITCH_FLAGS:
            opts[name] = True
        elif name in VALUE_FLAGS:
            if not equals:
                value = next(rest, None)
                if value is None or value.startswith("--"):
                    raise EventError(f"--{name} needs a value, e.g. --{name} 6h", 2)
            opts[name] = value
        else:
            raise EventError(f"unknown option --{name}", 2)
    return words, opts


def _when(text):
    """A time as a local datetime: 2h or 3d means that long ago, today, now, or 2026-10-15 14:30."""
    word = text.strip().lower()
    now = datetime.now().astimezone()
    if word == "now":
        return now
    if word == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    match = re.fullmatch(r"(\d+)\s*([mhdw])", word)
    if match:
        return now - timedelta(**{RELATIVE[match.group(2)]: int(match.group(1))})
    try:
        return datetime.fromisoformat(text.strip()).astimezone()
    except ValueError:
        raise EventError(f"could not read the time '{text}'. Use 2h, 3d, today, or 2026-10-15 14:30", 2)


def _since(opts, default):
    """The start of the time window: --since, or the default ("all" means no start)."""
    text = opts.get("since", default)
    if text is None or str(text).lower() == "all":
        return None
    return _when(text)


def _until(opts):
    return _when(opts["until"]) if opts.get("until") else None


def _logs(opts):
    text = opts.get("log")
    if not text:
        return list(DEFAULT_LOGS)
    return [part.strip() for part in text.split(",") if part.strip()]


def _levels(text):
    if text.lower() == "all":
        return [1, 2, 3, 4, 5]
    found = []
    for word in text.lower().split(","):
        word = word.strip()
        if word not in LEVELS:
            raise EventError(f"unknown level '{word}'. Use critical, error, warning, info or verbose, or all", 2)
        found.append(LEVELS[word])
    return sorted(set(found))


def _limit(opts, default):
    text = opts.get("limit")
    if text is None:
        return default
    if not str(text).isdigit() or int(text) < 1:
        raise EventError("--limit needs a number of at least 1", 2)
    return int(text)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"


def _query(levels=None, ids=None, since=None, until=None, after=None, pid=None, record=None, extra=None):
    """A Windows event query (XPath) built from the parts that are given."""
    parts = []
    if levels:
        parts.append("(" + " or ".join(f"Level={n}" for n in levels) + ")")
    if ids:
        parts.append("(" + " or ".join(f"EventID={i}" for i in ids) + ")")
    if since:
        parts.append(f"TimeCreated[@SystemTime>='{_iso(since)}']")
    if until:
        parts.append(f"TimeCreated[@SystemTime<='{_iso(until)}']")
    if after is not None:
        parts.append(f"EventRecordID>{after}")
    if record is not None:
        parts.append(f"EventRecordID={record}")
    if pid is not None:
        parts.append(f"Execution[@ProcessID='{pid}']")
    if extra:
        parts.append(extra)
    return f"*[System[{' and '.join(parts)}]]" if parts else "*"


def _filter_query(opts):
    """The query for evt filter and evt export, from the options given."""
    if opts.get("xpath"):
        used = [flag for flag in ("level", "provider", "id", "pid", "since", "until") if opts.get(flag)]
        if used:
            raise EventError("--xpath is a whole query on its own. Put the rest into it, or drop --" + used[0], 2)
        return opts["xpath"]
    ids = None
    if opts.get("id"):
        if not all(part.strip().isdigit() for part in opts["id"].split(",")):
            raise EventError("--id takes event numbers, e.g. --id 1000,1001", 2)
        ids = [int(part) for part in opts["id"].split(",")]
    pid = None
    if opts.get("pid"):
        if not opts["pid"].isdigit():
            raise EventError("--pid takes a process number", 2)
        pid = opts["pid"]
    levels = _levels(opts["level"]) if opts.get("level") else None
    return _query(levels=levels, ids=ids, since=_since(opts, None), until=_until(opts), pid=pid)


def _find(opts, query, limit=50, oldest=False, messages=True, providers=None):
    """Events for a command. --provider wins over the command's own list of providers."""
    names = [opts["provider"]] if opts.get("provider") else providers
    return _fetch(
        _logs(opts), query, _limit(opts, limit), oldest=oldest or bool(opts.get("oldest")),
        messages=messages, user=opts.get("user"), providers=names,
    )


def _days(since):
    return (datetime.now().astimezone() - since).total_seconds() / 86400


# ======================================================================
# LOGS — evt list
# ======================================================================
def _mb(size):
    return "-" if size is None else f"{size / 1048576:.1f} MB"


def _log_rows():
    rows = _powershell({"mode": "logs"}).get("logs") or []
    return sorted(rows, key=lambda row: row["name"].lower())


def _list(words, opts):
    mode = words[1].lower() if len(words) > 1 else "logs"
    if mode not in ("logs", "providers", "enabled", "disabled"):
        raise EventError("usage: evt list [providers|enabled|disabled]", 2)
    rows = _log_rows()
    if mode == "providers":
        found = defaultdict(list)
        for row in rows:
            for name in row["providers"]:
                found[name].append(row["name"])
        providers = [{"provider": name, "logs": sorted(found[name])} for name in sorted(found, key=str.lower)]
        if opts["json"]:
            _core.print_json(providers)
            return
        for item in providers:
            print(f"{item['provider']:<62}{', '.join(item['logs'])}")
        return
    if mode == "enabled":
        rows = [row for row in rows if row["enabled"]]
    if mode == "disabled":
        rows = [row for row in rows if not row["enabled"]]
    if opts["json"]:
        _core.print_json([{k: v for k, v in row.items() if k != "providers"} for row in rows])
        return
    print(f"{'LOG':<60}{'ON':<5}{'RECORDS':>10}  {'SIZE':>10}  {'MAX':>10}  MODE")
    for row in rows:
        color = "" if row["enabled"] else _net.GREY
        records = "-" if row["records"] is None else f"{row['records']:,}"
        print(color + f"{row['name'][:58]:<60}{'yes' if row['enabled'] else 'no':<5}{records:>10}  "
              f"{_mb(row['size']):>10}  {_mb(row['max']):>10}  {row['mode'].lower()}" + _net.RESET)


# ======================================================================
# THE EVERYDAY COMMANDS
# ======================================================================
def _errors(words, opts):
    levels = _levels(opts["level"]) if opts.get("level") else PROBLEM_LEVELS
    query = _query(levels=levels, since=_since(opts, "1d"), until=_until(opts))
    events = _find(opts, query)
    _print_events(events, opts, "no errors, critical events or warnings in that time")


def _recent(words, opts):
    count = 50
    if len(words) > 1:
        if not words[1].isdigit() or int(words[1]) < 1:
            raise EventError("usage: evt recent [N], where N is how many to show", 2)
        count = int(words[1])
    events = _find(opts, _query(until=_until(opts), since=_since(opts, None)), limit=count)
    _print_events(events, opts)


def _matches(e, needle):
    """Whether the text (already lower case) appears in the event's fields."""
    if needle.isdigit() and e["id"] == int(needle):
        return True
    texts = [e["message"], e["provider"], e["task"], e["computer"], e["keywords"], e["user"]]
    texts += list(e["data"].values())
    return any(needle in str(text).lower() for text in texts if text)


def _search(words, opts):
    if len(words) < 2:
        raise EventError("usage: evt search <text>, e.g. evt search disk or evt search 1000", 2)
    needle = " ".join(words[1:]).lower()
    levels = _levels(opts["level"]) if opts.get("level") else None
    scanned = _fetch(_logs(opts), _query(levels=levels, since=_since(opts, "7d"), until=_until(opts)),
                     limit=SEARCH_SCAN, messages=True, user=opts.get("user"))
    hits = [e for e in scanned if _matches(e, needle)][:_limit(opts, 50)]
    if not opts["json"] and len(scanned) >= SEARCH_SCAN:
        print(f"searched the newest {SEARCH_SCAN} events; add --since or --log to look further", file=sys.stderr)
    _print_events(hits, opts, f"nothing matched '{needle}'")


def _show_event(e):
    sections = [
        ("Event", [("id", e["id"]), ("level", e["level"]), ("time", e["time"]), ("provider", e["provider"]),
                   ("task", e["task"]), ("keywords", e["keywords"])]),
        ("Where", [("log", e["log"]), ("record", e["record"]), ("computer", e["computer"]), ("user", e["user"]),
                   ("process id", e["process_id"]), ("thread id", e["thread_id"]),
                   ("activity id", e["activity_id"])]),
    ]
    if e["data"]:
        sections.append(("Data", list(e["data"].items())))
    message = (e["message"] or "").strip() or "(no message: the provider's message text is not installed)"
    sections.append(("Message", [("text", message)]))
    _net.render(f"{e['log']} record {e['record']}", sections)
    print()
    try:
        print(xml.dom.minidom.parseString(e["xml"]).toprettyxml(indent="  ").strip())
    except Exception:  # the raw XML is still useful if it does not pretty-print
        print(e["xml"])


def _inspect(words, opts):
    if len(words) != 2 or not words[1].isdigit():
        raise EventError("usage: evt inspect <record>, e.g. evt inspect 4312 (add --log for another log)", 2)
    record = int(words[1])
    events = _fetch(_logs(opts), _query(record=record), limit=None, messages=True, user=opts.get("user"))
    if not events:
        raise EventError(f"no event with record {record} in {', '.join(_logs(opts))}. "
                         "Record numbers are per log, so check --log", 1)
    if opts["json"]:
        _core.print_json(events)
        return
    for index, e in enumerate(events):
        if index:
            print()
        _show_event(e)


def _filter(words, opts):
    query = _filter_query(opts)
    events = _find(opts, query, limit=50)
    _print_events(events, opts, "no events match those filters")


# ======================================================================
# WHAT WENT WRONG
# ======================================================================
def _crash_row(e):
    data = e["data"]
    if e["id"] == 1000:
        return {"kind": "crash", "app": data.get("AppName"), "version": data.get("AppVersion"),
                "module": data.get("ModuleName"), "module_version": data.get("ModuleVersion"),
                "exception": data.get("ExceptionCode")}
    if e["id"] == 1002:
        match = re.search(r"program (.+?) version (\S+)", e["message"] or "")
        return {"kind": "hang", "app": match.group(1) if match else None,
                "version": match.group(2) if match else None,
                "module": None, "module_version": None, "exception": None}
    return {"kind": "report", "app": None, "version": None, "module": None,
            "module_version": None, "exception": None}


def _crashes(words, opts):
    events = _find(opts, _query(since=_since(opts, "14d"), until=_until(opts), extra=CRASH_EXTRA), limit=50)
    rows = [dict(_crash_row(e), time=e["time"], record=e["record"], log=e["log"], id=e["id"]) for e in events]
    if opts["json"]:
        _core.print_json(rows)
        return
    if not rows:
        print("no application crashes or hangs in that time")
        return
    print(f"{'TIME':<21}{'KIND':<8}{'APPLICATION':<28}{'MODULE':<26}{'EXCEPTION':<12}RECORD")
    for row in rows:
        print(f"{row['time'][:19].replace('T', ' '):<21}{row['kind']:<8}{(row['app'] or '-')[:26]:<28}"
              f"{(row['module'] or '-')[:24]:<26}{(row['exception'] or '-'):<12}{row['record']}")
    print("\nA crash names the faulting module: that is the file to look at first (see evt inspect).")


def _ending_query(since, until=None):
    extra = ("((Provider[@Name='EventLog'] and (EventID=6005 or EventID=6006 or EventID=6008)) or "
             "(Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) or "
             "(Provider[@Name='User32'] and EventID=1074) or "
             "(Provider[@Name='BugCheck'] and EventID=1001))")
    return _query(since=since, until=until, extra=extra)


def _label(e):
    return ENDING_LABELS.get((e["provider"], e["id"]), e["provider"])


def _detail(e):
    message = (e["message"] or "").strip()
    if e["id"] == 1001:
        match = re.search(r"bugcheck was: (0x[0-9a-fA-F]+)", message)
        return f"bugcheck {match.group(1)}" if match else "blue screen"
    first = message.splitlines()[0].strip() if message else ""
    return first[:70]


def _shutdowns(words, opts):
    events = _fetch(["System"], _ending_query(_since(opts, "30d"), _until(opts)),
                    limit=_limit(opts, 200), oldest=True, messages=True)
    if opts["json"]:
        _core.print_json([dict(_public(e), label=_label(e), detail=_detail(e)) for e in events])
        return
    if not events:
        print("no shutdowns, restarts or blue screens in that time")
        return
    print(f"{'TIME':<21}{'EVENT':<52}{'ID':<7}DETAIL")
    for e in events:
        color = _net.RED if e["id"] in (41, 6008, 1001) else ""
        print(color + f"{_stamp(e):<21}{_label(e)[:50]:<52}{str(e['id']):<7}{_detail(e)}" + _net.RESET)
    print("\nAn unexpected shutdown or a restart without a clean one is what a crash or power loss leaves behind.")


def _stamp(e):
    return e["time"][:19].replace("T", " ")


def _boot(words, opts):
    since = _since(opts, "14d")
    endings = _fetch(["System"], _ending_query(since, _until(opts)), limit=None, oldest=True, messages=False)
    problems = _fetch(DEFAULT_LOGS, _query(levels=PROBLEM_LEVELS, since=since), limit=3000, messages=False)
    boot_ms = []
    try:
        durations = _fetch(["Microsoft-Windows-Diagnostics-Performance/Operational"],
                           _query(ids=[100], since=since), limit=None, messages=False)
        boot_ms = [(_at(d), int(d["data"]["BootTime"])) for d in durations if d["data"].get("BootTime", "").isdigit()]
        duration_note = None
    except EventError as e:
        duration_note = ("needs administrator rights to read the Diagnostics-Performance log"
                         if "administrator" in str(e) else str(e))

    boots, previous = [], None
    for e in sorted(endings, key=_at):
        if e["provider"] == "EventLog" and e["id"] == 6005:
            boots.append({"time": e["time"], "at": _at(e), "previous": previous, "boot_ms": None, "problems": []})
        elif (e["provider"], e["id"]) in ENDINGS:
            previous = ENDINGS[(e["provider"], e["id"])]
    for boot in boots:
        for moment, ms in boot_ms:
            if timedelta(0) <= moment - boot["at"] <= timedelta(minutes=15):
                boot["boot_ms"] = ms
                break
        boot["problems"] = [_public(p) for p in problems
                            if boot["at"] <= _at(p) < boot["at"] + BOOT_WINDOW]
    boots = boots[-_limit(opts, 10):][::-1]

    if opts["json"]:
        out = []
        for boot in boots:
            out.append({"time": boot["time"], "previous_end": boot["previous"], "boot_ms": boot["boot_ms"],
                        "slow": bool(boot["boot_ms"] and boot["boot_ms"] > SLOW_BOOT_MS),
                        "problems": boot["problems"]})
        _core.print_json(out)
        return
    if not boots:
        print("no boots in that time")
        return
    for boot in boots:
        before = boot["previous"] or "no shutdown was recorded before it"
        print(_net.GREEN + f"{boot['time'][:19].replace('T', ' ')}  started; before it: {before}" + _net.RESET)
        if boot["boot_ms"] is None:
            note = f" ({duration_note})" if duration_note else ""
            print(_net.GREY + "    boot time not recorded" + note + _net.RESET)
        else:
            slow = boot["boot_ms"] > SLOW_BOOT_MS
            color = _net.YELLOW if slow else _net.GREY
            print(color + f"    boot took {boot['boot_ms'] / 1000:.0f} s" + (" (slow)" if slow else "") + _net.RESET)
        if not boot["problems"]:
            print("    no errors or warnings in the first 10 minutes")
        else:
            print(_net.YELLOW + f"    {len(boot['problems'])} errors or warnings in the first 10 minutes:" + _net.RESET)
            for p in boot["problems"][:5]:
                print(_net.YELLOW + f"      {_stamp(p)}  {p['provider']} {p['id']}" + _net.RESET)
    print()


def _driver_query(opts, since):
    return _query(levels=_levels(opts["level"]) if opts.get("level") else PROBLEM_LEVELS, since=since,
                  until=_until(opts))


def _drivers(words, opts):
    events = _find(opts, _driver_query(opts, _since(opts, "7d")), limit=100, providers=DRIVER_PROVIDERS)
    _print_events(events, opts, "no driver problems in that time")
    if not opts["json"] and events:
        resets = sum(1 for e in events if e["provider"] == "Display" and e["id"] == 4101)
        if resets:
            print(f"\n{resets} display driver reset(s): the screen went black and came back (event 4101).")


def _service_name(data):
    """The service's name: its first field that is text, since a timeout puts its number first."""
    for key in ("param1", "param2", "param3"):
        value = data.get(key, "")
        if value and not value.isdigit():
            return value
    return None


def _services(words, opts):
    since = _since(opts, "7d")
    query = _query(levels=PROBLEM_LEVELS, ids=list(SERVICE_PROBLEMS), since=since, until=_until(opts))
    events = _find(opts, query, limit=200, messages=False, providers=["Service Control Manager"])
    rows = [dict(_public(e), service=_service_name(e["data"]), problem=SERVICE_PROBLEMS.get(e["id"]))
            for e in events]
    if opts["json"]:
        _core.print_json(rows)
        return
    if not rows:
        print("no service failures in that time")
        return
    print(f"{'TIME':<21}{'ID':<7}{'SERVICE':<36}PROBLEM")
    for row in rows:
        print(f"{row['time'][:19].replace('T', ' '):<21}{str(row['id']):<7}{(row['service'] or '-')[:34]:<36}"
              f"{row['problem']}")
    restarts = Counter(row["service"] for row in rows if row["id"] in SERVICE_RESTARTS and row["service"])
    for name, count in restarts.most_common():
        if count >= 2:
            print(_net.YELLOW + f"\n{name} stopped and restarted {count} times in that time" + _net.RESET)


def _network(words, opts):
    query = _query(levels=_levels(opts["level"]) if opts.get("level") else (
        [1, 2, 3, 4, 5] if opts.get("all") else PROBLEM_LEVELS), since=_since(opts, "1d"),
        until=_until(opts))
    events = _find(opts, query, limit=100, providers=NETWORK_PROVIDERS)
    _print_events(events, opts, "no network problems in that time")


def _security(words, opts):
    if opts.get("failed"):
        ids = [4625]
    elif opts.get("lockouts"):
        ids = [4740]
    elif opts.get("changes"):
        ids = list(SECURITY_CHANGES)
    else:
        ids = list(SECURITY_WHAT)
    query = _query(ids=ids, since=_since(opts, "1d"), until=_until(opts))
    events = _find(dict(opts, log=opts.get("log") or "Security"), query, limit=100, messages=False)
    rows = []
    for e in events:
        data = e["data"]
        rows.append(dict(_public(e), what=SECURITY_WHAT.get(e["id"]), account=data.get("TargetUserName"),
                         source=data.get("IpAddress") or data.get("CallerComputerName") or data.get("WorkstationName")
                         or data.get("SubjectUserName")))
    if opts["json"]:
        _core.print_json(rows)
        return
    if not rows:
        print("no matching security events. Windows records sign-ins and account changes only when auditing "
              "is on for them, and only administrators (or the Event Log Readers group) can read this log.")
        return
    print(f"{'TIME':<21}{'ID':<7}{'WHAT':<26}{'ACCOUNT':<26}FROM")
    for row in rows:
        print(f"{row['time'][:19].replace('T', ' '):<21}{str(row['id']):<7}{row['what']:<26}"
              f"{(row['account'] or '-')[:24]:<26}{row['source'] or '-'}")


# ======================================================================
# PATTERNS — correlate, timeline, frequency, baseline
# ======================================================================
def _clusters(events, gap_seconds):
    """Events in time order, split wherever the gap to the previous event is longer than gap_seconds."""
    groups = []
    for e in sorted(events, key=_at):
        if groups and (_at(e) - _at(groups[-1][-1])).total_seconds() <= gap_seconds:
            groups[-1].append(e)
        else:
            groups.append([e])
    return groups


def _shared(cluster):
    shared = {}
    pids = Counter(e["process_id"] for e in cluster if e["process_id"] is not None)
    pid_items = [pid for pid, count in pids.items() if count >= 2]
    if pid_items:
        shared["process_ids"] = sorted(pid_items)
    activities = Counter(e["activity_id"] for e in cluster if e["activity_id"])
    activity_items = [act for act, count in activities.items() if count >= 2]
    if activity_items:
        shared["activity_ids"] = sorted(activity_items)
    return shared


def _group_key(e, by):
    if by == "provider":
        return e["provider"]
    if by == "id":
        return f"{e['provider']} {e['id']}"
    if by == "process":
        return None if e["process_id"] is None else f"process {e['process_id']}"
    return e["activity_id"]


def _correlate(words, opts):
    by = opts.get("by", "time")
    if by not in ("time", "provider", "id", "process", "activity"):
        raise EventError("--by takes time, provider, id, process or activity", 2)
    levels = _levels(opts["level"]) if opts.get("level") else (
        [1, 2, 3, 4, 5] if opts.get("all") else PROBLEM_LEVELS)
    window = int(opts.get("window", 60)) if str(opts.get("window", "60")).isdigit() else None
    if window is None:
        raise EventError("--window takes seconds, e.g. --window 60", 2)
    events = _find(opts, _query(levels=levels, since=_since(opts, "1d"), until=_until(opts)),
                   limit=2000, messages=False)
    if by == "time":
        clusters = [c for c in _clusters(events, window) if len(c) >= 2 or opts.get("all")]
        out = []
        for cluster in clusters:
            out.append({
                "start": cluster[0]["time"], "end": cluster[-1]["time"], "count": len(cluster),
                "patterns": dict(Counter(f"{e['provider']} {e['id']}" for e in cluster)),
                **_shared(cluster),
            })
        if opts["json"]:
            _core.print_json(out)
            return
        if not out:
            print(f"no events happened within {window} seconds of each other")
            return
        for item in out[-30:]:
            print(_net.GREEN + f"{item['start'][:19].replace('T', ' ')} to {item['end'][11:19]}  "
                  f"{item['count']} events" + _net.RESET)
            for name, count in sorted(item["patterns"].items(), key=lambda kv: -kv[1])[:8]:
                print(f"    {count:>3} x {name}")
            shared = []
            if item.get("process_ids"):
                shared.append("process " + ", ".join(str(pid) for pid in item["process_ids"]))
            if item.get("activity_ids"):
                shared.append("activity " + ", ".join(item["activity_ids"]))
            if shared:
                print(_net.CYAN + "    shared: " + "; ".join(shared) + _net.RESET)
        if len(out) > 30:
            print(f"\n(showing the last 30 of {len(out)} groups)")
        return

    groups = defaultdict(list)
    for e in events:
        key = _group_key(e, by)
        if key:
            groups[key].append(e)
    rows = []
    for key, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        items.sort(key=_at)
        rows.append({"key": key, "count": len(items), "first": items[0]["time"], "last": items[-1]["time"]})
    if opts["json"]:
        _core.print_json(rows)
        return
    if not rows:
        print("nothing to group in that time")
        return
    for row in rows[:40]:
        print(f"{row['count']:>6}  {row['key'][:60]:<62}{row['first'][:19].replace('T', ' ')}  "
              f"to {row['last'][11:19]}")


def _offset(seconds):
    sign = "-" if seconds < 0 else "+"
    seconds = abs(int(seconds))
    return f"{sign}{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def _timeline(words, opts):
    if len(words) < 2:
        raise EventError("usage: evt timeline <time>, e.g. evt timeline \"2026-10-15 14:30\" or evt timeline 2h",
                         2)
    moment = _when(" ".join(words[1:]))
    minutes = opts.get("minutes", "15")
    if not str(minutes).isdigit():
        raise EventError("--minutes takes a number, e.g. --minutes 30", 2)
    span = timedelta(minutes=int(minutes))
    levels = _levels(opts["level"]) if opts.get("level") else [1, 2, 3, 4]
    events = _find(opts, _query(levels=levels, since=moment - span, until=moment + span), limit=1000,
                   oldest=True, messages=True)
    if opts["json"]:
        _core.print_json([dict(_public(e), offset_seconds=(_at(e) - moment).total_seconds()) for e in events])
        return
    print(f"timeline around {moment.strftime('%Y-%m-%d %H:%M:%S')} (+/- {minutes} minutes)")
    print(f"{'OFFSET':<11}{HEADER}")
    marked = False
    for e in events:
        if not marked and _at(e) >= moment:
            print(_net.CYAN + f"{'':<11}---- incident at {moment.strftime('%H:%M:%S')} ----" + _net.RESET)
            marked = True
        print(_color(e["severity"]) + f"{_offset((_at(e) - moment).total_seconds()):<11}" + _line(e) + _net.RESET)
    if not marked:
        print(_net.CYAN + f"{'':<11}---- incident at {moment.strftime('%H:%M:%S')} ----" + _net.RESET)
    if not events:
        print("nothing was logged in that window. Try a wider --minutes.")


def _frequency(words, opts):
    since = _since(opts, "7d")
    levels = _levels(opts["level"]) if opts.get("level") else PROBLEM_LEVELS
    limit = _limit(opts, 5000)
    events = _fetch(_logs(opts), _query(levels=levels, since=since, until=_until(opts)),
                    limit=limit, messages=False)
    patterns = _patterns(events)
    spikes = _spikes(events, opts.get("bucket", "hour"))
    truncated = len(events) >= limit
    if opts["json"]:
        _core.print_json({"truncated": truncated, "patterns": patterns, "spikes": spikes})
        return
    if truncated:
        print(f"(counts cover the newest {limit} events; add --since to narrow, or --limit to widen)")
    if not patterns:
        print("no event repeats in that time")
    else:
        print(f"{'COUNT':>7}  {'LOG':<12}{'PROVIDER':<36}{'ID':<8}FIRST")
        for item in patterns[:20]:
            print(f"{item['count']:>7}  {item['log'][:11]:<12}{item['provider'][:34]:<36}{str(item['id']):<8}"
                  f"{item['first'][:19].replace('T', ' ')}")
    if spikes is None:
        print("\nnot enough hours or days with events to look for spikes")
    elif spikes:
        print(_net.YELLOW + "\nspikes (much more than usual for that bucket):" + _net.RESET)
        for spike in spikes:
            top = ", ".join(f"{name} ({n})" for name, n in spike["top"])
            print(_net.YELLOW + f"  {spike['bucket']}  {spike['count']} events, usually about "
                  f"{spike['typical']:g}: {top}" + _net.RESET)
    else:
        print("\nno spikes")


def _patterns(events):
    found = {}
    for e in events:
        key = (e["log"], e["provider"], e["id"])
        item = found.setdefault(key, {"log": e["log"], "provider": e["provider"], "id": e["id"],
                                      "count": 0, "first": e["time"]})
        item["count"] += 1
        item["first"] = min(item["first"], e["time"])
    return sorted((item for item in found.values() if item["count"] >= 2), key=lambda item: -item["count"])


def _spikes(events, bucket):
    if bucket not in ("hour", "day"):
        raise EventError("--bucket takes hour or day", 2)
    fmt = "%Y-%m-%d %H:00" if bucket == "hour" else "%Y-%m-%d"
    counts, tops = Counter(), defaultdict(Counter)
    for e in events:
        key = _at(e).strftime(fmt)
        counts[key] += 1
        tops[key][f"{e['provider']} {e['id']}"] += 1
    if len(counts) < 3:
        return None
    typical = statistics.median(counts.values())
    threshold = max(5, 3 * typical)
    return [{"bucket": key, "count": count, "typical": typical, "top": tops[key].most_common(3)}
            for key, count in sorted(counts.items()) if count >= threshold]


def _counts(events):
    counts = Counter()
    for e in events:
        counts[f"{e['log']}|{e['provider']}|{e['id']}"] += 1
    return counts


def _baseline_path():
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return root / "w11-cli-console" / "events-baseline.json"


def _baseline(words, opts):
    action = words[1].lower() if len(words) > 1 else "compare"
    if action not in ("save", "compare"):
        raise EventError("usage: evt baseline save, or evt baseline to compare with it", 2)
    if action == "save":
        since = _since(opts, "7d")
        if since is None:
            raise EventError("a baseline needs a time window, e.g. --since 7d", 2)
        limit = _limit(opts, 5000)
        events = _fetch(_logs(opts), _query(levels=PROBLEM_LEVELS, since=since), limit=limit, messages=False)
        days = _days(since)
        data = {"saved": datetime.now().astimezone().isoformat(timespec="seconds"), "days": round(days, 3),
                "logs": _logs(opts), "counts": dict(_counts(events))}
        path = _baseline_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"saved {len(data['counts'])} kinds of error and warning over {days:.1f} days to {path}")
        if len(events) >= limit:
            print(f"(covers the newest {limit} events only; use --limit to widen)")
        return

    path = _baseline_path()
    if not path.exists():
        raise EventError("no baseline saved yet. Run 'evt baseline save' on a normal day first.", 1)
    saved = json.loads(path.read_text(encoding="utf-8"))
    since = _since(opts, "1d")
    if since is None:
        raise EventError("comparing needs a time window, e.g. --since 1d", 2)
    events = _fetch(_logs(opts), _query(levels=PROBLEM_LEVELS, since=since), limit=_limit(opts, 5000),
                    messages=False)
    ratio = _days(since) / saved["days"] if saved.get("days") else 0
    rows = []
    for key, count in _counts(events).items():
        if count < 5:
            continue
        expected = saved["counts"].get(key, 0) * ratio
        if expected and count < 3 * expected:
            continue
        log, provider, event_id = key.split("|", 2)
        rows.append({"log": log, "provider": provider, "id": event_id, "count": count,
                     "expected": round(expected, 2), "new": expected == 0})
    rows.sort(key=lambda row: -row["count"])
    if opts["json"]:
        _core.print_json(rows)
        return
    print(f"baseline saved {saved['saved'][:16].replace('T', ' ')}, over {saved['days']:g} days")
    if not rows:
        print("nothing is happening much more often than usual")
        return
    for row in rows:
        how = "NEW" if row["new"] else f"{row['count'] / row['expected']:.1f}x normal"
        print(_net.YELLOW + f"{row['count']:>7}  {how:<14}{row['log']} | {row['provider']} {row['id']}" + _net.RESET)


# ======================================================================
# EXPORT, WATCH, CLEAR
# ======================================================================
def _export(words, opts):
    if len(words) < 2:
        raise EventError("usage: evt export <file.json|file.csv|file.evtx> [filters]", 2)
    path = Path(words[1])
    kind = path.suffix.lower()
    if kind not in (".json", ".csv", ".evtx"):
        raise EventError("the file name must end in .json, .csv or .evtx", 2)
    if path.exists() and not opts.get("yes"):
        raise EventError(f"{path} already exists. Add --yes to replace it.", 1)
    query = _filter_query(opts)
    if kind == ".evtx":
        logs = _logs(opts)
        if len(logs) != 1:
            raise EventError("an .evtx export is one log at a time: add --log System, for example", 2)
        if opts.get("user"):
            raise EventError("--user cannot be used with an .evtx export. Export .json, then filter it.", 2)
        args = ["wevtutil", "epl", logs[0], str(path), f"/q:{query}"]
        if opts.get("yes"):
            args.append("/ow:true")
        ok, text = _net.run_tool(args)
        if not ok:
            raise EventError(_reason(text))
        print(f"saved {path}")
        return
    limit = None if opts.get("limit") == "0" else _limit(opts, 5000)
    events = _fetch(_logs(opts), query, limit=limit, messages=True, user=opts.get("user"),
                    providers=[opts["provider"]] if opts.get("provider") else None)
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == ".json":
        path.write_text(json.dumps([_public(e) for e in events], indent=2, default=str), encoding="utf-8")
    else:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["time", "level", "id", "log", "provider", "record", "process_id", "thread_id",
                             "computer", "user", "task", "keywords", "message", "data"])
            for e in events:
                writer.writerow([e["time"], e["level"], e["id"], e["log"], e["provider"], e["record"],
                                 e["process_id"], e["thread_id"], e["computer"], e["user"], e["task"],
                                 e["keywords"], (e["message"] or "").strip(), json.dumps(e["data"])])
    print(f"saved {len(events)} events to {path}")
    if limit and len(events) >= limit:
        print(f"(the newest {limit} only; use --limit 0 for all of them)")


def _watch(words, opts):
    logs = _logs(opts)
    levels = _levels(opts["level"]) if opts.get("level") else PROBLEM_LEVELS
    interval = float(opts.get("interval", 3))
    seconds = float(opts["seconds"]) if opts.get("seconds") else None
    last = {}
    for log in logs:
        newest = _fetch([log], "*", limit=1, messages=False)
        last[log] = newest[0]["record"] if newest else 0
    if not opts["json"]:
        print(f"watching {', '.join(logs)} for new events. Ctrl+C stops."
              + (f" Stops after {seconds:g} seconds." if seconds else ""))
    started = time.monotonic()
    try:
        while seconds is None or time.monotonic() - started < seconds:
            time.sleep(interval)
            for log in logs:
                found = _fetch([log], _query(levels=levels, after=last[log]), limit=500, oldest=True,
                               providers=[opts["provider"]] if opts.get("provider") else None)
                for e in found:
                    last[log] = max(last[log], e["record"])
                    if opts["json"]:
                        print(json.dumps(_public(e), default=str))
                    else:
                        print(_color(e["severity"]) + _line(e) + _net.RESET, flush=True)
    except KeyboardInterrupt:
        print()
    return


def _clear(words, opts):
    if len(words) != 2:
        raise EventError("usage: evt clear <log>, e.g. evt clear Application", 2)
    name = words[1]
    rows = {row["name"].lower(): row for row in _log_rows()}
    row = rows.get(name.lower())
    if row is None:
        raise EventError(f"no log called {name}. Run 'evt list' to see them.", 2)
    name = row["name"]
    _net.need_admin()
    records = "-" if row["records"] is None else f"{row['records']:,}"
    print(f"{name}: {records} records, {_mb(row['size'])} of {_mb(row['max'])}, "
          f"{'on' if row['enabled'] else 'off'}, {row['mode'].lower()}")
    backup = opts.get("backup")
    if not backup and not opts.get("no-backup"):
        raise EventError(
            "clearing deletes every record in the log. Save a copy first with --backup <file.evtx>, "
            "or add --no-backup to clear without one.", 2)
    if backup:
        path = Path(backup)
        if path.suffix.lower() != ".evtx":
            raise EventError("the backup file must end in .evtx", 2)
        ok, text = _net.run_tool(["wevtutil", "epl", name, str(path)])
        if not ok:
            raise EventError("the backup failed, so the log was not cleared: " + _reason(text))
        print(f"copy saved to {path}")
    try:
        typed = input(f"Type {name} to clear it (anything else cancels): ").strip()
    except (EOFError, KeyboardInterrupt):
        typed = ""
    if typed != name:
        print("cancelled")
        return
    ok, text = _net.run_tool(["wevtutil", "cl", name])
    if not ok:
        raise EventError(_reason(text))
    print(f"cleared {name}")


# ======================================================================
# COMMANDS — app.py calls run(args) with everything after "events"/"evt"
# ======================================================================
COMMANDS = {
    "list": _list, "ls": _list, "errors": _errors, "recent": _recent, "search": _search,
    "inspect": _inspect, "filter": _filter, "crashes": _crashes, "shutdowns": _shutdowns, "boot": _boot,
    "drivers": _drivers, "services": _services, "network": _network, "security": _security,
    "correlate": _correlate, "timeline": _timeline, "frequency": _frequency, "baseline": _baseline,
    "export": _export, "watch": _watch, "clear": _clear,
}


def run(args):
    """Run one events command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        words, opts = _parse(args)
        opts["json"], opts["yes"] = options["json"], options["yes"]
        if not words:
            raise EventError("usage: evt <command>. Run 'evt' for the list.", 2)
        handler = COMMANDS.get(words[0].lower())
        if handler is None:
            raise EventError(f"unknown command '{words[0]}'. Run 'evt' for the list.", 2)
        handler(words, opts)
        return 0
    except (EventError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

"""
services: Windows services, the background programs Windows runs. Routed from app.py ("services" or "svc").

    svc ls                       list every service with its id, state and startup type
    svc <id>                     show one service (a name works too: svc Spooler)
    svc search <words>           find services by name or display name
    svc status <id> [more]       state, process id and last exit code
    svc deps|dependents|tree <id>  what a service needs, what needs it, and the whole chain
    svc groups | accounts        services grouped by load-order group or by the account they run as
    svc exe <id>                 the program a service runs, and whether it is on disk
    svc triggers <id>            what starts a service on demand, when it is not started at boot
    svc delayed | disabled       services set to delayed start, or never to start
    svc failed                   services set to start that stopped with an error
    svc failures [days]          service failure events from the event log (default 7 days)
    svc stuck [sec]              services still waiting to start or stop after a pause
    svc permissions <id>         who may control the service, as Windows stores it
    svc <id> on|off              start it now, or stop it (stopping asks first)
    svc <id> restart             stop it and start it again
    svc <id> auto|manual|disabled
                                 start with Windows, start only when needed, or never start

Listing, showing and every read-only view need no administrator rights. Starting, stopping, restarting and
changing the startup type do, because Windows only lets administrators control services.
Setting a service to disabled asks first, and it is the one change here that can keep
a service from starting even after a restart. Changing it back to manual or auto undoes it.
Services are read through sc and the registry, the same as Windows' own Services window.
"""

import os
import re
import sys
import time
import winreg
from collections import defaultdict

import _core
import _net
import _probe

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "services"
ALIASES = ["svc"]
SUMMARY = "Find, inspect, start, stop and set Windows services"
# extra words people use, for 'settings search'
KEYWORDS = ["services.msc", "daemon", "service", "start a service", "stop a service"]
USAGE = ("svc ls | svc <id> | svc search <words> | svc failed | svc failures [days] | "
         "svc on|off|restart | svc auto|manual|disabled   (e.g. svc 12 restart)")
HELP = [
    ("svc ls", "list every service with its id, state and startup type"),
    ("svc <id>", "show one service: whether it runs, and how it starts"),
    ("svc search <words>", "find services by name or display name"),
    ("svc status <id> [more]", "state, process id and last exit code"),
    ("svc failed", "services set to start that stopped with an error"),
    ("svc failures [days]", "service failure events from the event log"),
    ("svc stuck [sec]", "services still waiting to start or stop after a pause"),
    ("svc deps <id>", "the services this one needs first"),
    ("svc dependents <id>", "the services that need this one"),
    ("svc tree <id>", "the whole chain of services this one needs"),
    ("svc exe <id>", "the program it runs, and whether that file is on disk"),
    ("svc triggers <id>", "what starts it on demand"),
    ("svc permissions <id>", "who may control it, as Windows stores it"),
    ("svc groups", "services grouped by load-order group"),
    ("svc accounts", "services grouped by the account they run as"),
    ("svc delayed", "services set to delayed start"),
    ("svc disabled", "services set never to start"),
    ("", "changes (need an administrator terminal)"),
    ("svc <id> on|off", "start it now, or stop it (asks first)"),
    ("svc <id> restart", "stop it and start it again"),
    ("svc <id> auto|manual|disabled", "start with Windows, start only when needed, or never (asks first)"),
]
TIP = (
    "Ids follow the list, sorted by name, so they shift. A name works too: svc status Spooler. "
    "The read-only views need no administrator rights. Changes need an administrator terminal."
)

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services" + "\\"
START_LABELS = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
RUN_ON = ("on", "start")
RUN_OFF = ("off", "stop")
RESTART = ("restart",)
# word -> the value sc config wants
STARTUP_WORDS = {"auto": "auto", "manual": "demand", "disabled": "disabled"}
SECONDS = 15  # how long to wait for a service to reach the state we asked for

# colours: green runs, grey is stopped, yellow is part way (starting or stopping)
STATE_COLORS = {"RUNNING": _net.GREEN, "STOPPED": _net.GREY}


class ServiceError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# SOURCES — every service, numbered by name
# ======================================================================
def _startup(name):
    """The startup type as Windows stores it in the service's registry key."""
    key = SERVICES_KEY + name
    start = _net.reg_read(key, "Start")
    if start == 2 and _net.reg_read(key, "DelayedAutostart") == 1:
        return "auto (delayed)"
    return START_LABELS.get(start, "unknown")


def _services():
    """Every service, sorted by name (ignoring case), with its id starting at 1."""
    text = _net.tool_ok(["sc", "query", "type=", "service", "state=", "all"], timeout=120)
    found = []
    for block in re.split(r"(?=SERVICE_NAME:)", text):
        name = re.search(r"SERVICE_NAME:\s*(\S+)", block)
        if not name:
            continue
        display = re.search(r"DISPLAY_NAME:\s*(.*)", block)
        state = re.search(r"STATE\s*:\s*\d+\s+(\w+)", block)
        found.append({
            "name": name.group(1),
            "display_name": display.group(1).strip() if display else "",
            "state": state.group(1).upper() if state else "UNKNOWN",
        })
    found.sort(key=lambda svc: svc["name"].lower())
    for index, svc in enumerate(found, start=1):
        svc["id"] = index
        svc["startup"] = _startup(svc["name"])
    return found


def _in(services, word):
    """The service with this id or name from a list already read; a bad word is a usage error."""
    if word.isdigit():
        for svc in services:
            if svc["id"] == int(word):
                return svc
        raise ServiceError(f"no service with id {word}. Run 'svc ls' to see them.", 2)
    for svc in services:
        if svc["name"].lower() == word.lower():
            return svc
    raise ServiceError(f"no service called {word}. Run 'svc ls' to see them.", 2)


def _get(word):
    return _in(_services(), word)


def _data(svc):
    return {
        "id": svc["id"],
        "name": svc["name"],
        "display_name": svc["display_name"],
        "state": svc["state"],
        "startup": svc["startup"],
    }


def _reread(svc):
    """Read the state and startup type again, so we report what Windows now says."""
    svc["state"] = _net.service_state(svc["name"])
    svc["startup"] = _startup(svc["name"])


def _wait_for(name, state):
    deadline = time.monotonic() + SECONDS
    while time.monotonic() < deadline:
        if _net.service_state(name) == state:
            return True
        time.sleep(0.5)
    return False


# ======================================================================
# READ-ONLY VIEWS — search, status, dependencies, groups, failures and so on. Nothing here changes a service.
# ======================================================================
TYPE_LABELS = {1: "kernel driver", 2: "file system driver", 16: "own process", 32: "shared process",
               256: "interactive", 272: "own process, interactive", 288: "shared process, interactive"}
TRIGGER_TYPES = {1: "device arrives", 2: "IP address becomes available", 3: "domain is joined",
                 4: "firewall port opens", 5: "group policy changes", 6: "network endpoint appears",
                 7: "custom event"}
PENDING = ("START_PENDING", "STOP_PENDING", "CONTINUE_PENDING", "PAUSE_PENDING")
SERVICE_FAILURE_IDS = [7000, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7032, 7034]
TREE_DEPTH_NOTE = "(loops back to a service already shown)"
STUCK_SECONDS = 10
MAX_STUCK = 120
FAILURE_DAYS = 7
MAX_FAILURE_DAYS = 30


def _config(name):
    """A service's settings as the registry holds them: what it runs, what it needs, who runs it."""
    key = SERVICES_KEY + name
    return {
        "image_path": _net.reg_read(key, "ImagePath"),
        "depends_on": list(_net.reg_read(key, "DependOnService", []) or []),
        "group": _net.reg_read(key, "Group") or None,
        "account": _net.reg_read(key, "ObjectName") or None,
        "type": TYPE_LABELS.get(_net.reg_read(key, "Type"), "other"),
    }


def _queryex(name):
    """State, process id and last exit code from sc. A missing value is None; a process id of 0 means none."""
    _, text = _net.run_tool(["sc", "queryex", name])
    state = re.search(r"STATE\s*:\s*\d+\s+(\w+)", text)
    pid = re.search(r"PID\s*:\s*(\d+)", text)
    code = re.search(r"WIN32_EXIT_CODE\s*:\s*(\d+)", text)
    return {"state": state.group(1).upper() if state else "UNKNOWN",
            "pid": int(pid.group(1)) or None if pid else None,
            "exit_code": int(code.group(1)) if code else None}


def _count(args, default, limit, usage):
    """An optional count from the arguments, checked against a limit."""
    if not args:
        return default
    if len(args) != 1 or not args[0].isdigit() or not 1 <= int(args[0]) <= limit:
        raise ServiceError(f"usage: {usage} (1 to {limit})", 2)
    return int(args[0])


def _table(found, options, title, empty="none"):
    if options["json"]:
        _core.print_json([_data(svc) for svc in found])
        return
    print(title)
    if not found:
        print(f"  {empty}")
        return
    rows = [(svc["id"], svc["name"], svc["state"].lower(), svc["startup"], svc["display_name"]) for svc in found]
    print(_probe.table(["ID", "NAME", "STATE", "STARTUP", "DISPLAY NAME"], rows))


def _search(args, options):
    if not args:
        raise ServiceError("usage: svc search <words>", 2)
    text = " ".join(args).lower()
    found = [svc for svc in _services() if text in svc["name"].lower() or text in svc["display_name"].lower()]
    _table(found, options, f"services matching '{text}' ({len(found)})", empty="no service matches")


def _status(args, options):
    if not args:
        raise ServiceError("usage: svc status <id or name> [more ...]", 2)
    services = _services()
    rows = []
    for word in args:
        svc = _in(services, word)
        live = _queryex(svc["name"])
        rows.append({**_data(svc), "state": live["state"], "pid": live["pid"], "exit_code": live["exit_code"]})
    if options["json"]:
        _core.print_json(rows)
        return
    print(_probe.table(["ID", "NAME", "STATE", "PID", "EXIT CODE", "STARTUP"],
                       [(r["id"], r["name"], r["state"].lower(), r["pid"] or "-",
                         "-" if r["exit_code"] is None else r["exit_code"], r["startup"]) for r in rows]))


def _deps(svc, options):
    rows = [{"name": name, "state": _queryex(name)["state"]} for name in _config(svc["name"])["depends_on"]]
    if options["json"]:
        _core.print_json({"service": svc["name"], "depends_on": rows})
        return
    if not rows:
        print(f"{svc['name']} needs no other service to start")
        return
    print(f"{svc['name']} needs these running first:")
    print(_probe.table(["NAME", "STATE"], [(r["name"], r["state"].lower()) for r in rows]))


def _dependents(svc, options):
    target = svc["name"].lower()
    found = [other for other in _services()
             if target in {name.lower() for name in _config(other["name"])["depends_on"]}]
    _table(found, options, f"services that need {svc['name']} ({len(found)})", empty="nothing needs it")


def _tree_of(name, trail):
    """The services this one needs, each with its own needs, down to the ends of the chain."""
    node = {"name": name, "state": _queryex(name)["state"].lower(), "needs": []}
    if name.lower() in trail:
        node["loops"] = True
        return node
    for child in _config(name)["depends_on"]:
        node["needs"].append(_tree_of(child, trail | {name.lower()}))
    return node


def _tree_lines(node, depth, lines):
    note = f" {TREE_DEPTH_NOTE}" if node.get("loops") else ""
    lines.append(f"{'  ' * depth}{node['name']} ({node['state']}){note}")
    for child in node["needs"]:
        _tree_lines(child, depth + 1, lines)


def _tree(svc, options):
    root = _tree_of(svc["name"], frozenset())
    if options["json"]:
        _core.print_json(root)
        return
    lines = []
    _tree_lines(root, 0, lines)
    print(f"what {svc['name']} waits for:")
    print("\n".join(lines))


def _groups(options):
    groups = defaultdict(list)
    for svc in _services():
        groups[_config(svc["name"])["group"] or "(no group)"].append(svc["name"])
    if options["json"]:
        _core.print_json({group: sorted(names, key=str.lower) for group, names in sorted(groups.items())})
        return
    rows = [(group, len(names), ", ".join(sorted(names, key=str.lower)[:4])) for group, names in sorted(groups.items())]
    print(_probe.table(["LOAD ORDER GROUP", "COUNT", "EXAMPLES"], rows))


BUILT_IN_ACCOUNTS = {"localsystem": "LocalSystem", "localservice": "LocalService", "networkservice": "NetworkService"}


def _account_label(account):
    """Windows writes the built-in accounts in several spellings; show one. Services with no account set run as
    the signed-in user, so they are labelled that way."""
    if not account:
        return "(not set: runs as the signed-in user)"
    return BUILT_IN_ACCOUNTS.get(account.split("\\")[-1].lower(), account)


def _accounts(options):
    accounts = defaultdict(list)
    for svc in _services():
        accounts[_account_label(_config(svc["name"])["account"])].append(svc["name"])
    if options["json"]:
        _core.print_json({account: sorted(names, key=str.lower) for account, names in sorted(accounts.items())})
        return
    rows = [(account, len(names), ", ".join(sorted(names, key=str.lower)[:3]))
            for account, names in sorted(accounts.items())]
    print(_probe.table(["RUNS AS", "COUNT", "EXAMPLES"], rows))


def _exe(svc, options):
    config = _config(svc["name"])
    path = config["image_path"] or ""
    match = re.match(r'\s*"?(.+?\.(?:exe|dll|sys))"?(\s|$)', path, re.IGNORECASE)
    program = match.group(1) if match else path.strip()
    if program.lower().startswith("\\systemroot"):
        program = os.environ.get("SystemRoot", r"C:\Windows") + program[len("\\SystemRoot"):]
    program = os.path.expandvars(program)
    arguments = path[match.end(1):].lstrip('"').strip() if match else ""
    host = re.search(r"-k\s+(\S+)", arguments)
    data = {"service": svc["name"], "program": program or None, "on_disk": bool(program) and os.path.isfile(program),
            "arguments": arguments or None, "shared_host_group": host.group(1) if host else None,
            "type": config["type"], "runs_as": config["account"]}
    if options["json"]:
        _core.print_json(data)
        return
    print(f"{svc['name']} runs")
    print(f"  program    {data['program'] or 'not recorded'}")
    print(f"  on disk    {'yes' if data['on_disk'] else 'NO: the file is missing or the path is not a file'}")
    if data["arguments"]:
        print(f"  arguments  {data['arguments']}")
    if data["shared_host_group"]:
        print(f"  shares the {data['shared_host_group']} host process with other services; "
              "see the process list (sys processes) for the host")
    print(f"  type       {data['type']}, runs as {data['runs_as'] or 'not recorded'}")


def _triggers(svc, options):
    base = SERVICES_KEY + svc["name"] + "\\TriggerInfo"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            subkeys = [winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])]
    except OSError:
        subkeys = []
    found = [TRIGGER_TYPES.get(_net.reg_read(f"{base}\\{sub}", "Type"), "other") for sub in subkeys]
    if options["json"]:
        _core.print_json({"service": svc["name"], "triggers": found})
        return
    if not found:
        print(f"{svc['name']} has no start triggers: it starts only as its startup type says")
        return
    print(f"{svc['name']} can start on demand when one of these happens:")
    for trigger in found:
        print(f"  {trigger}")


def _startup_list(predicate, options, title, empty):
    _table([svc for svc in _services() if predicate(svc)], options, title, empty=empty)


def _failed(options):
    rows = []
    for svc in _services():
        if not svc["startup"].startswith("auto") or svc["state"] == "RUNNING":
            continue
        live = _queryex(svc["name"])
        if live["state"] == "STOPPED" and live["exit_code"]:
            rows.append({**_data(svc), "exit_code": live["exit_code"]})
    if options["json"]:
        _core.print_json(rows)
        return
    if not rows:
        print("no service set to start is stopped with an error")
        return
    print(f"services set to start that stopped with an error ({len(rows)})")
    print(_probe.table(["ID", "NAME", "EXIT CODE", "DISPLAY NAME"],
                       [(r["id"], r["name"], r["exit_code"], r["display_name"]) for r in rows]))
    print("'svc failures' shows the events Windows logged for them.")


def _failures(args, options):
    import events  # the event log reader, shared with the evt page

    days = _count(args, FAILURE_DAYS, MAX_FAILURE_DAYS, "svc failures [days]")
    query = events._query(ids=SERVICE_FAILURE_IDS, since=events._when(f"{days}d"))
    rows = events._fetch(["System"], query, limit=200, providers=["Service Control Manager"])
    events._print_events(rows, options, empty=f"no service failures in the last {days} days")


def _stuck(args, options):
    seconds = _count(args, STUCK_SECONDS, MAX_STUCK, "svc stuck [sec]")
    pending = [svc["name"] for svc in _services() if svc["state"] in PENDING]
    if pending:
        time.sleep(seconds)
    rows = []
    for name in pending:
        live = _queryex(name)
        if live["state"] in PENDING:
            rows.append({"name": name, "state": live["state"], "pid": live["pid"]})
    if options["json"]:
        _core.print_json(rows)
        return
    if not pending:
        print("no service is waiting to start or stop")
    elif not rows:
        print(f"{len(pending)} service(s) were waiting; all finished within {seconds} s")
    else:
        print(f"stuck after {seconds} s:")
        print(_probe.table(["NAME", "STATE", "PID"], [(r["name"], r["state"].lower(), r["pid"] or "-") for r in rows]))


def _permissions(svc, options):
    ok, text = _net.run_tool(["sc", "sdshow", svc["name"]])
    if not ok:
        raise ServiceError(_net.explain(text))
    if options["json"]:
        _core.print_json({"service": svc["name"], "sddl": text.strip()})
        return
    print(f"{svc['name']}: who may control it (security descriptor, as Windows stores it)")
    print(text.strip())
    print("D: starts the access list. (A;...) allows and (D;...) denies; the two letters after the second ';' are the "
          "rights, e.g. RP start, WP stop, LC query status, SY the SYSTEM account, BA administrators.")


READ_WORDS = ("search", "status", "deps", "dependents", "tree", "groups", "accounts", "exe", "failures",
              "triggers", "delayed", "disabled", "stuck", "failed", "permissions")


def _read_only(args, options):
    word, rest = args[0].lower(), args[1:]
    if word == "search":
        _search(rest, options)
    elif word == "status":
        _status(rest, options)
    elif word == "groups":
        _groups(options)
    elif word == "accounts":
        _accounts(options)
    elif word == "failed":
        _failed(options)
    elif word == "failures":
        _failures(rest, options)
    elif word == "stuck":
        _stuck(rest, options)
    elif word == "delayed":
        _startup_list(lambda svc: svc["startup"] == "auto (delayed)", options,
                      "services set to delayed start", "none")
    elif word == "disabled":
        _startup_list(lambda svc: svc["startup"] == "disabled", options, "services set never to start", "none")
    else:
        if len(rest) != 1:
            raise ServiceError(f"usage: svc {word} <id or name>", 2)
        svc = _get(rest[0])
        {"deps": _deps, "dependents": _dependents, "tree": _tree, "exe": _exe, "triggers": _triggers,
         "permissions": _permissions}[word](svc, options)


# ======================================================================
# COMMANDS — app.py calls run(args) with everything after "services"/"svc"
# ======================================================================
def _list(options):
    services = _services()
    if options["json"]:
        _core.print_json([_data(svc) for svc in services])
        return
    print(f"{'ID':<6}{'NAME':<28}{'STATE':<10}{'STARTUP':<16}DISPLAY NAME")
    for svc in services:
        color = STATE_COLORS.get(svc["state"], _net.YELLOW)
        print(color + f"{svc['id']:<6}{svc['name'][:26]:<28}{svc['state'].lower():<10}"
                      f"{svc['startup']:<16}{svc['display_name'][:40]}" + _net.RESET)


def _show(svc, options):
    if options["json"]:
        _core.print_json(_data(svc))
        return
    color = STATE_COLORS.get(svc["state"], _net.YELLOW)
    print(f"{svc['name']} ({svc['display_name']})")
    print(color + f"  {svc['state'].lower()}" + _net.RESET + f", startup {svc['startup']}")


def _report(svc, options):
    _reread(svc)
    if options["json"]:
        _core.print_json(_data(svc))
    else:
        print(f"{svc['name']}: {svc['state'].lower()}, startup {svc['startup']}")


def _run_state(svc, word, options):
    name = svc["name"]
    want = "RUNNING" if word in RUN_ON else "STOPPED"
    if svc["state"] == want:
        print(f"{name} is already {want.lower()}")
        return

    _net.need_admin()  # check before announcing, so a refused change never says "starting..."
    if want == "STOPPED" and not _core.confirm(
        f"Stop {name} ({svc['display_name']})? Anything that uses it stops working until it starts "
        "again. [y/N]: ",
        options["yes"],
    ):
        print("cancelled")
        return

    if want == "RUNNING":
        print(f"starting {name}...")
        ok, text = _net.run_tool(["sc", "start", name])
        if not ok:
            hint = " Set its startup to manual or auto first." if "disabled" in text.lower() else ""
            raise ServiceError(_net.explain(text) + hint)
    else:
        print(f"stopping {name}...")
        ok, text = _net.run_tool(["sc", "stop", name])
        if not ok:
            raise ServiceError(_net.explain(text))

    if not _wait_for(name, want):
        raise ServiceError(f"{name} did not reach {want.lower()} within {SECONDS} seconds. Check it with 'svc {svc['id']}'.")
    _report(svc, options)


def _restart(svc, options):
    name = svc["name"]
    _net.need_admin()
    print(f"restarting {name}... expect it to be unavailable for a moment.")
    if not _net.restart_service(name, SECONDS):
        raise ServiceError(f"{name} did not come back to running. Try 'svc {svc['id']} on'.")
    _report(svc, options)


def _set_startup(svc, word, options):
    name = svc["name"]
    _net.need_admin()
    if word == "disabled" and not _core.confirm(
        f"Set {name} to disabled? It won't start with Windows, or when something asks for it, "
        f"until you set it to manual or auto again. [y/N]: ",
        options["yes"],
    ):
        print("cancelled")
        return
    ok, text = _net.run_tool(["sc", "config", name, "start=", STARTUP_WORDS[word]])
    if not ok:
        raise ServiceError(_net.explain(text))
    # the change is read back from the registry, so the report is what Windows stored
    _report(svc, options)
    if not options["json"]:
        print("This sets when it starts. It does not start or stop it now.")


def _change(args, options):
    if len(args) > 2:
        raise ServiceError("usage: svc <id> on|off|restart|auto|manual|disabled", 2)
    word = args[1].lower() if len(args) == 2 else None
    if word and word not in RUN_ON and word not in RUN_OFF and word not in RESTART and word not in STARTUP_WORDS:
        raise ServiceError("use on, off, restart, auto, manual or disabled, e.g. svc 12 restart", 2)

    svc = _get(args[0])
    if word is None:
        _show(svc, options)
        return
    if word in RUN_ON or word in RUN_OFF:
        _run_state(svc, word, options)
    elif word in RESTART:
        _restart(svc, options)
    elif word in STARTUP_WORDS:
        _set_startup(svc, word, options)
    else:
        raise ServiceError("use on, off, restart, auto, manual or disabled, e.g. svc 12 restart", 2)


def run(args):
    """Run one services command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        word = args[0].lower()
        if word in ("ls", "list"):
            if len(args) > 1:
                raise ServiceError("usage: svc ls", 2)
            _list(options)
        elif word in READ_WORDS:
            _read_only(args, options)
        else:
            _change(args, options)
        return 0
    except (ServiceError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

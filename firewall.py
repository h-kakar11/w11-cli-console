"""
firewall: Windows Firewall, read and changed from the command line. Routed from app.py
("firewall" or "fw").

    fw                                 each network profile (domain, private, public): on or off, and its defaults
    fw on|off [domain|private|public]  turn the firewall on or off for those profiles, or all three
                                       (administrator; turning it off asks first)
    fw rules [in|out] [allow|block] [on|off] [search <text>] [page <n>]
                                       every rule, numbered by name (ids shift as rules come and go)
    fw rule <id>                       one rule in full: its program, ports and addresses
    fw rule <id> on|off                turn one rule on or off (administrator; asks first)

Reading needs no administrator rights. Changes need an administrator terminal, and the page checks that
before it asks anything. Profiles and rules are read and changed with the NetSecurity PowerShell cmdlets
(Get-NetFirewallProfile, Get-NetFirewallRule, Set-NetFirewallProfile, Set-NetFirewallRule). Rules that
'net block' made are listed here too.
"""

import json
import os
import re
import subprocess
import sys

import _core
import _net

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "firewall"
ALIASES = ["fw"]
SUMMARY = "Windows Firewall: profiles, rules, turning them on or off"
# extra words people use, for 'settings search'
KEYWORDS = ["security", "block", "ports", "windows firewall", "rules", "allow an app"]
USAGE = "fw | fw on|off [profile] | fw rules [filters] | fw rule <id> [on|off]"
HELP = [
    ("fw", "each network profile: on or off, and its default for incoming traffic"),
    ("fw rules", "list the firewall rules, numbered"),
    ("fw rule <id>", "one rule in full: its program, ports and addresses"),
    ("fw on|off [profile]", "turn the firewall on or off for domain, private or public (administrator)"),
    ("fw rule <id> on|off", "turn one rule on or off (administrator)"),
]
TIP = "Public is for networks you do not trust, such as cafes and airports. Keep it on."
RUN_ALONE = True  # typing 'fw' on its own shows the status, which changes nothing

PROFILES = ("domain", "private", "public")
LIST_WORDS = ("rules", "ls", "list")
PAGE = 40  # rows per page in the rule list
# The name prefix netmon.py gives the rules made by 'net block'
BLOCK_PREFIX = "w11-cli-console-block-"
SAFE_NAME = re.compile(r"[A-Za-z0-9._{}-]+")  # rule names are passed to PowerShell, so only these characters


class FirewallError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# READING — PowerShell's NetSecurity cmdlets, one call per reading
# ======================================================================
def _ps(script, timeout=60):
    """Runs one PowerShell command and returns its output. Windows' reason is raised if it fails."""
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise FirewallError("could not run PowerShell")
    if result.returncode != 0:
        raise FirewallError(_net.explain(result.stderr + result.stdout))
    return result.stdout.strip()


def _rows(text):
    """The objects in ConvertTo-Json output, as a list (one object comes back without a list around it)."""
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        raise FirewallError("Windows gave a reading this page could not read")
    return [data] if isinstance(data, dict) else data


def _profiles():
    """{profile name: state, inbound, outbound}, for each profile Windows has."""
    rows = _rows(_ps("Get-NetFirewallProfile | Select-Object Name, "
                     "@{n='Enabled';e={$_.Enabled.ToString()}}, "
                     "@{n='Inbound';e={$_.DefaultInboundAction.ToString()}}, "
                     "@{n='Outbound';e={$_.DefaultOutboundAction.ToString()}} | ConvertTo-Json -Compress"))
    found = {}
    for row in rows:
        enabled = str(row.get("Enabled", "")).lower()
        found[str(row["Name"]).lower()] = {
            "state": {"true": "on", "false": "off"}.get(enabled, "not set"),
            "inbound": str(row.get("Inbound") or "-").lower(),
            "outbound": str(row.get("Outbound") or "-").lower(),
        }
    return found


def _networks():
    """(name, category) for each network this PC is connected to: public, private or domain."""
    try:
        rows = _rows(_ps("Get-NetConnectionProfile | Select-Object Name, "
                         "@{n='Category';e={$_.NetworkCategory.ToString()}} | ConvertTo-Json -Compress"))
    except FirewallError:
        return []  # no connection profiles is not an error for the status page
    return [(str(row["Name"]), str(row["Category"]).lower()) for row in rows]


def _rules():
    """Every firewall rule, numbered from 1 in name order. The list and the ids both come from here."""
    rows = _rows(_ps("Get-NetFirewallRule | Select-Object Name, DisplayName, DisplayGroup, "
                     "@{n='Enabled';e={$_.Enabled.ToString()}}, "
                     "@{n='Direction';e={$_.Direction.ToString()}}, "
                     "@{n='Action';e={$_.Action.ToString()}}, "
                     "@{n='Profile';e={$_.Profile.ToString()}} | ConvertTo-Json -Compress", timeout=120))
    rules = [{
        "name": str(row.get("Name") or ""),
        "display_name": str(row.get("DisplayName") or row.get("Name") or ""),
        "group": row.get("DisplayGroup") or None,
        "enabled": str(row.get("Enabled", "")).lower() == "true",
        "direction": "in" if str(row.get("Direction", "")).lower() == "inbound" else "out",
        "action": str(row.get("Action") or "").lower(),
        "profile": str(row.get("Profile") or "").lower(),
    } for row in rows]
    rules.sort(key=lambda rule: (rule["display_name"].lower(), rule["name"]))
    for number, rule in enumerate(rules, start=1):
        rule["id"] = number
    return rules


def _checked_name(rule):
    if not SAFE_NAME.fullmatch(rule["name"]):
        raise FirewallError(f"rule {rule['id']} has a name this page will not pass to Windows", 1)
    return rule["name"]


def _detail(rule):
    """What one rule matches: program, protocol, ports and addresses."""
    rows = _rows(_ps(
        f"$r = Get-NetFirewallRule -Name '{_checked_name(rule)}'; "
        "$a = $r | Get-NetFirewallApplicationFilter; $p = $r | Get-NetFirewallPortFilter; "
        "$f = $r | Get-NetFirewallAddressFilter; "
        "[pscustomobject]@{Program=[string]$a.Program; Protocol=[string]$p.Protocol; "
        "LocalPort=($p.LocalPort -join ','); RemotePort=($p.RemotePort -join ','); "
        "LocalAddress=($f.LocalAddress -join ','); RemoteAddress=($f.RemoteAddress -join ','); "
        "Description=[string]$r.Description} | ConvertTo-Json -Compress"))
    return rows[0] if rows else {}


def _or_any(value):
    return value if value else "any"


# ======================================================================
# CHANGES — profiles and rules. Each one checks for administrator rights, asks first, and reads back.
# ======================================================================
def _targets(words):
    """The profiles named after 'on' or 'off': none or 'all' means all three."""
    if not words or [word.lower() for word in words] == ["all"]:
        return list(PROFILES)
    names = []
    for word in words:
        if word.lower() not in PROFILES:
            raise FirewallError(f"'{word}' is not a profile. Use domain, private or public.", 2)
        names.append(word.lower())
    return names


def _set_profiles(words, options, on):
    names = _targets(words)
    _net.need_admin()
    word = "on" if on else "off"
    if not on:
        networks = _networks()
        public_now = [name for name, category in networks if category == "public"]
        warning = ("This PC stops filtering incoming and outgoing traffic on " + ", ".join(names) +
                   ". Every rule for them stops applying, including the blocks made with 'net block'.")
        if "public" in names and public_now:
            warning += f" You are on a public network now ({', '.join(public_now)}), so other devices there can reach this PC."
        if not _core.confirm(f"Turn the firewall off? {warning} To turn it back on: 'fw on {' '.join(names)}'. [y/N]: ",
                             options["yes"]):
            print("cancelled")
            return 0
    print(f"turning the firewall {word} for {', '.join(names)}...")
    _ps(f"Set-NetFirewallProfile -Profile {','.join(name.capitalize() for name in names)} "
        f"-Enabled {'True' if on else 'False'}")
    now = _profiles()
    _net.render("Windows Firewall, read back", [
        ("profiles", [(name, now.get(name, {}).get("state", "not found")) for name in names]),
    ])
    return 0


def _consequence(rule, on):
    if rule["action"] == "block":
        return "Traffic it blocks will be " + ("blocked." if on else "allowed through.")
    if on:
        return "Traffic it allows will be allowed through."
    return "Traffic it allows will no longer be allowed through, unless another rule allows it."


def _set_rule(rule, on, options):
    name = _checked_name(rule)
    _net.need_admin()
    verb = "on" if on else "off"
    opposite = "off" if on else "on"
    if not _core.confirm(f"Turn {verb} the rule '{rule['display_name']}'? {_consequence(rule, on)} "
                         f"To undo: 'fw rule {rule['id']} {opposite}'. [y/N]: ", options["yes"]):
        print("cancelled")
        return 0
    print(f"turning rule {rule['id']} {verb}...")
    _ps(f"Set-NetFirewallRule -Name '{name}' -Enabled {'True' if on else 'False'}")
    now = _ps(f"(Get-NetFirewallRule -Name '{name}').Enabled.ToString()")
    state = "on" if now.lower() == "true" else "off"
    print(f"rule {rule['id']} ({rule['display_name']}) is now {state}.")
    return 0


# ======================================================================
# SHOWING — status, the rule list, and one rule
# ======================================================================
def _status(options):
    profiles = _profiles()
    networks = _networks()
    if options["json"]:
        _core.print_json({"profiles": profiles, "networks": [{"name": n, "category": c} for n, c in networks]})
        return 0
    _net.render("Windows Firewall", [
        ("profiles", [
            (name, f"{profiles[name]['state']}, incoming {profiles[name]['inbound']}, "
                   f"outgoing {profiles[name]['outbound']}")
            for name in PROFILES if name in profiles
        ] or [("profiles", "none found")]),
        ("connected networks", [(name, category) for name, category in networks] or [("none", "-")]),
        ("change it with", [
            ("fw on|off <profile>", "turn a profile on or off (administrator; turning off asks first)"),
            ("fw rules", "list the firewall rules"),
            ("fw help", "everything this page can do"),
        ]),
    ])
    return 0


def _rule_filters(words):
    filters = {"direction": None, "action": None, "enabled": None, "search": None, "page": 1}
    usage = "usage: fw rules [in|out] [allow|block] [on|off] [search <text>] [page <n>]"
    index = 0
    while index < len(words):
        word = words[index].lower()
        if word in ("in", "out"):
            filters["direction"] = word
        elif word in ("allow", "block"):
            filters["action"] = word
        elif word in ("on", "off"):
            filters["enabled"] = word == "on"
        elif word == "search":
            filters["search"] = " ".join(words[index + 1:]).lower()
            if not filters["search"]:
                raise FirewallError(usage, 2)
            return filters
        elif word == "page" and index + 1 < len(words) and words[index + 1].isdigit() and int(words[index + 1]) >= 1:
            filters["page"] = int(words[index + 1])
            index += 2
            continue
        else:
            raise FirewallError(usage, 2)
        index += 1
    return filters


def _matches(rule, filters):
    if filters["direction"] and rule["direction"] != filters["direction"]:
        return False
    if filters["action"] and rule["action"] != filters["action"]:
        return False
    if filters["enabled"] is not None and rule["enabled"] != filters["enabled"]:
        return False
    if filters["search"] and filters["search"] not in rule["display_name"].lower():
        return False
    return True


def _rules_cmd(words, options):
    filters = _rule_filters(words)
    found = [rule for rule in _rules() if _matches(rule, filters)]
    pages = max(1, -(-len(found) // PAGE))
    if filters["page"] > pages:
        raise FirewallError(f"there are only {pages} page(s) of rules", 2)
    start = (filters["page"] - 1) * PAGE
    shown = found[start:start + PAGE]
    if options["json"]:
        _core.print_json({"page": filters["page"], "pages": pages, "total": len(found),
                          "rules": [dict(rule) for rule in shown]})
        return 0
    print(f"{'ID':<6}{'RULE':<44}{'DIR':<5}{'ACTION':<8}{'ON':<4}PROFILE")
    for rule in shown:
        color = _net.GREEN if rule["enabled"] else _net.GREY
        print(color + f"{rule['id']:<6}{rule['display_name'][:42]:<44}{rule['direction']:<5}"
              f"{rule['action']:<8}{'yes' if rule['enabled'] else 'no':<4}{rule['profile'] or '-'}" + _net.RESET)
    print(f"\npage {filters['page']} of {pages}, {len(found)} rule(s). 'fw rule <id>' explains one.")
    return 0


def _rule_cmd(words, options):
    if not words or not words[0].isdigit():
        raise FirewallError("usage: fw rule <id> [on|off]", 2)
    rules = _rules()
    rule = next((r for r in rules if r["id"] == int(words[0])), None)
    if rule is None:
        raise FirewallError(f"no rule with id {words[0]}. Run 'fw rules' to see them.", 2)
    if len(words) == 2 and words[1].lower() in ("on", "off"):
        return _set_rule(rule, words[1].lower() == "on", options)
    if len(words) != 1:
        raise FirewallError("usage: fw rule <id> [on|off]", 2)
    detail = _detail(rule)
    made_by = "net block (netmon)" if rule["display_name"].startswith(BLOCK_PREFIX) else "Windows or an app"
    if options["json"]:
        _core.print_json({**rule, **detail, "made_by": made_by})
        return 0
    _net.render(rule["display_name"], [
        ("rule", [
            ("direction", "incoming" if rule["direction"] == "in" else "outgoing"),
            ("action", rule["action"]), ("on", "yes" if rule["enabled"] else "no"),
            ("profiles", rule["profile"] or "-"), ("group", rule["group"] or "-"), ("made by", made_by),
        ]),
        ("what it matches", [
            ("program", _or_any(detail.get("Program"))), ("protocol", _or_any(detail.get("Protocol"))),
            ("local port", _or_any(detail.get("LocalPort"))), ("remote port", _or_any(detail.get("RemotePort"))),
            ("local address", _or_any(detail.get("LocalAddress"))),
            ("remote address", _or_any(detail.get("RemoteAddress"))),
        ]),
        ("change it with", [
            (f"fw rule {rule['id']} on|off", "turn it on or off (administrator; asks first)"),
        ]),
    ])
    return 0


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "firewall"/"fw"
# ======================================================================
def run(args):
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    if not args:
        args = ["status"]
    elif args[0].lower() in _core.HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    word, rest = args[0].lower(), args[1:]
    try:
        if word == "status" and not rest:
            return _status(options)
        if word in ("on", "off"):
            return _set_profiles(rest, options, word == "on")
        if word in LIST_WORDS:
            return _rules_cmd(rest, options)
        if word == "rule":
            return _rule_cmd(rest, options)
        raise FirewallError(f"usage: {USAGE}", 2)
    except (FirewallError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

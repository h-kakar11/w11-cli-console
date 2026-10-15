"""
location: Windows location services, the apps that use them, and location override.
Routed from app.py ("location" or "lc").

    lc                         every location setting, with what it is set to now
    lc on | lc off             location services for the whole PC (off needs administrator)
    lc access                  show whether apps may use your location
    lc access on | lc access off
    lc apps                    every app that has asked for location, numbered
    lc apps <id>               show one app
    lc apps <id> on | off      let that app use location, or block it
    lc recent                  apps that used location in the last 7 days
    lc override                show whether location override is allowed
    lc override on | off

Location services is the master switch. Turning it off sets the Windows policy
"Turn off location" (DisableLocation under HKLM), the same value gpedit.msc writes.
Nothing is deleted, and 'lc on' puts it back. Apps and their own choices are kept.

Location access for apps and the per-app switches live under the current user,
so they need no administrator rights. Ids follow the list, so run 'lc apps' first.
"""

import ctypes
import datetime
import json
import os
import subprocess
import sys
import winreg

import _core

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "location"
ALIASES = ["lc"]
SUMMARY = "Location services, app access, and the override"
USAGE = ("lc | lc why | lc on|off | lc access on|off | lc apps [<id> on|off] | lc recent | "
         "lc override on|off | add --json to lc, lc why or lc apps for JSON")
HELP = [
    ("lc", "list every location setting, with what it is set to now"),
    ("lc why", "say why location is off or blocked, and what would fix it"),
    ("lc on | lc off", "location services for the whole PC (off needs administrator)"),
    ("lc access on | off", "let apps use your location, or block all of them"),
    ("lc apps", "list apps that have asked for location, with ids"),
    ("lc apps <id> on | off", "let one app use location, or block it"),
    ("lc recent", "apps that used location in the last 7 days"),
    ("lc override on | off", "allow location override (a remote device's location)"),
]
TIP = "Run 'lc' for the full picture. Turning location services on or off needs an administrator terminal."
RUN_ALONE = True  # typing 'lc' on its own lists every location setting

POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
POLICY_VALUE = "DisableLocation"  # 1 = location off for the PC, 0 = on
CONSENT_KEY = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
NONPACKAGED = "NonPackaged"  # desktop programs: one subkey each, with the path in its name
OVERRIDE_KEY = r"Software\Microsoft\Windows\CurrentVersion\CPSS\Store\UserLocationOverridePrivacySetting"
RECENT_DAYS = 7
FILETIME_EPOCH = 116444736000000000  # 100-nanosecond ticks from 1601 to 1970
POLICY_SERVICE = "lfsvc"  # Geolocation Service: starts when an app asks for location
MDM_ENROLLMENTS = r"SOFTWARE\Microsoft\Enrollments"  # one subkey per device-management enrollment
FLAGS = ("--json", "--override-management")
# Built into every Windows install (policy precedence sources), so they do not mean an organisation manages the PC
WINDOWS_AUTHORITIES = ("Local Authority", "Cloud Authority", "Deploy Authority")

STATE_WORDS = {"Allow": "allowed", "Deny": "blocked", "Prompt": "asks each time"}
ADMIN_HINT = "this needs administrator rights. Run the terminal as administrator."
LIST_WORDS = ("ls", "list")
HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")


class LocationError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# REGISTRY — the only place this page reads or writes Windows settings
# ======================================================================
def _read(hive, path, name, default=None):
    try:
        with winreg.OpenKey(hive, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return default


def _write(hive, path, name, kind, value):
    try:
        with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, kind, value)
    except PermissionError:
        raise LocationError(ADMIN_HINT)


def _subkeys(hive, path):
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return []
    names = []
    with key:
        index = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, index))
            except OSError:
                return names
            index += 1


def _when(ticks):
    """A Windows FILETIME as local time, or None if it is not set."""
    if not ticks:
        return None
    return datetime.datetime.fromtimestamp((ticks - FILETIME_EPOCH) / 10**7)


# ======================================================================
# LOCATION SERVICES — the policy that turns location off for the whole PC
# ======================================================================
def _services_on():
    return _read(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY, POLICY_VALUE, 0) != 1


def _set_services(on):
    _write(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY, POLICY_VALUE, winreg.REG_DWORD, 0 if on else 1)
    if _services_on() != on:
        raise LocationError("the policy did not change. Check that the terminal is an administrator.")


# ======================================================================
# APPS — access for everyone, and one switch per app
# ======================================================================
def _access_on():
    """Let apps access your location: the switch for every app at once."""
    return _read(winreg.HKEY_CURRENT_USER, CONSENT_KEY, "Value", "Allow") == "Allow"


def _set_access(on):
    _write(winreg.HKEY_CURRENT_USER, CONSENT_KEY, "Value", winreg.REG_SZ, "Allow" if on else "Deny")


def _apps():
    """Every app that has asked for location, sorted by name and numbered from 1.
    The list and the numbers both come from here, so ids in 'lc apps' match 'lc apps <id>'."""
    found = []
    for name in _subkeys(winreg.HKEY_CURRENT_USER, CONSENT_KEY):
        if name == NONPACKAGED:
            continue
        found.append({
            "name": name.split("_")[0],  # Microsoft.WindowsCamera_8wekyb3d8bbwe -> Microsoft.WindowsCamera
            "where": "Store app",
            "path": f"{CONSENT_KEY}\\{name}",
        })
    desktop = f"{CONSENT_KEY}\\{NONPACKAGED}"
    for name in _subkeys(winreg.HKEY_CURRENT_USER, desktop):
        if name == "Executables":  # prompt history, not an app
            continue
        exe = name.replace("#", "\\")  # C:#Windows#netsh.exe -> C:\Windows\netsh.exe
        found.append({"name": os.path.basename(exe), "where": exe, "path": f"{desktop}\\{name}"})
    found.sort(key=lambda app: (app["name"].lower(), app["where"].lower()))
    for number, app in enumerate(found, start=1):
        app["id"] = number
        app["value"] = _read(winreg.HKEY_CURRENT_USER, app["path"], "Value")
        app["used"] = _when(_read(winreg.HKEY_CURRENT_USER, app["path"], "LastUsedTimeStop"))
    return found


def _get_app(app_id):
    for app in _apps():
        if app["id"] == app_id:
            return app
    raise LocationError(f"no app with id {app_id}. Run 'lc apps' to see them.", 2)


def _can_use(app, access_on):
    """Whether this app may get location right now, from its own switch or the switch for all apps."""
    if app["value"] is None:
        return access_on
    return app["value"] == "Allow"


def _state_label(app, access_on):
    if app["value"] in STATE_WORDS:
        return STATE_WORDS[app["value"]]
    return "follows all apps (" + ("on" if access_on else "off") + ")"


def _set_app(app, on):
    _write(winreg.HKEY_CURRENT_USER, app["path"], "Value", winreg.REG_SZ, "Allow" if on else "Deny")


# ======================================================================
# OVERRIDE — let apps use the location of a remote device (e.g. Remote Desktop)
# ======================================================================
def _override_on():
    return _read(winreg.HKEY_CURRENT_USER, OVERRIDE_KEY, "Value", 1) != 0


def _set_override(on):
    _write(winreg.HKEY_CURRENT_USER, OVERRIDE_KEY, "Value", winreg.REG_DWORD, 1 if on else 0)


# ======================================================================
# OUTPUT — every list is blue, the same as the other settings
# ======================================================================
def _on_off(word):
    word = word.lower()
    if word in ("on", "enable"):
        return True
    if word in ("off", "disable"):
        return False
    raise LocationError("use on or off, e.g. lc access off", 2)


def _overview():
    apps = _apps()
    access = _access_on()
    allowed = sum(1 for app in apps if _can_use(app, access))
    lines = [
        "location: every location setting, and what it is set to now",
        "",
        f"  {'SETTING':<30}{'NOW':<30}CHANGE IT WITH",
        f"  {'location services':<30}{'on' if _services_on() else 'off':<30}lc on | lc off",
        f"  {'let apps access location':<30}{'on' if access else 'off':<30}lc access on | lc access off",
        f"  {'apps that asked':<30}{f'{len(apps)} listed, {allowed} allowed':<30}lc apps",
        f"  {'used in the last 7 days':<30}{f'{len(_recent(apps))} app(s)':<30}lc recent",
        f"  {'allow location override':<30}{'on' if _override_on() else 'off':<30}lc override on | lc override off",
        "",
        "What each one does:",
        "  Location services is the switch for the whole PC. Off means no app and no Windows",
        "  feature can get your location. Turning it off sets a Windows policy, so it needs",
        "  an administrator terminal. Turning it back on removes the block.",
        "  Let apps access your location is the switch for every app. Off blocks them all,",
        "  and the per-app choices are kept for when you turn it back on.",
        "  Apps are the programs that have asked for your location. Each can be allowed or",
        "  blocked on its own, the same as the list in Settings.",
        "  Allow location override lets this PC use a remote device's location, such as",
        "  when you are on a Remote Desktop session.",
    ]
    return _core.BLUE + "\n".join(lines) + _core.RESET


def _recent(apps):
    """Apps that used location in the last RECENT_DAYS, newest first."""
    cutoff = datetime.datetime.now() - datetime.timedelta(days=RECENT_DAYS)
    used = [app for app in apps if app["used"] and app["used"] >= cutoff]
    return sorted(used, key=lambda app: app["used"], reverse=True)


def _app_row(app, access):
    when = app["used"].strftime("%Y-%m-%d %H:%M") if app["used"] else "never"
    return f"  {app['id']:<5}{app['name'][:30]:<32}{_state_label(app, access):<26}{when}"


def _apps_list():
    os.system("")  # enables ANSI colour codes in the Windows console
    apps = _apps()
    if not apps:
        print("(no app has asked for your location yet)")
        return
    access = _access_on()
    lines = [f"  {'ID':<5}{'APP':<32}{'ACCESS':<26}LAST USED"]
    lines += [_app_row(app, access) for app in apps]
    print(_core.BLUE + "\n".join(lines) + _core.RESET)


def _app_detail(app, access):
    print(_core.BLUE + f"{app['name']} ({app['where']})\n  access: {_state_label(app, access)}\n  "
          f"last used: {app['used'].strftime('%Y-%m-%d %H:%M') if app['used'] else 'never'}" + _core.RESET)


# ======================================================================
# DIAGNOSIS — one report with the reasons, for people and for agents (lc why --json)
# ======================================================================
def _managed_by():
    """Why an organisation manages this PC, as plain reasons. An empty list means it is not managed."""
    reasons = []
    domain = os.environ.get("USERDNSDOMAIN")
    if domain:
        reasons.append(f"this PC is joined to the domain {domain}")
    for enrollment in _subkeys(winreg.HKEY_LOCAL_MACHINE, MDM_ENROLLMENTS):
        provider = _read(winreg.HKEY_LOCAL_MACHINE, f"{MDM_ENROLLMENTS}\\{enrollment}", "ProviderID")
        if provider and provider not in WINDOWS_AUTHORITIES:
            reasons.append(f"this PC is enrolled in device management ({provider})")
    return reasons


def _policy_value():
    """The DisableLocation policy as it is written: 1 turns location off, None means no policy sets it."""
    return _read(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY, POLICY_VALUE)


def _service_state():
    """Geolocation Service: running, stopped or unknown. Stopped is normal when no app is asking."""
    try:
        out = subprocess.run(["sc", "query", POLICY_SERVICE], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    for line in out.splitlines():
        if "STATE" in line:
            return line.split()[-1].lower()
    return "unknown"


def _next_steps(services_on, reasons, access):
    steps = []
    if not services_on:
        if reasons:
            steps.append("Location services are off because of a policy set by your organisation: "
                         + "; ".join(reasons) + ". Turning them on overrides that policy, so ask your "
                         "administrator first. If this PC is yours and you decide to override it, run "
                         "'lc on --override-management' in an administrator terminal.")
        else:
            steps.append("Location services are off because of a local policy. Run 'lc on' in an "
                         "administrator terminal to turn them back on.")
    if not access:
        steps.append("Apps are blocked. Run 'lc access on' to let them use location again.")
    return steps


def _report():
    apps = _apps()
    access = _access_on()
    services_on = _services_on()
    reasons = _managed_by()
    return {
        "location_services": "on" if services_on else "off",
        "location_services_set_by": "policy" if _policy_value() == 1 else "default",
        "policy_key": f"HKLM\\{POLICY_KEY}\\{POLICY_VALUE}",
        "managed_by_organisation": reasons,
        "let_apps_access_location": "on" if access else "off",
        "allow_location_override": "on" if _override_on() else "off",
        "geolocation_service": _service_state(),
        "administrator": _is_admin(),
        "apps_asked": len(apps),
        "apps_allowed": sum(1 for app in apps if _can_use(app, access)),
        "apps_used_last_7_days": len(_recent(apps)),
        "next_steps": _next_steps(services_on, reasons, access),
    }


def _why_text(report):
    lines = [
        "location: why it is on or off, and what would change it",
        "",
        f"  {'location services':<28}{report['location_services']}",
        f"  {'set by':<28}{'a policy' if report['location_services_set_by'] == 'policy' else 'the default'}",
        f"  {'managed by organisation':<28}{'yes' if report['managed_by_organisation'] else 'no'}",
        f"  {'let apps access location':<28}{report['let_apps_access_location']}",
        f"  {'allow location override':<28}{report['allow_location_override']}",
        f"  {'geolocation service':<28}{report['geolocation_service']}",
        f"  {'running as administrator':<28}{'yes' if report['administrator'] else 'no'}",
        f"  {'apps that asked':<28}{report['apps_asked']} listed, {report['apps_allowed']} allowed",
        "",
    ]
    if report["next_steps"]:
        lines.append("Next steps:")
        lines += [f"  - {step}" for step in report["next_steps"]]
    else:
        lines.append("Nothing needs changing: location services and app access are both on.")
    return "\n".join(lines)


def _apps_json():
    access = _access_on()
    return [{
        "id": app["id"],
        "name": app["name"],
        "where": app["where"],
        "access": _state_label(app, access),
        "last_used": app["used"].isoformat(timespec="minutes") if app["used"] else None,
    } for app in _apps()]


# ======================================================================
# COMMANDS — each one reads or changes a single setting, and says what it did
# ======================================================================
def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _services(on, override=False):
    if not _is_admin():
        raise LocationError(ADMIN_HINT)  # checked first, so nothing is announced that will not happen
    if on and _policy_value() == 1:
        reasons = _managed_by()
        if reasons and not override:
            raise LocationError(
                "location services are turned off by a policy set by your organisation ("
                + "; ".join(reasons) + "). Turning them on overrides that policy, so ask your administrator. "
                "If this PC is yours and you want to override it, run 'lc on --override-management'.")
        if reasons:
            print("warning: overriding a policy set by your organisation. Device management or Group Policy "
                  "may set it back at its next refresh.")
    if on:
        print("turning location services on... apps and Windows features can get your location again.")
        _set_services(True)
        print("location services turned on")
        return
    print("turning location services off... expect Settings > Privacy & security > Location to show it "
          "off. Windows applies policy changes at the next refresh, or run 'gpupdate /force' to apply now.")
    _set_services(False)
    print("location services completely turned off")


def _access_command(rest):
    if not rest:
        print(f"let apps access your location: {'on' if _access_on() else 'off'}")
        return
    if len(rest) != 1:
        raise LocationError("usage: lc access on | lc access off", 2)
    on = _on_off(rest[0])
    _set_access(on)
    if on:
        print("apps can use your location again. Each app's own choice still applies.")
    else:
        print("let apps access your location: off. Every app is blocked until you turn it back on.")


def _apps_command(rest, options):
    if not rest or rest[0].lower() in LIST_WORDS:
        if len(rest) > 1:
            raise LocationError("usage: lc apps", 2)
        if options["json"]:
            print(json.dumps(_apps_json(), indent=2))
            return
        _apps_list()
        return
    try:
        app_id = int(rest[0])
    except ValueError:
        raise LocationError(f"expected an app id from 'lc apps', got: {rest[0]}", 2)
    app = _get_app(app_id)
    access = _access_on()
    if len(rest) == 1:
        _app_detail(app, access)
        return
    if len(rest) != 2:
        raise LocationError("usage: lc apps <id> on | off", 2)
    on = _on_off(rest[1])
    _set_app(app, on)
    print(f"{app['name']}: {'allowed' if on else 'blocked'}")
    if on and not access:
        print("note: apps are blocked for everyone right now. Run 'lc access on' to let this app use location.")


def _recent_command():
    apps = _apps()
    used = _recent(apps)
    if not used:
        print(f"no app has used your location in the last {RECENT_DAYS} days")
        return
    os.system("")  # enables ANSI colour codes in the Windows console
    access = _access_on()
    lines = [f"apps that used your location in the last {RECENT_DAYS} days, newest first", "",
             f"  {'ID':<5}{'APP':<32}{'ACCESS':<26}LAST USED"]
    lines += [_app_row(app, access) for app in used]
    print(_core.BLUE + "\n".join(lines) + _core.RESET)


def _override_command(rest):
    if not rest:
        print(f"allow location override: {'on' if _override_on() else 'off'}")
        return
    if len(rest) != 1:
        raise LocationError("usage: lc override on | lc override off", 2)
    on = _on_off(rest[0])
    _set_override(on)
    print(f"allow location override: {'on' if on else 'off'}")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "location"/"lc"
# ======================================================================
def _dispatch(args, options):
    word = args[0].lower()
    rest = args[1:]
    if word in ("on", "enable") and not rest:
        _services(True, options["override"])
    elif word in ("off", "disable") and not rest:
        _services(False)
    elif word == "why" and not rest:
        report = _report()
        if options["json"]:
            print(json.dumps(report, indent=2))
        else:
            print(_core.BLUE + _why_text(report) + _core.RESET)
    elif word == "access":
        _access_command(rest)
    elif word in ("apps", "app"):
        _apps_command(rest, options)
    elif word == "recent" and not rest:
        _recent_command()
    elif word == "override":
        _override_command(rest)
    else:
        raise LocationError(f"unknown location command: {args[0]}\nusage: {USAGE}", 2)


def run(args):
    """Run one location command; returns an exit code."""
    options = {"json": "--json" in args, "override": "--override-management" in args}
    args = [arg for arg in args if arg not in FLAGS]
    if not args:
        if options["json"]:
            print(json.dumps(_report(), indent=2))
        else:
            print(_overview())
        return 0
    if args[0].lower() in HELP_WORDS:
        print(f"usage: {USAGE}")
        return 0
    try:
        _dispatch(args, options)
        return 0
    except LocationError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

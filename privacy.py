"""
privacy: which apps may use the camera, microphone, location and more, and what is using them right now.
Routed from app.py ("privacy", "priv", "perm" or "permissions").

    priv                               every permission: who may use it, and what is using it right now
    priv now                           what is using the camera, microphone, location or screen capture now
    priv recent [days] [all]           sensitive permissions that apps used lately (7 days by default)
    priv sensitive                     camera, microphone, location, screen capture: who can use each
    priv <permission>                  one permission: its switches, and every app that has asked, numbered
    priv <permission> on|off           the switch for all your apps ("Let apps access your camera")
    priv <permission> <id> on|off      one app
    priv <permission> desktop on|off   "Let desktop apps access your camera"
    priv <permission> device on|off    the switch for every user of this PC (administrator)
    priv why <permission> [<id>]       why apps (or one app) cannot use it, and the command that fixes it
    priv app <text> [off]              everything one app can access; off blocks it everywhere
    priv general [<setting> [on|off]]  advertising ID, tailored experiences, diagnostic data, activity history ...
    priv open [<permission>|<page>]    open that page in Settings

This is Settings > Privacy & security > App permissions, plus the General and Diagnostics pages. Windows keeps
one switch chain per permission in the registry (the ConsentStore): an organisation policy, the switch for the
PC (HKLM), your switch for all apps, the switch for desktop programs, and one switch per app. The first switch
that says no wins. Store apps are listed by package name; desktop programs by the file they run. Windows records
when each app last started and stopped using a permission; a stop time of zero means it is using it right now.

Switches are per user and need no administrator rights, except "device". Location has its own page (lc) with more
settings: this page only reads it. Where a policy owns a switch, nothing here changes it. The few settings that
only a policy can change (diagnostic data, activity history) say so before they ask.
"""

import ntpath
import os
import re
import sys
import winreg
from datetime import datetime, timedelta

import _core
import _net
import _win

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "privacy"
ALIASES = ["priv", "perm", "permissions"]
SUMMARY = "App permissions: camera, microphone, location and more"
USAGE = ("priv | priv now | priv recent [days] | "
         "priv <permission> [on|off | <id> [on|off] | desktop|device [on|off]] | priv why <permission> [<id>] | "
         "priv app <text> [off] | priv sensitive | priv general [<setting> [on|off]] | priv open [<page>]")
HELP = [
    ("priv", "every permission: who may use it, and what is using it right now"),
    ("priv now", "what is using your camera, microphone, location or screen this second"),
    ("priv camera", "one permission: its switches, and every app that has asked, numbered"),
    ("priv camera off", "block every app from the camera (priv camera on lets them back)"),
    ("priv camera <id> off", "block one app (ids come from 'priv camera')"),
    ("priv recent", "sensitive permissions that apps used in the last 7 days"),
    ("", "more"),
    ("priv why camera [<id>]", "why apps (or one app) cannot use it, and the command that fixes it"),
    ("priv app <text>", "everything one app can access; 'priv app zoom off' blocks it everywhere"),
    ("priv sensitive", "camera, microphone, location, screen capture: who can use each"),
    ("priv camera desktop on|off", "'Let desktop apps access your camera'"),
    ("priv camera device on|off", "the switch for every user of this PC (administrator)"),
    ("priv general", "advertising ID, tailored experiences, diagnostic data, activity history"),
    ("priv general ads off", "turn one of them off (priv general shows the words)"),
    ("priv open camera", "open that page in Settings"),
]
TIP = ("Run 'priv' to see the permission names (camera, microphone, location, screenshots, contacts ...). Switches "
       "are per user and need no administrator rights; only 'device' does. Location has its own page: lc.")
RUN_ALONE = True  # typing 'priv' on its own shows every permission, which changes nothing

# ======================================================================
# CONSTANTS
# ======================================================================
CONSENT_ROOT = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
NONPACKAGED = "NonPackaged"  # desktop programs: one subkey each, with the path in its name (\ written as #)
POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"  # LetAppsAccess<Name> and its per-app lists
MDM_ENROLLMENTS = r"SOFTWARE\Microsoft\Enrollments"  # one subkey per device-management enrollment
# Built into every Windows install (policy precedence sources), so they do not mean an organisation manages the PC
WINDOWS_AUTHORITIES = ("Local Authority", "Cloud Authority", "Deploy Authority")
FILETIME_EPOCH = 116444736000000000  # 100-nanosecond ticks from 1601 to 1970
RECENT_DAYS = 7
MAX_DAYS = 365
ON_WORDS = ("on", "enable", "allow", "yes")
OFF_WORDS = ("off", "disable", "block", "deny", "no")
STATE_WORDS = {"allow": "allowed", "deny": "blocked", "prompt": "asks each time"}
LEVEL_TITLES = {"policy": "organisation policy", "device": "this PC (all users)", "user": "you (all apps)",
                "desktop": "desktop programs", "app": "the app itself"}

# (registry key, title, word to type, other words, Settings page, policy name, kind, what an app can do with it)
# kind: "watch" = it can see, hear or locate you; "personal" = it reads your data; "" = anything else.
# Anything in the permission store that is not listed here is still shown, under its raw key name.
KNOWN = [
    ("webcam", "Camera", "camera", ("cam", "webcam"), "privacy-webcam", "LetAppsAccessCamera", "watch",
     "take photos and record video with the camera"),
    ("microphone", "Microphone", "microphone", ("mic",), "privacy-microphone", "LetAppsAccessMicrophone", "watch",
     "record sound with the microphone"),
    ("location", "Location", "location", ("loc",), "privacy-location", "LetAppsAccessLocation", "watch",
     "find out where this PC is"),
    ("graphicsCaptureProgrammatic", "Screenshots", "screenshots", ("screen", "screenshot", "capture"),
     "privacy-graphicscaptureprogrammatic", "LetAppsAccessGraphicsCaptureProgrammatic", "watch",
     "take screenshots and record what is on your screen"),
    ("graphicsCaptureWithoutBorder", "Screenshot borders", "borders", ("screenshotborders",),
     "privacy-graphicscapturewithoutborder", "LetAppsAccessGraphicsCaptureWithoutBorder", "",
     "record the screen without the yellow border around it"),
    ("userAccountInformation", "Account info", "account", ("accountinfo",), "privacy-accountinfo",
     "LetAppsAccessAccountInfo", "personal", "see your name, picture and account details"),
    ("contacts", "Contacts", "contacts", (), "privacy-contacts", "LetAppsAccessContacts", "personal",
     "read your contacts"),
    ("appointments", "Calendar", "calendar", (), "privacy-calendar", "LetAppsAccessCalendar", "personal",
     "read your calendar"),
    ("phoneCall", "Phone calls", "phone", ("calls", "phonecalls"), "privacy-phonecalls", "LetAppsAccessPhone",
     "personal", "make phone calls from this PC"),
    ("phoneCallHistory", "Call history", "callhistory", (), "privacy-callhistory", "LetAppsAccessCallHistory",
     "personal", "read your call history"),
    ("email", "Email", "email", (), "privacy-email", "LetAppsAccessEmail", "personal", "read your email"),
    ("userDataTasks", "Tasks", "tasks", (), "privacy-tasks", "LetAppsAccessTasks", "personal", "read your tasks"),
    ("chat", "Messaging", "messaging", ("messages", "sms"), "privacy-messaging", "LetAppsAccessMessaging",
     "personal", "read and send text messages"),
    ("userNotificationListener", "Notifications", "notifications", (), "privacy-notifications",
     "LetAppsAccessNotifications", "personal", "read your notifications"),
    ("radios", "Radios", "radios", ("radio",), "privacy-radios", "LetAppsAccessRadios", "",
     "turn Bluetooth and other radios on and off"),
    ("appDiagnostics", "App diagnostics", "appdiagnostics", ("appdiag",), "privacy-appdiagnostics",
     "LetAppsGetDiagnosticInfo", "", "see what other apps are doing on this PC"),
    ("documentsLibrary", "Documents", "documents", ("docs",), "privacy-documents", None, "personal",
     "read your Documents folder"),
    ("downloadsFolder", "Downloads folder", "downloads", (), "privacy-downloadsfolder", None, "personal",
     "read your Downloads folder"),
    ("musicLibrary", "Music library", "music", (), "privacy-musiclibrary", None, "", "read your Music folder"),
    ("picturesLibrary", "Pictures", "pictures", ("photos",), "privacy-pictures", None, "personal",
     "read your Pictures folder"),
    ("videosLibrary", "Videos", "videos", (), "privacy-videos", None, "", "read your Videos folder"),
    ("broadFileSystemAccess", "File system", "files", ("filesystem",), "privacy-broadfilesystemaccess", None,
     "personal", "read every file you can open"),
    ("gazeInput", "Eye tracker", "eyetracker", ("gaze",), "privacy-eyetracker", "LetAppsAccessGazeInput", "watch",
     "see where you are looking"),
    ("humanPresence", "Presence sensing", "presence", (), "privacy-presence", "LetAppsAccessHumanPresence", "",
     "know whether you are sitting at the PC"),
]
KNOWN_BY_KEY = {item[0].lower(): (index, item) for index, item in enumerate(KNOWN)}
# Words people try that mean two things, so the error can say which one they probably want
AMBIGUOUS = {
    "diagnostics": "'priv appdiagnostics' (apps reading what other apps do) or 'priv general diagnostics' "
                   "(the diagnostic data Windows sends to Microsoft)",
    "activity": "'priv general activity' (activity history)",
    "ads": "'priv general ads' (the advertising ID)",
}
# Settings pages that are not one permission
OTHER_PAGES = {
    "general": "privacy-general", "diagnostics": "privacy-feedback", "activity": "privacy-activityhistory",
    "speech": "privacy-speech", "inking": "privacy-speechtyping", "voice": "privacy-voiceactivation",
    "background": "privacy-backgroundapps", "downloads-automatic": "privacy-automaticfiledownloads",
    "devices": "privacy-customdevices", "motion": "privacy-motion",
}

# The general privacy settings (priv general). "toggle" ones are a per-user value that Settings itself writes;
# "diagnostics" and "activity" can only be changed through a Windows policy (documented in the ADMX files and the
# Policy CSP), which Settings shows as managed. "private" is the choice that shares least.
HKCU, HKLM = _win.HKCU, _win.HKLM
GENERAL = [
    {"word": "ads", "title": "Advertising ID", "kind": "toggle", "private": "off",
     "what": "gives apps an ID that follows you from app to app, so they can show personalised ads",
     "hive": HKCU, "path": r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "value": "Enabled",
     "on": 1, "off": 0,
     "lock": (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1),
     "applies": None},
    {"word": "tailored", "title": "Tailored experiences", "kind": "toggle", "private": "off",
     "what": "lets Microsoft use your diagnostic data to suggest tips, ads and recommendations to you",
     "hive": HKCU, "path": r"Software\Microsoft\Windows\CurrentVersion\Privacy",
     "value": "TailoredExperiencesWithDiagnosticDataEnabled", "on": 1, "off": 0,
     "lock": (HKCU, r"Software\Policies\Microsoft\Windows\CloudContent",
              "DisableTailoredExperiencesWithDiagnosticData", 1),
     "applies": "the next time you sign in"},
    {"word": "language", "title": "Language list for websites", "kind": "toggle", "private": "off",
     "what": "lets websites see your language list to show you local content",
     "hive": HKCU, "path": r"Control Panel\International\User Profile", "value": "HttpAcceptLanguageOptOut",
     "on": 0, "off": 1, "lock": None, "applies": "the next time you sign in"},
    {"word": "launches", "title": "App launch tracking", "kind": "toggle", "private": "off",
     "what": "lets Windows count which apps you open, to rank Start and search results",
     "hive": HKCU, "path": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "value": "Start_TrackProgs",
     "on": 1, "off": 0, "lock": None, "applies": None},
    {"word": "diagnostics", "title": "Diagnostic data", "kind": "diagnostics", "private": "required",
     "what": "how much Windows sends to Microsoft about how it and your apps are working"},
    {"word": "activity", "title": "Activity history", "kind": "activity", "private": "off",
     "what": "lets Windows keep a list of what you did on this PC, and send it to Microsoft"},
]
DIAG_POLICY = (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection")  # set by Group Policy
DIAG_MDM = (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")  # set by device management
DIAG_WORDS = {0: "off (Enterprise editions only)", 1: "required only", 2: "enhanced", 3: "optional (full)"}
ACTIVITY_POLICY = (HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System")
ACTIVITY_VALUES = ("EnableActivityFeed", "PublishUserActivities", "UploadUserActivities")


class PrivacyError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# READING — the permission store: switches, apps, and when each app last used a permission
# ======================================================================
def _state(value):
    """A stored switch as allow, deny or prompt; None when the value is not there."""
    return None if value is None else str(value).lower()


def _when(ticks):
    """A Windows FILETIME as local time, or None if it is not set."""
    if not ticks:
        return None
    try:
        return datetime.fromtimestamp((ticks - FILETIME_EPOCH) / 10**7)
    except (OverflowError, OSError, ValueError):
        return None


def _ticks(values, name):
    item = values.get(name)
    return item[0] if item and isinstance(item[0], int) else 0


def _policy_list(values, name):
    """An app list from a policy value (a multi-string, or text split by ; or ,), as lower-case package names."""
    item = values.get(name.lower())
    raw = item[0] if item else None
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = re.split(r"[;,\n]", raw)
    return [text.strip().lower() for text in raw if text and text.strip()]


def _read_policy(stem, values):
    """What an organisation policy says about a permission: {"value": 0/1/2/None, "allow": [], "deny": [], "user": []}.
    0 leaves the person in control, 1 forces apps allowed, 2 forces them blocked; the lists name apps (package
    family names) that are the exception."""
    empty = {"value": None, "allow": [], "deny": [], "user": []}
    if not stem:
        return empty
    item = values.get(stem.lower())
    value = item[0] if item and isinstance(item[0], int) else None
    return {"value": value, "allow": _policy_list(values, stem + "_ForceAllowTheseApps"),
            "deny": _policy_list(values, stem + "_ForceDenyTheseApps"),
            "user": _policy_list(values, stem + "_UserInControlOfTheseApps")}


def _policy_effect(policy, family):
    """What policy says about one Store app: allow, deny, user (the person decides) or None (policy is silent).
    An app named in a list beats the permission-wide value; force-deny beats force-allow beats user-in-control."""
    if family in policy["deny"]:
        return "deny"
    if family in policy["allow"]:
        return "allow"
    if family in policy["user"]:
        return "user"
    return {1: "allow", 2: "deny", 0: "user"}.get(policy["value"])


def _managed(cap):
    policy = cap["policy"]
    return policy["value"] in (1, 2) or bool(policy["allow"] or policy["deny"] or policy["user"])


def _managed_reasons():
    """Why an organisation might manage this PC, as plain reasons. Empty means nothing points at one."""
    reasons = []
    domain = os.environ.get("USERDNSDOMAIN")
    if domain:
        reasons.append(f"this PC is joined to the domain {domain}")
    for enrollment in _win.reg_subkeys(HKLM, MDM_ENROLLMENTS):
        provider = _net.reg_read(f"{MDM_ENROLLMENTS}\\{enrollment}", "ProviderID", None, HKLM)
        if provider and provider not in WINDOWS_AUTHORITIES:
            reasons.append(f"this PC is enrolled in device management ({provider})")
    return reasons


def _running_programs():
    """The lower-case paths of the programs running now, or None when psutil is missing or cannot say."""
    try:
        import psutil
        return {(process.info.get("exe") or "").lower() for process in psutil.process_iter(["exe"])} - {""}
    except Exception:  # a missing package or a process that vanished: "cannot say" is the honest answer
        return None


def _make_app(kind, key, path, name, where):
    values = _win.reg_values(HKCU, path)
    started, stopped = _ticks(values, "LastUsedTimeStart"), _ticks(values, "LastUsedTimeStop")
    item = values.get("Value")
    return {"kind": kind, "key": key, "path": path, "name": name, "where": where,
            "family": where.lower(),  # the package family name (Store) or the file path (desktop), for matching
            "value": _state(item[0]) if item else None,
            "started": _when(started), "stopped": _when(stopped),
            "reported_in_use": bool(started) and not stopped, "stale": False, "in_use": False}


def _read_apps(cap):
    """Every app that has asked for this permission, sorted by name and numbered from 1. The list and the numbers
    both come from here, so the ids in 'priv camera' match 'priv camera 3'."""
    found = []
    for key in _win.reg_subkeys(HKCU, cap["path"]):
        if key.lower() == NONPACKAGED.lower():
            continue
        # Microsoft.WindowsCamera_8wekyb3d8bbwe -> Microsoft.WindowsCamera, the same name 'lc apps' shows
        found.append(_make_app("store", key, f"{cap['path']}\\{key}", key.split("_")[0], key))
    desktop = f"{cap['path']}\\{NONPACKAGED}"
    for key in _win.reg_subkeys(HKCU, desktop):
        if key.lower() == "executables":  # prompt history, not an app
            continue
        exe = key.replace("#", "\\")  # C:#Windows#netsh.exe -> C:\Windows\netsh.exe
        found.append(_make_app("desktop", key, f"{desktop}\\{key}", ntpath.basename(exe) or exe, exe))
    found.sort(key=lambda app: (app["name"].lower(), app["where"].lower()))
    for number, app in enumerate(found, start=1):
        app["id"] = number
    return found


def _read_capability(key, known, policy):
    if known:
        _, (_, title, word, others, page, stem, kind, what) = known
    else:
        title, word, others, page, stem, kind, what = key, key.lower(), (), None, None, "", None
    path = f"{CONSENT_ROOT}\\{key}"
    cap = {
        "key": key, "title": title, "word": word, "page": page, "kind": kind, "what": what, "path": path,
        "policy_name": stem, "known": bool(known),
        "words": {word, key.lower(), title.lower().replace(" ", ""), *others},
        "user": _state(_net.reg_read(path, "Value", None, HKCU)),
        "device": _state(_net.reg_read(path, "Value", None, HKLM)),
        "desktop": _state(_net.reg_read(f"{path}\\{NONPACKAGED}", "Value", None, HKCU)),
        "policy": _read_policy(stem, policy),
    }
    cap["apps"] = _read_apps(cap)
    return cap


def _capabilities():
    """Every permission this PC has, numbered from 1 in a fixed order: the well-known ones first, then any others by
    name. The list and the numbers both come from here."""
    names = {}
    for hive in (HKCU, HKLM):
        for key in _win.reg_subkeys(hive, CONSENT_ROOT):
            names.setdefault(key.lower(), key)
    if not names:
        return []
    order = sorted(names, key=lambda low: (KNOWN_BY_KEY[low][0] if low in KNOWN_BY_KEY else len(KNOWN), low))
    policy = {name.lower(): item for name, item in _win.reg_values(HKLM, POLICY_KEY).items()}
    caps = [_read_capability(names[low], KNOWN_BY_KEY.get(low), policy) for low in order]
    for number, cap in enumerate(caps, start=1):
        cap["id"] = number
    _mark_in_use(caps)
    return caps


def _mark_in_use(caps):
    """An app Windows has not seen stop is in use now. A desktop program that is not running anymore is stale: it
    stopped without Windows noticing (a crash), so it is not counted."""
    pending = [app for cap in caps for app in cap["apps"] if app["reported_in_use"]]
    running = _running_programs() if any(app["kind"] == "desktop" for app in pending) else None
    for app in pending:
        app["stale"] = app["kind"] == "desktop" and running is not None and app["where"].lower() not in running
        app["in_use"] = not app["stale"]


def _installed(app):
    """Whether a desktop program's file is still there. None for Store apps and for paths that are not on a drive
    of this PC (a network path can take a long time to answer)."""
    if app["kind"] != "desktop" or not re.match(r"^[A-Za-z]:\\", app["where"]):
        return None
    return os.path.exists(app["where"])


def _last_used(app):
    """When an app last used the permission: now (in use), the time it stopped, or None for never."""
    if app["in_use"]:
        return datetime.now()
    return app["stopped"] or app["started"]


# ======================================================================
# THE SWITCH CHAIN — policy, this PC, you, desktop programs, the app. The first one that says no wins.
# ======================================================================
def _row(level, state, blocks=False, fix=None, ignored=False):
    return {"level": level, "title": LEVEL_TITLES[level], "state": state, "blocks": blocks and not ignored,
            "fix": fix, "ignored": ignored}


def _switch_state(value):
    return STATE_WORDS.get(value, "not set (allowed)")


def _chain(cap, app=None):
    """The switches between an app (or any app, when none is given) and the permission, top to bottom."""
    word = cap["word"]
    if app is None:
        effect = {1: "allow", 2: "deny"}.get(cap["policy"]["value"])
    elif app["kind"] == "store":
        effect = _policy_effect(cap["policy"], app["family"])
    else:
        effect = None  # policy does not reach desktop programs
    allowed_by_policy = effect == "allow"
    rows = []
    if effect == "deny":
        rows.append(_row("policy", "blocked by your organisation", True, "only your administrator can change it"))
    elif effect == "allow":
        rows.append(_row("policy", "allowed by your organisation (the switches below are ignored)"))
    else:
        rows.append(_row("policy", "not set: you decide" if not _managed(cap) else "does not cover this: you decide"))
    rows.append(_row("device", _switch_state(cap["device"]), cap["device"] == "deny",
                     f"priv {word} device on  (administrator)", allowed_by_policy))
    rows.append(_row("user", _switch_state(cap["user"]), cap["user"] == "deny", f"priv {word} on", allowed_by_policy))
    if app is None or app["kind"] == "desktop":
        rows.append(_row("desktop", _switch_state(cap["desktop"]), cap["desktop"] == "deny",
                         f"priv {word} desktop on", allowed_by_policy))
    if app is not None:
        own = app["value"]
        text = STATE_WORDS.get(own, "not set (follows all apps)")
        rows.append(_row("app", text, own == "deny", f"priv {word} {app['id']} on", allowed_by_policy))
    return rows


def _access(cap, app):
    """Whether one app can use the permission now, and what stops it: {"allowed", "blocked_by", "label"}."""
    rows = _chain(cap, app)
    blocker = next((row for row in rows if row["blocks"]), None)
    if blocker:
        label = {"policy": "blocked by your organisation", "device": "blocked (off for this PC)",
                 "user": "blocked (all apps are off)", "desktop": "blocked (desktop apps are off)",
                 "app": "blocked"}[blocker["level"]]
        return {"allowed": False, "blocked_by": blocker["level"], "label": label}
    if rows[0]["state"].startswith("allowed by"):
        return {"allowed": True, "blocked_by": None, "label": "allowed by your organisation"}
    own = app["value"]
    if own == "prompt":
        return {"allowed": True, "blocked_by": None, "label": "asks each time"}
    if own == "allow":
        return {"allowed": True, "blocked_by": None, "label": "allowed"}
    return {"allowed": True, "blocked_by": None, "label": "follows all apps (on)"}


def _top_block(cap, desktop=False):
    """The first switch above the apps that blocks them all, or None. desktop adds the desktop-programs switch."""
    for row in _chain(cap):
        if row["level"] == "desktop" and not desktop:
            continue
        if row["blocks"]:
            return row
    return None


def _summary(cap, days=RECENT_DAYS):
    cutoff = datetime.now() - timedelta(days=days)
    apps = cap["apps"]
    return {
        "can_use": sum(1 for app in apps if _access(cap, app)["allowed"]),
        "total": len(apps),
        "recent": [app for app in apps if _last_used(app) and _last_used(app) >= cutoff],
        "in_use": [app for app in apps if app["in_use"]],
    }


# ======================================================================
# FINDING — a permission or an app by number or name
# ======================================================================
def _words_text(caps):
    return ", ".join(cap["word"] for cap in caps)


def _find_cap(word, caps):
    if not caps:
        raise PrivacyError("Windows has no permission store for this account "
                           f"(nothing under HKCU\\{CONSENT_ROOT}).")
    if word.isdigit():
        for cap in caps:
            if cap["id"] == int(word):
                return cap
        raise PrivacyError(f"no permission numbered {word}. Run 'priv' to see them.", 2)
    for cap in caps:
        if word in cap["words"]:
            return cap
    hint = f" Did you mean {AMBIGUOUS[word]}?" if word in AMBIGUOUS else ""
    raise PrivacyError(f"no permission called {word}.{hint} The names are: {_words_text(caps)}.", 2)


def _find_app(cap, word):
    apps = cap["apps"]
    if word.isdigit():
        for app in apps:
            if app["id"] == int(word):
                return app
        raise PrivacyError(f"no app with id {word} for {cap['title'].lower()}. "
                           f"Run 'priv {cap['word']}' to see them.", 2)
    lowered = word.lower()
    matches = [app for app in apps if lowered in (app["name"].lower(), app["where"].lower())]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise PrivacyError(f"no app called {word} for {cap['title'].lower()}. "
                           f"Run 'priv {cap['word']}' to see them, or use its id.", 2)
    raise PrivacyError(f"{len(matches)} apps are called {word} (ids " +
                       ", ".join(str(app["id"]) for app in matches) + "). Use the id.", 2)


def _on_off(word):
    """True for on, False for off, None for anything else."""
    word = word.lower()
    if word in ON_WORDS:
        return True
    if word in OFF_WORDS:
        return False
    return None


# ======================================================================
# OUTPUT
# ======================================================================
def _fmt(when):
    return when.strftime("%Y-%m-%d %H:%M") if when else "never"


def _since(when):
    if when is None:
        return "?"
    return when.strftime("%H:%M") if when.date() == datetime.now().date() else when.strftime("%Y-%m-%d %H:%M")


def _iso(when):
    return when.isoformat(timespec="seconds") if when else None


def _app_kind(app):
    return "Store app" if app["kind"] == "store" else "desktop program"


def _color_for(access, in_use=False):
    if in_use:
        return _net.YELLOW
    return _net.GREEN if access["allowed"] else _net.GREY


def _switch_word(cap, level):
    """A switch for the overview table: allowed, blocked, asks, or '-' when Windows has no such switch."""
    if level == "user":
        value = cap["user"]
        if cap["policy"]["value"] in (1, 2):
            return "allowed*" if cap["policy"]["value"] == 1 else "blocked*"
        return STATE_WORDS.get(value, "allowed").replace("asks each time", "asks")
    return STATE_WORDS.get(cap["device"], "-").replace("asks each time", "asks")


def _cap_json(cap, days=RECENT_DAYS):
    summary = _summary(cap, days)
    block = _top_block(cap)
    return {
        "id": cap["id"], "name": cap["word"], "key": cap["key"], "title": cap["title"],
        "kind": {"watch": "watch", "personal": "personal"}.get(cap["kind"], "other"),
        "you": cap["user"], "this_pc": cap["device"], "desktop_programs": cap["desktop"],
        "managed_by_policy": _managed(cap),
        "policy": {"setting": cap["policy_name"], "value": cap["policy"]["value"],
                   "force_allow": cap["policy"]["allow"], "force_deny": cap["policy"]["deny"],
                   "user_in_control": cap["policy"]["user"]},
        "blocked_by": block["level"] if block else None,
        "apps": summary["total"], "apps_can_use": summary["can_use"],
        "apps_used_recently": len(summary["recent"]), "recent_days": days,
        "in_use_now": [app["name"] for app in summary["in_use"]],
        "settings_page": f"ms-settings:{cap['page']}" if cap["page"] else None,
    }


def _app_json(cap, app):
    access = _access(cap, app)
    return {
        "id": app["id"], "name": app["name"], "kind": app["kind"], "where": app["where"],
        "own_switch": app["value"], "can_use": access["allowed"], "access": access["label"],
        "blocked_by": access["blocked_by"], "last_used": _iso(_last_used(app)),
        "in_use_now": app["in_use"], "stale": app["stale"], "installed": _installed(app),
    }


# ======================================================================
# OVERVIEW, NOW, RECENT, SENSITIVE — who may use what, and who is using it
# ======================================================================
def _watching_text(caps):
    """The sentence about the four permissions that can see, hear or locate you, and what is using them."""
    watch = [cap for cap in caps if cap["kind"] == "watch"]
    using = [(cap, app) for cap in watch for app in cap["apps"] if app["in_use"]]
    if not using:
        names = ", ".join(cap["title"].lower() for cap in watch) or "camera or microphone"
        return _net.GREEN + f"right now: nothing is using your {names}." + _net.RESET
    parts = [f"the {cap['title'].lower()} is in use by {app['name']} (since {_since(app['started'])})"
             for cap, app in using]
    return _net.YELLOW + "right now: " + "; ".join(parts) + "." + _net.RESET


def _overview(options):
    caps = _capabilities()
    if not caps:
        raise PrivacyError("Windows has no permission store for this account "
                           f"(nothing under HKCU\\{CONSENT_ROOT}).")
    summaries = {cap["id"]: _summary(cap) for cap in caps}
    if options["json"]:
        using = [{"permission": cap["word"], "app": app["name"], "kind": app["kind"], "since": _iso(app["started"])}
                 for cap in caps for app in cap["apps"] if app["in_use"]]
        _core.print_json({"permissions": [_cap_json(cap) for cap in caps], "in_use_now": using,
                          "managed_by_organisation": _managed_reasons(), "administrator": _core.is_admin()})
        return 0
    lines = ["privacy: who may use what on this PC, and what is using it right now", "",
             _watching_text(caps), ""]
    managed = [cap for cap in caps if _managed(cap)]
    if managed:
        lines.append(_net.YELLOW + "set by a policy (marked *): " + ", ".join(cap["title"] for cap in managed)
                     + ". 'priv why <permission>' says what that means." + _net.RESET)
        lines.append("")
    lines.append(f"{'NO.':<5}{'PERMISSION':<22}{'YOU':<10}{'THIS PC':<10}{'CAN USE':<10}"
                 f"{'USED IN 7 DAYS':<16}RIGHT NOW")
    for cap in caps:
        summary = summaries[cap["id"]]
        now = ", ".join(app["name"] for app in summary["in_use"][:2])
        if len(summary["in_use"]) > 2:
            now += f" +{len(summary['in_use']) - 2}"
        top = _top_block(cap, desktop=False)
        color = _net.YELLOW if summary["in_use"] else (_net.GREY if top else _net.GREEN)
        recent = f"{len(summary['recent'])} app(s)" if summary["recent"] else "-"
        lines.append(color + f"{cap['id']:<5}{cap['title'][:20]:<22}{_switch_word(cap, 'user'):<10}"
                     f"{_switch_word(cap, 'device'):<10}{str(summary['can_use']) + ' of ' + str(summary['total']):<10}"
                     f"{recent:<16}{now or 'nobody'}" + _net.RESET)
    lines += ["", "Type the name to see one: priv camera. The first switch that says no wins: a policy, then this PC,",
              "then you (all apps), then desktop programs, then the app itself.",
              "next: priv now | priv recent | priv camera | priv why camera | priv app <text> | priv general | "
              "priv help"]
    print("\n".join(lines))
    return 0


def _now_cmd(options):
    caps = _capabilities()
    rows = [(cap, app) for cap in caps for app in cap["apps"] if app["in_use"]]
    stale = [(cap, app) for cap in caps for app in cap["apps"] if app["stale"]]
    if options["json"]:
        _core.print_json({
            "checked": _iso(datetime.now()), "nothing_in_use": not rows,
            "in_use": [{"permission": cap["word"], "title": cap["title"], "app": app["name"], "kind": app["kind"],
                        "where": app["where"], "since": _iso(app["started"])} for cap, app in rows],
            "stale": [{"permission": cap["word"], "app": app["name"], "where": app["where"],
                       "started": _iso(app["started"])} for cap, app in stale],
        })
        return
    watch_titles = ", ".join(cap["title"].lower() for cap in caps if cap["kind"] == "watch")
    if not rows:
        print(_net.GREEN + f"nothing is using your {watch_titles or 'camera or microphone'} right now." + _net.RESET)
    else:
        print(f"{'PERMISSION':<22}{'APP':<34}{'KIND':<17}SINCE")
        for cap, app in rows:
            print(_net.YELLOW + f"{cap['title'][:20]:<22}{app['name'][:32]:<34}{_app_kind(app):<17}"
                  f"{_since(app['started'])}" + _net.RESET)
    for cap, app in stale:
        print(_net.GREY + f"not counted: {app['name']} is marked as using the {cap['title'].lower()}, but the program "
              "is not running (it stopped without Windows noticing)." + _net.RESET)
    print("\nWindows records the moment each app starts and stops using a permission; an app that has started "
          "and not stopped is in use. 'priv recent' shows what was used earlier.")


def _recent_cmd(words, options):
    days, everything = RECENT_DAYS, False
    for word in words:
        lowered = word.lower()
        if lowered == "all":
            everything = True
        elif lowered.rstrip("d").isdigit() and (lowered.endswith("d") or lowered.isdigit()):
            days = int(lowered.rstrip("d"))
        else:
            raise PrivacyError("usage: priv recent [days] [all]   (days 1 to 365; all includes every permission)", 2)
    if not 1 <= days <= MAX_DAYS:
        raise PrivacyError(f"days must be from 1 to {MAX_DAYS}", 2)
    cutoff = datetime.now() - timedelta(days=days)
    uses = []
    for cap in _capabilities():
        if not everything and cap["kind"] not in ("watch", "personal"):
            continue
        for app in cap["apps"]:
            last = _last_used(app)
            if last and last >= cutoff:
                uses.append((last, cap, app))
    uses.sort(key=lambda item: item[0], reverse=True)
    if options["json"]:
        _core.print_json({"days": days, "all_permissions": everything, "uses": [{
            "permission": cap["word"], "title": cap["title"], "app": app["name"], "kind": app["kind"],
            "where": app["where"], "last_used": _iso(None if app["in_use"] else last), "in_use_now": app["in_use"],
            "can_use_now": _access(cap, app)["allowed"], "access": _access(cap, app)["label"]}
            for last, cap, app in uses]})
        return
    if not uses:
        print(f"no app used a {'permission' if everything else 'sensitive permission'} in the last {days} day(s).")
        return
    print(f"permissions apps used in the last {days} day(s), newest first")
    print(f"\n{'WHEN':<18}{'PERMISSION':<22}{'APP':<34}ACCESS NOW")
    for last, cap, app in uses:
        access = _access(cap, app)
        when = "in use now" if app["in_use"] else _fmt(last)
        print(_color_for(access, app["in_use"]) + f"{when:<18}{cap['title'][:20]:<22}{app['name'][:32]:<34}"
              f"{access['label']}" + _net.RESET)
    print(f"\n{len(uses)} use(s). Windows keeps only the latest use of each permission by each app, "
          "not a full history.")


def _names_text(apps, limit=10):
    names = [app["name"] for app in apps]
    if not names:
        return "none"
    return ", ".join(names[:limit]) + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _sensitive_cmd(options):
    caps = [cap for cap in _capabilities() if cap["kind"] == "watch"]
    if options["json"]:
        _core.print_json({"permissions": [{
            **_cap_json(cap),
            "apps_allowed": [_app_json(cap, app) for app in cap["apps"] if _access(cap, app)["allowed"]]}
            for cap in caps]})
        return
    sections = []
    for cap in caps:
        summary = _summary(cap)
        allowed = [app for app in cap["apps"] if _access(cap, app)["allowed"]]
        block = _top_block(cap)
        sections.append((cap["title"], [
            ("switches", f"you: {_switch_word(cap, 'user')}   this PC: {_switch_word(cap, 'device')}   "
                         f"desktop programs: {STATE_WORDS.get(cap['desktop'], 'allowed')}"),
            ("blocked for all apps", f"yes, by {LEVEL_TITLES[block['level']]}" if block else "no"),
            ("apps that can use it", f"{len(allowed)} of {summary['total']}: {_names_text(allowed)}"),
            ("in use now", _names_text(summary["in_use"]) if summary["in_use"] else "nobody"),
            ("used in 7 days", _names_text(summary["recent"])),
            ("change it with", f"priv {cap['word']} off  |  priv {cap['word']} <id> off"),
        ]))
    if not sections:
        raise PrivacyError("Windows has no camera, microphone, location or screenshot permissions to show.")
    _net.render("who can see, hear or locate you", sections)


# ======================================================================
# ONE PERMISSION, AND ONE APP
# ======================================================================
def _show_location(cap, options):
    """Location is read here and changed on its own page, which also owns the location services policy."""
    summary = _summary(cap)
    if options["json"]:
        _core.print_json({**_cap_json(cap), "page": "lc"})
        return
    block = _top_block(cap)
    _net.render("Location (priv location)", [
        ("switches", [("you (all apps)", _switch_word(cap, "user")),
                      ("this PC (all users)", _switch_word(cap, "device")),
                      ("blocked for all apps", f"yes, by {LEVEL_TITLES[block['level']]}" if block else "no")]),
        ("apps", [("can use it", f"{summary['can_use']} of {summary['total']}"),
                  ("in use now", _names_text(summary["in_use"]) if summary["in_use"] else "nobody"),
                  ("used in 7 days", _names_text(summary["recent"]))]),
        ("everything else about location", [
            ("lc", "location services, the switch for all apps, per-app switches, recent use, the override"),
            ("lc why", "why location is off or blocked, and what would fix it")]),
    ])


def _right_now(summary):
    if not summary["in_use"]:
        return "nobody"
    return "; ".join(f"{app['name']} since {_since(app['started'])}" for app in summary["in_use"])


def _show_cap(cap, options):
    if cap["word"] == "location":
        return _show_location(cap, options)
    summary = _summary(cap)
    if options["json"]:
        _core.print_json({**_cap_json(cap), "switches": [{k: v for k, v in row.items() if k != "title"}
                                                         for row in _chain(cap)],
                          "app_list": [_app_json(cap, app) for app in cap["apps"]]})
        return
    word = cap["word"]
    changes = {"policy": "", "device": f"   (priv {word} device on|off, administrator)",
               "user": f"   (priv {word} on|off)", "desktop": f"   (priv {word} desktop on|off)"}
    chain = _chain(cap)
    _net.render(f"{cap['title']} (priv {word})", [
        ("what it lets an app do", [("an app can", cap["what"] or "use this permission"),
                                    ("Settings page", f"ms-settings:{cap['page']}  (priv open {word})"
                                     if cap["page"] else "-")]),
        ("switches (the first one that says no wins)",
         [(row["title"], row["state"] + changes.get(row["level"], "")) for row in chain]),
        ("right now", [("in use by", _right_now(summary))]),
    ])
    print()
    if not cap["apps"]:
        print(f"(no app has asked for the {cap['title'].lower()} yet)")
        return
    print(f"{'ID':<5}{'APP':<34}{'KIND':<17}{'ACCESS':<34}LAST USED")
    for app in cap["apps"]:
        access = _access(cap, app)
        used = "in use now" if app["in_use"] else _fmt(app["stopped"] or app["started"])
        missing = " (file not found)" if _installed(app) is False else ""
        print(_color_for(access, app["in_use"]) + f"{app['id']:<5}{(app['name'] + missing)[:32]:<34}"
              f"{_app_kind(app):<17}{access['label']:<34}{used}" + _net.RESET)
    print(f"\n{summary['can_use']} of {summary['total']} apps can use the {cap['title'].lower()}. "
          f"'priv {word} <id>' shows one; ids follow this list, so list again after apps come and go.")


def _show_app(cap, app, options):
    access = _access(cap, app)
    if options["json"]:
        _core.print_json({**_app_json(cap, app), "permission": cap["word"], "switches": [
            {k: v for k, v in row.items() if k != "title"} for row in _chain(cap, app)]})
        return
    word = cap["word"]
    installed = _installed(app)
    use_text = "now, since " + _since(app["started"]) if app["in_use"] else _fmt(app["stopped"] or app["started"])
    if app["stale"]:
        use_text = "marked as in use, but the program is not running"
    _net.render(f"{app['name']} and the {cap['title'].lower()}", [
        ("app", [("kind", _app_kind(app)),
                 ("where", app["where"] + (" (file not found)" if installed is False else ""))]),
        ("access", [("its own switch", STATE_WORDS.get(app["value"], "not set: follows all apps")),
                    ("can use it now", ("yes" if access["allowed"] else "no") + f"  ({access['label']})"),
                    ("last used", use_text)]),
        ("change it with", [(f"priv {word} {app['id']} off", "block this app"),
                            (f"priv {word} {app['id']} on", "allow this app"),
                            (f"priv why {word} {app['id']}", "why it can or cannot use it")]),
    ])


# ======================================================================
# WHY — the first switch in the chain that blocks, and what fixes it
# ======================================================================
def _fix_text(row, cap, app):
    level = row["level"]
    if level == "policy":
        reasons = _managed_reasons()
        return ("A policy set by your organisation decides this, so only your administrator can change it"
                + (f" ({'; '.join(reasons)})." if reasons else
                   " (a local policy: Local Group Policy Editor > Administrative Templates > Windows Components > "
                   "App Privacy, or the registry under " + POLICY_KEY + ")."))
    word = cap["word"]
    if level == "device":
        return f"The switch for this PC is off. Run 'priv {word} device on' in an administrator terminal."
    if level == "user":
        return f"Apps are blocked for you. Run 'priv {word} on' to let them use it again."
    if level == "desktop":
        return f"Desktop programs are blocked. Run 'priv {word} desktop on'."
    return f"{app['name']} is blocked on its own. Run 'priv {word} {app['id']} on'."


def _why_cmd(words, options):
    if not words or len(words) > 2:
        raise PrivacyError("usage: priv why <permission> [<id>]", 2)
    caps = _capabilities()
    cap = _find_cap(words[0].lower(), caps)
    app = _find_app(cap, words[1]) if len(words) == 2 else None
    rows = _chain(cap, app)
    blocker = next((row for row in rows if row["blocks"]), None)
    steps = [_fix_text(blocker, cap, app)] if blocker else []
    if app is None and not blocker:
        blocked_apps = [a for a in cap["apps"] if not _access(cap, a)["allowed"]]
        if blocked_apps:
            steps.append(f"{len(blocked_apps)} app(s) are blocked on their own: {_names_text(blocked_apps)}. "
                         f"'priv {cap['word']}' lists them.")
    if cap["word"] == "location":
        steps.append("For location services and the full diagnosis run 'lc why'.")
    if options["json"]:
        _core.print_json({
            "permission": cap["word"], "app": app["name"] if app else None,
            "can_use": not blocker, "blocked_by": blocker["level"] if blocker else None,
            "checks": [{"level": row["level"], "state": row["state"], "blocks": row["blocks"],
                        "ignored_because_of_policy": row["ignored"], "fix": row["fix"]} for row in rows],
            "managed_by_organisation": _managed_reasons() if _managed(cap) else [],
            "next_steps": steps,
        })
        return
    subject = f"{app['name']} and the {cap['title'].lower()}" if app else f"apps and the {cap['title'].lower()}"
    _net.render(f"why: {subject}", [
        ("switches, top to bottom (the first no wins)",
         [(row["title"], row["state"] + ("   <- this one blocks" if row["blocks"] else "")) for row in rows]),
    ])
    print()
    if blocker:
        print("what to do:")
        for step in steps:
            print(f"  - {step}")
    else:
        print(_net.GREEN + (f"{app['name']} can use the {cap['title'].lower()}." if app
                            else f"nothing blocks apps from the {cap['title'].lower()} at the top; each app's own "
                                 "switch decides.") + _net.RESET)
        for step in steps:
            print(f"  - {step}")


# ======================================================================
# CHANGES — each one refuses where a policy owns the switch, asks where it widens access, and reads back
# ======================================================================
def _no_location_changes(cap):
    if cap["word"] == "location":
        raise PrivacyError("location has its own page, which also owns the location services policy: "
                           "'lc access on|off' for all apps, 'lc apps <id> on|off' for one app, 'lc' for the rest.", 2)


def _check_unlocked(cap, app=None):
    """Refuse to change a switch that a policy owns: the change would be ignored or set back, and getting around an
    organisation's policy is not this page's job."""
    if app is None:
        owned = cap["policy"]["value"] in (1, 2)
    else:
        owned = app["kind"] == "store" and _policy_effect(cap["policy"], app["family"]) in ("allow", "deny")
    if not owned:
        return
    reasons = _managed_reasons()
    raise PrivacyError(f"the {cap['title'].lower()} is set by a policy"
                       + (f" ({'; '.join(reasons)})" if reasons else "")
                       + ", so this switch does not do anything. 'priv why "
                       + cap["word"] + (f" {app['id']}" if app else "") + "' says what it means; only your "
                       "administrator can change a policy.")


def _write_switch(hive, path, on):
    _win.reg_write(hive, path, "Value", "Allow" if on else "Deny", winreg.REG_SZ)


def _read_switch(hive, path):
    return _state(_net.reg_read(path, "Value", None, hive))


def _set_user(cap, on, options):
    _no_location_changes(cap)
    _check_unlocked(cap)
    word, title = cap["word"], cap["title"].lower()
    if (cap["user"] != "deny") == on:
        print(f"the {title} is already {'on' if on else 'off'} for all your apps.")
        return
    if on:
        free = sum(1 for app in cap["apps"] if app["value"] != "deny")
        if not _core.confirm(f"Let apps use the {title}? The {free} app(s) that are not blocked on their own can "
                             f"{cap['what'] or 'use it'} again. To undo: 'priv {word} off'. [y/N]: ", options["yes"]):
            print("cancelled")
            return
    _write_switch(HKCU, cap["path"], on)
    now = _read_switch(HKCU, cap["path"])
    if (now != "deny") != on:
        raise PrivacyError(f"Windows did not keep the change: the {title} switch is still {STATE_WORDS.get(now, now)}.")
    if on:
        print(f"{cap['title']}: on for all your apps. Each app's own choice still applies ('priv {word}' lists them).")
    else:
        print(f"{cap['title']}: off. Every app is blocked from the {title} until you run 'priv {word} on'; "
              "each app's own choice is kept.")
    cap["user"] = now
    block = _top_block(cap)
    if on and block:
        print(f"note: apps are still blocked by {LEVEL_TITLES[block['level']]}. {_fix_text(block, cap, None)}")


def _set_desktop(cap, on, options):
    _no_location_changes(cap)
    word, title = cap["word"], cap["title"].lower()
    if (cap["desktop"] != "deny") == on:
        print(f"desktop programs are already {'allowed' if on else 'blocked'} for the {title}.")
        return
    path = f"{cap['path']}\\{NONPACKAGED}"
    if on and not _core.confirm(f"Let desktop programs use the {title}? Programs you installed the usual way "
                                f"(not from the Store) can {cap['what'] or 'use it'}. "
                                f"To undo: 'priv {word} desktop off'. [y/N]: ", options["yes"]):
        print("cancelled")
        return
    _write_switch(HKCU, path, on)
    now = _read_switch(HKCU, path)
    if (now != "deny") != on:
        raise PrivacyError(f"Windows did not keep the change: the desktop switch is still {STATE_WORDS.get(now, now)}.")
    print(f"{cap['title']}: desktop programs are now {'allowed' if on else 'blocked'}.")
    if on and cap["user"] == "deny":
        print(f"note: apps are blocked for you right now. Run 'priv {word} on' to let them use it.")


def _set_device(cap, on, options):
    _no_location_changes(cap)
    _check_unlocked(cap)
    word, title = cap["word"], cap["title"].lower()
    if (cap["device"] != "deny") == on:
        print(f"the {title} is already {'on' if on else 'off'} for this PC.")
        return
    _net.need_admin()
    question = (f"Turn the {title} {'on' if on else 'off'} for EVERY user of this PC? " +
                (f"Apps can then {cap['what'] or 'use it'}, if your own switches allow it. " if on else
                 "No app of any user can use it until it is turned back on. ") +
                f"To undo: 'priv {word} device {'off' if on else 'on'}'. [y/N]: ")
    if not _core.confirm(question, options["yes"]):
        print("cancelled")
        return
    _write_switch(HKLM, cap["path"], on)
    now = _read_switch(HKLM, cap["path"])
    if (now != "deny") != on:
        raise PrivacyError(f"Windows did not keep the change: the PC switch is still {STATE_WORDS.get(now, now)}.")
    print(f"{cap['title']}: {'on' if on else 'off'} for this PC.")


def _set_app(cap, app, on, options):
    _no_location_changes(cap)
    _check_unlocked(cap, app)
    word, title = cap["word"], cap["title"].lower()
    if (app["value"] == "allow") == on and app["value"] in ("allow", "deny"):
        print(f"{app['name']} is already {'allowed' if on else 'blocked'}.")
        return
    if on and cap["kind"] in ("watch", "personal") and not _core.confirm(
            f"Let {app['name']} use the {title}? It will be able to {cap['what'] or 'use it'}. "
            f"To undo: 'priv {word} {app['id']} off'. [y/N]: ", options["yes"]):
        print("cancelled")
        return
    _write_switch(HKCU, app["path"], on)
    now = _read_switch(HKCU, app["path"])
    if now != ("allow" if on else "deny"):
        raise PrivacyError(f"Windows did not keep the change: {app['name']} is still {STATE_WORDS.get(now, now)}.")
    print(f"{app['name']}: {'allowed' if on else 'blocked'} for the {title}.")
    app["value"] = now
    access = _access(cap, app)
    if on and not access["allowed"]:
        print(f"note: it still cannot use it: {access['label']}. 'priv why {word} {app['id']}' says what to change.")


# ======================================================================
# ONE APP, ACROSS EVERY PERMISSION — priv app <text> [off]
# ======================================================================
def _app_cmd(words, options):
    off = bool(words) and words[-1].lower() == "off"
    words = words[:-1] if off else words
    text = " ".join(words).strip().lower()
    if not text:
        raise PrivacyError("usage: priv app <text> [off]   (part of the app's name, e.g. priv app zoom)", 2)
    groups = {}
    for cap in _capabilities():
        for app in cap["apps"]:
            if text in f"{app['name']} {app['where']}".lower():
                groups.setdefault((app["kind"], app["family"]), []).append((cap, app))
    ordered = sorted(groups.values(),
                     key=lambda entries: (entries[0][1]["name"].lower(), entries[0][1]["where"].lower()))
    if off:
        return _app_off(text, ordered, options)
    if options["json"]:
        _core.print_json({"query": text, "apps": [{
            "name": entries[0][1]["name"], "kind": entries[0][1]["kind"], "where": entries[0][1]["where"],
            "permissions": [{"permission": cap["word"], "title": cap["title"], "can_use": _access(cap, app)["allowed"],
                             "access": _access(cap, app)["label"], "own_switch": app["value"],
                             "last_used": _iso(_last_used(app)), "in_use_now": app["in_use"]}
                            for cap, app in entries]} for entries in ordered]})
        return
    if not ordered:
        print(f"no app matching '{text}' has asked for any permission.")
        return
    for entries in ordered:
        app = entries[0][1]
        print(_net.CYAN + f"{app['name']}  ({_app_kind(app)}: {app['where']})" + _net.RESET)
        print(f"  {'PERMISSION':<22}{'ACCESS':<34}LAST USED")
        for cap, entry in entries:
            access = _access(cap, entry)
            used = "in use now" if entry["in_use"] else _fmt(entry["stopped"] or entry["started"])
            print(_color_for(access, entry["in_use"]) + f"  {cap['title'][:20]:<22}{access['label']:<34}{used}"
                  + _net.RESET)
        print()
    print(f"{len(ordered)} app(s). 'priv app <text> off' blocks one app from everything it can use.")


def _app_off(text, ordered, options):
    if not ordered:
        raise PrivacyError(f"no app matching '{text}' has asked for any permission.", 2)
    if len(ordered) > 1:
        raise PrivacyError(f"'{text}' matches {len(ordered)} apps (" +
                           ", ".join(entries[0][1]["name"] for entries in ordered[:6]) +
                           "). Use more of the name, so only one app is blocked.", 2)
    entries = ordered[0]
    app = entries[0][1]
    todo, locked = [], []
    for cap, entry in entries:
        if entry["kind"] == "store" and _policy_effect(cap["policy"], entry["family"]) in ("allow", "deny"):
            locked.append(cap)
        elif entry["value"] != "deny":
            todo.append((cap, entry))
    if not todo:
        print(f"{app['name']} is already blocked from every permission it can change"
              + (f" ({len(locked)} are set by a policy)." if locked else "."))
        return
    titles = ", ".join(cap["title"].lower() for cap, _ in todo)
    if not _core.confirm(f"Block {app['name']} from {len(todo)} permission(s): {titles}? It keeps working, but it "
                         f"cannot use them. To undo one: 'priv <permission> <id> on'. [y/N]: ", options["yes"]):
        print("cancelled")
        return
    done = 0
    for cap, entry in todo:
        _write_switch(HKCU, entry["path"], False)
        if _read_switch(HKCU, entry["path"]) == "deny":
            done += 1
    print(f"{app['name']}: blocked from {done} of {len(todo)} permission(s).")
    if done != len(todo):
        raise PrivacyError("Windows did not keep every change. Run 'priv app " + text + "' to see what it is now.")
    if locked:
        print("not changed, because a policy owns them: " + ", ".join(cap["title"].lower() for cap in locked))


# ======================================================================
# GENERAL — the settings on Privacy & security > General, Diagnostics and Activity history
# ======================================================================
def _general_find(word):
    for item in GENERAL:
        if item["word"] == word.lower():
            return item
    words = ", ".join(item["word"] for item in GENERAL)
    raise PrivacyError(f"no general setting called {word}. The words are: {words}.", 2)


def _policy_number(hive, path, name):
    value = _net.reg_read(path, name, None, hive)
    return value if isinstance(value, int) else None


def _diag_read():
    """(level, who set it): the diagnostic data level from a policy, or (None, None) when no policy sets it."""
    for (hive, path), who in ((DIAG_MDM, "device management"), (DIAG_POLICY, "a policy")):
        level = _policy_number(hive, path, "AllowTelemetry")
        if level is not None:
            return level, who
    return None, None


def _activity_read():
    return {name: _policy_number(ACTIVITY_POLICY[0], ACTIVITY_POLICY[1], name) for name in ACTIVITY_VALUES}


def _general_state(item):
    """One general setting as {"word", "title", "state", "set_by", "locked", "private", "what", "change"}.
    state is on or off for a toggle, the level for diagnostic data, off or default for activity history; default
    means nothing is set, so Windows (Settings) decides."""
    word = item["word"]
    out = {"word": word, "title": item["title"], "what": item["what"], "private": item["private"],
           "state": "default", "set_by": "default", "locked": False, "applies": item.get("applies")}
    if item["kind"] == "toggle":
        raw = _net.reg_read(item["path"], item["value"], None, item["hive"])
        if raw is not None:
            out["state"] = "on" if raw == item["on"] else "off"
            out["set_by"] = "your choice"
        if item["lock"]:
            hive, path, name, forced = item["lock"]
            if _policy_number(hive, path, name) == forced:
                out.update(state="off", set_by="a policy", locked=True)  # both policies force the private choice
        out["change"] = f"priv general {word} on|off"
    elif item["kind"] == "diagnostics":
        level, who = _diag_read()
        if level is not None:
            out.update(state=DIAG_WORDS.get(level, f"level {level}"), set_by=who, locked=who == "device management")
        out["change"] = "priv general diagnostics required|default  (administrator)"
    else:
        values = _activity_read()
        if any(value is not None for value in values.values()):
            off = values["EnableActivityFeed"] == 0
            out.update(state="off" if off else "partly set", set_by="a policy")
        out["change"] = "priv general activity off|default  (administrator)"
    return out


def _general_cmd(words, options):
    if not words:
        return _general_list(options)
    item = _general_find(words[0])
    if len(words) == 1:
        return _general_show(item, options)
    if len(words) != 2:
        raise PrivacyError("usage: priv general <setting> on|off   (diagnostics: required|default, "
                           "activity: off|default)", 2)
    choice = words[1].lower()
    if item["kind"] == "toggle":
        on = _on_off(choice)
        if on is None:
            raise PrivacyError(f"use on or off, e.g. priv general {item['word']} off", 2)
        return _general_toggle(item, on, options)
    if item["kind"] == "diagnostics":
        if choice not in ("required", "default"):
            raise PrivacyError("use required (send only required diagnostic data) or default (put Windows' own "
                               "setting back): priv general diagnostics required", 2)
        return _diag_set(choice, options)
    if choice not in ("off", "default"):
        raise PrivacyError("use off (turn activity history off) or default (put Windows' own setting back): "
                           "priv general activity off", 2)
    return _activity_set(choice, options)


def _general_list(options):
    rows = [_general_state(item) for item in GENERAL]
    if options["json"]:
        _core.print_json({"settings": rows})
        return
    print(f"{'WORD':<13}{'SETTING':<30}{'NOW':<26}{'SET BY':<18}MORE PRIVATE")
    for row in rows:
        color = _net.GREEN if row["state"] == "on" else _net.GREY if row["state"] == "off" else ""
        if row["locked"]:
            color = _net.YELLOW
        print(color + f"{row['word']:<13}{row['title']:<30}{row['state']:<26}{row['set_by']:<18}{row['private']}"
              + (_net.RESET if color else ""))
    print("\nWhat they do:")
    for row in rows:
        print(f"  {row['word']:<13}{row['what']}")
    print("\nchange one: priv general ads off   |   priv general diagnostics required   |   priv general activity off")
    print("'default' means nothing is set, so Settings decides. More pages in Settings: priv open general|diagnostics|"
          "activity|speech|inking|voice")


def _general_show(item, options):
    row = _general_state(item)
    if options["json"]:
        _core.print_json(row)
        return
    _net.render(row["title"], [
        ("what it is", [("it", row["what"]), ("more private choice", row["private"])]),
        ("now", [("state", row["state"]), ("set by", row["set_by"]),
                 ("changed by", "a policy, so only an administrator can change it here" if row["locked"] else
                  row["change"])]),
    ])


def _managed_note(item):
    return ("Settings may now say some settings are managed by your organisation. Windows applies policy at its "
            "next refresh, or run 'gpupdate /force' to apply it now. Group Policy or device management can "
            "set it back.")


def _general_toggle(item, on, options):
    row = _general_state(item)
    if row["locked"]:
        raise PrivacyError(f"{item['title']} is set by a policy, so this switch does not do anything. Only your "
                           "administrator can change it.")
    if row["state"] == ("on" if on else "off") and row["set_by"] == "your choice":
        print(f"{item['title']} is already {'on' if on else 'off'}.")
        return
    if on and not _core.confirm(f"Turn {item['title']} on? It {item['what']}. "
                                f"To undo: 'priv general {item['word']} off'. [y/N]: ", options["yes"]):
        print("cancelled")
        return
    _win.reg_write(item["hive"], item["path"], item["value"], item["on"] if on else item["off"], winreg.REG_DWORD)
    now = _general_state(item)
    if now["state"] != ("on" if on else "off"):
        raise PrivacyError(f"Windows did not keep the change: {item['title']} is still {now['state']}.")
    print(f"{item['title']}: {now['state']}." + (f" It applies {item['applies']}." if item.get("applies") else ""))


def _diag_set(choice, options):
    level, who = _diag_read()
    if who == "device management":
        raise PrivacyError("diagnostic data is set by device management on this PC, so this page does not change it. "
                           "Only your administrator can.")
    wanted = 1 if choice == "required" else None
    if level == wanted:
        print("diagnostic data is already " + ("required only (set by a policy)." if wanted else "up to Settings."))
        return
    _net.need_admin()
    hive, path = DIAG_POLICY
    if choice == "required":
        question = ("Send only required diagnostic data? This sets a Windows policy (AllowTelemetry = 1), so Settings "
                    "shows the choice as managed and you cannot change it there until you run "
                    "'priv general diagnostics default'. " + _managed_note(None) + " [y/N]: ")
    else:
        question = ("Put Windows' own diagnostic data setting back? This removes the AllowTelemetry policy value on "
                    "this PC, so Settings decides again. Group Policy can set it again at its next refresh. [y/N]: ")
    if not _core.confirm(question, options["yes"]):
        print("cancelled")
        return
    if choice == "required":
        _win.reg_write(hive, path, "AllowTelemetry", 1, winreg.REG_DWORD)
    else:
        _win.reg_delete(hive, path, "AllowTelemetry")
    now = _general_state(_general_find("diagnostics"))
    print(f"Diagnostic data: {now['state']}" + (f" (set by {now['set_by']})." if now["set_by"] != "default" else
                                                  ". Settings decides."))
    if choice == "required":
        print(_managed_note(None))


def _activity_set(choice, options):
    values = _activity_read()
    if choice == "off" and values["EnableActivityFeed"] == 0 and values["PublishUserActivities"] == 0 \
            and values["UploadUserActivities"] == 0:
        print("activity history is already off (set by a policy).")
        return
    if choice == "default" and all(value is None for value in values.values()):
        print("activity history is already up to Settings: no policy is set.")
        return
    _net.need_admin()
    hive, path = ACTIVITY_POLICY
    if choice == "off":
        question = ("Turn activity history off? This sets three Windows policies (EnableActivityFeed, "
                    "PublishUserActivities, UploadUserActivities = 0), so Windows stops recording and sending what "
                    "you do. To undo: 'priv general activity default'. " + _managed_note(None) + " [y/N]: ")
    else:
        question = ("Put Windows' own activity history setting back? This removes the three activity history "
                    "policy values on this PC, so Settings decides again. Group Policy can set them again at its "
                    "next refresh. [y/N]: ")
    if not _core.confirm(question, options["yes"]):
        print("cancelled")
        return
    for name in ACTIVITY_VALUES:
        if choice == "off":
            _win.reg_write(hive, path, name, 0, winreg.REG_DWORD)
        else:
            _win.reg_delete(hive, path, name)
    now = _general_state(_general_find("activity"))
    print(f"Activity history: {now['state']}" + (f" (set by {now['set_by']})." if now["set_by"] != "default" else
                                                   ". Settings decides."))
    if choice == "off":
        print(_managed_note(None))


# ======================================================================
# OPEN — the same pages as Settings
# ======================================================================
def _open_cmd(words, options):
    if len(words) > 1:
        raise PrivacyError("usage: priv open [<permission>|general|diagnostics|activity|speech|inking|voice|"
                           "background]", 2)
    if not words:
        page, label = "privacy", "Privacy & security"
    else:
        word = words[0].lower()
        if word in OTHER_PAGES:
            page, label = OTHER_PAGES[word], word
        else:
            cap = _find_cap(word, _capabilities())
            if not cap["page"]:
                raise PrivacyError(f"Windows has no Settings page this page knows for {cap['title']}. "
                                   "'priv open' opens Privacy & security.", 2)
            page, label = cap["page"], cap["title"]
    print(f"opening Settings > Privacy & security > {label}...")
    _win.open_settings(f"ms-settings:{page}")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "privacy"/"priv"
# ======================================================================
def _permission_cmd(word, rest, options):
    cap = _find_cap(word, _capabilities())
    if not rest:
        return _show_cap(cap, options)
    selector = rest[0].lower()
    on = _on_off(selector)
    if on is not None:
        if len(rest) != 1:
            raise PrivacyError(f"usage: priv {cap['word']} on|off", 2)
        return _set_user(cap, on, options)
    if selector in ("desktop", "device"):
        if len(rest) == 1:
            return _show_switch(cap, selector, options)
        wanted = _on_off(rest[1]) if len(rest) == 2 else None
        if wanted is None:
            raise PrivacyError(f"usage: priv {cap['word']} {selector} on|off", 2)
        return (_set_desktop if selector == "desktop" else _set_device)(cap, wanted, options)
    if selector == "why":
        return _why_cmd([cap["word"], *rest[1:]], options)
    app = _find_app(cap, rest[0])
    if len(rest) == 1:
        return _show_app(cap, app, options)
    wanted = _on_off(rest[1]) if len(rest) == 2 else None
    if wanted is None:
        raise PrivacyError(f"usage: priv {cap['word']} <id> on|off", 2)
    return _set_app(cap, app, wanted, options)


def _show_switch(cap, which, options):
    value = cap[which]
    if options["json"]:
        _core.print_json({"permission": cap["word"], "switch": which, "state": value})
        return
    where = "every user of this PC" if which == "device" else "desktop programs"
    print(f"{cap['title']} for {where}: {STATE_WORDS.get(value, 'not set (allowed)')}   "
          f"(priv {cap['word']} {which} on|off)")


def run(args):
    """Run one privacy command; returns an exit code."""
    os.system("")  # enables ANSI colour codes in the Windows console
    args, options = _core.split_flags(args)
    try:
        if not args:
            return _overview(options)
        word, rest = args[0].lower(), args[1:]
        if word in _core.HELP_WORDS:
            print(f"usage: {USAGE}")
        elif word == "now" and not rest:
            _now_cmd(options)
        elif word == "recent":
            _recent_cmd(rest, options)
        elif word == "sensitive" and not rest:
            _sensitive_cmd(options)
        elif word == "why":
            _why_cmd(rest, options)
        elif word == "app":
            _app_cmd(rest, options)
        elif word == "general":
            _general_cmd(rest, options)
        elif word == "open":
            _open_cmd(rest, options)
        else:
            _permission_cmd(word, rest, options)
        return 0
    except (PrivacyError, _net.NetError) as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

"""
volume: system and per-app volume for Windows 11. Routed from app.py
("volume" or "vm").

    vm ls          list every audio source with its id (0 is the system)
    vm <id>        show the volume of one source
    vm <id> N      set one source to N percent (0-100)
    vm <name> N    the same by name: vm system 30, vm Chrome 50

Id 0 is the system (master) volume. Every other id is an app that is
playing or can play audio, such as Discord or Chrome. An app with several
audio sessions is one id, and changing it changes all of its sessions.
Ids are numbered by name, so they stay the same until apps start or stop;
a name (or "system") always means the same source, so scripts should use names.

Add --dry-run to see the change without making it, and --json --yes for a script.
The old level is saved first and 'rb last' puts it back; 'cs' can batch these
changes (operation: set). Windows keeps volume in steps, so the read-back may
differ from the request by 1 percent and still counts as applied.

Needs pycaw (see requirements.txt).
"""

import sys
import types

import psutil
from pycaw.pycaw import AudioUtilities

import _core
import _ops

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "volume"
ALIASES = ["vm", "vol"]
SUMMARY = "Alter system and per-app volume"
# extra words people use, for 'settings search'
KEYWORDS = ["sound", "audio", "mute", "loud", "quiet", "mixer", "app volume", "speakers"]
USAGE = "type vm ls, or 'volume list'. Change volume by typing 'volume <id> <0-100>' (id 0 = system; vm 3 50 = source 3 to 50%)"
HELP = [
    ("vm ls", "list every audio source with its id (0 is the system)"),
    ("vm <id>", "show the volume of one source"),
    ("vm <id|name> <0-100>", "set one source to that percent (vm system 30, vm Chrome 50)"),
]
TIP = "Example: vm Chrome 50 sets Chrome to 50%. Ids follow the list and shift as apps start; a name does not."
DRY_RUN = True  # the change takes --dry-run, and is saved to the journal for 'rb'
TOLERANCE = 1  # percent: Windows stores volume in steps, so a read-back can differ a little

SYSTEM_ID = 0
SYSTEM_NAME = "System"
SESSION_EXPIRED = 2  # AudioSessionStateExpired


class VolumeError(_core.CommandError):
    """An error with an exit code: 1 for device errors, 2 for bad usage; error is the machine-readable code."""

    def __init__(self, message, code=1, error=None):
        super().__init__(message, code, error)


# ======================================================================
# SOURCES — the system volume plus one entry per app with audio sessions
# ======================================================================
def _app_name(session):
    """A readable name for a session: the program name, without .exe."""
    if session.ProcessId == 0:
        return "System sounds"
    try:
        exe = session.Process.name()
    except (AttributeError, psutil.Error):
        return f"pid {session.ProcessId}"
    return exe[:-4] if exe.lower().endswith(".exe") else exe


def _apps():
    """Apps with audio sessions, one entry each, sorted by name."""
    groups = {}
    for session in AudioUtilities.GetAllSessions():
        if session.State == SESSION_EXPIRED:
            continue
        name = _app_name(session)
        groups.setdefault(name.lower(), {"name": name, "sessions": []})["sessions"].append(session)
    return sorted(groups.values(), key=lambda g: g["name"].lower())


def _sources():
    """[(id, name, group)] for every source. Group is None for the system."""
    sources = [(SYSTEM_ID, SYSTEM_NAME, None)]
    for index, group in enumerate(_apps(), start=1):
        sources.append((index, group["name"], group))
    return sources


def _get_source(source_id):
    for sid, name, group in _sources():
        if sid == source_id:
            return name, group
    raise VolumeError(f"no audio source with id {source_id}. Run 'vm ls' to see them.", 2, "not_found")


def _find(word):
    """(name, group) for an id, 'system', or an app name. A name never shifts; an id can."""
    word = str(word).strip()
    if word.isdigit():
        return _get_source(int(word))
    if word.lower() == SYSTEM_NAME.lower():
        return SYSTEM_NAME, None
    for _, name, group in _sources():
        if group is not None and name.lower() == word.lower():
            return name, group
    raise VolumeError(f"no audio source called {word}. Run 'vm ls' to see them.", 2, "not_found")


# ======================================================================
# GET / SET
# ======================================================================
def _get_percent(group):
    if group is None:
        endpoint = AudioUtilities.GetSpeakers().EndpointVolume
        return round(endpoint.GetMasterVolumeLevelScalar() * 100)
    return round(group["sessions"][0].SimpleAudioVolume.GetMasterVolume() * 100)


def _set_percent(group, percent):
    level = percent / 100
    if group is None:
        endpoint = AudioUtilities.GetSpeakers().EndpointVolume
        endpoint.SetMasterVolumeLevelScalar(level, None)
        return
    for session in group["sessions"]:
        session.SimpleAudioVolume.SetMasterVolume(level, None)


def _list(options):
    sources = _sources()
    levels = [(sid, name, _get_percent(group)) for sid, name, group in sources]
    if options["json"]:
        _core.print_json([{"id": sid, "name": name, "volume": percent} for sid, name, percent in levels])
        return
    print(f"{'ID':<4}{'SOURCE':<28}VOLUME")
    for sid, name, percent in levels:
        print(f"{sid:<4}{name:<28}{percent}%")
    if len(sources) == 1:
        print("(no apps are playing audio right now)")


# ======================================================================
# CHANGE — through the shared engine (_ops): planned, the old level saved to the journal, applied, read back.
# 'vm ...' and 'cs' run the same code.
# ======================================================================
def _percent(params):
    try:
        percent = float(params.get("percent"))
    except (TypeError, ValueError):
        raise VolumeError("percent needs a number from 0 to 100", 2, "usage")
    return max(0, min(100, round(percent)))


def _plan_set(params):
    name, group = _find(params.get("source"))
    after = _percent(params)
    before = _get_percent(group)
    return {
        "target": name, "before": {"percent": before}, "after": {"percent": after}, "noop": before == after,
        "needs_admin": False, "restart": "none", "disrupts": None, "confirm": None,
        "summary": f"set {name} volume: {before}% -> {after}%",
    }


def _apply_set(plan):
    _, group = _find(plan["target"])
    _set_percent(group, plan["after"]["percent"])


def _read_set(plan):
    _, group = _find(plan["target"])
    return {"percent": _get_percent(group)}


def _restore_set(plan):
    _, group = _find(plan["target"])
    _set_percent(group, plan["before"]["percent"])


def _close(expected, actual):
    return abs(expected["percent"] - actual["percent"]) <= TOLERANCE


def _param(name, required, text):
    return {"name": name, "required": required, "help": text}


OPERATIONS = {
    "set": {
        "summary": "set the system or one app's volume to a percent",
        "params": [
            _param("source", True, "system, or an app name from 'vm ls' (an id also works, but ids shift)"),
            _param("percent", True, "0 to 100; a value outside is clamped"),
        ],
        "changes_system": True, "needs_admin": False, "restart": "none",
        "side_effects": "Takes effect at once; a loud setting can be unpleasant. The read-back may differ by 1 percent.",
        "plan": _plan_set, "apply": _apply_set, "read": _read_set, "restore": _restore_set, "same": _close,
    },
}
_SELF = types.SimpleNamespace(NAME=NAME, OPERATIONS=OPERATIONS)


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "volume"/"vm"
# ======================================================================
def _dispatch(args, options):
    if args[0].lower() in ("ls", "list"):
        if options["dry_run"]:
            raise VolumeError("vm ls changes nothing, so --dry-run does nothing", 2, "usage")
        if len(args) > 1:
            raise VolumeError("usage: vm ls", 2, "usage")
        _list(options)
        return 0

    if len(args) == 1:
        if options["dry_run"]:
            raise VolumeError("showing a volume changes nothing, so --dry-run does nothing", 2, "usage")
        name, group = _find(args[0])
        _report(options, name, _get_percent(group))
        return 0
    if len(args) != 2:
        raise VolumeError(f"usage: vm {USAGE}", 2, "usage")
    return _ops.execute([{"module": _SELF, "op": "set", "params": {"source": args[0], "percent": args[1]}}], options)


def _report(options, name, percent):
    if options["json"]:
        _core.print_json({"name": name, "volume": percent})
    else:
        print(f"{name}: {percent}%")


def run(args):
    """Run one volume command; returns an exit code."""
    args, options = _core.split_flags(args, _core.DRY_FLAGS)
    if not args or args[0].lower() in _core.HELP_WORDS:
        print(f"usage: vm {USAGE}")
        return 0
    try:
        return _dispatch(args, options)
    except _core.CommandError as e:
        return _core.report_error(e)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

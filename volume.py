"""
volume: system and per-app volume for Windows 11. Routed from app.py
("volume" or "vm").

    vm ls          list every audio source with its id (0 is the system)
    vm <id>        show the volume of one source
    vm <id> N      set one source to N percent (0-100)

Id 0 is the system (master) volume. Every other id is an app that is
playing or can play audio, such as Discord or Chrome. An app with several
audio sessions is one id, and changing it changes all of its sessions.
Ids are numbered by name, so they stay the same until apps start or stop.

Needs pycaw (see requirements.txt).
"""

import sys

import psutil
from pycaw.pycaw import AudioUtilities

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "volume"
ALIASES = ["vm", "vol"]
SUMMARY = "Alter system and per-app volume"
USAGE = "vm ls | vm <id> | vm <id> <0-100>   (id 0 = system; vm 3 50 = source 3 to 50%)"

SYSTEM_ID = 0
SYSTEM_NAME = "System"
SESSION_EXPIRED = 2  # AudioSessionStateExpired


class VolumeError(Exception):
    """An error with an exit code: 1 for device errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


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
    raise VolumeError(f"no audio source with id {source_id}. Run 'vm ls' to see them.", 2)


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


def _list():
    sources = _sources()
    print(f"{'ID':<4}{'SOURCE':<28}VOLUME")
    for sid, name, group in sources:
        print(f"{sid:<4}{name:<28}{_get_percent(group)}%")
    if len(sources) == 1:
        print("(no apps are playing audio right now)")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "volume"/"vm"
# ======================================================================
def _dispatch(args):
    if args[0].lower() in ("ls", "list"):
        if len(args) > 1:
            raise VolumeError("usage: vm ls", 2)
        _list()
        return

    try:
        source_id = int(args[0])
    except ValueError:
        raise VolumeError(f"unknown volume command: {args[0]}\nusage: vm {USAGE}", 2)

    name, group = _get_source(source_id)

    if len(args) == 1:
        print(f"{name}: {_get_percent(group)}%")
        return

    try:
        percent = float(args[1])
    except ValueError:
        raise VolumeError("volume needs a number from 0 to 100", 2)
    percent = max(0, min(100, round(percent)))
    _set_percent(group, percent)
    print(f"{name}: {percent}%")


def run(args):
    """Run one volume command; returns an exit code."""
    if not args:
        print(f"usage: vm {USAGE}")
        return 0
    if args[0].lower() in ("help", "-h", "--help", "?"):
        print(f"usage: vm {USAGE}")
        return 0
    try:
        _dispatch(args)
        return 0
    except VolumeError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

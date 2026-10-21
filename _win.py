"""
Shared Windows plumbing for pages that read and change things through PowerShell, the registry and the
Settings app: defender, privacy, display, bluetooth, sound, environment and update use it.
The name starts with an underscore, so app.py does not load it as a page.

Errors are _net.NetError (a message and an exit code), the same as _probe.py raises, so a page catches
(its own error class, _net.NetError) the way device.py and firewall.py do.

  powershell(script)         run a script, get its output; Windows' reason is raised if it fails
  powershell_json(script)    run a script, get the objects it wrote as a list of dicts
  open_settings(uri)         open a page of the Settings app (ms-settings:...)
  reg_values / reg_subkeys / reg_write / reg_delete    the registry, with "needs administrator" turned into the hint
  data_dir / load_json / save_json                    small files kept in %LOCALAPPDATA%\\w11-cli-console
  ago(when)                  "5 minutes ago", "3 days ago", "never"
"""

import base64
import json
import os
import subprocess
import winreg
from datetime import datetime
from pathlib import Path

import _net
import _probe

HKCU, HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE

# Every script is wrapped so that a failure comes back as plain text on stderr with exit code 1. (PowerShell
# writes errors as CLIXML when it is given -EncodedCommand, which is unreadable; [Console]::Error is not.)
# Windows PowerShell 5.1 is what 'powershell' starts: no ??, no ?:, no &&, no ?. in scripts.
_WRAP = """\
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
try {
%s
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""
# The objects a script writes, as a JSON array whether there were none, one or many
_JSON_TAIL = """
$w11 = @(& { %s })
if ($w11.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject $w11 -Compress -Depth 8 }
"""


def powershell(script, timeout=60, env=None):
    """Run a PowerShell script and return what it wrote, stripped. A failure raises NetError with Windows' reason
    (or the administrator hint, when the reason is a refusal). env adds variables to this process's environment
    (read in the script as $env:NAME): that is how values reach a script without being pasted into its text."""
    if env:
        env = {**os.environ, **env}
    encoded = base64.b64encode((_WRAP % script).encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        raise _net.NetError(f"PowerShell took longer than {timeout} s, so it was stopped")
    except (OSError, subprocess.SubprocessError) as e:
        raise _net.NetError(f"could not run PowerShell: {e}")
    if result.returncode != 0:
        raise _net.NetError(_net.explain(result.stderr + result.stdout))
    return result.stdout.lstrip("﻿").strip()


def powershell_json(script, timeout=60, env=None):
    """Run a script and return the objects it wrote, as a list of dicts (empty if it wrote none). Dates come back as
    local ISO text. Pick the properties you need with Select-Object (a whole CIM object serialises to hundreds of
    fields), and format enums as text inside the script with .ToString(): they come out as numbers otherwise."""
    text = powershell(_JSON_TAIL % script, timeout, env)
    try:
        data = json.loads(text) if text else []
    except ValueError:
        raise _net.NetError("Windows gave a reading this page could not understand")
    data = _probe._dates(data)
    return [data] if isinstance(data, dict) else data


def open_settings(uri):
    """Open a page of the Settings app, such as 'ms-settings:bluetooth'. Used where Windows has no API for a setting
    (fashion.txt, rule 13): the page says what to choose there."""
    try:
        os.startfile(uri)
    except OSError as e:
        raise _net.NetError(f"could not open Settings ({uri}): {e}")


# ======================================================================
# REGISTRY — reading and writing for pages that keep their settings there
# ======================================================================
def reg_values(hive, path):
    """{name: (value, kind)} for the values of a key; {} if the key is missing or cannot be opened."""
    found = {}
    try:
        with winreg.OpenKey(hive, path) as key:
            index = 0
            while True:
                try:
                    name, value, kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                found[name] = (value, kind)
                index += 1
    except OSError:
        return {}
    return found


def reg_subkeys(hive, path):
    """The names of a key's subkeys; [] if the key is missing or cannot be opened."""
    names = []
    try:
        with winreg.OpenKey(hive, path) as key:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
    except OSError:
        return []
    return names


def reg_write(hive, path, name, value, kind=winreg.REG_DWORD):
    """Write one value, creating the key if it is missing. Windows refusing a write is the administrator hint."""
    try:
        with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, kind, value)
    except PermissionError:
        raise _net.NetError(_net.ADMIN_HINT)
    except OSError as e:
        raise _net.NetError(f"Windows would not write {name}: {e}")


def reg_delete(hive, path, name):
    """Delete one value. A value that is not there is not an error. Returns whether something was deleted."""
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
        return True
    except FileNotFoundError:
        return False
    except PermissionError:
        raise _net.NetError(_net.ADMIN_HINT)
    except OSError as e:
        raise _net.NetError(f"Windows would not delete {name}: {e}")


# ======================================================================
# SMALL FILES — snapshots, backups and caches that belong to this project, never to the project folder
# ======================================================================
def data_dir():
    """%LOCALAPPDATA%\\w11-cli-console, created if it is missing."""
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "w11-cli-console"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise _net.NetError(f"could not create {root}: {e}")
    return root


def load_json(name, default=None):
    """A JSON file from data_dir(); the default if it is missing or damaged."""
    try:
        return json.loads((data_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError, _net.NetError):
        return default


def save_json(name, data):
    """Write a JSON file into data_dir() in one step, so a crash cannot leave half a file."""
    path = data_dir() / name
    temp = path.with_name(path.name + ".tmp")
    try:
        temp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        os.replace(temp, path)
    except OSError as e:
        raise _net.NetError(f"could not save {path}: {e}")
    return path


# ======================================================================
# TIME
# ======================================================================
def ago(when, now=None):
    """How long ago a datetime (or ISO text) was: '5 minutes ago', '3 days ago'. None gives 'never'."""
    if when in (None, ""):
        return "never"
    if isinstance(when, str):
        try:
            when = datetime.fromisoformat(when)
        except ValueError:
            return when
    seconds = int(((now or datetime.now()) - when).total_seconds())
    if seconds < 0:
        return "in the future"
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size:
            count = seconds // size
            return f"{count} {unit}{'' if count == 1 else 's'} ago"
    return "just now"

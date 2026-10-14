"""
apps: installed apps, the same list as Windows 11's Settings > Installed apps.
Routed from app.py ("apps").

    apps ls        list installed apps, alphabetical, with an id
    apps rm <id>   uninstall one app (asks you to confirm first)

Apps come from two places: classic desktop programs (the Uninstall registry
keys, e.g. installers from the internet) and Microsoft Store packages (e.g.
Xbox, Windows Software Development Kit). System components and updates are
hidden, as Settings hides them.

Removing an app can't be undone, so 'apps rm' always asks first.
"""

import json
import math
import os
import shutil
import subprocess
import sys
import winreg

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "apps"
ALIASES = ["app"]
SUMMARY = "List and uninstall installed apps"
USAGE = "apps ls | apps rm <id>"

UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
]
HIDDEN_RELEASE_TYPES = {"hotfix", "security update", "update rollup", "service pack", "update"}


class AppsError(Exception):
    """An error with an exit code: 1 for system errors, 2 for bad usage."""

    def __init__(self, message, code=1):
        super().__init__(message)
        self.code = code


# ======================================================================
# SOURCES — desktop programs from the registry, Store packages from PowerShell
# ======================================================================
def _value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _desktop_apps():
    apps = []
    for hive, path in UNINSTALL_KEYS:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with root:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, subkey_name) as key:
                        name = _value(key, "DisplayName")
                        command = _value(key, "QuietUninstallString") or _value(key, "UninstallString")
                        hidden = _value(key, "SystemComponent") == 1
                        parent = _value(key, "ParentKeyName")
                        release = (_value(key, "ReleaseType") or "").lower()
                except OSError:
                    continue
                if not name or not command or hidden or parent or release in HIDDEN_RELEASE_TYPES:
                    continue
                apps.append({"name": str(name), "source": "desktop", "command": str(command)})
    return apps


STORE_SCRIPT = (
    "Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } | "
    "Select-Object Name, PackageFullName, DisplayName | ConvertTo-Json -Compress"
)


def _store_apps():
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", STORE_SCRIPT],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0 or not result.stdout.strip():
        return []
    packages = json.loads(result.stdout)
    if isinstance(packages, dict):  # ConvertTo-Json gives an object for a single package
        packages = [packages]
    apps = []
    for pkg in packages:
        display = pkg.get("DisplayName") or ""
        if not display or display.startswith("ms-resource:"):
            # no readable name in the package, so use the identity without the publisher,
            # e.g. Microsoft.XboxApp -> XboxApp, 28017CharlesMilette.TranslucentTB -> TranslucentTB
            identity = pkg["Name"]
            display = identity.split(".", 1)[1] if "." in identity else identity
        apps.append({"name": display, "source": "store", "command": pkg["PackageFullName"]})
    return apps


def _entries():
    """Every app, alphabetical, with its id (starting at 1)."""
    seen = set()
    apps = []
    for app in sorted(_desktop_apps() + _store_apps(), key=lambda a: a["name"].lower()):
        key = app["name"].lower()
        if key in seen:  # the same program can be registered twice
            continue
        seen.add(key)
        apps.append(app)
    for index, app in enumerate(apps, start=1):
        app["id"] = index
    return apps


def _get_app(app_id):
    for app in _entries():
        if app["id"] == app_id:
            return app
    raise AppsError(f"no app with id {app_id}. Run 'apps ls' to see them.", 2)


# ======================================================================
# UNINSTALL
# ======================================================================
def _uninstall(app):
    if app["source"] == "store":
        script = f"Remove-AppxPackage -Package '{app['command'].replace(chr(39), chr(39) * 2)}'"
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            raise AppsError(result.stderr.strip() or f"could not remove {app['name']}")
        return
    # the program's own uninstaller, as Settings runs it
    result = subprocess.run(app["command"], shell=True)
    if result.returncode != 0:
        raise AppsError(f"the uninstaller for {app['name']} exited with code {result.returncode}")


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "apps"
# ======================================================================
MAX_NAME_WIDTH = 32
ROW_COLORS = ["\033[96m", "\033[92m", "\033[93m", "\033[95m", "\033[94m", "\033[91m"]
RESET = "\033[0m"


def _list():
    """Print apps down each column, then start the next column, so long lists fit on screen."""
    apps = _entries()
    if not apps:
        print("(no apps found)")
        return

    name_width = min(max(len(app["name"]) for app in apps), MAX_NAME_WIDTH)
    cell = f"{{id:>4}}  {{name:<{name_width}}}  {{source:<7}}"
    header = cell.format(id="ID", name="NAME", source="SOURCE")
    gap = 4
    cell_width = len(header) + gap
    terminal_width = shutil.get_terminal_size((120, 30)).columns
    columns = max(1, terminal_width // cell_width)
    rows = math.ceil(len(apps) / columns)

    os.system("")  # enables ANSI colour codes in the Windows console
    print("".join([header.ljust(cell_width)] * columns).rstrip())
    for row in range(rows):
        line = ""
        for col in range(columns):
            index = col * rows + row  # fill each column top to bottom
            if index < len(apps):
                app = apps[index]
                # each id and name gets the same colour, so a row is easy to match up
                color = ROW_COLORS[(app["id"] - 1) % len(ROW_COLORS)]
                text = cell.format(id=app["id"], name=app["name"][:name_width], source=app["source"])
                line += f"{color}{text.ljust(cell_width)}{RESET}"
        print(line)


def _remove(args):
    if len(args) != 2:
        raise AppsError("usage: apps rm <id>", 2)
    try:
        app_id = int(args[1])
    except ValueError:
        raise AppsError("apps rm needs an app id from 'apps ls'", 2)

    app = _get_app(app_id)
    try:
        answer = input(f"Uninstall {app['name']}? This can't be undone. [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        answer = ""
    if answer not in ("y", "yes"):
        print("cancelled")
        return

    print(f"uninstalling {app['name']}... expect a prompt or a window from the uninstaller.")
    _uninstall(app)
    print(f"uninstalled {app['name']}")


def _dispatch(args):
    command = args[0].lower()
    if command in ("ls", "list"):
        if len(args) > 1:
            raise AppsError("usage: apps ls", 2)
        _list()
    elif command in ("rm", "remove", "delete", "uninstall", "del"):
        _remove(args)
    else:
        raise AppsError(f"unknown apps command: {args[0]}\nusage: apps {USAGE}", 2)


def run(args):
    """Run one apps command; returns an exit code."""
    if not args:
        print(f"usage: apps {USAGE}")
        return 0
    if args[0].lower() in ("help", "-h", "--help", "?"):
        print(f"usage: apps {USAGE}")
        return 0
    try:
        _dispatch(args)
        return 0
    except AppsError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

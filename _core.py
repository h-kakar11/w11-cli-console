"""
Shared pieces of w11-cli-console: finding the setting pages and drawing their intros.

app.py and the settings page both import this. The name starts with an underscore,
so app.py does not load it as a setting.
"""

import ctypes
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKIP = {"app.py"}
HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")
AGENT_FLAGS = ("--json", "--yes")  # --json: machine-readable output; --yes: answer a confirmation in advance
BLUE = "\033[34m"
RESET = "\033[0m"

_registry = None


def load_settings():
    """Import every setting file in this folder; returns {name_or_alias: module}."""
    settings = {}
    for path in sorted(HERE.glob("*.py")):
        if path.name in SKIP or path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as e:  # one broken file should not stop the console
            print(f"warning: could not load {path.name}: {e}", file=sys.stderr)
            continue
        if not hasattr(module, "NAME") or not hasattr(module, "run"):
            continue
        for key in [module.NAME, *getattr(module, "ALIASES", [])]:
            settings[key.lower()] = module
    return settings


def registry():
    """Every setting, loaded once: {name_or_alias: module}."""
    global _registry
    if _registry is None:
        _registry = load_settings()
    return _registry


def unique_settings():
    """Each setting once, in name order (aliases point at the same module)."""
    seen = {}
    for module in registry().values():
        seen[module.NAME] = module
    return [seen[name] for name in sorted(seen)]


def page_help(module):
    """The intro for one setting: what it can do, as a blue list, from the page's HELP rows.
    A row with an empty syntax, such as ("", "known networks"), is a heading for the rows under it."""
    rows = getattr(module, "HELP", [])
    width = max([len(syntax) for syntax, _ in rows], default=0) + 3
    lines = [f"{module.NAME}: {module.SUMMARY}"]
    aliases = getattr(module, "ALIASES", [])
    if aliases:
        lines.append("also called: " + ", ".join(aliases))
    lines.append("")
    for syntax, text in rows:
        if syntax:
            lines.append(f"  {syntax:<{width}}{text}")
        else:
            lines += ["", f" {text}"]
    if not rows:
        lines.append(f"  {module.USAGE}")
    tip = getattr(module, "TIP", "")
    if tip:
        lines += ["", tip]
    return BLUE + "\n".join(lines) + RESET


# ----------------------------------------------------------------------
# For pages that people and agents both use
# ----------------------------------------------------------------------
def split_flags(args, flags=AGENT_FLAGS):
    """The words after a setting name without these flags, and which were given: (args, {"json": bool, ...})."""
    lowered = [arg.lower() for arg in args]
    given = {flag.lstrip("-"): flag in lowered for flag in flags}
    return [arg for arg in args if arg.lower() not in flags], given


def confirm(question, yes=False):
    """Ask a y/N question; anything but y or yes is no. --yes answers it in advance, which an agent
    passes only after the person has agreed to that change."""
    if yes:
        print(question + "yes (--yes)")
        return True
    try:
        return input(question).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def print_json(data):
    print(json.dumps(data, indent=2, default=str))


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False

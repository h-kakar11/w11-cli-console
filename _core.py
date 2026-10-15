"""
Shared pieces of w11-cli-console: finding the setting pages and drawing their intros.

app.py and the settings page both import this. The name starts with an underscore,
so app.py does not load it as a setting.
"""

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKIP = {"app.py"}
HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")
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
    """The intro for one setting: what it can do, as a blue list, from the page's HELP rows."""
    rows = getattr(module, "HELP", [])
    width = max([len(syntax) for syntax, _ in rows], default=0) + 3
    lines = [f"{module.NAME}: {module.SUMMARY}"]
    aliases = getattr(module, "ALIASES", [])
    if aliases:
        lines.append("also called: " + ", ".join(aliases))
    lines.append("")
    if rows:
        lines += [f"  {syntax:<{width}}{text}" for syntax, text in rows]
    else:
        lines.append(f"  {module.USAGE}")
    tip = getattr(module, "TIP", "")
    if tip:
        lines += ["", tip]
    return BLUE + "\n".join(lines) + RESET

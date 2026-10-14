import importlib.util
import os
import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKIP = {"app.py"}


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


SETTINGS = load_settings()


def unique_settings():
    """Each setting once, in name order (aliases point at the same module)."""
    seen = {}
    for module in SETTINGS.values():
        seen[module.NAME] = module
    return [seen[name] for name in sorted(seen)]


def usage():
    lines = ["usage: py app.py <setting> [args]   (no setting starts the console)", "", "settings:"]
    modules = unique_settings()
    if not modules:
        lines.append("  (none found)")
    for module in modules:
        names = ", ".join([module.NAME, *getattr(module, "ALIASES", [])])
        lines.append(f"  {names}")
        lines.append(f"      {module.USAGE}")
        if getattr(module, "SUMMARY", ""):
            lines.append(f"      {module.SUMMARY}")
    return "\n".join(lines)


def run(argv):
    """Route one command line to its setting; returns an exit code."""
    if not argv:
        print(usage())
        return 0
    if argv[0].lower() in ("help", "-h", "--help", "?", "/?", "/help"):
        print(usage())
        return 0
    module = SETTINGS.get(argv[0].lower())
    if module is None:
        print(f"error: unknown setting: {argv[0]}\n{usage()}", file=sys.stderr)
        return 2
    return module.run(argv[1:])


INTRO_FILE = HERE / "intro.txt"
BLUE = "\033[34m"
PURPLE = "\033[38;5;129m"
YELLOW = "\033[33m"
RESET = "\033[0m"
DEFAULT_INTRO = PURPLE + "w11-cli-console. Type 'help' for settings, 'exit' to quit." + RESET


def intro_text():
    """The banner from intro.txt (blue), then the tagline (purple) and help hint (yellow)."""
    try:
        banner = BLUE + INTRO_FILE.read_text(encoding="utf-8").rstrip() + RESET
    except OSError:
        banner = DEFAULT_INTRO
    tagline = PURPLE + "w11-cli-console: an intuitive alternative to the windows settings app, with even more features." + RESET
    hint = YELLOW + "for help, type /? or /help" + RESET
    return banner + "\n" + tagline + "\n" + hint


def console():
    os.system("")  # enables ANSI colour codes in the Windows console
    print(intro_text())
    while True:
        try:
            line = input("w11> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line.lower() in ("exit", "quit", "q"):
            return 0
        try:
            argv = shlex.split(line)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            continue
        run(argv)


def main():
    if sys.platform != "win32":
        print("error: w11-cli-console only runs on Windows", file=sys.stderr)
        return 1
    if len(sys.argv) == 1:
        return console()
    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())

import os
import shlex
import sys

from _core import HELP_WORDS, HERE, page_help, registry, unique_settings

INTRO_FILE = HERE / "intro.txt"
PURPLE = "\033[38;5;129m"
YELLOW = "\033[33m"
RESET = "\033[0m"
DEFAULT_INTRO = PURPLE + "w11-cli-console. Type 'settings' to see what you can change, 'exit' to quit." + RESET


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
    if not argv or argv[0].lower() in HELP_WORDS:
        print(usage())
        return 0
    module = registry().get(argv[0].lower())
    if module is None:
        print(f"error: unknown setting: {argv[0]}\n{usage()}", file=sys.stderr)
        return 2
    # a setting typed alone, or with help, shows its intro instead of running,
    # unless the page sets RUN_ALONE (settings does: typing its name is the whole command)
    if len(argv) == 1 and not getattr(module, "RUN_ALONE", False):
        print(page_help(module))
        return 0
    if len(argv) > 1 and argv[1].lower() in HELP_WORDS:
        print(page_help(module))
        return 0
    return module.run(argv[1:])


def intro_text():
    """The banner from intro.txt (blue), then the tagline (purple) and help hint (yellow)."""
    try:
        banner = "\033[34m" + INTRO_FILE.read_text(encoding="utf-8").rstrip() + RESET
    except OSError:
        banner = DEFAULT_INTRO
    tagline = PURPLE + "w11-cli-console: an intuitive alternative to the windows settings app, with even more features." + RESET
    hint = YELLOW + "type settings to see everything you can change, or /? for help" + RESET
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

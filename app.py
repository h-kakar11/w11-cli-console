import contextlib
import io
import json
import os
import re
import shlex
import sys

import _core
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


def _has_flag(argv, flag):
    return any(word.lower() == flag for word in argv)


def _json_failure(exit_code, text):
    """Under --json a failure prints one error object on stderr: ok false, the exit code, a short error code and the message."""
    last = dict(_core.LAST_ERROR)
    message = last.get("message") or text.strip().removeprefix("error:").strip() or "the command failed"
    print(json.dumps(_core.error_json(exit_code, message, last.get("code"), last.get("details")), indent=2, default=str),
          file=sys.stderr)


def _guarded(module, args, as_json):
    """Run a setting. With --json, a failure is reported as JSON on stderr instead of free text (same exit code)."""
    if not as_json:
        return module.run(args)
    _core.LAST_ERROR.clear()
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        code = module.run(args)
    text = captured.getvalue()
    if not code:
        sys.stderr.write(text)  # warnings from a command that worked
        return code
    _json_failure(code, text)
    return code


def run(argv):
    """Route one command line to its setting; returns an exit code."""
    as_json = _has_flag(argv, "--json")
    _core.LAST_ERROR.clear()  # the console runs many commands in one process: an old error must not leak into this one
    if not argv or argv[0].lower() in HELP_WORDS:
        print(usage())
        return 0
    module = registry().get(argv[0].lower())
    if module is None:
        message = f"unknown setting: {argv[0]}"
        if as_json:
            _core.LAST_ERROR.update(code="not_found")
            _json_failure(2, message)
        else:
            print(f"error: {message}\n{usage()}", file=sys.stderr)
        return 2
    # --dry-run only means something to a page that can preview. Anywhere else it must not be ignored,
    # or the change would run for real
    if _has_flag(argv[1:], "--dry-run") and not getattr(module, "DRY_RUN", False):
        message = (f"{module.NAME} cannot preview changes, so --dry-run was not run. "
                   "Pages that can: " + ", ".join(m.NAME for m in unique_settings() if getattr(m, "DRY_RUN", False)) + ".")
        if as_json:
            _core.LAST_ERROR.update(code="usage")
            _json_failure(2, message)
        else:
            print(f"error: {message}", file=sys.stderr)
        return 2
    # a setting typed alone, or with help, shows its intro instead of running,
    # unless the page sets RUN_ALONE (settings does: typing its name is the whole command)
    if len(argv) == 1 and not getattr(module, "RUN_ALONE", False):
        print(page_help(module))
        return 0
    if len(argv) > 1 and argv[1].lower() in HELP_WORDS:
        print(page_help(module))
        return 0
    return _guarded(module, argv[1:], as_json)


def intro_text():
    """The banner from intro.txt (blue), then the tagline (purple) and help hint (yellow)."""
    try:
        banner = "\033[34m" + INTRO_FILE.read_text(encoding="utf-8").rstrip() + RESET
    except OSError:
        banner = DEFAULT_INTRO
    tagline = PURPLE + "w11-cli-console: an intuitive alternative to the windows settings app, with even more features." + RESET
    hint = YELLOW + "type settings to see everything you can change, or /? for help" + RESET
    return banner + "\n" + tagline + "\n" + hint


RAW_TOKEN = re.compile(r'"([^"]*)"|(\S+)')


def split_line(line, module=None):
    """Words of a typed line. shlex treats backslashes as escapes, which breaks registry paths,
    so a page with RAW_LINE = True gets quotes honoured and backslashes kept."""
    if module is not None and getattr(module, "RAW_LINE", False):
        return [quoted if bare == "" else bare for quoted, bare in RAW_TOKEN.findall(line)]
    return shlex.split(line)


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
            first = line.split(None, 1)[0].lower()
            argv = split_line(line, registry().get(first))
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

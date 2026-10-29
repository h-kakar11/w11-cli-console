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
DRY_FLAGS = AGENT_FLAGS + ("--dry-run",)  # --dry-run: show the exact changes and stop. Only pages with DRY_RUN = True take it
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
    given = {flag.lstrip("-").replace("-", "_"): flag in lowered for flag in flags}
    return [arg for arg in args if arg.lower() not in flags], given


def take_option(args, flag):
    """Take '--flag value' or '--flag=value' out of args: (the other words, the value or None)."""
    rest, value, index = [], None, 0
    while index < len(args):
        word = args[index]
        if word.lower() == flag:
            if index + 1 >= len(args):
                raise CommandError(f"{flag} needs a value", 2, "usage")
            value, index = args[index + 1], index + 2
        elif word.lower().startswith(flag + "="):
            value, index = word[len(flag) + 1:], index + 1
        else:
            rest.append(word)
            index += 1
    return rest, value


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


# ----------------------------------------------------------------------
# Errors with a machine-readable code. Exit codes stay 0 done, 1 system error, 2 bad usage.
# The code says which kind: usage, not_found, ambiguous, needs_admin, access_denied, verify_failed, failed ...
# ----------------------------------------------------------------------
class CommandError(Exception):
    """A failed command: a message, an exit code (1 or 2) and a short error code an agent can branch on."""

    def __init__(self, message, code=1, error=None, **details):
        super().__init__(message)
        self.code = code
        self.error = error or classify(str(message), code)
        self.details = details


def classify(message, exit_code=1):
    """Guess the error code from a message, for pages that raise their own error classes."""
    text = message.lower()
    if "administrator" in text or "elevat" in text:
        return "needs_admin"
    if "access denied" in text or "access is denied" in text:
        return "access_denied"
    if "ambiguous" in text or "more than one" in text:
        return "ambiguous"
    if exit_code == 2:
        if " no " in f" {text}" and ("called" in text or "with id" in text or "numbered" in text or "exist" in text):
            return "not_found"
        return "usage"
    if "does not exist" in text or "not found" in text or "no such" in text:
        return "not_found"
    return "failed"


LAST_ERROR = {}  # the latest error report_error printed, so app.py can turn it into JSON under --json


def report_error(error):
    """Print 'error: ...' to stderr for a failed command and return its exit code.
    Works for any error with a .code; CommandError also carries a machine-readable error code."""
    exit_code = getattr(error, "code", 1)
    exit_code = exit_code if isinstance(exit_code, int) and exit_code else 1
    LAST_ERROR.clear()
    LAST_ERROR.update(
        exit_code=exit_code,
        code=getattr(error, "error", None) or classify(str(error), exit_code),
        message=str(error),
        details=getattr(error, "details", {}),
    )
    print(f"error: {error}", file=sys.stderr)
    return exit_code


def error_json(exit_code, message, code=None, details=None):
    """The object --json prints to stderr when a command fails."""
    return {
        "ok": False,
        "exit_code": exit_code,
        "error": {"code": code or classify(message, exit_code), "message": message, **(details or {})},
    }


# ----------------------------------------------------------------------
# Stable identifiers: a name, path or key first; a list position only as a convenience
# ----------------------------------------------------------------------
def resolve(items, word, noun, listing, keys=("key", "name")):
    """The one item whose id (a list position) or stable key/name matches word.

    keys are the fields tried in order, compared ignoring case. A name that matches
    more than one item is an error that lists their keys, never a guess."""
    if word.isdigit():
        for item in items:
            if item.get("id") == int(word):
                return item
        raise CommandError(f"no {noun} with id {word}. Run '{listing}' to see them.", 2, "not_found")
    for field in keys:
        found = [item for item in items if str(item.get(field, "")).lower() == word.lower()]
        if len(found) == 1:
            return found[0]
        if len(found) > 1:
            names = ", ".join(str(item.get("key", item.get("name"))) for item in found)
            raise CommandError(f"{word} is ambiguous: it matches {names}. Use the full key.", 2, "ambiguous")
    raise CommandError(f"no {noun} called {word}. Run '{listing}' to see them.", 2, "not_found")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False

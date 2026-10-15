"""
settings: every setting in one list, with how to start with each. Routed from app.py
("settings" or "menu").

    settings              list every setting, numbered, with what it does
    settings <number>     open one setting from that list
    settings <name>       open one setting by name or short form, e.g. settings vm

In the console the list ends with a prompt: type a number or a name to open a
setting. Numbers follow the list, so use names when you want to be sure.
"""

import os
import sys

import _core

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "settings"
ALIASES = ["menu"]
SUMMARY = "Every setting, what it does, and how to start with it"
USAGE = "settings | settings <number or name>"
HELP = [
    ("settings", "list every setting, numbered, with what it does"),
    ("settings <number>", "open one setting from that list"),
    ("settings <name>", "open one setting by name, e.g. settings vm"),
]
TIP = "In the console, the list ends with a prompt: type a number or a name to open a setting."
RUN_ALONE = True  # typing 'settings' on its own runs this page, instead of showing its intro

HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")


class SettingsError(Exception):
    """An error with an exit code: 2 for bad usage."""

    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


# ======================================================================
# LIST — one numbered list, used for both the table and the numbers
# ======================================================================
def _entries():
    """(number, module) for every setting, sorted by name and numbered from 1."""
    return list(enumerate(_core.unique_settings(), start=1))


def _first_command(module):
    rows = getattr(module, "HELP", [])
    return rows[0][0] if rows else module.USAGE


def _table(entries):
    lines = [
        "every setting, and how to start with it",
        "",
        f"  {'NO.':<5}{'SETTING':<13}{'SHORT':<8}{'WHAT IT DOES':<57}START WITH",
    ]
    for number, module in entries:
        short = module.ALIASES[0] if module.ALIASES else "-"
        lines.append(f"  {number:<5}{module.NAME:<13}{short:<8}{module.SUMMARY:<57}{_first_command(module)}")
    lines += ["", "open one: settings 3, or settings vm. Any command works the same way: vm ls, bn 40, su ls."]
    return _core.BLUE + "\n".join(lines) + _core.RESET


# ======================================================================
# OPEN — shows one setting's intro, by its number or its name
# ======================================================================
def _open(word, entries):
    if word.isdigit():
        module = dict(entries).get(int(word))
        if module is None:
            raise SettingsError(f"no setting numbered {word}. Type 'settings' to see the list.")
    else:
        module = _core.registry().get(word.lower())
        if module is None:
            raise SettingsError(f"no setting called {word}. Type 'settings' to see the list.")
    print(_core.page_help(module))
    return 0


def _prompt(entries):
    """In the console, ask which setting to open. Only asks when typing at a terminal."""
    if not sys.stdin.isatty():
        return 0
    try:
        choice = input("open which one? type a number or a name, or press Enter to skip: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if not choice:
        return 0
    return _open(choice, entries)


# ======================================================================
# COMMAND — app.py calls run(args) with everything after "settings"
# ======================================================================
def run(args):
    """Run one settings command; returns an exit code."""
    try:
        if args and args[0].lower() in HELP_WORDS:
            print(f"usage: {USAGE}")
            return 0
        entries = _entries()
        if not args:
            os.system("")  # enables ANSI colour codes in the Windows console
            print(_table(entries))
            return _prompt(entries)
        if len(args) > 1:
            raise SettingsError(f"usage: {USAGE}")
        return _open(args[0], entries)
    except SettingsError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

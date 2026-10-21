"""
settings: every setting in one list, with how to start with each. Routed from app.py
("settings" or "menu").

    settings              list every setting, numbered, with what it does
    settings <number>     open one setting from that list
    settings <name>       open one setting by name or short form, e.g. settings vm
    settings search <words>   find the setting and command for something, e.g. settings search night light
    settings --json       every setting as data: names, short forms, and each command with what it does

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
USAGE = "settings | settings <number or name> | settings search <words> | settings --json"
HELP = [
    ("settings", "list every setting, numbered, with what it does"),
    ("settings <number>", "open one setting from that list"),
    ("settings <name>", "open one setting by name, e.g. settings vm"),
    ("settings search <words>", "find the command for something, e.g. settings search night light"),
    ("settings --json", "every setting and command as data, for scripts and AI agents"),
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
def _find(word, entries):
    if word.isdigit():
        module = dict(entries).get(int(word))
        if module is None:
            raise SettingsError(f"no setting numbered {word}. Type 'settings' to see the list.")
    else:
        module = _core.registry().get(word.lower())
        if module is None:
            raise SettingsError(f"no setting called {word}. Type 'settings' to see the list.")
    return module


def _open(word, entries):
    print(_core.page_help(_find(word, entries)))
    return 0


# ======================================================================
# JSON — for agents: what each setting is called, what it does, and every command it takes
# ======================================================================
def _describe(number, module):
    """One setting as data. Each command carries the heading it sits under in the intro (None for the everyday ones)."""
    group, commands = None, []
    for syntax, text in getattr(module, "HELP", []):
        if syntax:
            commands.append({"command": syntax, "does": text, "group": group})
        else:
            group = text
    return {
        "number": number, "name": module.NAME, "aliases": list(getattr(module, "ALIASES", [])),
        "summary": module.SUMMARY, "usage": module.USAGE, "tip": getattr(module, "TIP", ""),
        "runs_alone": bool(getattr(module, "RUN_ALONE", False)), "commands": commands,
    }


def _json(args, entries):
    if not args:
        _core.print_json([_describe(number, module) for number, module in entries])
        return 0
    if len(args) > 1:
        raise SettingsError(f"usage: {USAGE}")
    module = _find(args[0], entries)
    number = next(number for number, item in entries if item is module)
    _core.print_json(_describe(number, module))
    return 0


# ======================================================================
# SEARCH — like the search box in the Settings app: which setting, and which command, for what I want to do
# ======================================================================
SEARCH_WORDS = ("search", "find")
# How much a word counts for, by where it was found. A page can add words people use for it with KEYWORDS = [...]
WEIGHTS = {"name": 10, "prefix": 6, "keyword": 5, "summary": 4, "command": 3, "tip": 1}


def _rows(module):
    """(syntax, description, group) for each command in the page's intro; group is None for the everyday ones."""
    group, rows = None, []
    for syntax, text in getattr(module, "HELP", []):
        if syntax:
            rows.append((syntax, text, group))
        else:
            group = text
    return rows


def _score(term, module, rows):
    """How well one word matches a setting: the best place it was found, or 0."""
    names = [module.NAME.lower(), *[alias.lower() for alias in getattr(module, "ALIASES", [])]]
    if term in names:
        return WEIGHTS["name"]
    if any(name.startswith(term) for name in names):
        return WEIGHTS["prefix"]
    if any(term in word.lower() for word in getattr(module, "KEYWORDS", [])):
        return WEIGHTS["keyword"]
    if term in module.SUMMARY.lower():
        return WEIGHTS["summary"]
    if any(term in (syntax + " " + text).lower() for syntax, text, _ in rows):
        return WEIGHTS["command"]
    if term in getattr(module, "TIP", "").lower():
        return WEIGHTS["tip"]
    return 0


def _search(words, entries, options):
    if not words:
        raise SettingsError("usage: settings search <words>, e.g. settings search night light")
    terms = [word.lower() for word in words]
    found = []
    for number, module in entries:
        rows = _rows(module)
        scores = [_score(term, module, rows) for term in terms]
        if not all(scores):  # every word has to be found somewhere in the setting
            continue
        shown = [row for row in rows if any(term in (row[0] + " " + row[1]).lower() for term in terms)]
        found.append((sum(scores), number, module, shown or rows[:1]))
    found.sort(key=lambda item: (-item[0], item[2].NAME))
    if options["json"]:
        _core.print_json([{
            "number": number, "name": module.NAME, "aliases": list(getattr(module, "ALIASES", [])),
            "summary": module.SUMMARY, "score": score,
            "commands": [{"command": syntax, "does": text, "group": group} for syntax, text, group in shown],
        } for score, number, module, shown in found])
        return 0
    os.system("")  # enables ANSI colour codes in the Windows console
    if not found:
        print(f"nothing matches '{' '.join(words)}'. Type 'settings' to see every setting.")
        return 0
    lines = [f"settings that match '{' '.join(words)}'", ""]
    for score, number, module, shown in found:
        names = ", ".join([module.NAME, *getattr(module, "ALIASES", [])])
        lines += [f"  {module.NAME}  ({names})  {module.SUMMARY}"]
        width = max(len(syntax) for syntax, _, _ in shown[:6]) + 3
        lines += [f"      {syntax:<{width}}{text}" for syntax, text, _ in shown[:6]]
        if len(shown) > 6:
            lines.append(f"      ... and {len(shown) - 6} more. Type the setting's name for its intro.")
        lines.append("")
    lines.append("open one: settings <name>, or run any command shown.")
    print(_core.BLUE + "\n".join(lines) + _core.RESET)
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
    args, options = _core.split_flags(args)
    try:
        if args and args[0].lower() in HELP_WORDS:
            print(f"usage: {USAGE}")
            return 0
        entries = _entries()
        if args and args[0].lower() in SEARCH_WORDS:
            return _search(args[1:], entries, options)
        if options["json"]:
            return _json(args, entries)
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

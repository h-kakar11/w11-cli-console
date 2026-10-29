"""
catalog: a machine-readable list of every command. Routed from app.py ("catalog" or "cat").

    cat                    the pages, and which of them take batched changes
    cat <page>             one page: its operations with their arguments, permissions and side effects
    cat --json             everything as data, for an agent

Pages that run changes through the shared engine (reg, services, startup, volume) declare each operation:
its arguments, whether it changes the system, whether it needs administrator, whether a restart or
sign-out follows, and its side effects. Those are the operations 'cs' can batch and 'rb' can undo.

The other commands are listed from their help text only. Their "changes_system", "needs_admin" and
"restart" are null with "declared": false, which means nobody has declared them yet, not that the answer is no.
"""

import sys

import _core

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "catalog"
ALIASES = ["cat"]
SUMMARY = "List every command, its arguments and side effects"
# extra words people use, for 'settings search'
KEYWORDS = ["commands", "list", "discover", "machine", "readable", "agent", "permissions", "schema", "operations"]
USAGE = "cat [page] [--json]"
HELP = [
    ("cat", "the pages, and which of them take batched changes"),
    ("cat <page>", "one page: operations, arguments, permissions and side effects"),
    ("cat --json", "the whole catalog as data"),
    ("cat <page> --json", "one page as data"),
]
TIP = "Example: cat reg --json. An agent reads this, then sends changes with cs or runs a direct command."

HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")

CONVENTIONS = {
    "flags": {
        "--json": "machine-readable output on stdout; errors become JSON on stderr",
        "--yes": "the person has already agreed; skip the confirmation",
        "--dry-run": "show the exact changes and stop (pages that declare dry_run)",
        "--atomic": "cs only: undo the applied changes if a later one fails",
        "--expect": "cs only: apply only if the plan fingerprint still matches the preview",
    },
    "exit_codes": {"0": "success, or the person declined", "1": "the system refused or something failed (including needs administrator)",
                   "2": "bad arguments or confirmation required"},
    "error_codes": ["usage", "not_found", "ambiguous", "needs_admin", "access_denied", "confirmation_required",
                    "plan_changed", "nothing_to_undo", "too_large", "failed"],
    "batch_input": {"changes": [{"page": "<page>", "op": "<operation>", "args": {"<parameter>": "<value>"}}]},
    "undo": "rb <journal id>, or rb last",
}


def _operation(module, name, spec):
    return {
        "id": f"{module.NAME} {name}", "page": module.NAME, "op": name, "summary": spec["summary"],
        "params": [{"name": p["name"], "required": bool(p.get("required")), "help": p.get("help", "")} for p in spec.get("params", [])],
        "changes_system": spec.get("changes_system"), "needs_admin": spec.get("needs_admin"),
        "restart": spec.get("restart", "none"), "side_effects": spec.get("side_effects", ""),
        "dry_run": True, "undoable": "restore" in spec, "declared": True,
    }


def _commands(module):
    group, rows = None, []
    for syntax, text in getattr(module, "HELP", []):
        if syntax:
            rows.append({"command": syntax, "does": text, "group": group, "changes_system": None,
                         "needs_admin": None, "restart": None, "declared": False})
        else:
            group = text
    return rows


def describe(module):
    operations = getattr(module, "OPERATIONS", None) or {}
    return {
        "name": module.NAME, "aliases": list(getattr(module, "ALIASES", [])), "summary": module.SUMMARY,
        "usage": module.USAGE, "runs_alone": bool(getattr(module, "RUN_ALONE", False)),
        "dry_run": bool(getattr(module, "DRY_RUN", False)), "batchable": bool(operations),
        "operations": [_operation(module, name, operations[name]) for name in sorted(operations)],
        "commands": _commands(module),
    }


def _find(word):
    module = _core.registry().get(word.lower())
    if module is None:
        raise _core.CommandError(f"no page called {word}. Run 'cat' to see them.", 2, "not_found")
    return module


def _yes_no(value):
    return {True: "yes", False: "no", "depends": "depends", None: "?"}.get(value, str(value))


def _show_page(info):
    print(f"{info['name']}: {info['summary']}")
    if info["aliases"]:
        print("also called: " + ", ".join(info["aliases"]))
    print(f"dry-run: {_yes_no(info['dry_run'])}   batchable: {_yes_no(info['batchable'])}")
    for op in info["operations"]:
        print(f"\n  {op['id']}: {op['summary']}")
        print(f"    changes system: {_yes_no(op['changes_system'])}   administrator: {_yes_no(op['needs_admin'])}   follow-up: {op['restart']}")
        for param in op["params"]:
            print(f"    {param['name']}{'' if param['required'] else ' (optional)'}: {param['help']}")
        if op["side_effects"]:
            print(f"    side effects: {op['side_effects']}")
    if info["commands"]:
        print("\n  commands (from help; permissions not declared):")
        for row in info["commands"]:
            print(f"    {row['command']:<40}{row['does']}")


def run(args):
    """Show the catalog; returns an exit code."""
    args, options = _core.split_flags(args)
    try:
        if args and args[0].lower() in HELP_WORDS:
            print(f"usage: {USAGE}")
            return 0
        if len(args) > 1:
            raise _core.CommandError(f"usage: {USAGE}", 2, "usage")
        if args:
            info = describe(_find(args[0]))
            if options["json"]:
                _core.print_json(info)
            else:
                _show_page(info)
            return 0
        pages = [describe(module) for module in _core.unique_settings()]
        if options["json"]:
            _core.print_json({"conventions": CONVENTIONS, "pages": pages})
            return 0
        print(f"  {'PAGE':<13}{'SHORT':<8}{'BATCH':<7}{'DRY-RUN':<9}WHAT IT DOES")
        for info in pages:
            short = info["aliases"][0] if info["aliases"] else "-"
            print(f"  {info['name']:<13}{short:<8}{_yes_no(info['batchable']):<7}{_yes_no(info['dry_run']):<9}{info['summary']}")
        print("\nSee one page: cat <page>. The whole thing as data: cat --json.")
        return 0
    except _core.CommandError as error:
        return _core.report_error(error)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

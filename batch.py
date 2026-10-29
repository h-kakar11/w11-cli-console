"""
batch: several changes as one reviewable operation. Routed from app.py ("batch" or "cs").

    cs <file>                  read the changes from a JSON file, show them, ask once, apply them
    cs <file> --dry-run        show the exact changes, the plan fingerprint and what needs administrator; change nothing
    cs <file> --yes            apply them, the person having approved the group
    cs - ...                   read the changes from standard input instead of a file

The file holds the changes, each one a page, an operation and its arguments (run 'cat' to see which
pages take part and what their operations need):

    {"changes": [
      {"page": "regedit", "op": "set", "args": {"path": "HKCU\\\\Software\\\\Example", "name": "Port", "type": "dword", "value": 8080}},
      {"page": "services", "op": "startup", "args": {"service": "Spooler", "mode": "manual"}}
    ]}

Every change is planned first (a bad one stops the whole run before anything is touched), then the
group is checked for administrator rights, shown, and asked about once. Previous values are saved before
anything changes; each change is applied and read back in order. The first failure stops the run: the
rest are skipped, and the report says which applied, which failed and how to undo them ('rb <id>').
--atomic also undoes the changes that had already applied.

For an agent: preview with --dry-run --json, show the person, then apply with --yes --expect <plan>
where <plan> is the plan_hash from the preview. If anything changed since the preview the run stops
(plan_changed) with nothing done.
"""

import json
import sys
from pathlib import Path

import _core
import _ops

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "batch"
ALIASES = ["cs"]
SUMMARY = "Preview and apply several changes as one group"
# extra words people use, for 'settings search'
KEYWORDS = ["group", "several", "bulk", "atomic", "transaction", "agent", "script", "apply", "preview"]
USAGE = "cs <file.json> [--dry-run] [--yes] [--atomic] [--expect <plan>] [--json]   (cs - reads standard input)"
HELP = [
    ("cs <file>", "show the changes in a JSON file, ask once, then apply them"),
    ("cs <file> --dry-run", "show the exact changes and a plan fingerprint; change nothing"),
    ("cs <file> --yes", "apply the group without asking (the person has already agreed)"),
    ("cs <file> --yes --expect <plan>", "apply only if the plan is still the one that was previewed"),
    ("cs <file> --atomic", "if one change fails, undo the ones already applied"),
    ("cs -", "read the changes from standard input"),
]
TIP = ("Each change is {\"page\": \"regedit\", \"op\": \"set\", \"args\": {...}}. Run 'cat' to see the pages and "
       "operations. After a run, 'rb last' undoes the whole group.")
DRY_RUN = True  # cs takes --dry-run

HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")


def _read(source):
    if source == "-":
        return sys.stdin.read(), "standard input"
    try:
        return Path(source).read_text(encoding="utf-8-sig"), source
    except OSError as error:
        raise _core.CommandError(f"could not read {source}: {error.strerror or error}", 2, "not_found")


def _changes(text, where):
    try:
        data = json.loads(text)
    except ValueError as error:
        raise _core.CommandError(f"{where} is not valid JSON: {error}", 2, "usage")
    changes = data.get("changes") if isinstance(data, dict) else data
    if not isinstance(changes, list) or not changes:
        raise _core.CommandError(f'{where} must hold a list of changes: {{"changes": [{{"page": ..., "op": ..., "args": {{}}}}]}}', 2, "usage")
    return changes


def _items(changes):
    registry = _core.registry()
    items = []
    for number, change in enumerate(changes, start=1):
        if not isinstance(change, dict) or not isinstance(change.get("page"), str) or not isinstance(change.get("op"), str):
            raise _core.CommandError(f'change {number} needs a "page" and an "op"', 2, "usage")
        extra = sorted(set(change) - {"page", "op", "args"})
        if extra:
            raise _core.CommandError(f"change {number} has unknown field(s): {', '.join(extra)}", 2, "usage")
        args = change.get("args", {})
        if not isinstance(args, dict):
            raise _core.CommandError(f'change {number}: "args" must be an object', 2, "usage")
        module = registry.get(change["page"].lower())
        if module is None or not getattr(module, "OPERATIONS", None):
            raise _core.CommandError(
                f"change {number}: {change['page']} has no operations that can be batched. Run 'cat' to see which pages do.",
                2, "not_found")
        items.append({"module": module, "op": change["op"], "params": dict(args)})
    return items


def run(args):
    """Preview, approve and apply a group of changes; returns an exit code."""
    args, options = _core.split_flags(args, _core.DRY_FLAGS + ("--atomic",))
    try:
        if not args or args[0].lower() in HELP_WORDS:
            print(f"usage: {USAGE}")
            return 0
        args, expect = _core.take_option(args, "--expect")
        if len(args) != 1:
            raise _core.CommandError(f"usage: {USAGE}", 2, "usage")
        text, where = _read(args[0])
        options["expect"] = expect
        return _ops.execute(_items(_changes(text, where)), options, batch=True, label=args[0])
    except _core.CommandError as error:
        return _core.report_error(error)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

"""
rollback: put back what an earlier change replaced. Routed from app.py ("rollback", "rb" or "undo").

    rb ls                  the journal: every change run so far, newest last
    rb show <id>           one entry: what each change did and its previous value
    rb last                undo the newest entry that still has something to undo
    rb <id>                undo one entry (an id, or the start of one)
    rb <id> --dry-run      show what undoing it would restore; change nothing

Every change made through reg, services, startup, volume or cs saves the previous value to the
journal BEFORE it changes anything. Undoing puts the changes back newest first, reads each one back,
and reports any that did not go back. A value that was changed again since is overwritten, and the
preview says so. Add --json for data and --yes when the person has agreed.

The journal is %LOCALAPPDATA%\\w11-cli-console\\journal.json; the last 200 entries are kept.
"""

import sys

import _core
import _ops

# ======================================================================
# SETTING INFO — read by app.py to list and route this setting
# ======================================================================
NAME = "rollback"
ALIASES = ["rb", "undo"]
SUMMARY = "Undo earlier changes from the saved previous values"
# extra words people use, for 'settings search'
KEYWORDS = ["undo", "restore", "revert", "journal", "history", "back", "previous"]
USAGE = "rb ls | rb show <id> | rb last | rb <id> [--dry-run] [--yes] [--json]"
HELP = [
    ("rb ls", "list every saved change run, newest last"),
    ("rb show <id>", "what one run changed, and the value each change replaced"),
    ("rb last", "undo the newest run that still has something to undo"),
    ("rb <id>", "undo one run (an id from 'rb ls', or the start of one)"),
    ("rb <id> --dry-run", "show what undoing would restore; change nothing"),
]
TIP = "Example: rb last --dry-run shows what the last change replaced. Drop --dry-run to put it back."
DRY_RUN = True  # rb <id> takes --dry-run

HELP_WORDS = ("help", "-h", "--help", "?", "/?", "/help")


def _row(entry):
    left = len(_ops._undoable_items(entry))
    return {
        "id": entry["id"], "time": entry.get("time"), "status": entry.get("status"), "label": entry.get("label"),
        "batch": entry.get("batch", False), "changes": len(entry["items"]), "left_to_undo": left,
    }


def _list(options):
    rows = [_row(entry) for entry in _ops.load_journal()]
    if options["json"]:
        _core.print_json(rows)
        return 0
    if not rows:
        print("the journal is empty: nothing has been changed through this console yet")
        return 0
    print(f"{'ID':<20}{'STATUS':<22}{'CHANGES':<9}{'LEFT':<6}WHAT")
    for row, entry in zip(rows, _ops.load_journal()):
        first = entry["items"][0]
        what = f"{first['page']} {first['op']} {first['target']}" + (f" (+{len(entry['items']) - 1} more)" if len(entry["items"]) > 1 else "")
        print(f"{row['id']:<20}{str(row['status']):<22}{row['changes']:<9}{row['left_to_undo']:<6}{what}")
    return 0


def _show(word, options):
    entry = _ops.find_entry(_ops.load_journal(), word)
    if options["json"]:
        _core.print_json(entry)
        return 0
    print(f"{entry['id']}  {entry.get('time', '')}  status: {entry.get('status')}" + (f"  ({entry['label']})" if entry.get("label") else ""))
    for item in entry["items"]:
        print(f"  {item['index']}. {item['page']} {item['op']} {item['target']}: {item['status']}")
        print(f"       {item['summary']}")
        if item.get("error"):
            print(f"       {item['error']['code']}: {item['error']['message']}")
    return 0


def run(args):
    """Run one rollback command; returns an exit code."""
    args, options = _core.split_flags(args, _core.DRY_FLAGS)
    try:
        if not args or args[0].lower() in HELP_WORDS:
            print(f"usage: {USAGE}")
            return 0
        word = args[0].lower()
        if word in ("ls", "list"):
            if len(args) > 1:
                raise _core.CommandError("usage: rb ls", 2, "usage")
            return _list(options)
        if word == "show":
            if len(args) != 2:
                raise _core.CommandError("usage: rb show <id>", 2, "usage")
            return _show(args[1], options)
        if len(args) != 1:
            raise _core.CommandError(f"usage: {USAGE}", 2, "usage")
        return _ops.rollback(args[0], options)
    except _core.CommandError as error:
        return _core.report_error(error)


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

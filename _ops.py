"""
Shared change engine for pages whose changes can be previewed, batched and undone.
The name starts with an underscore, so app.py does not load it as a page.

A page that takes part defines OPERATIONS, one entry per kind of change, and sets DRY_RUN = True:

    OPERATIONS = {"set": {
        "summary": "...", "params": [{"name": "path", "required": True, "help": "..."}],
        "changes_system": True, "needs_admin": "when", "restart": "none", "side_effects": "...",
        "plan":    f(params) -> plan   read the current state, resolve the target, say what will change
        "apply":   f(plan)             make the change
        "read":    f(plan) -> state    read the real state back, in the same shape as plan["after"]
        "restore": f(plan)             put plan["before"] back
    }}

A plan is a JSON-able dict: target (a stable name or path), summary, before, after, noop, needs_admin
(True, False or None when unknown), disrupts (text or None), restart (none, signout or restart; unknown when
Windows cannot say), confirm (a question to ask a person before a single change, or None).

execute() runs one change or a batch the same way every time:
    plan every change first -> stop on any error before touching anything
    check administrator rights and warn about anything that may cut connectivity
    --dry-run prints the exact changes and stops
    ask once for the whole group (--yes answers in advance)
    write the journal (the previous values) BEFORE applying, then apply one at a time
    read every change back and compare it with what was asked for
    stop at the first failure (--atomic also undoes the ones already applied)
    report what applied, what failed, what was skipped, and the rollback command

rollback() puts the previous values of a journal entry back, newest change first.
"""

import hashlib
import json
import time

import _core

JOURNAL_FILE = "journal.json"
KEEP = 200  # journal entries kept; the oldest are dropped
RESTART_RANK = {"none": 0, "signout": 1, "restart": 2}
UNDOABLE = ("applied", "unverified", "applying", "failed_changed", "rollback_failed")  # rollback_failed: try again

CONNECTIVITY_NOTE = "may interrupt network connections while it applies"


# ======================================================================
# JOURNAL — one entry per run, written before anything changes
# ======================================================================
def _store():
    import _win  # imported late: _win needs Windows modules, and this keeps the engine light

    return _win


def load_journal():
    entries = _store().load_json(JOURNAL_FILE, [])
    return entries if isinstance(entries, list) else []


def save_journal(entries):
    _store().save_json(JOURNAL_FILE, entries[-KEEP:])


def _new_id(entries):
    base = time.strftime("%Y%m%d-%H%M%S")
    taken = {entry["id"] for entry in entries}
    candidate, number = base, 1
    while candidate in taken:
        number += 1
        candidate = f"{base}-{number}"
    return candidate


def find_entry(entries, word):
    """A journal entry by id, a unique id prefix, or 'last' (the newest one with something left to undo)."""
    if word.lower() == "last":
        for entry in reversed(entries):
            if _undoable_items(entry):
                return entry
        raise _core.CommandError("nothing in the journal can be rolled back.", 1, "nothing_to_undo")
    exact = [entry for entry in entries if entry["id"] == word]
    found = exact or [entry for entry in entries if entry["id"].startswith(word)]
    if len(found) == 1:
        return found[0]
    if not found:
        raise _core.CommandError(f"no journal entry called {word}. Run 'rb ls' to see them.", 2, "not_found")
    raise _core.CommandError(
        f"{word} matches more than one journal entry: {', '.join(e['id'] for e in found)}.", 2, "ambiguous"
    )


def _undoable_items(entry):
    return [item for item in entry["items"] if item["status"] in UNDOABLE]


# ======================================================================
# SMALL HELPERS pages share
# ======================================================================
def denied(what):
    """An error for an access-denied failure that says what to do, based on whether we are elevated."""
    if _core.is_admin():
        return _core.CommandError(
            f"Windows denied {what} even though this terminal is running as administrator. "
            "The item is protected (owned by TrustedInstaller or SYSTEM, or blocked by policy or security software).",
            1, "access_denied",
        )
    return _core.CommandError(
        f"Windows denied {what}. This terminal is not running as administrator. Run the terminal as administrator.",
        1, "needs_admin",
    )


def find_operation(module, op):
    operations = getattr(module, "OPERATIONS", None)
    if not operations or op not in operations:
        names = ", ".join(sorted(operations or {})) or "none"
        raise _core.CommandError(f"{module.NAME} has no operation called {op}. Its operations: {names}.", 2, "not_found")
    return operations[op]


def check_params(module, op, spec, params):
    names = {param["name"] for param in spec.get("params", [])}
    unknown = sorted(set(params) - names)
    if unknown:
        raise _core.CommandError(
            f"{module.NAME} {op} does not take {', '.join(unknown)}. Its parameters: {', '.join(sorted(names))}.", 2, "usage"
        )
    missing = [p["name"] for p in spec.get("params", []) if p.get("required") and params.get(p["name"]) is None]
    if missing:
        raise _core.CommandError(f"{module.NAME} {op} needs {', '.join(missing)}.", 2, "usage")


def same(spec, expected, actual):
    compare = spec.get("same")
    return compare(expected, actual) if compare else expected == actual


def plan_hash(items):
    """A fingerprint of what the plan would do, so an approved preview cannot quietly turn into a different change."""
    basis = [[i["page"], i["op"], i["plan"].get("target"), i["plan"].get("before"), i["plan"].get("after")] for i in items]
    return hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()[:16]


# ======================================================================
# PLAN — nothing changes here
# ======================================================================
def build(items):
    """Plan every item. Any error stops the whole run before anything is touched."""
    for number, item in enumerate(items, start=1):
        module, op = item["module"], item["op"]
        try:
            spec = find_operation(module, op)
            check_params(module, op, spec, item["params"])
            plan = spec["plan"](item["params"])
        except _core.CommandError as error:
            error.details = {**error.details, "change": number}
            if len(items) > 1:
                error.args = (f"change {number} ({module.NAME} {op}): {error}",)
            raise
        item.update(index=number, page=module.NAME, spec=spec, plan=plan, status="noop" if plan.get("noop") else "planned")
        item.setdefault("error", None)
    seen = {}
    for item in items:  # two changes to one target would each be planned from the same starting state
        key = (item["page"], item["plan"].get("target"))
        if key in seen:
            raise _core.CommandError(
                f"changes {seen[key]} and {item['index']} both change {key[1]}. Combine them into one.", 2, "usage")
        seen[key] = item["index"]
    return items


def _admin_blocked(items):
    if _core.is_admin():
        return []
    return [i for i in items if i["plan"].get("needs_admin") and i["status"] != "noop"]


def _restart_summary(items):
    level, unknown = "none", False
    for item in items:
        if item["status"] not in ("applied", "unverified", "planned", "rolled_back"):
            continue
        need = item["plan"].get("restart", "none")
        if need == "unknown":
            unknown = True
        elif RESTART_RANK.get(need, 0) > RESTART_RANK[level]:
            level = need
    return level, unknown


# ======================================================================
# APPLY — one at a time, read back each time
# ======================================================================
def _failure(error):
    if isinstance(error, _core.CommandError):
        return {"code": error.error, "message": str(error)}
    if isinstance(error, PermissionError):
        converted = denied("the change")
        return {"code": converted.error, "message": str(converted)}
    return {"code": _core.classify(str(error)), "message": str(error)}


def _apply_one(item, entry, entries):
    spec, plan = item["spec"], item["plan"]
    entry_item = entry["items"][item["index"] - 1]
    entry_item["status"] = "applying"
    save_journal(entries)  # the trail exists before the change does
    try:
        spec["apply"](plan)
    except (_core.CommandError, OSError) as error:
        item["error"] = _failure(error)
        item["status"] = "failed_changed" if _changed(item) else "failed"
        return
    try:
        current = spec["read"](plan)
    except (_core.CommandError, OSError) as error:
        item["error"] = {"code": "verify_failed", "message": f"the change ran but could not be read back: {error}"}
        item["status"] = "unverified"
        return
    item["current"] = current
    if same(spec, plan.get("after"), current):
        item["status"] = "applied"
    else:
        item["error"] = {
            "code": "verify_failed",
            "message": f"Windows reports {_short(current)} but {_short(plan.get('after'))} was asked for.",
        }
        item["status"] = "unverified"


def _changed(item):
    """After a failed apply, did anything change anyway? Read it back and compare with the old state."""
    try:
        return not same(item["spec"], item["plan"].get("before"), item["spec"]["read"](item["plan"]))
    except (_core.CommandError, OSError):
        return True  # cannot tell, so assume it did and keep it in the undo list


def _short(value):
    text = json.dumps(value, default=str)
    return text if len(text) <= 80 else text[:77] + "..."


def _undo_items(items, entry, entries):
    """Put back the earlier changes of this run, newest first. Used by --atomic."""
    for item in reversed(items):
        if item["status"] not in ("applied", "unverified", "failed_changed"):
            continue
        item["status"] = _restore(item["spec"], item["plan"], item)
        entry["items"][item["index"] - 1]["status"] = item["status"]
        save_journal(entries)


def _restore(spec, plan, item):
    """Run restore and read back. Returns 'rolled_back' or 'rollback_failed' and sets item['rollback_error']."""
    try:
        spec["restore"](plan)
        current = spec["read"](plan)
    except (_core.CommandError, OSError) as error:
        item["rollback_error"] = _failure(error)
        return "rollback_failed"
    if not same(spec, plan.get("before"), current):
        item["rollback_error"] = {
            "code": "verify_failed",
            "message": f"after restoring, Windows reports {_short(current)} but {_short(plan.get('before'))} was expected.",
        }
        return "rollback_failed"
    item["current"] = current
    return "rolled_back"


# ======================================================================
# REPORT
# ======================================================================
def _title(item):
    return f"{item['page']} {item['op']} {item['plan'].get('target', '')}".strip()


def _change_data(item):
    plan = item["plan"]
    data = {
        "index": item.get("index"),
        "page": item["page"],
        "op": item["op"],
        "target": plan.get("target"),
        "summary": plan.get("summary"),
        "status": item["status"],
        "before": plan.get("before"),
        "after": plan.get("after"),
        "needs_admin": plan.get("needs_admin"),
        "disrupts_connectivity": bool(plan.get("disrupts")),
        "restart": plan.get("restart", "none"),
    }
    if "current" in item:
        data["current"] = item["current"]
    if item.get("error"):
        data["error"] = item["error"]
    if item.get("rollback_error"):
        data["rollback_error"] = item["rollback_error"]
    return data


def _overall(items, dry_run, cancelled, atomic):
    if cancelled:
        return "cancelled"
    if dry_run:
        return "dry_run"
    statuses = {item["status"] for item in items}
    if statuses <= {"noop"}:
        return "noop"
    if not statuses & {"failed", "failed_changed", "unverified", "rollback_failed", "skipped"}:
        return "applied"
    if atomic and statuses <= {"rolled_back", "failed", "skipped", "noop"}:
        return "rolled_back"
    standing = statuses & {"applied", "failed_changed", "unverified", "rollback_failed"}
    if len(items) > 1 and standing:
        return "partial"
    return "unverified" if statuses == {"unverified"} else "failed"


def _envelope(items, status, entry, blocked, admin, hash_, as_batch):
    level, unknown = _restart_summary(items)
    ok = status in ("applied", "noop", "dry_run", "cancelled")
    data = {
        "ok": ok,
        "status": status,
        "dry_run": status == "dry_run",
        "batch": as_batch,
        "journal_id": entry["id"] if entry else None,
        "plan_hash": hash_,
        "needs_admin": any(i["plan"].get("needs_admin") for i in items),
        "is_admin": admin,
        "preflight": {
            "ok": not blocked,
            "blocked": [{"index": i["index"], "reason": "needs administrator rights"} for i in blocked],
            "may_disrupt_connectivity": [i["index"] for i in items if i["plan"].get("disrupts")],
        },
        "restart_needed": level,
        "restart_unknown": unknown,
        "changes": [_change_data(i) for i in items],
        "undo": f"rb {entry['id']}" if entry and _undoable_items(entry) else None,
    }
    return data


def _print_preview(items, blocked, admin, batch):
    heading = f"{len(items)} change(s) planned" if batch else "planned change"
    print(_core.BLUE + heading + _core.RESET)
    for item in items:
        plan = item["plan"]
        flags = []
        if plan.get("needs_admin"):
            flags.append("needs administrator")
        elif plan.get("needs_admin") is None:
            flags.append("administrator need unknown")
        if plan.get("disrupts"):
            flags.append("may disrupt connectivity")
        mark = "no change" if item["status"] == "noop" else plan.get("summary")
        tail = f"   [{', '.join(flags)}]" if flags else ""
        print(f"  {item['index']}. {_title(item)}: {mark}{tail}")
        if plan.get("disrupts") and item["status"] != "noop":
            print(f"       {plan['disrupts']}")
    level, unknown = _restart_summary(items)
    need = {"none": "no restart or sign-out", "signout": "a sign-out", "restart": "a restart"}[level]
    print(f"  after applying: {need}" + ("; some changes could not say whether more is needed" if unknown else ""))
    if blocked:
        names = ", ".join(str(i["index"]) for i in blocked)
        print(f"  blocked: change {names} need administrator rights and this terminal is not elevated")


def _print_result(items, status, entry):
    labels = {
        "applied": "applied", "noop": "already as asked", "failed": "FAILED", "failed_changed": "FAILED (may have changed)",
        "unverified": "applied but read-back differs", "skipped": "skipped", "rolled_back": "rolled back",
        "rollback_failed": "ROLLBACK FAILED",
    }
    for item in items:
        line = f"  {item['index']}. {_title(item)}: {labels.get(item['status'], item['status'])}"
        if item["status"] in ("applied", "rolled_back"):
            line += f" ({item['plan'].get('summary') if item['status'] == 'applied' else 'restored'})"
        print(line)
        for key in ("error", "rollback_error"):
            if item.get(key):
                print(f"       {item[key]['code']}: {item[key]['message']}")
    if entry and _undoable_items(entry):
        print(f"undo with: rb {entry['id']}   (preview it first with: rb {entry['id']} --dry-run)")


# ======================================================================
# EXECUTE — the whole flow
# ======================================================================
def execute(items, options, batch=False, label=None):
    """Plan, preview, confirm, journal, apply and read back. Returns an exit code.

    items are dicts: {"module": page module, "op": name, "params": {...}}.
    options: json, yes, dry_run, atomic (booleans) and expect (a plan_hash or None)."""
    as_json = options.get("json", False)
    items = build(items)
    admin = _core.is_admin()
    blocked = _admin_blocked(items)
    hash_ = plan_hash(items)

    if options.get("expect") and options["expect"] != hash_:
        raise _core.CommandError(
            f"the plan changed since it was previewed (expected {options['expect']}, now {hash_}). "
            "Nothing was changed. Preview it again.", 1, "plan_changed",
        )

    if options.get("dry_run"):
        if as_json:
            _core.print_json(_envelope(items, "dry_run", None, blocked, admin, hash_, batch))
        else:
            _print_preview(items, blocked, admin, batch)
            print(f"plan: {hash_}   (nothing was changed)")
        return 0

    if blocked:
        names = ", ".join(f"{i['index']} ({_title(i)})" for i in blocked)
        raise _core.CommandError(
            f"change {names} needs administrator rights and this terminal is not elevated. "
            "Run the terminal as administrator. Nothing was changed.", 1, "needs_admin",
            blocked=[i["index"] for i in blocked],
        )

    work = [i for i in items if i["status"] != "noop"]
    if not work:
        if as_json:
            _core.print_json(_envelope(items, "noop", None, [], admin, hash_, batch))
        else:
            for item in items:
                print(f"{_title(item)}: already as asked, nothing to do")
        return 0

    if not _confirmed(items, work, options, batch, as_json):
        if as_json:
            _core.print_json(_envelope(items, "cancelled", None, [], admin, hash_, batch))
        else:
            print("cancelled")
        return 0

    entries = load_journal()
    entry = {
        "id": _new_id(entries), "time": time.strftime("%Y-%m-%dT%H:%M:%S"), "label": label, "batch": batch,
        "atomic": bool(options.get("atomic")), "status": "pending",
        "items": [{
            "index": i["index"], "page": i["page"], "op": i["op"], "params": i["params"],
            "target": i["plan"].get("target"), "summary": i["plan"].get("summary"),
            "plan": {k: v for k, v in i["plan"].items() if k != "confirm"}, "status": i["status"],
        } for i in items],
    }
    entries.append(entry)
    save_journal(entries)

    stopped = False
    for item in items:
        if item["status"] == "noop":
            continue
        if stopped:
            item["status"] = "skipped"
        else:
            if not as_json:
                print(f"applying {item['index']}/{len(items)}: {_title(item)}...")
            _apply_one(item, entry, entries)
            stopped = item["status"] not in ("applied",)
        entry["items"][item["index"] - 1]["status"] = item["status"]
    save_journal(entries)

    if stopped and options.get("atomic"):
        _undo_items(items, entry, entries)

    status = _overall(items, False, False, options.get("atomic"))
    entry["status"] = status
    for item in items:
        entry["items"][item["index"] - 1]["status"] = item["status"]
        if item.get("error"):
            entry["items"][item["index"] - 1]["error"] = item["error"]
    save_journal(entries)

    if as_json:
        _core.print_json(_envelope(items, status, entry, [], admin, hash_, batch))
    elif status in ("applied", "noop"):
        _print_single_success(items, entry, batch)
    elif batch or len(items) > 1:
        _print_result(items, status, entry)
    if status in ("applied", "noop"):
        return 0

    failed = next((i for i in items if i.get("error") or i.get("rollback_error")), None)
    problem = (failed.get("error") or failed.get("rollback_error")) if failed else None
    problem = problem or {"code": "failed", "message": "the change failed"}
    if batch:
        count = sum(1 for i in items if i.get("error"))
        message = f"{count} of {len(items)} change(s) failed: change {failed['index'] if failed else '?'}: {problem['message']}"
    else:
        message = problem["message"]
    raise _core.CommandError(message, 1, problem["code"], journal_id=entry["id"], status=status)


def _print_single_success(items, entry, batch):
    if batch or len(items) > 1:
        _print_result(items, "applied", entry)
        return
    item = items[0]
    print(f"{_title(item)}: {item['plan'].get('summary')}")
    level, unknown = _restart_summary(items)
    if level != "none":
        print("needs " + ("a sign-out" if level == "signout" else "a restart") + " to take full effect")
    if entry and _undoable_items(entry):
        print(f"undo with: rb {entry['id']}")


def _confirmed(items, work, options, batch, as_json):
    """One question for a batch; for a single change, the page's own question if it has one.
    options["asked"] means the caller (the registry editor) has already asked a person."""
    if options.get("asked"):
        return True
    yes = options.get("yes", False)
    if as_json:
        # a JSON caller cannot answer a prompt; it must preview, get approval, then pass --yes
        needs = batch or any(i["plan"].get("confirm") for i in work)
        if needs and not yes:
            raise _core.CommandError(
                "this change needs approval. Preview it with --dry-run, then run it again with --yes "
                "once the person has agreed.", 2, "confirmation_required",
            )
        return True
    if not batch:
        question = next((i["plan"]["confirm"] for i in work if i["plan"].get("confirm")), None)
        if question is None:
            return True
        _print_preview_quiet(items)
        return _core.confirm(question, yes)
    _print_preview(items, _admin_blocked(items), _core.is_admin(), True)
    return _core.confirm(
        f"Apply these {len(work)} change(s) as one group? Every previous value is saved first, "
        "and 'rb last' puts them all back. [y/N]: ",
        yes,
    )


def _print_preview_quiet(items):
    for item in items:
        if item["plan"].get("disrupts") and item["status"] != "noop":
            print(f"note: {item['plan']['disrupts']}")


# ======================================================================
# ROLLBACK
# ======================================================================
def rollback(entry_id, options):
    """Restore the previous values of one journal entry, newest change first. Returns an exit code."""
    as_json = options.get("json", False)
    entries = load_journal()
    entry = find_entry(entries, entry_id)
    todo = _undoable_items(entry)
    if not todo:
        raise _core.CommandError(f"{entry['id']} has nothing left to roll back (status {entry['status']}).", 1, "nothing_to_undo")

    registry = _core.registry()
    items = []
    for stored in reversed(todo):
        module = registry.get(stored["page"].lower())
        if module is None:
            raise _core.CommandError(f"the page {stored['page']} is not available, so change {stored['index']} cannot be undone.", 1)
        spec = find_operation(module, stored["op"])
        try:
            current = spec["read"](stored["plan"])
        except (_core.CommandError, OSError) as error:
            raise _core.CommandError(f"could not read {stored['target']} before restoring it: {error}", 1, _failure(error)["code"])
        items.append({
            "module": module, "page": stored["page"], "op": stored["op"], "spec": spec, "plan": stored["plan"],
            "index": stored["index"], "status": "planned", "current": current, "stored": stored,
            "drifted": not same(spec, stored["plan"].get("after"), current),
        })

    admin = _core.is_admin()
    blocked = _admin_blocked(items)

    def data():
        return {
            "ok": True, "status": "dry_run" if options.get("dry_run") else "rolled_back", "journal_id": entry["id"],
            "preflight": {"ok": not blocked, "blocked": [i["index"] for i in blocked]},
            "changes": [{
                "index": i["index"], "page": i["page"], "op": i["op"], "target": i["plan"].get("target"),
                "current": i["current"], "restore_to": i["plan"].get("before"), "status": i["status"],
                "changed_since": i["drifted"],
                **({"rollback_error": i["rollback_error"]} if i.get("rollback_error") else {}),
            } for i in items],
        }

    if options.get("dry_run"):
        if as_json:
            _core.print_json(data())
        else:
            print(_core.BLUE + f"rollback of {entry['id']} would restore:" + _core.RESET)
            for i in items:
                drift = "   (changed again since)" if i["drifted"] else ""
                print(f"  {i['index']}. {_title(i)}: {_short(i['current'])} -> {_short(i['plan'].get('before'))}{drift}")
            print("(nothing was changed)")
        return 0

    if blocked:
        raise _core.CommandError(
            f"change {', '.join(str(i['index']) for i in blocked)} needs administrator rights to undo and this terminal "
            "is not elevated. Run the terminal as administrator. Nothing was changed.", 1, "needs_admin",
        )
    if as_json and not options.get("yes"):
        raise _core.CommandError("rolling back needs approval. Preview it with --dry-run, then use --yes.", 2, "confirmation_required")
    drifted = [i for i in items if i["drifted"]]
    question = f"Roll back {len(items)} change(s) from {entry['id']}?"
    if drifted:
        question += f" {len(drifted)} changed again since and will be overwritten."
    if not as_json and not _core.confirm(question + " [y/N]: ", options.get("yes", False)):
        print("cancelled")
        return 0

    for item in items:
        item["status"] = _restore(item["spec"], item["plan"], item)
        item["stored"]["status"] = item["status"]
        save_journal(entries)
    failed = [i for i in items if i["status"] != "rolled_back"]
    entry["status"] = "partially_rolled_back" if failed or _undoable_items(entry) else "rolled_back"
    save_journal(entries)

    if as_json:
        out = data()
        out["ok"] = not failed
        out["status"] = entry["status"]
        _core.print_json(out)
    else:
        for i in items:
            label = "rolled back" if i["status"] == "rolled_back" else "ROLLBACK FAILED"
            print(f"  {i['index']}. {_title(i)}: {label}")
            if i.get("rollback_error"):
                print(f"       {i['rollback_error']['code']}: {i['rollback_error']['message']}")
    if failed:
        raise _core.CommandError(
            f"{len(failed)} of {len(items)} change(s) could not be rolled back: {failed[0]['rollback_error']['message']}",
            1, failed[0]["rollback_error"]["code"], journal_id=entry["id"],
        )
    return 0


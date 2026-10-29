"""The shared change engine (_ops), 'cs' batches, 'rb' rollback and the catalog, on a page made for the purpose.

The page is a dictionary standing in for a setting. Its operations can be told to fail, to change something and
then fail, or to read back a different value, which is how the failures part-way through a batch are produced."""

import contextlib
import io
import json
import types

from tests.fakes import Sandbox

import _core
import _ops
import batch
import catalog
import rollback


def make_page(state, **faults):
    """A page with one operation, 'set', that writes state[target]. faults: fail={targets}, half={targets}, drift={target: value}."""
    fail, half, drift = faults.get("fail", set()), faults.get("half", set()), faults.get("drift", {})
    admin = faults.get("admin", set())

    def plan(params):
        target = params["name"]
        value = params["value"]
        if not isinstance(value, int):
            raise _core.CommandError("value must be a number", 2, "usage")
        before = state.get(target)
        return {
            "target": target, "summary": f"set {target}: {before} -> {value}", "before": {"value": before},
            "after": {"value": value}, "noop": before == value, "needs_admin": target in admin,
            "disrupts": "drops the network" if target == "net" else None, "restart": "signout" if target == "ui" else "none",
            "confirm": f"Really set {target}? [y/N]: " if target == "risky" else None,
        }

    def apply(plan):
        target = plan["target"]
        if target in half:
            state[target] = plan["after"]["value"]
            raise _core.CommandError("it broke half way", 1, "failed")
        if target in fail:
            raise _core.CommandError("windows said no", 1, "failed")
        state[target] = drift.get(target, plan["after"]["value"])

    def read(plan):
        return {"value": state.get(plan["target"])}

    def restore(plan):
        if plan["target"] in faults.get("restore_fail", set()):
            raise _core.CommandError("cannot put it back", 1, "failed")
        state[plan["target"]] = plan["before"]["value"]

    spec = {
        "summary": "set a number", "changes_system": True, "needs_admin": "depends", "restart": "none", "side_effects": "none",
        "params": [{"name": "name", "required": True, "help": "the setting"}, {"name": "value", "required": True, "help": "a number"}],
        "plan": plan, "apply": apply, "read": read, "restore": restore,
    }
    page = types.SimpleNamespace(NAME="fake", ALIASES=["fk"], SUMMARY="a test page", USAGE="fk", HELP=[("fk x", "does x")],
                                 OPERATIONS={"set": spec}, DRY_RUN=True)
    return page


def change(name, value):
    return {"page": "fake", "op": "set", "args": {"name": name, "value": value}}


class EngineCase(Sandbox):
    def start(self, state=None, **faults):
        self.state = {"a": 1, "b": 2, "c": 3} if state is None else state
        self.page = make_page(self.state, **faults)
        self.use(self.page)

    def items(self, *pairs):
        return [{"module": self.page, "op": "set", "params": {"name": n, "value": v}} for n, v in pairs]

    def execute(self, pairs, batch=False, **options):
        opts = {"json": False, "yes": True, "dry_run": False, "atomic": False, "expect": None, **options}
        return self.call(_ops.execute, self.items(*pairs), opts, batch)

    def ops(self, items, options, batch=False):
        """_ops.execute with its output captured (kept in self.out); errors still propagate."""
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                return _ops.execute(items, options, batch)
        finally:
            self.out = buffer.getvalue()

    def run_cs(self, changes, *flags):
        path = f"{self.data}/changes.json"
        with open(path, "w") as handle:
            json.dump({"changes": changes}, handle)
        return self.call(batch.run, [path, *flags])


class SingleChange(EngineCase):
    def test_applies_reads_back_and_journals(self):
        self.start()
        code, out, _ = self.execute([("a", 10)])
        self.assertEqual(code, 0)
        self.assertEqual(self.state["a"], 10)
        entry = self.journal()[-1]
        self.assertEqual(entry["status"], "applied")
        self.assertEqual(entry["items"][0]["plan"]["before"], {"value": 1})

    def test_json_envelope(self):
        self.start()
        code, out, _ = self.execute([("ui", 5)], json=True)
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "applied")
        self.assertEqual(data["restart_needed"], "signout")
        self.assertEqual(data["changes"][0]["current"], {"value": 5})
        self.assertEqual(data["undo"], f"rb {data['journal_id']}")

    def test_dry_run_changes_nothing_and_shows_a_plan_hash(self):
        self.start()
        code, out, _ = self.execute([("a", 10)], dry_run=True)
        self.assertEqual((code, self.state["a"]), (0, 1))
        self.assertIn("plan:", out)
        self.assertEqual(self.journal(), [])
        code, out, _ = self.execute([("a", 10)], dry_run=True, json=True)
        data = json.loads(out)
        self.assertEqual((data["status"], data["dry_run"]), ("dry_run", True))
        self.assertEqual(data["changes"][0]["before"], {"value": 1})
        self.assertEqual(data["changes"][0]["after"], {"value": 10})

    def test_already_as_asked_is_a_noop(self):
        self.start()
        code, out, _ = self.execute([("a", 1)], json=True)
        self.assertEqual((code, json.loads(out)["status"]), (0, "noop"))
        self.assertEqual(self.journal(), [])

    def test_failure_exits_1_and_says_whether_anything_changed(self):
        self.start(fail={"a"})
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10)), {"yes": True})
        self.assertEqual((caught.exception.code, caught.exception.error), (1, "failed"))
        self.assertEqual(self.journal()[-1]["items"][0]["status"], "failed")
        self.assertEqual(self.state["a"], 1)

    def test_failure_that_changed_something_is_failed_changed_and_undoable(self):
        self.start(half={"a"})
        with self.assertRaises(_core.CommandError):
            self.ops(self.items(("a", 10)), {"yes": True})
        self.assertEqual(self.journal()[-1]["items"][0]["status"], "failed_changed")
        self.assertEqual(self.state["a"], 10)
        code, _, _ = self.call(_ops.rollback, "last", {"yes": True})
        self.assertEqual((code, self.state["a"]), (0, 1))

    def test_read_back_that_differs_is_unverified_not_applied(self):
        self.start(drift={"a": 99})
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10)), {"yes": True})
        self.assertEqual(caught.exception.error, "verify_failed")
        self.assertEqual(self.journal()[-1]["items"][0]["status"], "unverified")

    def test_page_confirmation_question_is_asked_and_no_cancels(self):
        self.start({"risky": 0})
        self.answers = ["n"]
        code, out, _ = self.execute([("risky", 1)], yes=False)
        self.assertEqual((code, self.state["risky"]), (0, 0))
        self.assertIn("cancelled", out)
        self.assertEqual(self.prompts, ["Really set risky? [y/N]: "])
        self.assertEqual(self.journal(), [])

    def test_changes_that_need_no_question_do_not_ask(self):
        self.start()
        code, _, _ = self.execute([("a", 2)], yes=False)
        self.assertEqual((code, self.prompts, self.state["a"]), (0, [], 2))

    def test_json_without_yes_demands_confirmation_only_where_one_is_needed(self):
        self.start({"risky": 0, "a": 1})
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("risky", 1)), {"json": True})
        self.assertEqual((caught.exception.code, caught.exception.error), (2, "confirmation_required"))
        self.assertEqual(self.state["risky"], 0)
        code, out, _ = self.execute([("a", 2)], json=True, yes=False)
        self.assertEqual(code, 0)

    def test_bad_arguments_exit_2_before_anything_changes(self):
        self.start()
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", "text")), {"yes": True})
        self.assertEqual(caught.exception.code, 2)
        with self.assertRaises(_core.CommandError) as caught:
            _ops.execute([{"module": self.page, "op": "set", "params": {"name": "a", "colour": 1}}], {"yes": True})
        self.assertEqual(caught.exception.error, "usage")
        with self.assertRaises(_core.CommandError) as caught:
            _ops.execute([{"module": self.page, "op": "nope", "params": {}}], {"yes": True})
        self.assertEqual(caught.exception.error, "not_found")


class AdminPreflight(EngineCase):
    admin = False

    def test_blocked_before_anything_is_applied(self):
        self.start(admin={"b"})
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10), ("b", 20)), {"yes": True}, batch=True)
        self.assertEqual((caught.exception.code, caught.exception.error), (1, "needs_admin"))
        self.assertEqual(self.state, {"a": 1, "b": 2, "c": 3})  # not even the change that needed no administrator
        self.assertEqual(self.journal(), [])

    def test_dry_run_reports_what_is_blocked(self):
        self.start(admin={"b"})
        code, out, _ = self.execute([("a", 10), ("b", 20)], batch=True, dry_run=True, json=True)
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertFalse(data["preflight"]["ok"])
        self.assertEqual([b["index"] for b in data["preflight"]["blocked"]], [2])
        self.assertFalse(data["is_admin"])
        self.assertTrue(data["needs_admin"])

    def test_a_noop_that_would_need_admin_does_not_block(self):
        self.start(admin={"b"})
        code, _, _ = self.execute([("b", 2)])
        self.assertEqual(code, 0)


class Batches(EngineCase):
    def test_group_is_shown_asked_once_and_applied_in_order(self):
        self.start()
        self.answers = ["y"]
        code, out, _ = self.execute([("a", 10), ("b", 20)], batch=True, yes=False)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.prompts), 1)
        self.assertIn("2 change(s)", self.prompts[0])
        self.assertEqual(self.state, {"a": 10, "b": 20, "c": 3})
        self.assertEqual(self.journal()[-1]["status"], "applied")
        self.assertTrue(self.journal()[-1]["batch"])

    def test_declining_the_group_applies_nothing(self):
        self.start()
        self.answers = ["n"]
        code, out, _ = self.execute([("a", 10), ("b", 20)], batch=True, yes=False)
        self.assertEqual((code, self.state), (0, {"a": 1, "b": 2, "c": 3}))
        self.assertEqual(self.journal(), [])

    def test_json_batch_needs_yes(self):
        self.start()
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10), ("b", 20)), {"json": True}, batch=True)
        self.assertEqual((caught.exception.code, caught.exception.error), (2, "confirmation_required"))

    def test_a_bad_change_anywhere_stops_the_whole_run_unapplied(self):
        self.start()
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10), ("b", "x")), {"yes": True}, batch=True)
        self.assertIn("change 2", str(caught.exception))
        self.assertEqual(self.state["a"], 1)

    def test_two_changes_to_one_target_are_refused(self):
        self.start()
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10), ("a", 11)), {"yes": True}, batch=True)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.state["a"], 1)

    def test_failure_part_way_stops_skips_the_rest_and_reports_each(self):
        self.start(fail={"b"})
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10), ("b", 20), ("c", 30)), {"yes": True}, batch=True)
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(self.state, {"a": 10, "b": 2, "c": 3})
        entry = self.journal()[-1]
        self.assertEqual([i["status"] for i in entry["items"]], ["applied", "failed", "skipped"])
        self.assertEqual(entry["status"], "partial")

    def test_json_report_after_a_partial_run(self):
        self.start(fail={"b"})
        with self.assertRaises(_core.CommandError):
            self.ops(self.items(("a", 10), ("b", 20), ("c", 30)), {"yes": True, "json": True}, True)
        data = json.loads(self.out)
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "partial")
        self.assertEqual([c["status"] for c in data["changes"]], ["applied", "failed", "skipped"])
        self.assertEqual(data["changes"][1]["error"]["code"], "failed")
        self.assertTrue(data["undo"].startswith("rb "))

    def test_atomic_puts_back_what_had_applied(self):
        self.start(fail={"c"})
        with self.assertRaises(_core.CommandError):
            self.ops(self.items(("a", 10), ("b", 20), ("c", 30)), {"yes": True, "atomic": True}, batch=True)
        self.assertEqual(self.state, {"a": 1, "b": 2, "c": 3})
        entry = self.journal()[-1]
        self.assertEqual([i["status"] for i in entry["items"]], ["rolled_back", "rolled_back", "failed"])
        self.assertEqual(entry["status"], "rolled_back")

    def test_atomic_reports_a_rollback_that_failed(self):
        self.start(fail={"c"}, restore_fail={"a"})
        with self.assertRaises(_core.CommandError):
            self.ops(self.items(("a", 10), ("b", 20), ("c", 30)), {"yes": True, "atomic": True}, batch=True)
        entry = self.journal()[-1]
        self.assertEqual([i["status"] for i in entry["items"]], ["rollback_failed", "rolled_back", "failed"])
        self.assertEqual(self.state["a"], 10)  # said plainly, and still in the undo list
        self.assertNotEqual(entry["status"], "rolled_back")

    def test_expect_accepts_the_previewed_plan_and_refuses_a_changed_one(self):
        self.start()
        _, out, _ = self.execute([("a", 10), ("b", 20)], batch=True, dry_run=True, json=True)
        plan = json.loads(out)["plan_hash"]
        self.state["a"] = 5  # something changed since the preview
        with self.assertRaises(_core.CommandError) as caught:
            self.ops(self.items(("a", 10), ("b", 20)), {"yes": True, "expect": plan}, batch=True)
        self.assertEqual((caught.exception.code, caught.exception.error), (1, "plan_changed"))
        self.assertEqual(self.state["a"], 5)
        self.state["a"] = 1
        code, _, _ = self.execute([("a", 10), ("b", 20)], batch=True, expect=plan)
        self.assertEqual((code, self.state["a"]), (0, 10))

    def test_restart_and_connectivity_are_summarised(self):
        self.start()
        _, out, _ = self.execute([("ui", 1), ("net", 1)], batch=True, dry_run=True, json=True)
        data = json.loads(out)
        self.assertEqual(data["restart_needed"], "signout")
        self.assertEqual(data["preflight"]["may_disrupt_connectivity"], [2])
        _, out, _ = self.execute([("ui", 1), ("net", 1)], batch=True, dry_run=True)
        self.assertIn("may disrupt connectivity", out)
        self.assertIn("a sign-out", out)


class Rollback(EngineCase):
    def apply_two(self):
        self.execute([("a", 10), ("b", 20)], batch=True)
        return self.journal()[-1]["id"]

    def test_rollback_restores_newest_first_and_reads_back(self):
        self.start()
        journal_id = self.apply_two()
        code, out, _ = self.call(rollback.run, [journal_id, "--yes"])
        self.assertEqual((code, self.state), (0, {"a": 1, "b": 2, "c": 3}))
        self.assertEqual(self.journal()[-1]["status"], "rolled_back")
        code, _, err = self.call(rollback.run, [journal_id, "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("nothing left to roll back", err)

    def test_rollback_dry_run_shows_the_restore_and_drift(self):
        self.start()
        journal_id = self.apply_two()
        self.state["a"] = 77  # changed again by something else
        code, out, _ = self.call(rollback.run, [journal_id, "--dry-run", "--json"])
        data = json.loads(out)
        by_index = {c["index"]: c for c in data["changes"]}
        self.assertEqual((code, data["status"]), (0, "dry_run"))
        self.assertEqual(by_index[1]["restore_to"], {"value": 1})
        self.assertTrue(by_index[1]["changed_since"])
        self.assertFalse(by_index[2]["changed_since"])
        self.assertEqual(self.state["a"], 77)

    def test_rollback_asks_and_no_leaves_everything(self):
        self.start()
        journal_id = self.apply_two()
        self.answers = ["n"]
        code, out, _ = self.call(rollback.run, [journal_id])
        self.assertIn("cancelled", out)
        self.assertEqual(self.state["a"], 10)

    def test_rollback_json_needs_yes(self):
        self.start()
        journal_id = self.apply_two()
        code, _, err = self.call(rollback.run, [journal_id, "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(_core.LAST_ERROR["code"], "confirmation_required")

    def test_failed_rollback_is_reported_and_can_be_retried(self):
        self.start(restore_fail={"a"})
        journal_id = self.apply_two()
        code, _, err = self.call(rollback.run, [journal_id, "--yes"])
        self.assertEqual(code, 1)
        self.assertEqual(self.state, {"a": 10, "b": 2, "c": 3})
        self.assertEqual(self.journal()[-1]["status"], "partially_rolled_back")
        self.page.OPERATIONS["set"]["restore"] = lambda plan: self.state.__setitem__(plan["target"], plan["before"]["value"])
        code, _, _ = self.call(rollback.run, [journal_id, "--yes"])
        self.assertEqual((code, self.state["a"]), (0, 1))
        self.assertEqual(self.journal()[-1]["status"], "rolled_back")

    def test_last_skips_entries_with_nothing_to_undo(self):
        self.start()
        first = self.apply_two()
        self.execute([("c", 30)])
        self.call(rollback.run, ["last", "--yes"])  # undoes c
        self.assertEqual(self.state["c"], 3)
        code, _, _ = self.call(rollback.run, ["last", "--yes"])  # now the earlier batch
        self.assertEqual((code, self.state["a"]), (0, 1))
        code, _, err = self.call(rollback.run, ["last", "--yes"])
        self.assertEqual(code, 1)
        self.assertEqual(_core.LAST_ERROR["code"], "nothing_to_undo")

    def test_ls_show_and_unknown_ids(self):
        self.start()
        journal_id = self.apply_two()
        code, out, _ = self.call(rollback.run, ["ls", "--json"])
        rows = json.loads(out)
        self.assertEqual((rows[0]["id"], rows[0]["changes"], rows[0]["left_to_undo"]), (journal_id, 2, 2))
        code, out, _ = self.call(rollback.run, ["ls"])
        self.assertIn(journal_id, out)
        code, out, _ = self.call(rollback.run, ["show", journal_id[:8]])
        self.assertEqual(code, 0)
        self.assertIn("fake set a", out)
        code, _, err = self.call(rollback.run, ["nonsense"])
        self.assertEqual(code, 2)
        code, _, err = self.call(rollback.run, [])
        self.assertEqual(code, 0)

    def test_empty_journal(self):
        self.start()
        code, out, _ = self.call(rollback.run, ["ls"])
        self.assertEqual(code, 0)
        self.assertIn("empty", out)


class BatchCommand(EngineCase):
    def test_file_batch_end_to_end_with_dry_run_then_apply(self):
        self.start()
        changes = [change("a", 10), change("b", 20)]
        code, out, _ = self.run_cs(changes, "--dry-run", "--json")
        plan = json.loads(out)["plan_hash"]
        self.assertEqual(self.state["a"], 1)
        code, out, _ = self.run_cs(changes, "--yes", "--json", "--expect", plan)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "applied")
        self.assertEqual(self.state, {"a": 10, "b": 20, "c": 3})

    def test_partial_failure_exit_code_and_journal(self):
        self.start(fail={"b"})
        code, out, err = self.run_cs([change("a", 10), change("b", 20), change("c", 30)], "--yes")
        self.assertEqual(code, 1)
        self.assertIn("skipped", out)
        self.assertIn("rb ", out)
        self.assertEqual(self.state["a"], 10)

    def test_atomic_flag(self):
        self.start(fail={"b"})
        code, _, _ = self.run_cs([change("a", 10), change("b", 20)], "--yes", "--atomic")
        self.assertEqual((code, self.state["a"]), (1, 1))

    def test_bad_input_exits_2_and_names_the_problem(self):
        self.start()
        cases = [
            ('not json', "not valid JSON"),
            ('{"changes": []}', "must hold a list"),
            ('{"changes": [{"op": "set"}]}', 'needs a "page" and an "op"'),
            ('{"changes": [{"page": "fake", "op": "set", "args": [], "x": 1}]}', "unknown field"),
            ('{"changes": [{"page": "fake", "op": "set", "args": 5}]}', '"args" must be an object'),
            ('{"changes": [{"page": "nowhere", "op": "set"}]}', "no operations that can be batched"),
            ('{"changes": [{"page": "fake", "op": "set", "args": {"name": "a"}}]}', "needs value"),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                path = f"{self.data}/bad.json"
                with open(path, "w") as handle:
                    handle.write(text)
                code, _, err = self.call(batch.run, [path, "--yes"])
                self.assertEqual(code, 2, err)
                self.assertIn(expected, err)
        self.assertEqual(self.state["a"], 1)
        code, _, err = self.call(batch.run, [f"{self.data}/missing.json"])
        self.assertEqual(code, 2)
        code, _, err = self.call(batch.run, [])
        self.assertEqual(code, 0)

    def test_bare_list_and_bom_are_accepted(self):
        self.start()
        path = f"{self.data}/bom.json"
        with open(path, "w", encoding="utf-8-sig") as handle:
            json.dump([change("a", 7)], handle)
        code, _, _ = self.call(batch.run, [path, "--yes"])
        self.assertEqual((code, self.state["a"]), (0, 7))

    def test_stdin(self):
        import unittest.mock
        self.start()
        with unittest.mock.patch("sys.stdin", io.StringIO(json.dumps({"changes": [change("a", 8)]}))):
            code, _, _ = self.call(batch.run, ["-", "--yes"])
        self.assertEqual((code, self.state["a"]), (0, 8))


class Catalog(EngineCase):
    def test_operations_are_described_and_legacy_commands_are_not_guessed(self):
        self.start()
        info = catalog.describe(self.page)
        self.assertTrue(info["batchable"])
        op = info["operations"][0]
        self.assertEqual((op["id"], op["changes_system"], op["needs_admin"], op["declared"]), ("fake set", True, "depends", True))
        self.assertEqual([p["name"] for p in op["params"]], ["name", "value"])
        row = info["commands"][0]
        self.assertEqual((row["changes_system"], row["needs_admin"], row["declared"]), (None, None, False))

    def test_cat_json_for_a_page_and_unknown_page(self):
        self.start()
        code, out, _ = self.call(catalog.run, ["fake", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["operations"][0]["op"], "set")
        code, _, err = self.call(catalog.run, ["nowhere"])
        self.assertEqual(code, 2)
        code, out, _ = self.call(catalog.run, ["fake"])
        self.assertIn("fake set", out)

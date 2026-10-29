"""reg get / set / del / mkkey / rmkey: arguments, exit codes, confirmation, dry-run, read-back and rollback."""

import json
import unittest

from tests.fakes import FAKE, Sandbox, get, put

import regedit

KEY = "HKCU\\Software\\Example"


def dword(number):
    return (number, FAKE.REG_DWORD)


def text(value):
    return (value, FAKE.REG_SZ)


class Sandbox(Sandbox):
    def setUp(self):
        super().setUp()
        self.use(regedit)


class ReadTests(Sandbox):
    def test_get_value_text_and_json(self):
        put(FAKE, KEY, Port=dword(80))
        code, out, _ = self.call(regedit.run, ["get", KEY, "Port"])
        self.assertEqual(code, 0)
        self.assertIn("80", out)
        code, out, _ = self.call(regedit.run, ["get", KEY, "Port", "--json"])
        self.assertEqual(json.loads(out), {"path": KEY, "name": "Port", "exists": True, "type": "REG_DWORD", "data": 80})

    def test_get_missing_value_and_key_are_not_found_with_exit_2(self):
        put(FAKE, KEY)
        code, _, err = self.call(regedit.run, ["get", KEY, "Nope"])
        self.assertEqual(code, 2)
        self.assertIn("no value called Nope", err)
        code, _, err = self.call(regedit.run, ["get", "HKCU\\Software\\Missing", "x"])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_get_key_details_json(self):
        put(FAKE, KEY + "\\Sub", A=text("a"))
        put(FAKE, KEY, B=text("b"))
        code, out, _ = self.call(regedit.run, ["get", KEY, "--json"])
        data = json.loads(out)
        self.assertEqual((data["subkeys"], data["values"]), (1, 1))

    def test_ls_json_lists_keys_and_values_by_name(self):
        put(FAKE, KEY + "\\Sub")
        put(FAKE, KEY, B=text("b"))
        code, out, _ = self.call(regedit.run, ["ls", KEY, "--json"])
        data = json.loads(out)
        self.assertEqual([k["name"] for k in data["keys"]], ["Sub"])
        self.assertEqual(data["values"], [{"name": "B", "type": "REG_SZ", "data": "b"}])

    def test_bad_usage_exits_2(self):
        for args in (["get"], ["set", KEY], ["set", KEY, "x", "--value", "1"], ["del", KEY], ["bogus"],
                     ["get", "NOHIVE\\x", "y"], ["ls", "a", "b"], ["get", KEY, "x", "--dry-run"]):
            with self.subTest(args=args):
                code, _, err = self.call(regedit.run, args)
                self.assertEqual(code, 2, err)
                self.assertTrue(err.startswith("error:"))

    def test_slash_path_gets_a_hint(self):
        code, _, err = self.call(regedit.run, ["get", "HKCU/Software/Example", "x"])
        self.assertEqual(code, 2)
        self.assertIn("backslashes", err)

    def test_json_error_goes_through_report_error(self):
        import _core
        code, _, err = self.call(regedit.run, ["get", KEY, "x", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(_core.LAST_ERROR["code"], "not_found")


class SetTests(Sandbox):
    def test_set_creates_key_and_value_and_reads_back(self):
        code, out, _ = self.call(regedit.run, ["set", KEY, "Port", "--type", "dword", "--value", "8080", "--json", "--yes"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "applied")
        self.assertEqual(data["changes"][0]["current"], {"exists": True, "type": "REG_DWORD", "data": 8080})
        self.assertEqual(data["restart_unknown"], True)
        self.assertEqual(data["undo"], "rb " + data["journal_id"])
        self.assertEqual(get(FAKE, KEY)["values"]["Port"], (8080, FAKE.REG_DWORD))

    def test_set_without_flags_equals_form_and_hex(self):
        code, _, _ = self.call(regedit.run, ["set", KEY, "Mask", "--type=dword", "--value=0x1F"])
        self.assertEqual(code, 0)
        self.assertEqual(get(FAKE, KEY)["values"]["Mask"][0], 31)

    def test_new_value_needs_a_type_but_an_existing_one_keeps_its_own(self):
        put(FAKE, KEY, Port=dword(1))
        code, _, _ = self.call(regedit.run, ["set", KEY, "Port", "--value", "2"])
        self.assertEqual(code, 0)
        self.assertEqual(get(FAKE, KEY)["values"]["Port"], (2, FAKE.REG_DWORD))
        code, _, err = self.call(regedit.run, ["set", KEY, "New", "--value", "2"])
        self.assertEqual(code, 2)
        self.assertIn("needs --type", err)

    def test_bad_number_and_range_exit_2_and_change_nothing(self):
        put(FAKE, KEY)
        for value in ("abc", "-1", "4294967296"):
            code, _, err = self.call(regedit.run, ["set", KEY, "P", "--type", "dword", "--value", value])
            self.assertEqual(code, 2, err)
        self.assertEqual(get(FAKE, KEY)["values"], {})
        self.assertEqual(self.journal(), [])

    def test_dry_run_changes_nothing_and_writes_no_journal(self):
        put(FAKE, KEY, Port=dword(1))
        code, out, _ = self.call(regedit.run, ["set", KEY, "Port", "--value", "9", "--dry-run", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["status"], "dry_run")
        self.assertEqual(data["changes"][0]["before"]["data"], 1)
        self.assertEqual(data["changes"][0]["after"]["data"], 9)
        self.assertEqual(get(FAKE, KEY)["values"]["Port"][0], 1)
        self.assertEqual(self.journal(), [])
        self.assertTrue(data["plan_hash"])

    def test_dry_run_text_names_the_change(self):
        put(FAKE, KEY, Port=dword(1))
        code, out, _ = self.call(regedit.run, ["set", KEY, "Port", "--value", "9", "--dry-run"])
        self.assertIn("1", out)
        self.assertIn("nothing was changed", out)

    def test_same_value_is_a_noop_with_no_journal(self):
        put(FAKE, KEY, Port=dword(5))
        code, out, _ = self.call(regedit.run, ["set", KEY, "Port", "--value", "5", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "noop")
        self.assertEqual(self.journal(), [])

    def test_hklm_without_admin_is_blocked_before_anything_changes(self):
        put(FAKE, "HKLM\\SOFTWARE\\Locked")
        FAKE.denied.add("hklm\\software\\locked")
        self.admin_now = False
        code, _, err = self.call(regedit.run, ["set", "HKLM\\SOFTWARE\\Locked", "x", "--type", "sz", "--value", "1"])
        self.assertEqual(code, 1)
        self.assertIn("administrator", err)
        self.assertEqual(self.journal(), [])
        # the same refusal, as data
        code, out, err = self.call(regedit.run, ["set", "HKLM\\SOFTWARE\\Locked", "x", "--type", "sz", "--value", "1", "--dry-run", "--json"])
        data = json.loads(out)
        self.assertEqual(data["needs_admin"], True)
        self.assertFalse(data["preflight"]["ok"])

    def test_admin_but_still_denied_reports_a_protected_key(self):
        put(FAKE, "HKLM\\SOFTWARE\\Locked")
        FAKE.denied.add("hklm\\software\\locked")
        self.admin_now = True
        code, _, err = self.call(regedit.run, ["set", "HKLM\\SOFTWARE\\Locked", "x", "--type", "sz", "--value", "1"])
        self.assertEqual(code, 1)
        self.assertIn("even though", err)

    def test_multi_sz_and_binary(self):
        self.call(regedit.run, ["set", KEY, "List", "--type", "multi_sz", "--value", "a;b"])
        self.call(regedit.run, ["set", KEY, "Bin", "--type", "binary", "--value", "0A FF"])
        values = get(FAKE, KEY)["values"]
        self.assertEqual(values["List"][0], ["a", "b"])
        self.assertEqual(values["Bin"][0], b"\x0a\xff")

    def test_default_value_name(self):
        code, _, _ = self.call(regedit.run, ["set", KEY, "(default)", "--type", "sz", "--value", "hi"])
        self.assertEqual(code, 0)
        self.assertEqual(get(FAKE, KEY)["values"][""][0], "hi")


class RollbackTests(Sandbox):
    def undo(self, *args):
        import _ops
        return _ops.rollback(args[0], {"json": "--json" in args, "yes": True, "dry_run": "--dry-run" in args})

    def test_undo_of_a_changed_value_restores_it(self):
        put(FAKE, KEY, Port=dword(80))
        self.call(regedit.run, ["set", KEY, "Port", "--value", "9"])
        code, _, _ = self.call(self.undo, "last")
        self.assertEqual(code, 0)
        self.assertEqual(get(FAKE, KEY)["values"]["Port"], (80, FAKE.REG_DWORD))
        self.assertEqual(self.journal()[-1]["status"], "rolled_back")

    def test_undo_of_a_created_value_and_key_removes_both(self):
        self.call(regedit.run, ["set", KEY + "\\Deep\\Er", "x", "--type", "sz", "--value", "1"])
        self.assertIsNotNone(get(FAKE, KEY + "\\Deep\\Er"))
        code, _, _ = self.call(self.undo, "last")
        self.assertEqual(code, 0)
        self.assertIsNone(get(FAKE, KEY + "\\Deep"))
        self.assertIsNone(get(FAKE, KEY))

    def test_undo_of_a_deleted_value_brings_back_type_and_data(self):
        put(FAKE, KEY, Blob=(b"\x01\x02", FAKE.REG_BINARY))
        self.call(regedit.run, ["del", KEY, "Blob", "--yes"])
        self.assertNotIn("Blob", get(FAKE, KEY)["values"])
        self.call(self.undo, "last")
        self.assertEqual(get(FAKE, KEY)["values"]["Blob"], (b"\x01\x02", FAKE.REG_BINARY))

    def test_undo_twice_says_nothing_left(self):
        put(FAKE, KEY, Port=dword(80))
        self.call(regedit.run, ["set", KEY, "Port", "--value", "9"])
        self.call(self.undo, "last")
        import _core
        with self.assertRaises(_core.CommandError) as caught:
            self.undo("last")
        self.assertEqual(caught.exception.error, "nothing_to_undo")

    def test_rollback_dry_run_shows_the_restore_and_changes_nothing(self):
        put(FAKE, KEY, Port=dword(80))
        self.call(regedit.run, ["set", KEY, "Port", "--value", "9"])
        code, out, _ = self.call(self.undo, "last", "--dry-run", "--json")
        data = json.loads(out)
        self.assertEqual(data["status"], "dry_run")
        self.assertEqual(data["changes"][0]["restore_to"]["data"], 80)
        self.assertEqual(get(FAKE, KEY)["values"]["Port"][0], 9)

    def test_rollback_flags_a_value_changed_again_since(self):
        put(FAKE, KEY, Port=dword(80))
        self.call(regedit.run, ["set", KEY, "Port", "--value", "9"])
        put(FAKE, KEY, Port=dword(77))
        code, out, _ = self.call(self.undo, "last", "--dry-run", "--json")
        self.assertTrue(json.loads(out)["changes"][0]["changed_since"])


class DeleteTests(Sandbox):
    def test_del_asks_and_no_means_no(self):
        put(FAKE, KEY, Port=dword(1))
        self.answers = ["n"]
        code, out, _ = self.call(regedit.run, ["del", KEY, "Port"])
        self.assertEqual(code, 0)
        self.assertIn("cancelled", out)
        self.assertIn("rb last", self.prompts[0])
        self.assertIn("Port", get(FAKE, KEY)["values"])
        self.assertEqual(self.journal(), [])

    def test_del_yes_answer_deletes(self):
        put(FAKE, KEY, Port=dword(1))
        self.answers = ["y"]
        code, _, _ = self.call(regedit.run, ["del", KEY, "Port"])
        self.assertEqual(code, 0)
        self.assertNotIn("Port", get(FAKE, KEY)["values"])

    def test_json_without_yes_demands_approval_and_changes_nothing(self):
        put(FAKE, KEY, Port=dword(1))
        code, _, err = self.call(regedit.run, ["del", KEY, "Port", "--json"])
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        self.assertIn("Port", get(FAKE, KEY)["values"])

    def test_json_yes_output_is_pure_json(self):
        put(FAKE, KEY, Port=dword(1))
        code, out, _ = self.call(regedit.run, ["del", KEY, "Port", "--json", "--yes"])
        self.assertEqual(json.loads(out)["status"], "applied")

    def test_del_of_a_missing_value_is_a_noop_but_a_missing_key_is_an_error(self):
        put(FAKE, KEY)
        code, out, _ = self.call(regedit.run, ["del", KEY, "Nope", "--json"])
        self.assertEqual(json.loads(out)["status"], "noop")
        code, _, err = self.call(regedit.run, ["del", "HKCU\\Software\\Missing", "x", "--yes"])
        self.assertEqual(code, 2)


class KeyTests(Sandbox):
    def test_mkkey_creates_and_second_time_is_noop(self):
        code, _, _ = self.call(regedit.run, ["mkkey", KEY + "\\A\\B"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(get(FAKE, KEY + "\\A\\B"))
        code, out, _ = self.call(regedit.run, ["mkkey", KEY + "\\A\\B", "--json"])
        self.assertEqual(json.loads(out)["status"], "noop")

    def test_mkkey_undo_removes_only_what_it_made(self):
        put(FAKE, KEY)
        self.call(regedit.run, ["mkkey", KEY + "\\A\\B"])
        import _ops
        self.call(_ops.rollback, "last", {"yes": True})
        self.assertIsNone(get(FAKE, KEY + "\\A"))
        self.assertIsNotNone(get(FAKE, KEY))

    def test_rmkey_deletes_the_tree_and_undo_restores_every_value(self):
        put(FAKE, KEY + "\\Sub\\Deeper", Deep=(b"\xff", FAKE.REG_BINARY), N=dword(3))
        put(FAKE, KEY + "\\Sub", S=text("s"), M=(["a", "b"], FAKE.REG_MULTI_SZ))
        put(FAKE, KEY, Top=(7, FAKE.REG_QWORD))
        code, out, _ = self.call(regedit.run, ["rmkey", KEY, "--yes", "--json"])
        self.assertEqual(code, 0)
        self.assertIsNone(get(FAKE, KEY))
        entry_id = json.loads(out)["journal_id"]
        import _ops
        self.call(_ops.rollback, entry_id, {"yes": True})
        self.assertEqual(get(FAKE, KEY)["values"]["Top"], (7, FAKE.REG_QWORD))
        self.assertEqual(get(FAKE, KEY + "\\Sub")["values"]["M"], (["a", "b"], FAKE.REG_MULTI_SZ))
        self.assertEqual(get(FAKE, KEY + "\\Sub\\Deeper")["values"]["Deep"], (b"\xff", FAKE.REG_BINARY))
        self.assertEqual(self.journal()[-1]["status"], "rolled_back")

    def test_rmkey_refuses_the_top_two_levels(self):
        code, _, err = self.call(regedit.run, ["rmkey", "HKLM\\SOFTWARE", "--yes"])
        self.assertEqual(code, 2)
        self.assertIn("too high", err)

    def test_rmkey_refuses_a_key_too_big_to_back_up_and_deletes_nothing(self):
        for number in range(regedit.MAX_BACKUP_ITEMS + 5):
            put(FAKE, KEY, **{f"v{number}": text("x")})
        code, _, err = self.call(regedit.run, ["rmkey", KEY, "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("too many", err)
        self.assertIsNotNone(get(FAKE, KEY))

    def test_rmkey_asks_with_the_undo_in_the_question(self):
        put(FAKE, KEY, A=text("a"))
        self.answers = ["n"]
        self.call(regedit.run, ["rmkey", KEY])
        self.assertIn("rb last", self.prompts[0])
        self.assertIsNotNone(get(FAKE, KEY))


class EditorTests(Sandbox):
    def test_editor_commands_go_through_the_journal(self):
        put(FAKE, KEY, Port=dword(1))
        editor = regedit.Editor()
        editor.path = ["HKCU", "Software", "Example"]
        self.call(editor.run, ["set", "Port", "5"])
        self.call(editor.run, ["add", "Name", "sz", "hello"])
        self.assertEqual(get(FAKE, KEY)["values"]["Port"][0], 5)
        self.assertEqual(len(self.journal()), 2)

    def test_editor_rm_asks_through_the_engine(self):
        put(FAKE, KEY, Port=dword(1))
        editor = regedit.Editor()
        editor.path = ["HKCU", "Software", "Example"]
        self.answers = ["n"]
        self.call(editor.run, ["rm", "Port"])
        self.assertIn("Port", get(FAKE, KEY)["values"])

    def test_editor_rmdir_with_contents_needs_the_name_typed(self):
        put(FAKE, KEY + "\\Sub", A=text("a"))
        editor = regedit.Editor()
        editor.path = ["HKCU", "Software", "Example"]
        self.answers = ["wrong"]
        self.call(editor.run, ["rmdir", "Sub"])
        self.assertIsNotNone(get(FAKE, KEY + "\\Sub"))
        self.answers = ["Sub"]
        self.call(editor.run, ["rmdir", "Sub"])
        self.assertIsNone(get(FAKE, KEY + "\\Sub"))


if __name__ == "__main__":
    unittest.main()

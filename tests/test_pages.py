"""The services, startup and volume changes: names instead of ids, dry-run, read-back, undo, and what a refusal says.

Windows is faked: sc is a small state machine over the fake registry, the Run keys are the fake registry, and the audio
sessions are plain objects. This proves the code's logic, not that Windows accepts the calls (see tests/SMOKE.md)."""

import json
import os
import sys
import types
import unittest.mock

from tests.fakes import FAKE, Sandbox, get, put

for name in ("psutil", "pycaw", "pycaw.pycaw"):  # volume imports these at the top; the tests never use the real ones
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["psutil"].Error = type("Error", (Exception,), {})
sys.modules["pycaw.pycaw"].AudioUtilities = types.SimpleNamespace()

import _core
import _net
import _ops
import rollback
import services
import startup
import volume

SVC = "SYSTEM\\CurrentControlSet\\Services\\"


class ServiceCase(Sandbox):
    """sc as a state machine: {name: {"state", "start"}}; the start type lives in the fake registry like Windows keeps it."""

    def setUp(self):
        super().setUp()
        self.use(services, rollback)
        self.sc = {}
        self.add("Spooler", "RUNNING", 2, "Print Spooler")
        self.add("Dhcp", "RUNNING", 2, "DHCP Client")
        self.add("Fax", "STOPPED", 3, "Fax")
        self.add("Cdrom", "STOPPED", 1, "CD-ROM Driver")
        self.calls = []
        for target, value in (("run_tool", self.fake_sc),):
            patch = unittest.mock.patch.object(_net, target, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = unittest.mock.patch.object(services, "SECONDS", 0.05)
        patch.start()
        self.addCleanup(patch.stop)
        self.refuse = None  # an sc verb that fails: "start", "stop", "config"

    def add(self, name, state, start, display):
        self.sc[name] = {"state": state}
        put(FAKE, "HKLM\\" + SVC + name, Start=(start, FAKE.REG_DWORD), DisplayName=(display, FAKE.REG_SZ))

    def start_value(self, name):
        return get(FAKE, "HKLM\\" + SVC + name)["values"]["Start"][0]

    def fake_sc(self, args, timeout=60):
        self.calls.append(args)
        verb = args[1]
        if verb == "query" and len(args) == 3:
            name = next((n for n in self.sc if n.lower() == args[2].lower()), None)
            if name is None:
                return False, "[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service."
            return True, f"SERVICE_NAME: {name}\n        TYPE : 10  WIN32_OWN_PROCESS\n        STATE              : 4  {self.sc[name]['state']}"
        if verb == "query":
            return True, "\n".join(f"SERVICE_NAME: {n}\nDISPLAY_NAME: {n}\n        STATE              : 4  {v['state']}\n" for n, v in self.sc.items())
        if self.refuse == verb:
            return False, "[SC] OpenService FAILED 5:\n\nAccess is denied."
        name = args[2]
        if verb == "start":
            self.sc[name]["state"] = "RUNNING"
        elif verb == "stop":
            self.sc[name]["state"] = "STOPPED"
        elif verb == "config":
            word = args[4]
            key = get(FAKE, "HKLM\\" + SVC + name)
            key["values"]["Start"] = ({"auto": 2, "demand": 3, "disabled": 4, "delayed-auto": 2}[word], FAKE.REG_DWORD)
            if word == "delayed-auto":
                key["values"]["DelayedAutostart"] = (1, FAKE.REG_DWORD)
            else:
                key["values"].pop("DelayedAutostart", None)
        return True, "[SC] SUCCESS"


class ServiceChanges(ServiceCase):
    def test_stop_by_name_is_asked_applied_read_back_and_undone(self):
        self.answers = ["y"]
        code, out, _ = self.call(services.run, ["Spooler", "off"])
        self.assertEqual((code, self.sc["Spooler"]["state"]), (0, "STOPPED"))
        self.assertIn("Stop Spooler (Print Spooler)", self.prompts[0])
        self.assertIn("rb last", self.prompts[0])
        code, _, _ = self.call(rollback.run, ["last", "--yes"])
        self.assertEqual((code, self.sc["Spooler"]["state"]), (0, "RUNNING"))

    def test_name_is_case_insensitive_and_canonical_in_the_journal(self):
        self.call(services.run, ["spooler", "off", "--yes"])
        self.assertEqual(self.journal()[-1]["items"][0]["target"], "Spooler")

    def test_declining_changes_nothing(self):
        self.answers = ["n"]
        code, out, _ = self.call(services.run, ["Spooler", "off"])
        self.assertEqual((code, self.sc["Spooler"]["state"]), (0, "RUNNING"))
        self.assertEqual(self.journal(), [])

    def test_start_needs_no_question(self):
        code, _, _ = self.call(services.run, ["Fax", "on"])
        self.assertEqual((code, self.prompts, self.sc["Fax"]["state"]), (0, [], "RUNNING"))

    def test_already_in_the_state_is_a_noop(self):
        code, out, _ = self.call(services.run, ["Spooler", "on", "--json"])
        self.assertEqual((code, json.loads(out)["status"]), (0, "noop"))

    def test_restart(self):
        with unittest.mock.patch.object(_net, "restart_service", lambda name, seconds=15: True) as _:
            code, out, _ = self.call(services.run, ["Spooler", "restart", "--yes", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], "applied")

    def test_dry_run_json_names_the_exact_change_and_what_it_needs(self):
        code, out, _ = self.call(services.run, ["Dhcp", "off", "--dry-run", "--json"])
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(self.sc["Dhcp"]["state"], "RUNNING")
        change = data["changes"][0]
        self.assertEqual((change["target"], change["before"], change["after"]), ("Dhcp", {"state": "RUNNING"}, {"state": "STOPPED"}))
        self.assertTrue(change["needs_admin"])
        self.assertTrue(change["disrupts_connectivity"])
        self.assertEqual(data["preflight"]["may_disrupt_connectivity"], [1])
        self.assertEqual(self.journal(), [])

    def test_startup_type_set_read_back_and_undone_including_delayed(self):
        put(FAKE, "HKLM\\" + SVC + "Spooler", DelayedAutostart=(1, FAKE.REG_DWORD))
        self.assertEqual(services._startup("Spooler"), "auto (delayed)")
        code, _, _ = self.call(services.run, ["Spooler", "manual", "--yes"])
        self.assertEqual((code, self.start_value("Spooler")), (0, 3))
        code, _, _ = self.call(rollback.run, ["last", "--yes"])
        self.assertEqual(code, 0)
        self.assertEqual(services._startup("Spooler"), "auto (delayed)")

    def test_disabled_asks_and_the_question_names_the_undo(self):
        self.answers = ["y"]
        self.call(services.run, ["Fax", "disabled"])
        self.assertIn("rb last", self.prompts[0])
        self.assertEqual(self.start_value("Fax"), 4)

    def test_driver_start_types_are_left_alone(self):
        code, _, err = self.call(services.run, ["Cdrom", "auto", "--yes"])
        self.assertEqual(code, 1)
        self.assertEqual(_core.LAST_ERROR["code"], "unsupported")
        self.assertEqual(self.start_value("Cdrom"), 1)

    def test_unknown_service_and_bad_words_exit_2(self):
        for args, kind in ((["Nope", "off", "--yes"], "not_found"), (["Spooler", "sideways"], "usage"),
                           (["Spooler", "on", "extra"], "usage")):
            with self.subTest(args=args):
                code, _, err = self.call(services.run, args)
                self.assertEqual((code, _core.LAST_ERROR["code"]), (2, kind))

    def test_dry_run_on_a_read_only_command_exits_2(self):
        for args in (["ls", "--dry-run"], ["Spooler", "--dry-run"], ["status", "Spooler", "--dry-run"]):
            with self.subTest(args=args):
                code, _, _ = self.call(services.run, args)
                self.assertEqual(code, 2)

    def test_denied_when_not_elevated_says_so_and_changes_nothing(self):
        self.admin_now = False
        code, _, err = self.call(services.run, ["Spooler", "off", "--yes"])
        self.assertEqual((code, _core.LAST_ERROR["code"]), (1, "needs_admin"))
        self.assertIn("administrator", err)
        self.assertEqual(self.sc["Spooler"]["state"], "RUNNING")
        self.assertEqual(self.journal(), [])

    def test_windows_refusing_while_elevated_is_reported_and_journaled(self):
        self.refuse = "stop"
        code, _, err = self.call(services.run, ["Spooler", "off", "--yes"])
        self.assertEqual(code, 1)
        self.assertEqual(_core.LAST_ERROR["code"], "needs_admin")  # sc says access denied; the hint names administrator
        self.assertEqual(self.journal()[-1]["items"][0]["status"], "failed")

    def test_service_that_never_reaches_the_state_is_reported(self):
        original = self.fake_sc

        def stuck(args, timeout=60):
            if args[1] == "stop":
                return True, "[SC] SUCCESS"  # accepted, but the state never changes
            return original(args, timeout)

        with unittest.mock.patch.object(_net, "run_tool", stuck):
            code, _, err = self.call(services.run, ["Spooler", "off", "--yes"])
        self.assertEqual((code, _core.LAST_ERROR["code"]), (1, "timeout"))

    def test_batch_of_two_services_with_the_second_failing(self):
        import batch
        self.use(batch)
        path = f"{self.data}/s.json"
        with open(path, "w") as handle:
            json.dump({"changes": [
                {"page": "services", "op": "startup", "args": {"service": "Fax", "mode": "auto"}},
                {"page": "services", "op": "state", "args": {"service": "Spooler", "state": "stopped"}},
            ]}, handle)
        self.refuse = "stop"
        code, out, _ = self.call(batch.run, [path, "--yes", "--atomic"])
        self.assertEqual(code, 1)
        self.assertEqual(self.start_value("Fax"), 3)  # the first change was put back
        self.assertEqual([i["status"] for i in self.journal()[-1]["items"]], ["rolled_back", "failed"])

    def test_catalog_declares_both_operations(self):
        import catalog
        info = catalog.describe(services)
        self.assertEqual([o["op"] for o in info["operations"]], ["startup", "state"])
        self.assertTrue(all(o["needs_admin"] is True and o["undoable"] for o in info["operations"]))


class StartupCase(Sandbox):
    RUN = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    APPROVED = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"

    def setUp(self):
        super().setUp()
        self.use(startup, rollback)
        put(FAKE, "HKCU\\" + self.RUN, OneDrive=("C:\\od.exe", FAKE.REG_SZ), Zed=("C:\\zed.exe", FAKE.REG_EXPAND_SZ))
        put(FAKE, "HKLM\\" + self.RUN, OneDrive=("C:\\od-all.exe", FAKE.REG_SZ))
        self.folder = os.path.join(self.data, "Startup")
        os.makedirs(self.folder)
        patch = unittest.mock.patch.multiple(startup, USER_FOLDER=self.folder, ALL_USERS_FOLDER=os.path.join(self.data, "none"))
        patch.start()
        self.addCleanup(patch.stop)

    def enabled(self, word):
        return startup._get_entry(word)["enabled"]


class StartupChanges(StartupCase):
    def test_keys_are_stable_and_listed(self):
        code, out, _ = self.call(startup.run, ["ls", "--json"])
        keys = [row["key"] for row in json.loads(out)]
        self.assertEqual(sorted(keys), ["machine/run/OneDrive", "user/run/OneDrive", "user/run/Zed"])

    def test_ambiguous_name_is_refused_but_the_key_works(self):
        code, _, err = self.call(startup.run, ["OneDrive", "off", "--yes"])
        self.assertEqual((code, _core.LAST_ERROR["code"]), (2, "ambiguous"))
        self.assertIn("user/run/OneDrive", err)
        code, _, _ = self.call(startup.run, ["user/run/OneDrive", "off", "--yes"])
        self.assertEqual(code, 0)
        self.assertFalse(self.enabled("user/run/OneDrive"))
        self.assertTrue(self.enabled("machine/run/OneDrive"))

    def test_disable_then_undo_removes_the_approval_value_it_created(self):
        self.call(startup.run, ["Zed", "off", "--yes"])
        self.assertFalse(self.enabled("Zed"))
        self.assertIn("Zed", get(FAKE, "HKCU\\" + self.APPROVED)["values"])
        code, _, _ = self.call(rollback.run, ["last", "--yes"])
        self.assertEqual(code, 0)
        self.assertTrue(self.enabled("Zed"))
        self.assertNotIn("Zed", get(FAKE, "HKCU\\" + self.APPROVED)["values"])

    def test_undo_puts_back_the_exact_approval_bytes(self):
        original = bytes([0x06]) + bytes(11)
        put(FAKE, "HKCU\\" + self.APPROVED, Zed=(original, FAKE.REG_BINARY))
        self.call(startup.run, ["Zed", "off", "--yes"])
        self.call(rollback.run, ["last", "--yes"])
        self.assertEqual(get(FAKE, "HKCU\\" + self.APPROVED)["values"]["Zed"][0], original)

    def test_enable_when_already_enabled_is_a_noop(self):
        code, out, _ = self.call(startup.run, ["Zed", "on", "--json"])
        self.assertEqual(json.loads(out)["status"], "noop")

    def test_signout_is_reported(self):
        code, out, _ = self.call(startup.run, ["Zed", "off", "--yes", "--json"])
        data = json.loads(out)
        self.assertEqual((data["restart_needed"], data["restart_unknown"]), ("signout", False))

    def test_all_users_entries_need_admin_and_nothing_changes_without_it(self):
        self.admin_now = False
        code, out, _ = self.call(startup.run, ["machine/run/OneDrive", "off", "--dry-run", "--json"])
        data = json.loads(out)
        self.assertEqual((code, data["needs_admin"], data["preflight"]["ok"]), (0, True, False))
        code, _, err = self.call(startup.run, ["machine/run/OneDrive", "off", "--yes"])
        self.assertEqual((code, _core.LAST_ERROR["code"]), (1, "needs_admin"))
        self.assertTrue(self.enabled("machine/run/OneDrive"))
        code, _, _ = self.call(startup.run, ["Zed", "off", "--yes"])  # the user's own needs none
        self.assertEqual(code, 0)

    def test_access_denied_while_elevated_says_the_item_is_protected(self):
        FAKE.denied.add("hkcu\\" + self.APPROVED.lower())
        code, _, err = self.call(startup.run, ["Zed", "off", "--yes"])
        self.assertEqual((code, _core.LAST_ERROR["code"]), (1, "access_denied"))
        self.assertIn("protected", err)

    def test_remove_run_value_is_asked_and_undone_with_its_type(self):
        self.answers = ["y"]
        code, _, _ = self.call(startup.run, ["rm", "Zed"])
        self.assertEqual(code, 0)
        self.assertIn("rb last", self.prompts[0])
        self.assertNotIn("Zed", get(FAKE, "HKCU\\" + self.RUN)["values"])
        self.call(rollback.run, ["last", "--yes"])
        self.assertEqual(get(FAKE, "HKCU\\" + self.RUN)["values"]["Zed"], ("C:\\zed.exe", FAKE.REG_EXPAND_SZ))

    def test_remove_declined_changes_nothing(self):
        self.answers = ["n"]
        self.call(startup.run, ["rm", "Zed"])
        self.assertIn("Zed", get(FAKE, "HKCU\\" + self.RUN)["values"])

    def test_remove_folder_shortcut_is_restored_byte_for_byte(self):
        path = os.path.join(self.folder, "App.lnk")
        with open(path, "wb") as handle:
            handle.write(b"\x4c\x00\x00\x00binary shortcut")
        code, _, _ = self.call(startup.run, ["rm", "user/folder/App.lnk", "--yes"])
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(path))
        self.call(rollback.run, ["last", "--yes"])
        with open(path, "rb") as handle:
            self.assertEqual(handle.read(), b"\x4c\x00\x00\x00binary shortcut")

    def test_remove_dry_run_changes_nothing(self):
        code, out, _ = self.call(startup.run, ["rm", "Zed", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("Zed", get(FAKE, "HKCU\\" + self.RUN)["values"])
        self.assertIn("plan:", out)

    def test_ids_still_work_and_unknown_things_exit_2(self):
        code, out, _ = self.call(startup.run, ["ls", "--json"])
        first = json.loads(out)[0]
        code, out, _ = self.call(startup.run, ["1", "--json"])
        self.assertEqual((code, json.loads(out)["key"]), (0, first["key"]))
        for args in (["99"], ["Nope"], ["Zed", "sideways"], ["ls", "--dry-run"]):
            with self.subTest(args=args):
                code, _, _ = self.call(startup.run, args)
                self.assertEqual(code, 2)


class FakeSession:
    def __init__(self, pid, name, level):
        self.ProcessId, self.State = pid, 1
        self.Process = types.SimpleNamespace(name=lambda: name)
        self.SimpleAudioVolume = types.SimpleNamespace(
            GetMasterVolume=lambda: self.level, SetMasterVolume=lambda level, ctx: setattr(self, "level", level))
        self.level = level


class VolumeCase(Sandbox):
    def setUp(self):
        super().setUp()
        self.use(volume, rollback)
        self.master = 0.30
        self.sessions = [FakeSession(10, "Chrome.exe", 0.5), FakeSession(11, "Chrome.exe", 0.5), FakeSession(12, "Discord.exe", 0.8)]
        self.step = None  # a function that distorts what Windows stores, to test the tolerance
        endpoint = types.SimpleNamespace(
            GetMasterVolumeLevelScalar=lambda: self.master,
            SetMasterVolumeLevelScalar=lambda level, ctx: setattr(self, "master", self.step(level) if self.step else level))
        utilities = types.SimpleNamespace(GetAllSessions=lambda: self.sessions,
                                          GetSpeakers=lambda: types.SimpleNamespace(EndpointVolume=endpoint))
        patch = unittest.mock.patch.object(volume, "AudioUtilities", utilities)
        patch.start()
        self.addCleanup(patch.stop)


class VolumeChanges(VolumeCase):
    def test_set_by_name_changes_every_session_of_the_app_and_is_undone(self):
        code, _, _ = self.call(volume.run, ["chrome", "20"])
        self.assertEqual((code, [s.level for s in self.sessions]), (0, [0.2, 0.2, 0.8]))
        self.call(rollback.run, ["last", "--yes"])
        self.assertEqual([s.level for s in self.sessions], [0.5, 0.5, 0.8])

    def test_system_by_name_and_id_zero(self):
        self.call(volume.run, ["system", "45"])
        self.assertEqual(self.master, 0.45)
        self.call(volume.run, ["0", "10"])
        self.assertEqual(self.master, 0.1)

    def test_id_still_works_and_shows_the_name(self):
        code, out, _ = self.call(volume.run, ["1", "--json"])
        self.assertEqual((code, json.loads(out)), (0, {"name": "Chrome", "volume": 50}))

    def test_dry_run_reports_the_exact_change(self):
        code, out, _ = self.call(volume.run, ["Discord", "30", "--dry-run", "--json"])
        change = json.loads(out)["changes"][0]
        self.assertEqual((change["target"], change["before"], change["after"]), ("Discord", {"percent": 80}, {"percent": 30}))
        self.assertEqual(self.sessions[2].level, 0.8)
        self.assertEqual(self.journal(), [])

    def test_values_are_clamped_and_must_be_numbers(self):
        self.call(volume.run, ["system", "150"])
        self.assertEqual(self.master, 1.0)
        code, _, _ = self.call(volume.run, ["system", "loud"])
        self.assertEqual(code, 2)

    def test_read_back_within_one_percent_counts_as_applied(self):
        self.step = lambda level: round(level * 50) / 50  # volume kept in 2% steps
        code, out, _ = self.call(volume.run, ["system", "51", "--yes", "--json"])
        self.assertEqual((code, json.loads(out)["status"]), (0, "applied"))
        self.assertEqual(round(self.master * 100), 52)

    def test_read_back_further_off_is_reported_unverified(self):
        self.step = lambda level: 0.9
        code, out, _ = self.call(volume.run, ["system", "51", "--yes", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "unverified")

    def test_no_such_app_exits_2_and_unchanged(self):
        code, _, err = self.call(volume.run, ["Spotify", "10", "--yes"])
        self.assertEqual((code, _core.LAST_ERROR["code"]), (2, "not_found"))

    def test_rollback_when_the_app_has_quit_is_reported_not_hidden(self):
        self.call(volume.run, ["Discord", "10", "--yes"])
        self.sessions.pop()
        code, _, err = self.call(rollback.run, ["last", "--yes"])
        self.assertEqual((code, _core.LAST_ERROR["code"]), (1, "not_found"))
        self.assertEqual(self.journal()[-1]["status"], "applied")  # still undoable once the app plays audio again
        self.sessions.append(FakeSession(12, "Discord.exe", 0.1))
        code, _, _ = self.call(rollback.run, ["last", "--yes"])
        self.assertEqual((code, self.sessions[-1].level), (0, 0.8))

    def test_no_admin_is_needed(self):
        self.admin_now = False
        code, _, _ = self.call(volume.run, ["system", "10", "--yes"])
        self.assertEqual(code, 0)

"""Commands that change the PC: each must name its target, ask first, check administrator rights before
announcing anything, reject bad words with exit 2, and leave the PC alone when the answer is no.
Every Windows call is replaced by a recorder, so nothing here touches the machine running the tests."""

import json
from types import SimpleNamespace

import pytest

import _net

# ---------------------------------------------------------------------- startup
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"


@pytest.fixture
def startup(modules, fake_registry):
    reg = fake_registry
    reg.put(reg.HKEY_CURRENT_USER, RUN, "Slack", r"C:\slack.exe", reg.REG_SZ)
    reg.put(reg.HKEY_LOCAL_MACHINE, RUN, "Zoom", r"C:\zoom.exe", reg.REG_SZ)
    reg.writes.clear()
    modules["startup"].reg = reg
    return modules["startup"]


def test_startup_list_json(startup, capsys):
    assert startup.run(["ls", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [(r["id"], r["name"], r["enabled"], r["scope"]) for r in rows] == [
        (1, "Slack", True, "user"), (2, "Zoom", True, "all users")]


def test_startup_off_writes_the_disabled_marker_and_reads_it_back(startup, capsys):
    reg = startup.reg
    assert startup.run(["1", "off"]) == 0
    assert capsys.readouterr().out.strip() == "Slack: disabled"
    assert reg.get(reg.HKEY_CURRENT_USER, APPROVED, "Slack")[0] == startup.DISABLED_MARKER


def test_startup_bad_word_is_exit_2_and_writes_nothing(startup, capsys):
    assert startup.run(["1", "maybe"]) == 2
    assert "use on or off" in capsys.readouterr().err
    assert startup.reg.writes == []


def test_startup_unknown_id_and_non_numeric_id_are_exit_2(startup):
    assert startup.run(["9", "off"]) == 2
    assert startup.run(["x", "off"]) == 2
    assert startup.run(["rm", "x"]) == 2
    assert startup.run(["rm"]) == 2
    assert startup.reg.writes == []


def test_startup_all_users_change_without_administrator_is_exit_1(startup, capsys):
    startup.reg.deny_writes = True        # a terminal that is not elevated: Windows refuses writes to HKLM
    assert startup.run(["2", "off"]) == 1
    assert "administrator" in capsys.readouterr().err


def test_startup_remove_names_the_target_and_declining_deletes_nothing(startup, answers, capsys):
    asked = answers("n")
    assert startup.run(["rm", "1"]) == 0
    assert "Remove Slack from startup?" in asked[0] and "[y/N]" in asked[0]
    assert "cancelled" in capsys.readouterr().out
    assert startup.reg.get(startup.reg.HKEY_CURRENT_USER, RUN, "Slack") == r"C:\slack.exe"


def test_startup_remove_with_yes_deletes_and_reports(startup, capsys):
    assert startup.run(["rm", "1", "--yes"]) == 0
    assert "removed Slack from startup" in capsys.readouterr().out
    assert startup.reg.get(startup.reg.HKEY_CURRENT_USER, RUN, "Slack") is None


# ---------------------------------------------------------------------- process
@pytest.fixture
def process(modules, monkeypatch):
    mod = modules["process"]
    procs = [
        {"pid": 10, "name": "notepad.exe", "memory": 1000, "protected": False},
        {"pid": 11, "name": "notepad.exe", "memory": 1000, "protected": False},
        {"pid": 4, "name": "lsass.exe", "memory": 1000, "protected": True},
    ]
    mod.ended = []
    monkeypatch.setattr(mod, "_processes", lambda: [dict(p) for p in procs])
    monkeypatch.setattr(mod, "_terminate", lambda proc: mod.ended.append(proc["pid"]))
    return mod


def test_prc_kill_asks_naming_the_target_and_no_ends_nothing(process, answers, capsys):
    asked = answers("n")
    assert process.run(["kill", "1"]) == 0
    assert "End lsass.exe?" not in asked[0]            # id 1 is lsass.exe (sorted by name): it is a system process
    assert "Are you sure?" in asked[0]
    assert process.ended == []


def test_prc_kill_system_process_needs_two_yeses(process, answers):
    asked = answers("y", "n")
    process.run(["kill", "1"])
    assert len(asked) == 2 and "last warning" in asked[1]
    assert process.ended == []


def test_prc_kill_user_process_names_the_count_and_ends_every_instance(process, answers, capsys):
    asked = answers("y")
    assert process.run(["kill", "2"]) == 0
    assert "End notepad.exe (2 processes)?" in asked[0]
    assert sorted(process.ended) == [10, 11]
    assert "ended notepad.exe (2 processes)" in capsys.readouterr().out


def test_prc_kill_bad_arguments_are_exit_2(process, capsys):
    for argv in (["kill"], ["kill", "x"], ["kill", "99"], ["kill", "1", "2"]):
        assert process.run(argv) == 2
    assert process.ended == []


# ---------------------------------------------------------------------- apps
@pytest.fixture
def apps(modules, monkeypatch):
    mod = modules["apps"]
    mod.removed = []
    monkeypatch.setattr(mod, "_entries", lambda: [{"id": 1, "name": "Paint.NET", "source": "desktop", "command": "x"}])
    monkeypatch.setattr(mod, "_uninstall", lambda app: mod.removed.append(app["name"]))
    return mod


def test_apps_rm_names_the_app_and_declining_removes_nothing(apps, answers, capsys):
    asked = answers("")
    assert apps.run(["rm", "1"]) == 0
    assert "Uninstall Paint.NET?" in asked[0]
    assert apps.removed == [] and "cancelled" in capsys.readouterr().out


def test_apps_rm_yes_removes_and_reports(apps, capsys):
    assert apps.run(["rm", "1", "--yes"]) == 0
    assert apps.removed == ["Paint.NET"]
    assert "uninstalled Paint.NET" in capsys.readouterr().out


def test_apps_rm_bad_arguments_are_exit_2(apps):
    for argv in (["rm"], ["rm", "x"], ["rm", "9"], ["frob"], ["ls", "extra"]):
        assert apps.run(argv) == 2
    assert apps.removed == []


# ---------------------------------------------------------------------- firewall
@pytest.fixture
def firewall(modules, monkeypatch):
    mod = modules["firewall"]
    mod.commands = []

    def ps(script, timeout=60):
        mod.commands.append(script)
        return "True"
    monkeypatch.setattr(mod, "_ps", ps)
    monkeypatch.setattr(mod, "_profiles", lambda: {n: {"state": "on", "inbound": "block", "outbound": "allow"}
                                                   for n in mod.PROFILES})
    monkeypatch.setattr(mod, "_networks", lambda: [("Cafe Wi-Fi", "public")])
    monkeypatch.setattr(_net, "render", lambda *a, **k: None)
    return mod


def changes(mod):
    return [c for c in mod.commands if c.startswith(("Set-", "New-", "Remove-"))]


def test_fw_bad_profile_is_exit_2_before_the_admin_check(firewall, as_admin, capsys):
    as_admin(False)
    assert firewall.run(["off", "lan"]) == 2
    assert "not a profile" in capsys.readouterr().err
    assert changes(firewall) == []


def test_fw_change_without_administrator_is_exit_1_and_silent(firewall, as_admin, capsys):
    as_admin(False)
    assert firewall.run(["off", "public", "--yes"]) == 1
    captured = capsys.readouterr()
    assert "administrator" in captured.err and "turning" not in captured.out
    assert changes(firewall) == []


def test_fw_off_warns_about_the_public_network_and_declining_changes_nothing(firewall, as_admin, answers, capsys):
    as_admin(True)
    asked = answers("n")
    assert firewall.run(["off", "public"]) == 0
    assert "Cafe Wi-Fi" in asked[0] and "fw on public" in asked[0]
    assert changes(firewall) == []


def test_fw_off_yes_turns_only_the_named_profile_off(firewall, as_admin):
    as_admin(True)
    assert firewall.run(["off", "public", "--yes"]) == 0
    assert changes(firewall) == ["Set-NetFirewallProfile -Profile Public -Enabled False"]


def test_fw_on_needs_no_confirmation(firewall, as_admin):
    as_admin(True)
    assert firewall.run(["on"]) == 0           # input() is blocked, so a prompt would fail this test
    assert changes(firewall) == ["Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"]


# ---------------------------------------------------------------------- events
def test_evt_clear_refuses_without_a_backup_choice_and_asks_for_the_log_name(modules, as_admin, monkeypatch, capsys):
    mod = modules["events"]
    as_admin(True)
    ran = []
    row = {"name": "Application", "records": 5, "size": 1024, "max": 2048, "enabled": True, "mode": "Circular"}
    monkeypatch.setattr(mod, "_log_rows", lambda: [row])
    monkeypatch.setattr(_net, "run_tool", lambda args, timeout=60: ran.append(args) or (True, ""))
    assert mod.run(["clear", "Application"]) == 2
    assert "--backup" in capsys.readouterr().err and ran == []
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")        # anything but the log name cancels
    assert mod.run(["clear", "Application", "--no-backup"]) == 0
    assert ran == []
    monkeypatch.setattr("builtins.input", lambda prompt="": "Application")
    assert mod.run(["clear", "Application", "--no-backup"]) == 0
    assert ran == [["wevtutil", "cl", "Application"]]


# ---------------------------------------------------------------------- location
@pytest.fixture
def location(modules, fake_registry, monkeypatch):
    monkeypatch.delenv("USERDNSDOMAIN", raising=False)
    mod = modules["location"]
    mod.reg = fake_registry
    return mod


def policy(mod):
    return mod.reg.get(mod.reg.HKEY_LOCAL_MACHINE, mod.POLICY_KEY, mod.POLICY_VALUE)


def test_lc_off_without_administrator_is_exit_1_and_writes_nothing(location, as_admin, capsys):
    as_admin(False)
    assert location.run(["off"]) == 1
    captured = capsys.readouterr()
    assert "administrator" in captured.err and "turning" not in captured.out
    assert policy(location) is None


def test_lc_off_as_administrator_sets_the_policy_and_reports(location, as_admin, capsys):
    as_admin(True)
    assert location.run(["off"]) == 0
    assert policy(location) == 1
    assert "location services completely turned off" in capsys.readouterr().out


def test_lc_on_refuses_to_override_an_organisation_policy_without_the_flag(location, as_admin, monkeypatch, capsys):
    as_admin(True)
    location.reg.put(location.reg.HKEY_LOCAL_MACHINE, location.POLICY_KEY, location.POLICY_VALUE, 1)
    monkeypatch.setenv("USERDNSDOMAIN", "CORP.EXAMPLE")
    assert location.run(["on"]) == 1
    assert "policy set by your organisation" in capsys.readouterr().err
    assert policy(location) == 1                                   # untouched
    assert location.run(["on", "--override-management"]) == 0      # the person said so explicitly
    assert policy(location) == 0


def test_lc_bad_words_are_exit_2_and_write_nothing(location, as_admin):
    as_admin(True)
    for argv in (["access", "maybe"], ["access", "on", "off"], ["apps", "x"], ["apps", "99"], ["override", "maybe"],
                 ["frobnicate"], ["off", "now"]):
        assert location.run(argv) == 2, argv
    assert location.reg.writes == []


def test_lc_overview_json_is_valid(location, monkeypatch, capsys):
    monkeypatch.setattr(location, "_service_state", lambda: "stopped")
    assert location.run(["--json"]) == 0
    assert isinstance(json.loads(capsys.readouterr().out), dict)


# ---------------------------------------------------------------------- flags shared by every page
@pytest.mark.parametrize("stem", ["services", "startup", "process", "apps", "firewall"])
def test_help_words_exit_0_without_touching_windows(stem, modules, capsys):
    for word in ("help", "--help", "?"):
        assert modules[stem].run([word]) == 0
    assert capsys.readouterr().out.strip()

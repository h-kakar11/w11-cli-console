"""services: argument validation, administrator checks, confirmation and JSON — against a fake `sc`."""

import json

import pytest

import _net

SC_ALL = """
SERVICE_NAME: Audiosrv
DISPLAY_NAME: Windows Audio
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING

SERVICE_NAME: Spooler
DISPLAY_NAME: Print Spooler
        TYPE               : 110  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
"""


class FakeSc:
    """Answers `sc query`, `sc start`, `sc stop` and `sc config` from a small table, and records every call."""

    def __init__(self):
        self.state = {"Audiosrv": "RUNNING", "Spooler": "STOPPED"}
        self.calls = []

    def __call__(self, args, timeout=60):
        self.calls.append(list(args))
        if args[:2] == ["sc", "query"] and len(args) > 2 and args[2] == "type=":
            return True, SC_ALL
        if args[:2] == ["sc", "query"]:
            return True, f"SERVICE_NAME: {args[2]}\n        STATE              : 4  {self.state[args[2]]}"
        if args[:2] == ["sc", "start"]:
            self.state[args[2]] = "RUNNING"
            return True, ""
        if args[:2] == ["sc", "stop"]:
            self.state[args[2]] = "STOPPED"
            return True, ""
        return True, ""

    def changes(self):
        return [c for c in self.calls if c[:2] in (["sc", "start"], ["sc", "stop"], ["sc", "config"])]


@pytest.fixture
def svc(modules, fake_registry, monkeypatch):
    sc = FakeSc()
    monkeypatch.setattr(_net, "run_tool", sc)
    monkeypatch.setattr(modules["services"].time, "sleep", lambda s: None)
    for name in ("Audiosrv", "Spooler"):
        fake_registry.put(fake_registry.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\" + name, "Start", 2)
    modules["services"].sc = sc
    return modules["services"]


def test_ls_json_lists_every_service(svc, capsys):
    assert svc.run(["ls", "--json"]) == 0
    # ls --json is a list of services, numbered by name
    data = json.loads(capsys.readouterr().out)
    rows = data if isinstance(data, list) else data.get("services", data)
    assert [r["name"] for r in rows] == ["Audiosrv", "Spooler"]
    assert rows[0]["id"] == 1 and rows[1]["state"] == "STOPPED"


def test_show_by_id_and_by_name_in_json(svc, capsys):
    assert svc.run(["2", "--json"]) == 0
    by_id = json.loads(capsys.readouterr().out)
    assert svc.run(["spooler", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == by_id
    assert by_id["name"] == "Spooler" and by_id["startup"] == "auto"


def test_unknown_service_is_exit_2_and_changes_nothing(svc, as_admin, capsys):
    as_admin(True)
    assert svc.run(["99", "on"]) == 2
    assert "no service with id 99" in capsys.readouterr().err
    assert svc.sc.changes() == []


def test_bad_action_word_is_exit_2_before_any_windows_lookup(svc, as_admin, capsys):
    as_admin(True)
    assert svc.run(["2", "frobnicate"]) == 2
    assert "use on, off, restart" in capsys.readouterr().err
    assert svc.sc.calls == []          # not even a read: bad words are rejected first (fashion.txt, rule 8)


def test_too_many_words_is_exit_2_before_any_windows_lookup(svc, capsys):
    assert svc.run(["2", "on", "now"]) == 2
    assert "usage: svc <id>" in capsys.readouterr().err
    assert svc.sc.calls == []


def test_a_bad_word_wins_over_a_missing_administrator(svc, as_admin, capsys):
    as_admin(False)
    assert svc.run(["2", "frobnicate"]) == 2
    capsys.readouterr()


def test_change_without_administrator_is_exit_1_and_changes_nothing(svc, as_admin, capsys):
    as_admin(False)
    for argv in (["2", "on"], ["1", "off", "--yes"], ["2", "restart"], ["2", "disabled", "--yes"]):
        assert svc.run(argv) == 1
        err = capsys.readouterr()
        assert "administrator" in err.err
        assert "starting" not in err.out and "stopping" not in err.out and "restarting" not in err.out
    assert svc.sc.changes() == []


def test_start_reports_what_windows_now_says(svc, as_admin, capsys):
    as_admin(True)
    assert svc.run(["Spooler", "on", "--json"]) == 0
    out = capsys.readouterr().out
    assert json.loads(out[out.index("{"):])["state"] == "RUNNING"
    assert ["sc", "start", "Spooler"] in svc.sc.changes()


def test_starting_a_running_service_says_so_and_does_nothing(svc, as_admin, capsys):
    as_admin(True)
    assert svc.run(["Audiosrv", "on"]) == 0
    assert "already running" in capsys.readouterr().out
    assert svc.sc.changes() == []


def test_stop_names_the_service_asks_first_and_declining_changes_nothing(svc, as_admin, answers, capsys):
    as_admin(True)
    asked = answers("n")
    assert svc.run(["Audiosrv", "off"]) == 0
    assert "Stop Audiosrv (Windows Audio)?" in asked[0]
    assert "[y/N]" in asked[0]
    assert "cancelled" in capsys.readouterr().out
    assert svc.sc.changes() == []


def test_stop_with_yes_flag_does_not_prompt(svc, as_admin, capsys):
    as_admin(True)
    assert svc.run(["Audiosrv", "off", "--yes"]) == 0       # a prompt would hit the blocked input()
    assert ["sc", "stop", "Audiosrv"] in svc.sc.changes()
    assert "stopped" in capsys.readouterr().out


def test_disabled_asks_first_and_names_the_way_back(svc, as_admin, answers):
    as_admin(True)
    asked = answers("no")
    assert svc.run(["Spooler", "disabled"]) == 0
    assert "Spooler" in asked[0] and "manual or auto" in asked[0]
    assert svc.sc.changes() == []


def test_manual_and_auto_need_no_confirmation(svc, as_admin):
    as_admin(True)
    assert svc.run(["Spooler", "manual"]) == 0
    assert ["sc", "config", "Spooler", "start=", "demand"] in svc.sc.changes()

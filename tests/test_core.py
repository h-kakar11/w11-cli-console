"""The shared helpers every page leans on: flags, confirmations, JSON, the admin check."""

import json

import _core


def test_split_flags_removes_known_flags_and_reports_them():
    args, options = _core.split_flags(["12", "off", "--JSON", "--yes"])
    assert args == ["12", "off"]
    assert options == {"json": True, "yes": True}


def test_split_flags_leaves_other_words_alone():
    args, options = _core.split_flags(["--wait", "scan"])
    assert args == ["--wait", "scan"]
    assert options == {"json": False, "yes": False}


def test_confirm_accepts_only_y_and_yes(answers):
    answers("y", "YES", "n", "", "sure", " yes ")
    assert [_core.confirm("ok? ") for _ in range(6)] == [True, True, False, False, False, True]


def test_confirm_yes_flag_skips_the_prompt_and_says_so(capsys):
    assert _core.confirm("Stop it? [y/N]: ", yes=True) is True      # input() is blocked: a prompt would fail the test
    assert "yes (--yes)" in capsys.readouterr().out


def test_confirm_treats_a_closed_terminal_as_no(answers):
    answers()  # no replies queued: input() raises EOFError
    assert _core.confirm("ok? ") is False


def test_print_json_is_valid_json(capsys):
    _core.print_json({"name": "Spooler", "id": 3, "path": __import__("pathlib").Path("x")})
    data = json.loads(capsys.readouterr().out)
    assert data["name"] == "Spooler" and data["id"] == 3


def test_is_admin_follows_windows_and_survives_errors(monkeypatch):
    import ctypes
    monkeypatch.setattr(ctypes.windll.shell32, "IsUserAnAdmin", lambda: 1)
    assert _core.is_admin() is True
    monkeypatch.setattr(ctypes.windll.shell32, "IsUserAnAdmin", lambda: 0)
    assert _core.is_admin() is False

    def broken():
        raise OSError("no shell")
    monkeypatch.setattr(ctypes.windll.shell32, "IsUserAnAdmin", broken)
    assert _core.is_admin() is False


def test_page_help_lists_rows_headings_aliases_and_tip(modules):
    text = _core.page_help(modules["services"])
    assert "services:" in text and "also called: svc" in text
    assert "svc ls" in text and "changes (need an administrator terminal)" in text
    assert modules["services"].TIP in text

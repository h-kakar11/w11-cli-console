"""app.run: which page a command reaches, what the page contract promises, and that names do not collide."""

import pytest

import app
import _core

from conftest import PAGE_FILES

# Pages that are in the folder but cannot be routed yet. Each one is listed with the reason, so the list
# only ever shrinks: a page that gets finished must be removed from here (strict xfail).
UNFINISHED = {"defender": "defender.py stops after its switch table: it has no run(), so app.py cannot route it"}


@pytest.fixture
def routed(modules):
    """The registry as app.py sees it, built from the same pages the other tests use."""
    return _core.registry()


def routable(stem, modules):
    return hasattr(modules[stem], "run")


@pytest.mark.parametrize("stem", [pytest.param(s, marks=pytest.mark.xfail(strict=True, reason=UNFINISHED[s]))
                                  if s in UNFINISHED else s for s in PAGE_FILES])
def test_every_page_file_has_a_run_function(stem, modules):
    assert callable(getattr(modules[stem], "run", None)), f"{stem}.py has no run(args)"


def test_every_finished_page_is_routed_by_its_name(modules, routed):
    for stem, module in modules.items():
        if hasattr(module, "run"):
            assert routed[module.NAME.lower()].NAME == module.NAME


def test_no_name_or_alias_belongs_to_two_pages(modules):
    owners = {}
    for module in modules.values():
        if not hasattr(module, "run"):
            continue
        for key in [module.NAME, *getattr(module, "ALIASES", [])]:
            key = key.lower()
            assert owners.setdefault(key, module.NAME) == module.NAME, (
                f"'{key}' is claimed by {owners[key]} and {module.NAME}")


def test_names_and_aliases_are_lower_case_single_words(modules):
    for module in modules.values():
        for key in [module.NAME, *getattr(module, "ALIASES", [])]:
            assert key == key.lower() and key.split() == [key], f"{module.NAME}: bad name '{key}'"


def test_a_name_is_not_repeated_in_its_own_aliases(modules):
    for module in modules.values():
        aliases = getattr(module, "ALIASES", [])
        assert module.NAME not in aliases, f"{module.NAME} lists itself as an alias"
        assert len(set(aliases)) == len(aliases), f"{module.NAME} repeats an alias"


def test_names_do_not_shadow_the_words_app_treats_as_help(modules):
    for module in modules.values():
        for key in [module.NAME, *getattr(module, "ALIASES", [])]:
            assert key not in _core.HELP_WORDS


@pytest.mark.parametrize("stem", PAGE_FILES)
def test_page_header_follows_the_contract(stem, modules):
    module = modules[stem]
    assert isinstance(module.NAME, str) and module.NAME
    assert isinstance(getattr(module, "ALIASES", []), list)
    assert module.SUMMARY and len(module.SUMMARY) <= 60, f"{stem}: SUMMARY is {len(module.SUMMARY)} characters"
    assert module.USAGE
    for row in getattr(module, "HELP", []):
        assert len(row) == 2 and all(isinstance(part, str) for part in row), f"{stem}: bad HELP row {row!r}"


def test_unknown_setting_is_exit_2(capsys):
    assert app.run(["nosuchpage"]) == 2
    err = capsys.readouterr().err
    assert "unknown setting: nosuchpage" in err


def test_no_arguments_and_help_words_print_usage_and_succeed(capsys):
    for argv in ([], ["help"], ["--help"], ["/?"]):
        assert app.run(argv) == 0
        assert "settings:" in capsys.readouterr().out


def test_usage_lists_every_routable_page_once(routed):
    text = app.usage()
    for module in _core.unique_settings():
        assert text.count(f"  {module.NAME}") >= 1


def test_name_and_alias_reach_the_same_page(routed):
    assert routed["svc"] is routed["services"]
    assert routed["bt"] is routed["bluetooth"]
    assert routed["wu"] is routed["update"]


def test_a_name_alone_shows_the_intro_and_does_not_run_the_page(routed, monkeypatch, capsys):
    called = []
    monkeypatch.setattr(routed["services"], "run", lambda args: called.append(args) or 0)
    assert app.run(["svc"]) == 0
    assert not called
    assert "svc ls" in capsys.readouterr().out


def test_help_word_after_a_name_shows_the_intro(routed, monkeypatch, capsys):
    monkeypatch.setattr(routed["services"], "run", lambda args: pytest.fail("help must not run the page"))
    assert app.run(["svc", "help"]) == 0
    assert "svc ls" in capsys.readouterr().out


def test_arguments_and_exit_code_pass_through(routed, monkeypatch):
    seen = []
    monkeypatch.setattr(routed["services"], "run", lambda args: seen.append(args) or 7)
    assert app.run(["SVC", "12", "restart"]) == 7
    assert seen == [["12", "restart"]]


def test_run_alone_pages_run_when_typed_alone(routed, monkeypatch):
    runs = []
    monkeypatch.setattr(routed["settings"], "run", lambda args: runs.append(args) or 0)
    assert getattr(routed["settings"], "RUN_ALONE", False)
    assert app.run(["settings"]) == 0
    assert runs == [[]]


def test_main_refuses_to_run_off_windows(monkeypatch, capsys):
    monkeypatch.setattr(app.sys, "platform", "linux")
    assert app.main() == 1
    assert "only runs on Windows" in capsys.readouterr().err

"""
Test setup. Nothing in this folder may change the PC it runs on:

- windows_fakes.install() makes the pages importable without Windows.
- guard_windows (autouse) makes any real subprocess, os.startfile or os.system call fail the test, so a page
  that reaches for Windows must be given a fake first.
- fake_registry swaps a dictionary-backed winreg into every page that imports it.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for folder in (ROOT, ROOT / "tests"):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import windows_fakes  # noqa: E402

windows_fakes.install()

import _core  # noqa: E402

PAGE_FILES = sorted(p.stem for p in ROOT.glob("*.py") if p.name != "app.py" and not p.name.startswith("_"))


class Blocked(AssertionError):
    """A test reached the real Windows; give the page a fake instead."""


@pytest.fixture(autouse=True)
def guard_windows(monkeypatch):
    def blocked(what):
        def refuse(*args, **kwargs):
            raise Blocked(f"test tried to use the real {what}: {args!r}")
        return refuse

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, blocked(f"subprocess.{name}"))
    monkeypatch.setattr(os, "startfile", blocked("os.startfile"), raising=False)
    monkeypatch.setattr(os, "system", lambda command: 0 if command == "" else blocked("os.system")(command))
    # pages keep small files in %LOCALAPPDATA%; send them to a throwaway folder if a test gets that far
    monkeypatch.setenv("LOCALAPPDATA", str(ROOT / ".pytest_cache" / "localappdata"))
    # a test that does not say otherwise runs from a terminal that nobody is typing into
    monkeypatch.setattr("builtins.input", blocked("input()"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)


@pytest.fixture(scope="session")
def modules():
    """Every setting page, loaded once: {file stem: module}."""
    import importlib.util
    loaded = {}
    for stem in PAGE_FILES:
        spec = importlib.util.spec_from_file_location(stem, ROOT / f"{stem}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        loaded[stem] = module
    return loaded


@pytest.fixture
def fake_registry(monkeypatch, modules):
    """A FakeRegistry used by every page's `winreg`, and by _win and _net."""
    import _net
    import _win
    fake = windows_fakes.FakeRegistry()
    for module in (*modules.values(), _net, _win):
        if hasattr(module, "winreg"):
            monkeypatch.setattr(module, "winreg", fake)
    return fake


@pytest.fixture
def answers(monkeypatch):
    """Set what the person types at the next prompts: answers("n"), answers("y", "yes"). Returns the questions asked."""
    asked = []

    def give(*replies):
        queue = list(replies)

        def fake_input(prompt=""):
            asked.append(prompt)
            if not queue:
                raise EOFError
            return queue.pop(0)
        monkeypatch.setattr("builtins.input", fake_input)
        return asked
    return give


@pytest.fixture
def as_admin(monkeypatch):
    """Make every admin check say yes (True) or no (False). Covers _core.is_admin and the pages' own checks."""
    def set_admin(value):
        monkeypatch.setattr(_core, "is_admin", lambda: value)
        monkeypatch.setattr("ctypes.windll.shell32.IsUserAnAdmin", lambda: int(value), raising=False)
    return set_admin

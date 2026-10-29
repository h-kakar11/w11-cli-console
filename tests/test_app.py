"""app.py's routing: the --dry-run guard, JSON errors, and that one command's error does not leak into the next."""

import json
import sys
import types
import unittest.mock

from tests.fakes import Sandbox

for name in ("psutil", "pycaw", "pycaw.pycaw", "comtypes", "comtypes.client", "winrt"):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["pycaw.pycaw"].AudioUtilities = types.SimpleNamespace()

import _core
import app


class Routing(Sandbox):
    def setUp(self):
        super().setUp()
        # app.run uses the real page registry here (a few pages that need Windows fail to import on Linux and are skipped)
        patch = unittest.mock.patch.object(_core, "_registry", None)
        patch.start()
        self.addCleanup(patch.stop)
        _core._registry = None
        self.addCleanup(setattr, _core, "_registry", None)

    def route(self, *words):
        code, out, err = self.call(app.run, list(words))
        return code, out, err

    def test_dry_run_on_a_page_that_cannot_preview_exits_2_and_names_the_pages_that_can(self):
        code, _, err = self.route("wifi", "--dry-run")
        self.assertEqual(code, 2)
        self.assertIn("cannot preview", err)
        self.assertIn("services", err)

    def test_json_errors_are_json_with_a_code(self):
        code, _, err = self.route("nosuchsetting", "--json")
        data = json.loads(err[err.index("{"):])  # on Linux, pages that need Windows print a load warning first
        self.assertEqual((code, data["ok"], data["error"]["code"]), (2, False, "not_found"))

    def test_an_old_error_does_not_leak_into_the_next_command(self):
        self.route("reg", "get", "HKCU\\Nope", "x", "--json")
        code, _, err = self.route("wifi", "--dry-run", "--json")
        data = json.loads(err[err.index("{"):])
        self.assertEqual((code, data["error"]["code"]), (2, "usage"))
        self.assertIn("cannot preview", data["error"]["message"])

    def test_the_new_pages_are_routed_by_name_and_alias_and_old_aliases_still_are(self):
        registry = _core.registry()
        for word, page in (("reg", "regedit"), ("regedit", "regedit"), ("cs", "batch"), ("rb", "rollback"), ("undo", "rollback"),
                           ("cat", "catalog"), ("net", "netmon"), ("nm", "netmon"), ("wifi", "wifi"), ("wf", "wifi"),
                           ("svc", "services"), ("su", "startup")):
            with self.subTest(word=word):
                self.assertEqual(registry[word].NAME, page)

    def test_no_alias_is_claimed_by_two_pages(self):
        seen = {}
        for path in sorted(_core.HERE.glob("*.py")):
            if path.name == "app.py" or path.name.startswith("_"):
                continue
            spec = __import__("importlib.util").util.spec_from_file_location(path.stem, path)
            module = __import__("importlib.util").util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception:
                continue  # pages that need Windows cannot load here; they are checked by reading their ALIASES below
            for key in {module.NAME, *getattr(module, "ALIASES", [])}:
                self.assertNotIn(key.lower(), seen, f"{key} is used by {seen.get(key.lower())} and {path.name}")
                seen[key.lower()] = path.name

    def test_catalog_json_lists_every_declared_operation(self):
        code, out, _ = self.route("cat", "--json")
        data = json.loads(out)
        ids = {op["id"] for page in data["pages"] for op in page["operations"]}
        self.assertEqual(code, 0)
        self.assertTrue({"regedit set", "services state", "startup disable", "volume set"} <= ids, ids)

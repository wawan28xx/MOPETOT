"""Test ObjC class-dump parser (engines/objc_dump.py) + iOS hook generator (web/poc_engine.py).

Unit: swift demangler + hook scoring (synthetic corpus dir).
Integrasi (opsional): bila ada scan iOS di web/results dengan sources_ios_symbols,
pastikan loader + hook generator menghasilkan output.
"""
import sys
import json
import unittest
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "web"))

from engines.objc_dump import swift_demangle_partial, dump_binary  # noqa: E402
from poc_engine import generate_ios_hook_script, ios_inspect, _js_escape  # noqa: E402


class TestSwiftDemangle(unittest.TestCase):
    def test_module_class(self):
        self.assertEqual(swift_demangle_partial("_$s9Alamofire7SessionC"), "Alamofire.Session")

    def test_module_class_method(self):
        out = swift_demangle_partial("_$s9Alamofire7SessionC10cachedRespyAA")
        self.assertEqual(out, "Alamofire.Session.cachedResp")

    def test_invalid(self):
        self.assertIsNone(swift_demangle_partial("not_a_swift_symbol"))
        self.assertIsNone(swift_demangle_partial(""))


class TestJsEscape(unittest.TestCase):
    def test_escape(self):
        self.assertEqual(_js_escape("a'b\\c"), "a\\'b\\\\c")


class TestHookGeneratorSynthetic(unittest.TestCase):
    def _make_corpus(self):
        tmp = Path(tempfile.mkdtemp())
        sym = tmp / "sources_ios_symbols"
        sym.mkdir()
        (sym / "MyApp_classes.json").write_text(json.dumps({
            "binary": "MyApp", "arch": "arm64",
            "stats": {"classes": 2, "methods": 3, "categories": 0, "ivars": 0},
            "classes": [
                {"name": "LoginManager", "super": "NSObject", "swift": False,
                 "methods": [["doLogin:password:", "@v@@"], ["viewDidLoad", "v16@0:8"]],
                 "class_methods": [], "ivars": [], "props": [], "protocols": []},
                {"name": "NSString", "super": "NSObject", "swift": False,
                 "methods": [], "class_methods": [], "ivars": [], "props": [], "protocols": []},
            ],
            "categories": [],
        }), encoding="utf-8")
        (sym / "Legacy_classes.h").write_text(
            "// fallback\n// --- Methods / Selectors ---\n"
            "-[OldAuth validateToken:]\n-[OldAuth doStuff]\n", encoding="utf-8")
        return tmp

    def test_hook_selected(self):
        r = generate_ios_hook_script(self._make_corpus())
        sels = {(h["class"], h["selector"]) for h in r["hooks"]}
        self.assertIn(("LoginManager", "doLogin:password:"), sels)
        # selector ObjC mempertahankan ':' (kolon) — frida butuh selector lengkap
        self.assertIn(("OldAuth", "validateToken:"), sels)
        # system class (NSString) & non-interesting selector tidak di-hook
        self.assertNotIn(("LoginManager", "viewDidLoad"), sels)
        self.assertNotIn(("OldAuth", "doStuff"), sels)  # selector tak menarik walau class auth
        self.assertIn("Interceptor.attach", r["script"])
        self.assertIn("ObjC.classes", r["script"])

    def test_inspect(self):
        data = ios_inspect(self._make_corpus())
        self.assertEqual(data["stats"]["binaries"], 2)
        names = {c["class"] for b in data["bins"] for c in b["classes"]}
        self.assertIn("LoginManager", names)
        self.assertIn("OldAuth", names)

    def test_inspect_query(self):
        data = ios_inspect(self._make_corpus(), query="login")
        names = {c["class"] for b in data["bins"] for c in b["classes"]}
        self.assertIn("LoginManager", names)
        self.assertNotIn("OldAuth", names)

    def test_empty_corpus(self):
        tmp = Path(tempfile.mkdtemp())
        r = generate_ios_hook_script(tmp)
        self.assertEqual(r["hooks"], [])
        self.assertIn("rescan", r["note"])


class TestDumpBinary(unittest.TestCase):
    def test_not_macho(self):
        tmp = Path(tempfile.mkdtemp()) / "f.bin"
        tmp.write_bytes(b"\x00" * 64)
        r = dump_binary(tmp)
        self.assertFalse(r["ok"])

    def test_real_binary_if_available(self):
        """Integrasi: pakai binary iOS hasil scan bila ada (skip jika tidak)."""
        cand = None
        results = ROOT / "web" / "results"
        for d in results.iterdir() if results.exists() else []:
            if not d.name.isdigit():
                continue
            for b in (d / "work" / "ipa_root").rglob("*.framework"):
                binp = b / b.name
                if binp.exists():
                    cand = binp
                    break
            if cand:
                break
        if not cand:
            self.skipTest("tidak ada binary iOS di web/results")
        r = dump_binary(cand)
        # hasil sah apapun: ok=True dengan stats, atau error ter-definisi
        self.assertIn("ok", r)
        if r.get("ok"):
            self.assertGreater(r["stats"]["classes"], 0)
            self.assertIn("@interface", r["header"])
        else:
            self.assertTrue(r.get("error"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

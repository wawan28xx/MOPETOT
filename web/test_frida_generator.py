# -*- coding: utf-8 -*-
"""Smoke test RASP-aware Frida bypass generator (deterministic, tanpa network)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import py_compile

py_compile.compile(str(Path(__file__).resolve().parent / "poc_engine.py"), doraise=True)
print("[1] py_compile poc_engine.py OK")

from poc_engine import PoCEngine

eng = PoCEngine()

# --- profil: analisis RASP ---
p = eng._analyze_rasp_profile(
    "TERDETEKSI (runtime protection komersial): free_rasp_dart", ["flutter"],
    [{"category": "Crypto"}])
assert p["commercial"] and p["anti_frida"] and p["flutter"] and p["crypto"]
assert not p["rootbeer"] and not p["anti_vm"] and not p["anti_debug"]

p2 = eng._analyze_rasp_profile("SEBAGIAN (in-app security check: anti-debug (1), anti-VM (9))", [], [])
assert p2["anti_frida"] and p2["anti_debug"] and p2["anti_vm"] and not p2["commercial"]

p3 = eng._analyze_rasp_profile("", [], [])
assert not p3["anti_frida"] and not p3["commercial"] and not p3["flutter"]

p4 = eng._analyze_rasp_profile(
    "TERDETEKSI (library anti-tamper/root-detection: DexGuard (RASP/packer))", [], [])
assert p4["commercial"], "DexGuard via label library harus dianggap komersial"
print("[2] _analyze_rasp_profile OK")

# --- generator: blok sesuai profil ---
js = eng.generate_frida_bypass_script(
    "com.pegadaianagen", [{"category": "Crypto"}],
    "TERDETEKSI (runtime protection komersial): free_rasp_dart", ["flutter"])
for marker in ("ANTI-FRIDA-DETECTION", "RASP KILL-SWITCH GUARD", "CATATAN FLUTTER",
               "CRYPTO DUMPER", "SSL-Conscrypt", "TrustManagerImpl", "check$okhttp"):
    assert marker in js, "hilang: " + marker
assert "com.scottyab.rootbeer" not in js, "RootBeer tidak boleh ada utk target non-RootBeer"
assert "free_rasp_dart" in js and "com.pegadaianagen" in js
print("[3] generator komersial+flutter+crypto OK")

# --- generator: RootBeer ---
js2 = eng.generate_frida_bypass_script(
    "com.greatday.app", [], "TERDETEKSI (library anti-tamper/root-detection: RootBeer (root detection))")
assert "ROOTBEER SPESIFIK" in js2 and "com.scottyab.rootbeer.RootBeer" in js2
assert "CATATAN FLUTTER" not in js2 and "RASP KILL-SWITCH GUARD" not in js2
assert "ANTI-FRIDA-DETECTION" in js2, "proteksi apapun -> anti-frida wajib"
print("[4] generator RootBeer OK")

# --- generator: tanpa RASP -> script minimal ---
js3 = eng.generate_frida_bypass_script("com.target.app", [], "TIDAK TERDETEKSI (tidak ada indikasi runtime protection)")
assert "ANTI-FRIDA-DETECTION" not in js3, "tanpa RASP tidak perlu anti-frida native"
assert "RASP KILL-SWITCH GUARD" not in js3
for marker in ("SSL PINNING BYPASS", "ROOT DETECTION BYPASS", "BIOMETRIC AUTO-PASS"):
    assert marker in js3, "bypass standar harus tetap ada: " + marker
print("[5] generator tanpa RASP OK")

# --- sanity: struktur JS valid ---
for name, j in (("komersial", js), ("rootbeer", js2), ("clean", js3)):
    assert j.count("{") == j.count("}"), "brace imbalance: " + name
    assert "Java.perform" in j and "tryBlock" in j
print("[6] sanity struktur JS OK")

# --- sweep: SEMUA scan existing harus menghasilkan blok yang tepat ---
results_dir = Path(__file__).resolve().parent / "results"
swept = 0
for d in sorted(results_dir.iterdir()):
    fj = d / "findings.json"
    if not fj.is_file():
        continue
    try:
        data = json.loads(fj.read_text(encoding="utf-8"))
    except Exception:
        continue
    meta = data.get("meta") or {}
    rasp = str(meta.get("rasp") or "")
    fw = [str(f).lower() for f in (data.get("frameworks") or [])]
    j = eng.generate_frida_bypass_script(meta.get("package") or "?", data.get("findings") or [], rasp, fw)
    rl = rasp.lower()
    prof = eng._analyze_rasp_profile(rasp, fw, data.get("findings") or [])
    exp = {
        "ANTI-FRIDA-DETECTION": prof["anti_frida"],
        "RASP KILL-SWITCH GUARD": prof["commercial"],
        "ROOTBEER SPESIFIK": "rootbeer" in rl,
        "ANTI-VM BYPASS": "anti-vm" in rl,
        "ptrace hook aktif": "anti-debug" in rl,
        "CATATAN FLUTTER": "flutter" in fw,
    }
    for marker, want in exp.items():
        got = marker in j
        if want and not got:
            raise AssertionError(f"scan {d.name}: blok {marker} harus ada (rasp={rasp[:60]})")
        if (not want) and got:
            raise AssertionError(f"scan {d.name}: blok {marker} tidak perlu (rasp={rasp[:60]})")
    assert j.count("{") == j.count("}"), "brace imbalance scan " + d.name
    swept += 1
print(f"[7] sweep {swept} scan existing OK (blok sesuai RASP masing-masing)")

print("\nALL FRIDA GENERATOR CHECKS PASSED")

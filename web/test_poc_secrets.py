# -*- coding: utf-8 -*-
"""Smoke test Tier 1: Secret PoC generator (deterministic, tanpa network)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import py_compile

py_compile.compile(str(Path(__file__).resolve().parent / "poc_engine.py"), doraise=True)
print("[1] py_compile poc_engine.py OK")

from poc_engine import PoCEngine

eng = PoCEngine()


def sec(rid, m, sev="high", fp="res/values/strings.xml", ln=1):
    return {"rule_id": rid, "match": m, "severity": sev, "file_path": fp,
            "line_number": ln, "category": "x", "context": ""}


# --- dispatcher: klasifikasi tipe ---
K = PoCEngine._secret_kind
assert K("gcp_api_key", "AIzaSyB00000000000000000000000000000000") == "google_api_key"
assert K("AWS_KEY", "AKIAIOSFODNN7EXAMPLE") == "aws"
assert K("x", "sk_live_abc123") == "stripe"
assert K("x", "https://hooks.slack.com/services/T1/B2/xxx") == "slack_webhook"
assert K("x", "https://discord.com/api/webhooks/1/abc") == "discord_webhook"
assert K("x", "ghp_abc123") == "github_token"
assert K("x", "SG.abc.def") == "sendgrid"
assert K("x", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") == "jwt"
assert K("x", "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----") == "private_key"
assert K("firebase_url", "https://app.firebaseio.com") == "firebase_url"
assert K("login_credential_pair", "user:pass") == "generic_credential"
assert K("aes_key_hex_32", "a1b2c3d4") == "crypto_material"
assert K("email_address", "a@b.com") == ""
assert K("gcp_oauth_client_id", "123.apps.googleusercontent.com") == "oauth_client_id"
print("[2] _secret_kind dispatcher OK")


# --- PoC google api key ---
p = eng.generate_secret_poc(sec("gcp_api_key", "AIzaSyB00000000000000000000000000000000"))
assert p and p["poc_type"] == "google_api_key" and p["mode"] == "PASIF"
assert "generativelanguage.googleapis.com" in p["code"]
assert "AIzaSyB00000000000000000000000000000000" in p["code"]
assert p["language"] == "python"
print("[3] google_api_key PoC OK")


# --- PoC firebase URL ---
p = eng.generate_secret_poc(sec("firebase_url", "https://app.firebaseio.com", "medium"))
assert p and p["mode"] == "PASIF" and ".json" in p["code"] and "PUT" in p["code"]
print("[4] firebase_url PoC OK")


# --- PoC JWT decode ---
p = eng.generate_secret_poc(sec("hardcoded_jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"))
assert p and p["language"] == "python" and "urlsafe_b64decode" in p["code"]
print("[5] jwt PoC OK")


# --- PoC private key ---
p = eng.generate_secret_poc(sec("rsa_private_key", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----", "critical"))
assert p and p["language"] == "bash" and "openssl pkey" in p["code"]
print("[6] private_key PoC OK")


# --- PoC slack webhook: mode AKTIF ---
p = eng.generate_secret_poc(sec("slack_webhook", "https://hooks.slack.com/services/T1/B2/xxx"))
assert p and p["mode"] == "AKTIF" and "curl" in p["code"]
print("[7] slack_webhook PoC (AKTIF) OK")


# --- PoC generic credential: mode TEMPLATE ---
p = eng.generate_secret_poc(sec("login_credential_pair", "SamplePass123!FixtureOnly000000"))
assert p and p["mode"] == "TEMPLATE" and "Basic" in p["code"]
print("[8] generic_credential PoC (TEMPLATE) OK")


# --- bulk: filter severity + dedupe + cap ---
secs = [
    sec("gcp_api_key", "AIzaSyAAA", "high"),
    sec("gcp_api_key", "AIzaSyAAA", "high"),      # duplikat nilai -> dedupe
    sec("gcp_api_key", "AIzaSyBBB", "high"),
    sec("email_address", "a@b.com", "low"),        # low -> dilewati
    sec("hardcoded_password", "secret123", "medium"),
]
secs += [sec("gcp_api_key", "AIzaSy%02d" % i, "high") for i in range(40)]
pocs = eng.generate_secret_pocs(secs)
values = [p["match"] for p in pocs]
assert len(values) == len(set(values)), "harus dedupe"
assert all(p["severity"].lower() != "low" for p in pocs), "low harus terfilter"
assert len(pocs) <= 30, "cap 30"
assert "a@b.com" not in values
print(f"[9] bulk filter+dedupe+cap OK ({len(pocs)} PoC dari {len(secs)} temuan)")


# --- semua PoC: field wajib ada ---
for poc in pocs:
    for f in ("poc_type", "title", "severity", "file_path", "match", "code", "language", "mode", "rule_id"):
        assert poc.get(f) not in (None, ""), f"field {f} kosong di {poc.get('poc_type')}"
    assert poc["mode"] in ("PASIF", "AKTIF", "TEMPLATE")
print("[10] field wajib semua PoC OK")

print("\nALL SECRET POC CHECKS PASSED")

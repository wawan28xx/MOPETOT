"""Test: rule PEM tidak lagi match header doang, tapi tetap match key asli."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secret_scanner import load_rules, scan_corpus

REAL_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJK
LMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv
-----END RSA PRIVATE KEY-----"""

LABELS_ONLY = """-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----END EC PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
unknown
"""

CERT_REAL = """-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIE1234567890abcdefghijklmnopqrstuvwxyzABCD
EFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop
-----END CERTIFICATE-----"""

tmp = Path(tempfile.mkdtemp())
corpus = tmp / "corpus"
(corpus / "strings_native").mkdir(parents=True)
(corpus / "strings_native/AAINetwork.strings").write_text(LABELS_ONLY, encoding="utf-8")
(corpus / "assets").mkdir()
(corpus / "assets/real_key.pem").write_text(REAL_KEY, encoding="utf-8")
(corpus / "assets/cert.pem").write_text(CERT_REAL, encoding="utf-8")

rules = load_rules()
findings, stats = scan_corpus(corpus, rules, quiet=True)

by_rule = {}
for f in findings:
    by_rule.setdefault(f.rule.id, []).append(f)

print("temuan:", {k: len(v) for k, v in by_rule.items()})

# 1. Label PEM sendirian TIDAK boleh dilaporkan
assert not any("strings_native" in f.filepath for f in findings), "label PEM masih dilaporkan!"
print("[1] Label PEM tanpa body -> TIDAK dilaporkan OK")

# 2. Private key asli (dengan base64 body) HARUS dilaporkan
rsa = [f for f in by_rule.get("rsa_private_key", []) if "real_key.pem" in f.filepath]
assert rsa, "private key asli harus terdeteksi!"
m = rsa[0].match
assert "-----BEGIN RSA PRIVATE KEY-----" in m and len(m) > 40, m
print("[2] RSA private key asli terdeteksi OK | match:", repr(m[:70]) + "...")

# 3. Certificate asli juga terdeteksi
cert = [f for f in by_rule.get("certificate_pem", []) if "cert.pem" in f.filepath]
assert cert, "certificate asli harus terdeteksi!"
print("[3] Certificate asli terdeteksi OK")

print("\nALL PEM RULE CHECKS PASSED")

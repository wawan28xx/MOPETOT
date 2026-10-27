# -*- coding: utf-8 -*-
"""Smoke test Credential Login Tester (mock requests — tanpa network)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import py_compile
py_compile.compile(str(Path(__file__).resolve().parent / "verification.py"), doraise=True)
print("[1] py_compile verification.py OK")

import verification


class FakeResp:
    def __init__(self, status=200, text="", cookies=""):
        self.status_code = status
        self.text = text
        self.headers = {"Set-Cookie": cookies} if cookies else {}


def run_case(name, responses, url="https://api.target.test/login", user="u", pw="p", expect=""):
    """responses: list of (status, text, setcookie) dipakai berurutan per request."""
    seq = list(responses)

    def fake_request(method, u, timeout=10.0, verify=False, **kw):
        return FakeResp(*seq.pop(0))

    real_req = verification.requests.request
    verification.requests.request = fake_request
    try:
        out = verification.check_credential_login(url, user, pw)
    finally:
        verification.requests.request = real_req
    got = out.get("verdict")
    mark = "OK  " if got == expect else "FAIL"
    print(f"[{mark}] {name:38} -> {got} (harus {expect})")
    assert got == expect, f"{name}: {got} != {expect}"
    return out


# 1. VALID: 2xx + token di body (baseline 401)
run_case("auth-gate: 2xx setelah 401 baseline",
         [(401, "unauthorized", ""), (200, '{"access_token":"eyJhbGciOiJFUzI1NiJ9.x"}', "")],
         expect="VALID_LOGIN")

# 2. VALID: 200 + Set-Cookie session (urutan request: baseline, json:username[break], form, basic)
run_case("2xx + Set-Cookie session",
         [(200, "welcome", ""), (200, "", "SESSIONID=abc123; Path=/"),
          (200, "welcome", ""), (200, "welcome", "")],
         expect="VALID_LOGIN")

# 3. INVALID: semua 401/403
run_case("401 di semua metode",
         [(401, "no", ""), (401, "no", ""), (401, "no", ""), (401, "no", ""), (401, "no", "")],
         expect="INVALID")

# 4. INCONCLUSIVE: 2xx polos sama seperti baseline
run_case("200 polos (bukan endpoint login)",
         [(200, "ok", ""), (200, "ok", ""), (200, "ok", ""), (200, "ok", ""), (200, "ok", "")],
         expect="INCONCLUSIVE")

# 5. LIKELY: 2xx dengan respons jelas beda dari baseline
run_case("2xx beda jauh dari baseline",
         [(200, "login page html" * 10, ""), (200, '{"success":true,"user_id":42,"role":"admin"}', ""),
          (200, "login page html" * 10, ""), (200, "login page html" * 10, ""), (200, "login page html" * 10, "")],
         expect="LIKELY_VALID")

# 6. ERROR: input salah
out = verification.check_credential_login("ftp://x", "u", "p")
assert out["verdict"] == "ERROR", out
out = verification.check_credential_login("https://x", "", "")
assert out["verdict"] == "ERROR", out
print("[OK  ] input invalid -> ERROR")

# 7. ERROR: koneksi gagal semua
def fail_req(*a, **kw):
    raise verification.requests.exceptions.ConnectionError("down")

verification.requests.request = fail_req
try:
    out = verification.check_credential_login("https://mati.test/api", "u", "p")
finally:
    pass
assert out["verdict"] == "ERROR", out
print("[OK  ] semua koneksi gagal -> ERROR (bukan INVALID)")

# 8. evidence terisi
seq = [(401, "unauthorized", ""), (401, "no", ""), (401, "no", ""), (401, "no", ""), (401, "no", "")]
def fake2(method, u, timeout=10.0, verify=False, **kw):
    return FakeResp(*seq.pop(0))
verification.requests.request = fake2
out = verification.check_credential_login("https://x.test/login", "u", "p")
assert out["evidence"] and "401" in out["evidence"], out
print("[OK  ] evidence attempts terisi")

print("\nALL CREDENTIAL LOGIN CHECKS PASSED")

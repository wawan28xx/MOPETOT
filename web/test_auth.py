"""Test auth Mopetot — login page, session, proteksi route, logout."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient

import app as app_module
from auth import SESSION_COOKIE

client = TestClient(app_module.app)


def test_auth_flow():
    # 1. Tanpa session: halaman redirect ke /login
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login", r.status_code
    print("[1] GET / tanpa session -> 303 /login OK")

    # 2. API tanpa session -> 401 JSON
    r = client.get("/api/scan/59/secrets")
    assert r.status_code == 401 and r.json()["detail"] == "Not authenticated"
    print("[2] GET /api/... tanpa session -> 401 OK")

    # 3. Halaman login ke-render
    r = client.get("/login")
    assert r.status_code == 200 and "MOPETOT" in r.text and "Jack In" in r.text
    print("[3] GET /login -> 200, logo MOPETOT + form OK")

    # 4. Kredensial salah -> 401 + ACCESS DENIED
    r = client.post("/login", data={"username": "mopetot", "password": "salah"}, follow_redirects=False)
    assert r.status_code == 401 and "ACCESS DENIED" in r.text
    print("[4] Login password salah -> 401 ACCESS DENIED OK")

    # 5. Kredensial default benar -> 303 + cookie httponly
    r = client.post("/login", data={"username": "mopetot", "password": "P@petot"}, follow_redirects=False)
    assert r.status_code == 303, r.status_code
    cookie = r.cookies.get(SESSION_COOKIE)
    assert cookie, "cookie session tidak ter-set"
    print("[5] Login default (mopetot / P@petot) -> 303 + cookie session OK")

    # 6. Dengan session: halaman & API bisa diakses
    r = client.get("/")
    assert r.status_code == 200 and "cp-logo-word" in r.text, r.status_code
    r2 = client.get("/api/scan/59/secrets")
    assert r2.status_code == 200
    print("[6] GET / + API dengan session -> 200 OK")

    # 7. Logout -> cookie dihapus, akses ditolak lagi
    r = client.get("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r2 = client.get("/", follow_redirects=False)
    assert r2.status_code == 303
    print("[7] Logout -> redirect /login + session invalid OK")

    # 8. Override env kredensial
    import os
    os.environ["MOPETOT_USER"] = "nightcity"
    os.environ["MOPETOT_PASS"] = "choom2077"
    r = client.post("/login", data={"username": "nightcity", "password": "choom2077"}, follow_redirects=False)
    assert r.status_code == 303, "env override harus bisa login"
    r2 = client.post("/login", data={"username": "mopetot", "password": "P@petot"}, follow_redirects=False)
    assert r2.status_code == 401, "kredensial default harus ditolak saat di-override"
    print("[8] Override env MOPETOT_USER/MOPETOT_PASS OK")
    os.environ.pop("MOPETOT_USER")
    os.environ.pop("MOPETOT_PASS")

    print("\nALL AUTH CHECKS PASSED")


test_auth_flow()

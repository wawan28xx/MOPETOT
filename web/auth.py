"""Auth Mopetot — session in-memory + cookie httponly.

Kredensial default: mopetot / P@petot (override via env MOPETOT_USER /
MOPETOT_PASS). Session disimpan di memori: restart server = login ulang.
"""
import os
import secrets
import time

DEFAULT_USER = "mopetot"
DEFAULT_PASS = "P@petot"
SESSION_COOKIE = "mopetot_session"
SESSION_TTL = 12 * 3600  # 12 jam

# token -> expiry
_sessions: dict = {}


def get_user() -> str:
    return os.environ.get("MOPETOT_USER") or DEFAULT_USER


def get_pass() -> str:
    return os.environ.get("MOPETOT_PASS") or DEFAULT_PASS


def login(username: str, password: str):
    """Return token session jika kredensial valid, selain itu None."""
    ok_user = secrets.compare_digest(str(username or ""), get_user())
    ok_pass = secrets.compare_digest(str(password or ""), get_pass())
    if ok_user and ok_pass:
        _prune()
        token = secrets.token_urlsafe(32)
        _sessions[token] = time.time() + SESSION_TTL
        return token
    return None


def valid(token) -> bool:
    exp = _sessions.get(token or "")
    return bool(exp and exp > time.time())


def logout(token) -> None:
    _sessions.pop(token or "", None)


def _prune() -> None:
    now = time.time()
    for t in [t for t, exp in _sessions.items() if exp < now]:
        _sessions.pop(t, None)

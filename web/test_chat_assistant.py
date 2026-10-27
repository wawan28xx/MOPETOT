"""Smoke test Verification Assistant (chat) — tanpa mengubah DB asli & tanpa network."""
import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

import py_compile

WEB = Path(__file__).resolve().parent
sys.path.insert(0, str(WEB))

for f in ("chat.py", "app.py", "database/db.py"):
    py_compile.compile(str(WEB / f), doraise=True)
print("[1] py_compile OK: chat.py, app.py, database/db.py")

# --- gunakan salinan DB supaya DB asli tidak tersentuh ---
tmpdir = tempfile.mkdtemp()
db_copy = Path(tmpdir) / "test.db"
shutil.copy(WEB / "database/mobile_audit.db", db_copy)

import database.db as dbm
dbm.DB_PATH = str(db_copy)

import chat

# --- nilai secret utuh (masking dihapus by design: bantu validasi manual pentester) ---
RAW_KEY = "AIzaSyABCDEF1234567890abcdefghij"
assert not hasattr(chat, "mask_secret"), "mask_secret harus sudah dihapus"
print("[2] masking dihapus OK")

# --- skills: playbook + context terbaca untuk system prompt ---
skills_txt = chat.load_skills()
assert "verification-playbook" in skills_txt.lower() or "VERDICT" in skills_txt
assert len(skills_txt) <= chat.SKILLS_TOTAL_CAP + 200
print(f"[2b] load_skills OK ({len(skills_txt)} chars)")

# --- build_validation_message: nilai secret UTUH masuk prompt (bantu validasi manual) ---
_secret = {
    "rule_id": "google_api_key", "category": "Google", "severity": "HIGH",
    "file_path": "res/values/strings.xml", "line_number": 4086,
    "match": RAW_KEY,
    "context": '<string name="google_api_key">' + RAW_KEY + '</string>',
}
_ev = "Google API key " + RAW_KEY + " RESTRICTED di 10 scopes"
_msg = chat.build_validation_message(_secret, "google-api", RAW_KEY, _ev)
assert RAW_KEY in _msg, "nilai secret utuh harus masuk prompt validasi!"
assert "- Target: " + RAW_KEY in _msg
assert "VERDICT" in _msg
_msg_nosecret = chat.build_validation_message(None, "firebase", "https://x.firebaseio.com", "")
assert "firebase" in _msg_nosecret
print("[2c] build_validation_message OK (nilai utuh, tanpa secret juga aman)")

# --- config: default = vibe CLI, model glm-5-3 ---
for k in ("MOBILE_AUDIT_LLM_PROVIDER", "MOBILE_AUDIT_LLM_MODEL",
          "MOBILE_AUDIT_LLM_BASE_URL", "MOBILE_AUDIT_LLM_API_KEY",
          "MOBILE_AUDIT_VIBE_CMD", "MOBILE_AUDIT_VIBE_TIMEOUT",
          "MISTRAL_API_KEY", "OPENCODE_API_KEY"):
    os.environ.pop(k, None)
cfg = chat.get_llm_config()
assert cfg["provider"] == "vibe", cfg
assert cfg["model"] == "glm-5-3", cfg
assert cfg["configured"] == bool(chat._find_vibe_cmd()), cfg
print("[3] get_llm_config (default vibe / glm-5-3) OK, configured =", cfg["configured"])

# --- config: fallback mistral masih jalan ---
os.environ["MOBILE_AUDIT_LLM_PROVIDER"] = "mistral"
os.environ["MISTRAL_API_KEY"] = "test-key"
cfg = chat.get_llm_config()
assert cfg["configured"] and cfg["provider"] == "mistral"
assert cfg["base_url"] == "https://api.mistral.ai/v1"
assert cfg["model"] == "mistral-small-latest"
print("[4] get_llm_config (fallback mistral) OK")

# --- config: opencode ---
os.environ["MOBILE_AUDIT_LLM_PROVIDER"] = "opencode"
os.environ["OPENCODE_API_KEY"] = "zen-key"
os.environ["MOBILE_AUDIT_LLM_MODEL"] = "some-model"
cfg = chat.get_llm_config()
assert cfg["configured"] and cfg["provider"] == "opencode"
print("[5] get_llm_config (fallback opencode) OK")

# --- context builder: nilai secret UTUH (bantu validasi manual pentester) ---
os.environ.pop("MOBILE_AUDIT_LLM_PROVIDER", None)
secret = {
    "rule_id": "gcp_api_key", "category": "GCP", "severity": "high",
    "file_path": "assets/config.json", "line_number": 42,
    "match": "AIzaSyABCDEF1234567890abcdefghij",
    "context": 'api_key = "AIzaSyABCDEF1234567890abcdefghij"\nmode = "prod"',
}
verifier = [{"module": "google", "target": "AIzaSyABCDEF1234567890abcdefghij",
             "result_html": "<b>VALID</b> key aktif"}]
ctx = chat.build_finding_context(secret, verifier)
assert "AIzaSyABCDEF1234567890abcdefghij" in ctx, "nilai secret utuh harus ada di context!"
assert "- Nilai: AIzaSyABCDEF1234567890abcdefghij" in ctx
assert "VALID key aktif" in ctx
print("[6] build_finding_context OK (nilai secret utuh)")

# --- vibe completion: mock subprocess, validasi command + env + prompt ---
for k in ("MOBILE_AUDIT_LLM_PROVIDER", "MOBILE_AUDIT_LLM_MODEL",
          "MISTRAL_API_KEY", "OPENCODE_API_KEY"):
    os.environ.pop(k, None)
os.environ["MOBILE_AUDIT_VIBE_CMD"] = "vibe"  # biar configured=True
captured = {}

class FakeProc:
    def __init__(self, lines, err_lines=(), returncode=0):
        self.returncode = returncode
        self._out = iter(list(lines))
        self._err = iter(list(err_lines))
    @property
    def stdout(self):
        return self._out
    @property
    def stderr(self):
        return self._err
    def wait(self, timeout=None):
        return 0
    def kill(self):
        pass

def fake_popen(cmd, **kwargs):
    captured["cmd"] = cmd
    captured["env"] = kwargs.get("env", {})
    return FakeProc(["jawaban analisis dari vibe\n"])

real_popen = chat.subprocess.Popen
chat.subprocess.Popen = fake_popen
try:
    reply = chat.ask_assistant(secret, verifier, [], "analisis dong")
finally:
    chat.subprocess.Popen = real_popen

assert reply == "jawaban analisis dari vibe"
cmd = captured["cmd"]
assert cmd[0] == "vibe" and cmd[1] == "-p" and "--output" in cmd and "text" in cmd, cmd
assert captured["env"].get("VIBE_ACTIVE_MODEL") == "glm-5-3", captured["env"]
assert "AIzaSyABCDEF1234567890abcdefghij" in cmd[2], "nilai secret utuh harus ikut ke prompt vibe"
assert "JANGAN menjalankan tools" in cmd[2]
assert "INSTRUKSI SISTEM" in cmd[2] and "PERTANYAAN HUNTER" in cmd[2]
print("[7] vibe completion OK (command + VIBE_ACTIVE_MODEL + prompt utuh)")

# --- vibe error path: exit != 0 tanpa output -> retry lalu ChatError ---
os.environ["MOBILE_AUDIT_VIBE_RETRIES"] = "0"
def fake_popen_err(cmd, **kwargs):
    return FakeProc([], ["boom"], returncode=1)
chat.subprocess.Popen = fake_popen_err
try:
    chat.ask_assistant(secret, None, [], "tes")
    raise AssertionError("harusnya raise ChatError")
except chat.ChatError as e:
    assert "exit 1" in str(e) and "boom" in str(e), str(e)
finally:
    chat.subprocess.Popen = real_popen
    os.environ.pop("MOBILE_AUDIT_VIBE_RETRIES", None)
print("[8] vibe error path OK (exit != 0 tanpa jawaban -> ChatError + retry)")

# --- vibe robust: exit != 0 tapi jawaban keluar -> jawaban dipakai ---
chat.subprocess.Popen = lambda cmd, **kw: FakeProc(["jawaban utuh\n"], ["warn x"])
try:
    r2 = chat.ask_assistant(secret, None, [], "tes")
    assert r2 == "jawaban utuh", r2
finally:
    chat.subprocess.Popen = real_popen
print("[8b] vibe robust path OK (exit != 0 dengan jawaban -> jawaban dipakai)")

# --- HTTP fallback: dipatch requests.post biar tanpa network ---
os.environ["MOBILE_AUDIT_LLM_PROVIDER"] = "mistral"
os.environ["MISTRAL_API_KEY"] = "test-key"

class FakeResp:
    status_code = 200
    def json(self):
        return {"choices": [{"message": {"content": "jawaban http"}}]}
chat.requests.post = lambda *a, **kw: FakeResp()
reply = chat.ask_assistant(secret, verifier, [], "analisis via http")
assert reply == "jawaban http"
os.environ.pop("MOBILE_AUDIT_LLM_PROVIDER", None)
print("[9] HTTP fallback provider OK (mock)")

# --- DB helpers ---
async def db_test():
    await dbm.init_db()
    db = await dbm.get_db()
    try:
        cur = await db.execute("SELECT id FROM scans LIMIT 1")
        row = await cur.fetchone()
        scan_id = row["id"] if row else 999999
        await dbm.insert_chat_message(db, scan_id, 77, "user", "tes pertanyaan")
        await dbm.insert_chat_message(db, scan_id, 77, "assistant", "tes jawaban")
        hist = await dbm.get_chat_history(db, scan_id, 77)
        assert len(hist) == 2 and hist[0]["role"] == "user"
        general = await dbm.get_chat_history(db, scan_id)
        assert len(general) == 0  # tanpa secret_id = null bucket
        await dbm.clear_chat_history(db, scan_id, 77)
        hist = await dbm.get_chat_history(db, scan_id, 77)
        assert len(hist) == 0
        return scan_id
    finally:
        await db.close()

scan_id = asyncio.run(db_test())
print(f"[10] chat_history helpers OK (scan_id={scan_id})")

shutil.rmtree(tmpdir)
print("\nALL CHECKS PASSED")

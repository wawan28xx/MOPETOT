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

# --- masking ---
assert chat.mask_secret("AIzaSyABCDEF1234567890abcdefghij") == "AIzaSy********ghij"
assert chat.mask_secret("short") == "sh****"
assert chat.mask_secret("") == ""
print("[2] mask_secret OK")

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

# --- context builder: secret harus ter-mask ---
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
assert "AIzaSyABCDEF1234567890abcdefghij" not in ctx, "SECRET MENTAH BOCOR DI CONTEXT!"
assert "AIzaSy********ghij" in ctx
assert "VALID key aktif" in ctx
print("[6] build_finding_context OK (secret ter-mask)")

# --- vibe completion: mock subprocess, validasi command + env + prompt ---
for k in ("MOBILE_AUDIT_LLM_PROVIDER", "MOBILE_AUDIT_LLM_MODEL",
          "MISTRAL_API_KEY", "OPENCODE_API_KEY"):
    os.environ.pop(k, None)
os.environ["MOBILE_AUDIT_VIBE_CMD"] = "vibe"  # biar configured=True
captured = {}

class FakeCompleted:
    returncode = 0
    stdout = "jawaban analisis dari vibe"
    stderr = ""

def fake_run(cmd, **kwargs):
    captured["cmd"] = cmd
    captured["env"] = kwargs.get("env", {})
    return FakeCompleted()

real_run = chat.subprocess.run
chat.subprocess.run = fake_run
try:
    reply = chat.ask_assistant(secret, verifier, [], "analisis dong")
finally:
    chat.subprocess.run = real_run

assert reply == "jawaban analisis dari vibe"
cmd = captured["cmd"]
assert cmd[0] == "vibe" and cmd[1] == "-p" and "--output" in cmd and "text" in cmd, cmd
assert captured["env"].get("VIBE_ACTIVE_MODEL") == "glm-5-3", captured["env"]
assert "AIzaSyABCDEF1234567890abcdefghij" not in cmd[2], "SECRET MENTAH DI PROMPT VIBE!"
assert "AIzaSy********ghij" in cmd[2]
assert "JANGAN menjalankan tools" in cmd[2]
assert "INSTRUKSI SISTEM" in cmd[2] and "PERTANYAAN HUNTER" in cmd[2]
print("[7] vibe completion OK (command + VIBE_ACTIVE_MODEL + prompt ter-mask)")

# --- vibe error path: exit code != 0 ---
def fake_run_err(cmd, **kwargs):
    return type("Err", (), {"returncode": 1, "stdout": "", "stderr": "boom"})()
chat.subprocess.run = fake_run_err
try:
    chat.ask_assistant(secret, None, [], "tes")
    raise AssertionError("harusnya raise ChatError")
except chat.ChatError as e:
    assert "exit code 1" in str(e) and "boom" in str(e)
finally:
    chat.subprocess.run = real_run
print("[8] vibe error path OK")

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

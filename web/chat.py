"""Verification Assistant — AI chatbox untuk membantu verifikasi temuan hardcoded secrets.

BACKEND DEFAULT: Mistral Vibe CLI (lokal, single-line command):
    vibe -p "<prompt>" --output text        # model dipilih via env VIBE_ACTIVE_MODEL

Model default: alias "glm-5-3" (dari ~/.vibe/config.toml milik user).
Override: MOBILE_AUDIT_LLM_MODEL (alias model vibe), MOBILE_AUDIT_VIBE_CMD (path
executable vibe bila tidak di PATH), MOBILE_AUDIT_VIBE_TIMEOUT (detik).

Fallback opsional (provider HTTP OpenAI-compatible) via env:
  MOBILE_AUDIT_LLM_PROVIDER = mistral | opencode | custom
  MOBILE_AUDIT_LLM_BASE_URL / MOBILE_AUDIT_LLM_API_KEY / MOBILE_AUDIT_LLM_MODEL

PENTING: nilai secret diberikan UTUH (tanpa masking) ke provider — ini memang
dibutuhkan pentester untuk validasi manual pada audit berizin.
"""
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# ---------------- Skills (folder ../skills, di-inject ke system prompt) ----------
SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
SKILLS_TOTAL_CAP = 9000  # total karakter semua skill yang di-inject ke prompt
_skills_cache = {"mtime": None, "text": ""}


def load_skills() -> str:
    """Baca semua skills/*.md -> satu blok teks untuk system prompt.

    Cache mtime: reload hanya jika ada file yang berubah/berkurang.
    Cap total SKILLS_TOTAL_CAP karakter (sisanya dipotong + penanda).
    """
    try:
        files = sorted(SKILLS_DIR.glob("*.md")) if SKILLS_DIR.is_dir() else []
        stamp = tuple((f.name, f.stat().st_mtime, f.stat().st_size) for f in files)
    except OSError:
        files, stamp = [], None
    if stamp == _skills_cache["mtime"]:
        return _skills_cache["text"]

    parts = []
    total = 0
    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not content:
            continue
        room = SKILLS_TOTAL_CAP - total
        if room <= 200:
            break
        if len(content) > room:
            content = content[:room] + "\n[TRUNCATED - kurangi ukuran skill]"
        parts.append("### SKILL: " + f.stem.upper() + "\n" + content)
        total += len(content)

    text = "\n\n".join(parts)
    _skills_cache["mtime"] = stamp
    _skills_cache["text"] = text
    return text


def build_validation_message(secret, module: str, target: str,
                             evidence: str) -> str:
    """Bangun prompt VALIDASI temuan (fitur Validate with Agent di Live Verifier)."""
    lines = ["VALIDATION REQUEST - ikuti verification playbook."]
    if secret:
        lines.append(
            "- Rule: %s | Category: %s | Severity awal: %s" % (
                secret.get("rule_id") or "-",
                secret.get("category") or "-",
                secret.get("severity") or "-"))
        lines.append("- File: %s line %s" % (
            secret.get("file_path") or "-", secret.get("line_number") or "?"))
        ctx = (secret.get("context") or "").strip()
        if ctx:
            lines.append("- Kode sekitar: " + ctx[:300])
    lines.append("- Live Verifier module: " + (module or "-"))
    lines.append("- Target: " + (target or "-"))
    if evidence:
        lines.append("- Hasil verifier: " + evidence[:600])
    else:
        lines.append("- Hasil verifier: belum dijalankan (nyatakan di verdict).")
    lines.append("Berikan: VERDICT (CONFIRMED/LIKELY/UNCONFIRMED) + EVIDENCE + "
                 "LATERAL MOVEMENT + SEVERITY (P1-P5) + NEXT SAFE STEPS.")
    return "\n".join(lines)

VIBE_DEFAULT_MODEL = "glm-5-3"        # alias model di ~/.vibe/config.toml
VIBE_DEFAULT_TIMEOUT = 240            # detik; override MOBILE_AUDIT_VIBE_TIMEOUT
VIBE_MAX_TURNS = "2"                  # cukup untuk Q&A tanpa tool loop
VIBE_RETRIES = 2                       # retry saat vibe gagal transient (rate limit dsb.)


def _vibe_attempt(cmd: List[str], env: dict, timeout: float,
                  log: Optional[Any] = None):
    """Satu percobaan jalankan vibe. Return (reply, exit_code, stderr_tail).

    stdout/stderr di-stream per baris ke `log` bila diberikan (live UI).
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        env=env, cwd=tempfile.gettempdir(),
    )
    stdout_chunks: List[str] = []
    stderr_lines: List[str] = []

    def _pump(stream, prefix: str, collect_out: bool, collect_err: bool):
        try:
            for line in stream:
                line = line.rstrip()
                if not line:
                    continue
                if log:
                    log(prefix + line)
                if collect_out:
                    stdout_chunks.append(line)
                if collect_err:
                    stderr_lines.append(line)
        except Exception:
            pass

    out_thread = threading.Thread(target=_pump, args=(proc.stdout, "📡 vibe> ", True, False), daemon=True)
    err_thread = threading.Thread(target=_pump, args=(proc.stderr, "⚠️ vibe> ", False, True), daemon=True)
    out_thread.start()
    err_thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
    out_thread.join(timeout=5)
    err_thread.join(timeout=5)
    reply = "\n".join(stdout_chunks).strip()
    if timed_out:
        # deadline: jawaban parsial/utuh yang sudah keluar tetap dipakai
        return reply, 124, "timeout (jawaban parsial diterima bila ada)"
    return reply, proc.returncode, "\n".join(stderr_lines[-8:])

HTTP_PRESETS: Dict[str, Dict[str, str]] = {
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "key_env": "MISTRAL_API_KEY",
        "default_model": "mistral-small-latest",
    },
    "opencode": {
        "base_url": "https://opencode.ai/zen/v1",
        "key_env": "OPENCODE_API_KEY",
        "default_model": "",
    },
}

REQUEST_TIMEOUT = 90
MAX_HISTORY_TURNS = 10  # pasangan user+assistant terakhir yang dikirim sebagai konteks


class ChatError(Exception):
    """Error yang aman ditampilkan ke user (tanpa api key/stacktrace)."""


# ---------------- Agent job (live activity log untuk UI) ----------------
# Job = satu eksekusi agent (validate/chat) dengan log tahapan + stream
# stdout/stderr vibe CLI. UI poll GET status dan menampilkan log secara live.
AGENT_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_MAX_JOB_LOG_LINES = 400          # cap baris log per job (anti memory bengkak)
_MAX_JOB_LOG_LINE_LEN = 300       # cap panjang satu baris log
_MAX_JOBS = 50                    # cap job tersimpan; terlama dibuang


def agent_job_new() -> str:
    """Buat job baru (status running) -> job_id."""
    jid = uuid.uuid4().hex[:12]
    with _JOBS_LOCK:
        if len(AGENT_JOBS) >= _MAX_JOBS:
            for old in sorted(AGENT_JOBS.items(), key=lambda kv: kv[1]["created"])[: len(AGENT_JOBS) - _MAX_JOBS + 1]:
                AGENT_JOBS.pop(old[0], None)
        AGENT_JOBS[jid] = {
            "status": "running", "logs": [], "reply": "", "error": "",
            "created": time.time(),
        }
    return jid


def agent_job_log(job_id: str, text: str) -> None:
    """Append satu baris aktivitas agent (dengan timestamp)."""
    ts = time.strftime("%H:%M:%S")
    line = "[%s] %s" % (ts, str(text)[:_MAX_JOB_LOG_LINE_LEN])
    with _JOBS_LOCK:
        job = AGENT_JOBS.get(job_id)
        if not job:
            return
        job["logs"].append(line)
        if len(job["logs"]) > _MAX_JOB_LOG_LINES:
            del job["logs"][: len(job["logs"]) - _MAX_JOB_LOG_LINES]


def agent_job_finish(job_id: str, reply: str = "", error: str = "") -> None:
    with _JOBS_LOCK:
        job = AGENT_JOBS.get(job_id)
        if not job:
            return
        job["status"] = "error" if error else "done"
        job["reply"] = reply or ""
        job["error"] = error or ""


def agent_job_get(job_id: str) -> Optional[Dict[str, Any]]:
    """Snapshot state job untuk polling UI."""
    with _JOBS_LOCK:
        job = AGENT_JOBS.get(job_id)
        if not job:
            return None
        return {"status": job["status"], "logs": list(job["logs"]),
                "reply": job["reply"], "error": job["error"]}


def make_logger(job_id: str):
    """Return callable log(job_id sudah terikat) untuk diteruskan ke completion."""
    def _log(text: str) -> None:
        agent_job_log(job_id, text)
    return _log


def _find_vibe_cmd() -> Optional[str]:
    explicit = (os.environ.get("MOBILE_AUDIT_VIBE_CMD") or "").strip()
    if explicit:
        return explicit
    return shutil.which("vibe")


def get_llm_config() -> Dict[str, Any]:
    provider = (os.environ.get("MOBILE_AUDIT_LLM_PROVIDER") or "vibe").strip().lower()

    if provider == "vibe":
        model = (os.environ.get("MOBILE_AUDIT_LLM_MODEL") or VIBE_DEFAULT_MODEL).strip()
        vibe_cmd = _find_vibe_cmd()
        return {
            "provider": "vibe",
            "base_url": "",
            "api_key": "",
            "model": model,
            "configured": bool(vibe_cmd),
            "missing_env": [] if vibe_cmd else ["CLI `vibe` tidak ditemukan di PATH"],
            "vibe_cmd": vibe_cmd or "vibe",
        }

    if provider in HTTP_PRESETS:
        preset = HTTP_PRESETS[provider]
        base_url = os.environ.get("MOBILE_AUDIT_LLM_BASE_URL") or preset["base_url"]
        api_key = (os.environ.get("MOBILE_AUDIT_LLM_API_KEY")
                   or os.environ.get(preset["key_env"]) or "").strip()
        model = (os.environ.get("MOBILE_AUDIT_LLM_MODEL")
                 or preset["default_model"]).strip()
        missing = []
        if not api_key:
            missing.append(preset["key_env"])
        if not model:
            missing.append("MOBILE_AUDIT_LLM_MODEL")
    else:
        # custom: OpenAI-compatible apa pun (mis. Ollama local)
        provider = "custom"
        base_url = (os.environ.get("MOBILE_AUDIT_LLM_BASE_URL") or "").strip().rstrip("/")
        api_key = (os.environ.get("MOBILE_AUDIT_LLM_API_KEY") or "").strip()
        model = (os.environ.get("MOBILE_AUDIT_LLM_MODEL") or "").strip()
        missing = []
        if not base_url:
            missing.append("MOBILE_AUDIT_LLM_BASE_URL")
        if not api_key:
            missing.append("MOBILE_AUDIT_LLM_API_KEY")
        if not model:
            missing.append("MOBILE_AUDIT_LLM_MODEL")
    return {
        "provider": provider,
        "base_url": base_url,
        "model": model,
        "configured": not missing,
        "missing_env": missing,
    }


SYSTEM_PROMPT = """Kamu adalah "Verification Assistant" di dalam Mobile Audit Tool, sebuah toolkit pentest aplikasi mobile yang dipakai untuk audit berizin (bug bounty / pentest klien dengan scope resmi).

Tugas kamu: membantu hunter menganalisis dan memverifikasi temuan hardcoded secret / endpoint yang ditemukan scanner.

Aturan keras:
1. Nilai secret diberikan DALAM BENTUK UTUH (tanpa masking) supaya kamu bisa membantu validasi teknis pentester secara presisi. Ini audit berizin — perlakuan nilai sebagai data sensitif: jangan sarankan mem-publish nilai mentah ke laporan publik, gunakan format ter-mask saat menyusun REPORT DRAFT.
2. Hasil Live Verifier deterministik (jika ada) adalah sumber KEBENARAN utama. Rujuk verdict itu; jika bertentangan dengan tebakanmu, utamakan hasil verifier dan jelaskan kemungkinan penyebabnya.
3. Berikan analisis yang konkret dan actionable: tipe kredensial, attack path yang paling mungkin, langkah verifikasi PASIF/AMAN dulu (mis. cek scope, format, dokumentasi provider), lalu langkah aktif bila perlu, perkiraan severity (P1-P5 / CVSS kasar), dan dampak bisnisnya.
4. Jika diminta, susun draft kalimat laporan siap submit bug bounty (judul, deskripsi, langkah reproduksi, impact) dalam bahasa Inggris atau Indonesia sesuai permintaan.
5. Jangan pernah mengarang hasil verifikasi yang belum dilakukan. Bilang saja "belum diverifikasi" kalau tidak ada datanya.
6. Jawab ringkas, terstruktur (bullet/numbered), dan dalam bahasa yang sama dengan pertanyaan user.
"""


def _strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()


def build_finding_context(secret: dict, verifier_rows: Optional[List[dict]] = None) -> str:
    """Rangkum satu temuan secret untuk prompt. Nilai secret diberikan UTUH
    (tanpa masking) untuk membantu validasi manual pentester dalam audit berizin."""
    context = str(secret.get("context") or "")
    lines = [
        "### Konteks Temuan (dari scanner Mobile Audit Tool)",
        f"- Rule: {secret.get('rule_id') or '-'}",
        f"- Kategori: {secret.get('category') or '-'}",
        f"- Severity: {secret.get('severity') or '-'}",
        f"- File: {secret.get('file_path') or '-'} (line {secret.get('line_number') or '?'})",
        f"- Nilai: {str(secret.get('match') or '-')}",
    ]
    if context:
        snippet = context.strip().splitlines()
        snippet = " / ".join(s.strip() for s in snippet if s.strip())[:400]
        lines.append(f"- Snippet kode sekitar: {snippet}")

    if verifier_rows:
        lines.append("### Hasil Live Verifier (deterministik, jalur audit berizin)")
        for row in verifier_rows[:8]:
            target = str(row.get("target") or "")
            verdict = _strip_html(str(row.get("result_html") or "")).strip()
            if len(verdict) > 260:
                verdict = verdict[:260] + "..."
            lines.append(f"- [{row.get('module') or '?'}] target={target or '?'} -> {verdict or 'belum ada hasil'}")
    return "\n".join(lines)


# ------------------------- VIBE CLI (backend default) -------------------------

VIBE_PROMPT_MAX = 28000             # batas command line Windows ~32767 chars


def _build_vibe_prompt(messages: List[dict]) -> str:
    """Rangkai seluruh percakapan jadi SATU prompt untuk `vibe -p` (one-shot).

    Prompt dijaga di bawah VIBE_PROMPT_MAX: bila terlalu panjang, percakapan
    paling lama dibuang duluan (system prompt + pertanyaan terakhir dipertahankan).
    """
    parts = []
    for m in messages:
        role = m.get("role")
        content = str(m.get("content") or "").strip()
        if not content:
            continue
        if role == "system":
            parts.append("### INSTRUKSI SISTEM\n" + content)
        elif role == "assistant":
            parts.append("### JAWABAN ASSISTANT SEBELUMNYA\n" + content)
        else:
            parts.append("### PERTANYAAN HUNTER\n" + content)
    parts.append(
        "### FORMAT JAWABAN\n"
        "Balas PERTANYAAN HUNTER terakhir sebagai Verification Assistant, "
        "sesuai INSTRUKSI SISTEM. Jawab langsung dalam teks biasa. "
        "JANGAN menjalankan tools, command, shell, atau membaca file apa pun — "
        "semua data yang kamu butuhkan sudah ada di prompt ini."
    )
    # buang percakapan paling lama bila prompt mendekati batas command line
    while len(parts) > 3 and len("\n\n".join(parts)) > VIBE_PROMPT_MAX:
        parts.pop(1)
    return "\n\n".join(parts)


def _vibe_completion(messages: List[dict], cfg: Dict[str, Any],
                     log: Optional[Any] = None) -> str:
    """Jalankan single-line command: vibe -p "<prompt>" --output text (model via env).

    Robust terhadap kegagalan transient (rate limit, gangguan provider, exit != 0
    dengan jawaban tetap keluar): jawaban dipakai bila ada; retry otomatis bila
    kosong. stdout/stderr di-stream per baris ke `log` (live UI) bila diberikan.
    """
    prompt = _build_vibe_prompt(messages)
    timeout = float(os.environ.get("MOBILE_AUDIT_VIBE_TIMEOUT") or VIBE_DEFAULT_TIMEOUT)
    retries = int(os.environ.get("MOBILE_AUDIT_VIBE_RETRIES") or VIBE_RETRIES)
    env = os.environ.copy()
    env["VIBE_ACTIVE_MODEL"] = cfg["model"]
    cmd = [
        cfg["vibe_cmd"], "-p", prompt,
        "--output", "text",
        "--max-turns", VIBE_MAX_TURNS,
        "--time-limit", str(int(timeout)),
    ]
    if log:
        log("🚀 Eksekusi CLI: %s -p <prompt %d chars> --output text --max-turns %s --time-limit %ds (cwd: temp)"
            % (cfg["vibe_cmd"], len(prompt), VIBE_MAX_TURNS, int(timeout)))
        log("🧠 Model aktif: %s (via VIBE_ACTIVE_MODEL)" % cfg["model"])

    last_err = ""
    for attempt in range(1 + max(0, retries)):
        if attempt:
            log and log("🔁 Retry %d/%d — kegagalan sebelumnya: %s. Tunggu 5s..."
                        % (attempt, retries, last_err[:150] or "-"))
            time.sleep(5)
        t0 = time.time()
        try:
            reply, code, err_tail = _vibe_attempt(cmd, env, timeout, log)
        except FileNotFoundError as e:
            raise ChatError("CLI `vibe` (%s) tidak bisa dijalankan: %s. "
                            "Set MOBILE_AUDIT_VIBE_CMD ke path vibe atau install ulang."
                            % (cfg["vibe_cmd"], e))
        if log:
            log("⏱️ Proses vibe selesai: exit %s dalam %.1fs (jawaban: %d chars)"
                % (code, time.time() - t0, len(reply)))
        if reply:
            if code != 0:
                log and log("⚠️ exit code %s tapi jawaban tersedia — jawaban dipakai." % code)
            return reply
        last_err = "exit %s: %s" % (code, err_tail[:200] or "tanpa output")

    raise ChatError("`vibe` gagal setelah %d percobaan: %s. Cek koneksi/model."
                    % (1 + max(0, retries), last_err[:300]))


# ------------------------- HTTP provider (fallback opsional) -------------------------

def _http_completion(messages: List[dict], cfg: Dict[str, Any],
                     log: Optional[Any] = None) -> str:
    """Panggil endpoint chat/completions (OpenAI-compatible)."""
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 1200,
    }
    headers = {"Content-Type": "application/json"}
    if cfg.get("api_key"):
        headers["Authorization"] = "Bearer " + cfg["api_key"]
    if log:
        log("🚀 POST %s/chat/completions (model: %s)" % (cfg["base_url"], cfg["model"]))
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        raise ChatError(f"Provider {cfg['provider']} timeout setelah {REQUEST_TIMEOUT}s.")
    except requests.exceptions.ConnectionError:
        raise ChatError(f"Gagal terhubung ke provider {cfg['provider']} ({cfg['base_url']}).")
    if log:
        log("⏱️ Respons HTTP %d dari %s" % (resp.status_code, cfg["provider"]))
    if resp.status_code == 401:
        raise ChatError("API key ditolak (401). Cek key provider kamu.")
    if resp.status_code == 404:
        raise ChatError(f"Endpoint/model tidak ditemukan (404). Cek MOBILE_AUDIT_LLM_MODEL (saat ini: {cfg['model']}).")
    if resp.status_code == 429:
        raise ChatError("Rate limit provider (429). Tunggu sebentar lalu coba lagi.")
    if resp.status_code >= 400:
        raise ChatError(f"Provider error HTTP {resp.status_code}: {resp.text[:200]}")
    try:
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError):
        raise ChatError("Format response provider tidak dikenali.")
    return (content or "").strip()


def chat_completion(messages: List[dict], config: Optional[dict] = None,
                    log: Optional[Any] = None) -> str:
    """Satu putaran completion via backend aktif (vibe CLI atau HTTP). Blocking call."""
    cfg = config or get_llm_config()
    if not cfg["configured"]:
        raise ChatError(
            "Backend AI belum dikonfigurasi. "
            + ", ".join(cfg["missing_env"])
            + " (backend saat ini: " + cfg["provider"] + ")"
        )
    if cfg["provider"] == "vibe":
        return _vibe_completion(messages, cfg, log)
    return _http_completion(messages, cfg, log)


def ask_assistant(secret: dict, verifier_rows: Optional[List[dict]],
                  history: Optional[List[dict]], user_message: str,
                  config: Optional[dict] = None,
                  log: Optional[Any] = None) -> str:
    """Satu putaran percakapan. history = list of {role, content} (lama -> baru).

    Bila `log` diberikan: tiap tahap (skills, konteks temuan, history, prompt)
    dilaporkan untuk ditampilkan live di UI.
    """
    if log:
        log("📚 Muat skill AI dari skills/*.md ...")
    skills = load_skills()
    if log:
        log("📚 Skill ter-inject: %d chars (verification playbook + konteks MOPETOT)" % len(skills))
    sys_content = SYSTEM_PROMPT if not skills else SYSTEM_PROMPT + "\n\n" + skills
    messages = [{"role": "system", "content": sys_content}]
    if log and secret:
        log("🔎 Konteks temuan: %s @ %s:%s (nilai utuh, tanpa masking)"
            % (secret.get("rule_id") or "-", secret.get("file_path") or "?",
               secret.get("line_number") or "?"))
    if secret:
        messages.append({"role": "system", "content": build_finding_context(secret, verifier_rows)})
    if log:
        log("🧪 Evidence Live Verifier: %d row cache" % (len(verifier_rows or [])))
        log("🧾 Riwayat percakapan: %d pesan sebelumnya" % (len(history or [])))
    if history:
        for h in history[-(MAX_HISTORY_TURNS * 2):]:
            role = h.get("role")
            if role in ("user", "assistant"):
                messages.append({"role": role, "content": str(h.get("content") or "")[:4000]})
    messages.append({"role": "user", "content": (user_message or "").strip()[:4000]})
    if log:
        log("🧾 Total prompt: %d pesan, %d chars" % (len(messages), sum(len(m["content"]) for m in messages)))
    return chat_completion(messages, config, log)

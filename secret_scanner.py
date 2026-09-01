"""Secret scanner: jalankan regex rules (secrets.json) terhadap seluruh corpus."""
import base64
import json
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from engines.common import is_library_source


def _verify_base64_creds(s):
    """True jika s benar-benar base64 yang mendecode ke teks printable berformat user:pass."""
    s = s.strip()
    if not s or len(s) < 12 or len(s) > 200:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
        return False
    pad = "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s + pad, validate=True)
    except Exception:
        return False
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    # Wajib printable + format user:pass (satu colon, dua sisi non-empty,
    # tanpa spasi/JSON/dll biar JWT header & blok JSON tidak lolos)
    if not all(0x20 <= ord(c) < 0x7F for c in text):
        return False
    if ":" not in text:
        return False
    user, _, pw = text.partition(":")
    if not user or not pw or ":" in pw:
        return False
    if len(user) > 64 or len(pw) > 128:
        return False
    if not re.fullmatch(r"[^\s{}'\"`]+", user) or not re.fullmatch(r"[^\s{}'\"`]+", pw):
        return False
    return True


VERIFIERS = {
    "base64_creds": _verify_base64_creds,
}


DEFAULT_RULES = Path(__file__).resolve().parent / "rules" / "secrets.json"
MAX_FILE_SIZE = 15 * 1024 * 1024
MAX_MATCHES_PER_RULE = 30
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".ttf", ".otf", ".woff",
             ".woff2", ".so", ".dylib", ".dll", ".dex", ".arsc", ".hbc", ".keystore", ".jar"}
SKIP_NAMES = {".git"}

# Direktori hasil-dekompilasi/ekstraksi artefak strings biner yang bukan sumber
# kredensial aplikasi sendiri (perlu library filter via is_library_source, bukan
# skip total — native app menyimpan endpoint/secrets di kode sendiri).
SKIP_DIR_PARTS = ("sources_kotlin", "sources_js", "jd-cli", "javap",
                  "strings_other", "strings_wasm", "strings_dx", "strings_js")

# Path marker library/3rd-party yang mayoritas noise untuk rule bernilai-rendah.
# Berlaku untuk rule dengan flag "skip_libraries": true (dipakai di rules/secrets.json).
# Catatan: decoded_res/smali TIDAK di-blacklist di sini — filter library dilakukan
# via is_library_source() di iter_scan_files (semua rule), jadi smali app sendiri
# (mis. com/greatday/...) tetap di-scan di fast mode (--skip-jadx).
LIBRARY_NOISE_PATHS = [
    "/meta-inf/", "/third_party_licenses/",
    "/sources/androidx/", "/sources/android/", "/sources/androidx/annotation/",
    "/sources/com/google/", "/sources/com/bumptech/", "/sources/com/chuckerteam/",
    "/sources/com/github/", "/sources/com/facebook/", "/sources/com/twitter/",
    "/sources/org/jsoup/", "/sources/org/jetbrains/", "/sources/org/intellij/",
    "/sources/okhttp3/", "/sources/retrofit2/", "/sources/io/realm/", "/sources/io/reactivex/",
    "/sources/kotlin/", "/sources/kotlinx/", "/sources/javax/", "/sources/jdk/",
    "/sources/sun/", "/sources/rx/", "/sources/j$/", "/sources/java/",
    "/assets/res/",
]


class Rule:
    def __init__(self, data):
        self.id = data.get("id", "rule")
        self.category = data.get("category", "other")
        self.severity = data.get("severity", "info")
        self.description = data.get("description", "")
        self.enabled = data.get("enabled", True)
        flags = data.get("flags", 0)
        self.regex = re.compile(data["pattern"], flags | re.DOTALL)
        self.verify = VERIFIERS.get(data.get("verify", ""))
        # Skip library-noise path markers bila rule ditandai skip_libraries
        self.skip_paths = list(LIBRARY_NOISE_PATHS if data.get("skip_libraries") else [])
        for sp in data.get("skip_paths", []):
            self.skip_paths.append(sp.lower())
        # Cap jumlah match per baris untuk rule bising (mis. data chart / minified JS)
        self.line_cap = int(data.get("line_cap") or 0)

    def to_dict(self):
        return {
            "id": self.id, "category": self.category, "severity": self.severity,
            "description": self.description,
        }


class Finding:
    def __init__(self, rule, filepath, line, match, context):
        self.rule = rule
        self.filepath = filepath
        self.line = line
        self.match = match
        self.context = context

    def to_dict(self):
        return {
            "rule": self.rule.id,
            "category": self.rule.category,
            "severity": self.rule.severity,
            "description": self.rule.description,
            "file": self.filepath,
            "line": self.line,
            "match": self.match[:200],
            "context": self.context[:300],
        }


def load_rules(path=None):
    path = Path(path) if path else DEFAULT_RULES
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Rule(r) for r in data.get("rules", []) if r.get("enabled", True)]


def iter_scan_files(corpus_dir: Path):
    for p in sorted(corpus_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() in SKIP_EXTS:
            continue
        if any(part in SKIP_NAMES for part in p.parts):
            continue
        if any(part in SKIP_DIR_PARTS for part in p.parts):
            continue
        try:
            rel = p.relative_to(corpus_dir).parts
        except ValueError:
            rel = p.parts
        if is_library_source(rel):
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        yield p


def _safe_lines(content: str):
    return content.splitlines()


def _scan_file(p: Path, rules, quiet: bool):
    """Scan satu file terhadap semua rules. Dikembalikan: (findings, files, lines)."""
    findings = []
    try:
        raw = p.read_bytes()
    except OSError:
        return findings, 0, 0
    text = None
    for enc in ("utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return findings, 0, 0
    lines = _safe_lines(text)
    path_norm = str(p).replace("\\", "/").lower()
    for rule in rules:
        if rule.skip_paths and any(sp in path_norm for sp in rule.skip_paths):
            continue
        matches = list(rule.regex.finditer(text))
        if rule.verify:
            matches = [m for m in matches if rule.verify(m.group(0))]
        if not matches:
            continue
        counted = 0
        per_line = {}
        for m in matches[:MAX_MATCHES_PER_RULE]:
            line_no = text.count("\n", 0, m.start()) + 1
            if rule.line_cap:
                prev = per_line.get(line_no, 0)
                if prev >= rule.line_cap:
                    continue
                per_line[line_no] = prev + 1
            if line_no <= len(lines):
                ctx = lines[line_no - 1].strip()
            else:
                ctx = m.group(0)
            findings.append(Finding(rule, str(p), line_no, m.group(0), ctx))
            counted += 1
        if not quiet:
            print(f"  [!] {rule.id} x{counted}  {p}", flush=True)
    return findings, 1, len(lines)


def _scan_batch(batch_files, rules, quiet):
    findings = []
    files = 0
    lines = 0
    for p in batch_files:
        f, fcount, lcount = _scan_file(p, rules, quiet)
        findings.extend(f)
        files += fcount
        lines += lcount
    return findings, files, lines


def scan_corpus(corpus_dir: Path, rules, quiet=False, workers=None):
    findings = []
    stats = {"files": 0, "lines": 0}

    all_files = list(iter_scan_files(corpus_dir))
    if not all_files:
        print("  [>] Tidak ada file untuk di-scan (semua disaring)", flush=True)
        return findings, stats
    total = len(all_files)
    print(f"  [>] Scan dimulai: {total} file, {len(rules)} rule", flush=True)
    t0 = time.time()

    def _report_progress(done):
        pct = done * 100 // total
        el = time.time() - t0
        print(f"  [>] Scan progress: {done}/{total} file ({pct}%), {el:.0f}s elapsed", flush=True)

    if workers is None:
        workers = min(os.cpu_count() or 2, 8)
    if workers <= 1 or len(all_files) < 64:
        for i, p in enumerate(all_files, 1):
            f, fcount, lcount = _scan_file(p, rules, quiet)
            findings.extend(f)
            stats["files"] += fcount
            stats["lines"] += lcount
            if i % max(1, total // 10) == 0 or i == total:
                _report_progress(i)
        return findings, stats

    batch_size = max(1, len(all_files) // (workers * 4))
    batches = [all_files[i:i + batch_size] for i in range(0, len(all_files), batch_size)]
    done = 0
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for f, fcount, lcount in pool.map(_scan_batch, batches, [rules] * len(batches), [quiet] * len(batches)):
            findings.extend(f)
            stats["files"] += fcount
            stats["lines"] += lcount
            done += fcount
            if done % max(1, total // 10) < fcount or done >= total:
                _report_progress(min(done, total))
    return findings, stats


def dedupe(findings):
    """Kelompokkan findings sama (rule+match) lintas file."""
    groups = {}
    for f in findings:
        key = (f.rule.id, f.match[:120])
        groups.setdefault(key, []).append(f)
    return groups


def summarize(findings):
    by_sev = {}
    for f in findings:
        by_sev[f.rule.severity] = by_sev.get(f.rule.severity, 0) + 1
    by_cat = {}
    for f in findings:
        by_cat[f.rule.category] = by_cat.get(f.rule.category, 0) + 1
    return {"by_severity": by_sev, "by_category": by_cat}

"""Code Explorer — browse & grep corpus hasil scan. 100% lokal, pure function.

Input semua function adalah Path corpus (bukan scan_id) supaya mudah
di-unit-test tanpa server. See design/CODE_EXPLORER_DESIGN.md.

Skala: corpus nyata bisa 100k+ file (jadx) — makanya:
- list_dir() lazy per-direktori (bukan walk full).
- grep() pakai GNU grep eksternal bila ada (Git for Windows) — jauh lebih
  cepat daripada iterasi Python; fallback ke Python re.
"""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

# Ekstensi yang pasti binary — tidak dibaca viewer & tidak di-grep
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".so", ".dylib", ".dll", ".o", ".a", ".lib", ".pyd",
    ".dex", ".arsc", ".hbc", ".jar", ".zip", ".apk", ".aab", ".ipa", ".apks",
    ".keystore", ".jks", ".bks", ".p12",
    ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
    ".exe", ".msi", ".pdf", ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".3gp",
    ".class", ".wasm", ".unity3d", ".asset", ".resources",
}

MAX_LINE_LEN = 500          # line_text di-response di-cap (JS minified satu baris)
DEFAULT_PAGE_LINES = 500
MAX_PAGE_LINES = 2000
NULL_SNIFF_BYTES = 1024
MAX_DIR_FILES = 500          # file per direktori yang dirender di tree (lebih banyak: pakai grep)
GREP_TIMEOUT = 120            # detik, cap fast-path GNU grep
GREP_MATCH_LIMIT = 500


class ExplorerError(Exception):
    """Error aman untuk ditampilkan ke user."""


def safe_resolve(corpus: Path, rel_path: str) -> Path:
    """Resolve path relatif corpus dengan path-traversal protection."""
    corpus_root = corpus.resolve()
    candidate = (corpus_root / rel_path.lstrip("/\\")).resolve()
    try:
        candidate.relative_to(corpus_root)
    except ValueError:
        raise ExplorerError("Path di luar corpus (traversal ditolak)")
    return candidate


def normalize_rel_path(corpus: Path, file_path: str) -> str:
    """Terima path corpus-relatif ATAU absolut (dengan prefix corpus) -> relatif."""
    p = str(file_path or "").strip()
    if not p:
        return ""
    root_variants = {str(corpus.resolve()), str(corpus.resolve()).replace("\\", "/"),
                     str(corpus), str(corpus).replace("\\", "/")}
    for prefix in sorted(root_variants, key=len, reverse=True):
        if p.startswith(prefix) and len(p) > len(prefix):
            p = p[len(prefix):]
            break
    return p.lstrip("/\\").replace("\\", "/")


def looks_text(data: bytes) -> bool:
    """Sniff binary: NULL byte di awal file = binary."""
    return b"\x00" not in data[:NULL_SNIFF_BYTES]


def list_dir(corpus: Path, rel_dir: str = "", max_files: int = MAX_DIR_FILES) -> Dict:
    """Listing lazy satu level direktori (skalabel utk corpus 100k+ file)."""
    d = safe_resolve(corpus, rel_dir or "")
    if not d.is_dir():
        raise ExplorerError("Direktori tidak ditemukan di corpus")

    dirs: List[str] = []
    files: List[Dict] = []
    try:
        with os.scandir(d) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        dirs.append(entry.name)
                    elif entry.is_file(follow_symlinks=False):
                        ext = os.path.splitext(entry.name)[1].lower()
                        if ext in BINARY_EXTS:
                            continue
                        files.append({
                            "name": entry.name,
                            "ext": ext or ".",
                            "size": entry.stat(follow_symlinks=False).st_size,
                        })
                except OSError:
                    continue
    except OSError:
        raise ExplorerError("Gagal membaca direktori")

    dirs.sort()
    files.sort(key=lambda x: x["name"])
    return {
        "dir": normalize_rel_path(corpus, rel_dir),
        "dirs": dirs,
        "files": files[:max_files],
        "total_files": len(files),
        "truncated": len(files) > max_files,
    }


def filter_files(corpus: Path, pattern: str, limit: int = 200) -> List[Dict]:
    """Cari NAMA file di corpus (fast: rg --files / os.walk). Untuk tree filter."""
    pattern = (pattern or "").strip()
    if not pattern:
        raise ExplorerError("Filter kosong")
    q = pattern.lower()
    out: List[Dict] = []
    rg_bin = _find_ripgrep()
    if rg_bin:
        cmd = [rg_bin, "--files", "--no-messages", "--no-ignore", str(corpus)]
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
        for raw in proc.stdout.splitlines():
            p = raw.decode("utf-8", errors="replace").strip()
            if not p:
                continue
            rel = _make_rel(corpus, p)
            if q in rel.lower():
                out.append({"path": rel, "size": None, "ext": os.path.splitext(rel)[1].lower() or "."})
                if len(out) >= limit:
                    break
    else:
        for f in corpus.rglob("*"):
            try:
                if not f.is_file() or f.suffix.lower() in BINARY_EXTS:
                    continue
                rel = f.relative_to(corpus.resolve()).as_posix()
                if q in rel.lower():
                    out.append({"path": rel, "size": f.stat().st_size,
                                "ext": f.suffix.lower() or "."})
                    if len(out) >= limit:
                        break
            except OSError:
                continue
    return out


def read_file(corpus: Path, rel_path: str, offset: int = 0,
              limit: int = DEFAULT_PAGE_LINES) -> Dict:
    """Baca file teks per-baris (paging). Return lines + total + truncated."""
    p = safe_resolve(corpus, normalize_rel_path(corpus, rel_path))
    if not p.exists() or not p.is_file():
        raise ExplorerError("File tidak ditemukan di corpus")
    if p.suffix.lower() in BINARY_EXTS:
        raise ExplorerError("File binary tidak didukung viewer")
    try:
        raw = p.read_bytes()
    except OSError:
        raise ExplorerError("Gagal membaca file")
    if not looks_text(raw):
        raise ExplorerError("File binary tidak didukung viewer")

    text = raw.decode("utf-8", errors="replace")
    all_lines = text.splitlines()
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or DEFAULT_PAGE_LINES), MAX_PAGE_LINES))
    page = all_lines[offset:offset + limit]
    return {
        "path": p.relative_to(corpus.resolve()).as_posix(),
        "lines": [{"no": offset + i + 1, "text": l[:MAX_LINE_LEN]} for i, l in enumerate(page)],
        "total_lines": len(all_lines),
        "offset": offset,
        "next_offset": offset + limit if offset + limit < len(all_lines) else None,
        "size": len(raw),
    }


def grep(corpus: Path, query: str, regex_mode: bool = False,
         case_sensitive: bool = False, scope: str = "", ext: str = "",
         limit: int = 500) -> Dict:
    """Grep corpus. Return matches [{path, line_no, line_text}] + stat."""
    query = (query or "").strip()
    if not query:
        raise ExplorerError("Query kosong")
    if len(query) > 500:
        raise ExplorerError("Query terlalu panjang")

    flags = 0 if case_sensitive else re.IGNORECASE
    if regex_mode:
        try:
            pattern = re.compile(query, flags)
        except re.error as e:
            raise ExplorerError(f"Regex tidak valid: {e}")
    else:
        pattern = re.compile(re.escape(query), flags)

    scope = (scope or "").strip().strip("/")
    ext = (ext or "").strip().lower()
    if ext and not ext.startswith("."):
        ext = "." + ext
    limit = max(1, min(int(limit or 500), 500))

    # Prioritas engine: ripgrep (vendored, tercepat) -> GNU grep -> Python.
    rg_bin = _find_ripgrep()
    if rg_bin:
        return _rg_external(rg_bin, corpus, query, regex_mode, case_sensitive,
                            scope, ext, limit, pattern)
    grep_bin = _find_grep()
    if grep_bin:
        return _grep_external(grep_bin, corpus, query, regex_mode, case_sensitive,
                              scope, ext, limit, pattern)

    return _grep_python(pattern, corpus, scope, ext, limit)


def _find_ripgrep() -> Optional[str]:
    # 1. ripgrep vendored di repo: <repo>/bin/ripgrep/rg.exe
    vendored = Path(__file__).resolve().parent.parent / "bin" / "ripgrep" / "rg.exe"
    if vendored.exists():
        return str(vendored)
    # 2. ripgrep di PATH
    return shutil.which("rg")


def _rg_external(rg_bin: str, corpus: Path, query: str, regex_mode: bool,
                 case_sensitive: bool, scope: str, ext: str, limit: int,
                 pattern=None) -> Dict:
    """Fast path ripgrep — paralel, jauh lebih cepat utk corpus 100k+ file."""
    started = time.monotonic()
    search_root = corpus if not scope else (corpus / scope)
    if not search_root.is_dir():
        raise ExplorerError("Scope direktori tidak ditemukan")

    cmd = [rg_bin, "-n", "--no-heading", "--no-messages", "--color", "never"]
    if not regex_mode:
        cmd.append("-F")
    if not case_sensitive:
        cmd.append("-i")
    if ext:
        cmd += ["-g", "*" + ext]
    cmd += ["-e", query, str(search_root)]

    matches: List[Dict] = []
    truncated = False
    path_re = re.compile(r"^(.*):(\d+):(.*)$", re.DOTALL)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            m = path_re.match(line)
            if not m:
                continue  # skip "binary file matches" / warning line
            rel = _make_rel(corpus, m.group(1))
            matches.append({
                "path": rel,
                "line_no": int(m.group(2)),
                "line_text": _match_snippet(m.group(3), pattern) if pattern
                             else m.group(3).strip()[:MAX_LINE_LEN],
            })
            if len(matches) >= limit:
                truncated = True
                break
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)

    by_file: Dict[str, List[Dict]] = {}
    for m in matches:
        by_file.setdefault(m["path"], []).append(m)
    return {
        "matches": matches,
        "match_count": len(matches),
        "file_count": len(by_file),
        "truncated": truncated,
        "files_scanned": None,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "query": query,
        "engine": "ripgrep",
    }


def _find_grep() -> Optional[str]:
    g = shutil.which("grep")
    if g:
        return g
    for p in (r"C:\Program Files\Git\usr\bin\grep.exe",
              r"C:\Program Files (x86)\Git\usr\bin\grep.exe"):
        if Path(p).exists():
            return p
    return None


# Cache prefix corpus (str.resolve() mahal — jangan panggil per-line output rg/grep)
_REL_PREFIX_CACHE: Dict[str, List[str]] = {}


def _root_prefixes(corpus: Path) -> List[str]:
    key = str(corpus)
    variants = _REL_PREFIX_CACHE.get(key)
    if not variants:
        variants = sorted(
            {str(corpus.resolve()).replace("\\", "/"),
             str(corpus).replace("\\", "/")},
            key=len, reverse=True,
        )
        _REL_PREFIX_CACHE[key] = variants
    return variants


def _make_rel(corpus: Path, match_path: str) -> str:
    """Path output rg/grep (bisa Windows/MSYS) -> relatif POSIX."""
    p = match_path.replace("\\", "/")
    for prefix in _root_prefixes(corpus):
        if p.startswith(prefix + "/"):
            p = p[len(prefix) + 1:]
            break
    return p


def _match_snippet(line: str, pattern) -> str:
    """Snippet sekitar match (untuk file minified satu baris panjang)."""
    stripped = line.strip()
    if len(stripped) <= MAX_LINE_LEN:
        return stripped
    m = pattern.search(stripped)
    if not m:
        return stripped[:MAX_LINE_LEN]
    start = max(0, min(m.start() - 200, len(stripped) - MAX_LINE_LEN))
    return ("…" if start > 0 else "") + stripped[start:start + MAX_LINE_LEN]


def _grep_external(grep_bin: str, corpus: Path, query: str, regex_mode: bool,
                   case_sensitive: bool, scope: str, ext: str, limit: int,
                   pattern=None) -> Dict:
    started = time.monotonic()
    search_root = corpus if not scope else (corpus / scope)
    if not search_root.is_dir():
        raise ExplorerError("Scope direktori tidak ditemukan")

    # CATATAN: build grep (Git for Windows) rusak dengan kombinasi "-F -i"
    # (exit 6 tanpa output), jadi SELALU pakai -E: query literal di-escape ke ERE.
    _ERE_SPECIALS = r"\.^$*+?()[]{}|"
    ere_query = query if regex_mode else "".join("\\" + c if c in _ERE_SPECIALS else c for c in query)

    cmd = [grep_bin, "-r", "-n", "-I", "--no-messages", "--exclude-dir", ".git", "-E"]
    if not case_sensitive:
        cmd.append("-i")
    if ext:
        cmd += ["--include", "*" + ext]
    cmd += [ere_query, str(search_root)]

    matches: List[Dict] = []
    truncated = False
    path_re = re.compile(r"^(.*):(\d+):(.*)$", re.DOTALL)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                m = path_re.match(line)
                if not m:
                    continue
                rel = _make_rel(corpus, m.group(1))
                matches.append({
                    "path": rel,
                    "line_no": int(m.group(2)),
                    "line_text": _match_snippet(m.group(3), pattern) if pattern
                                 else m.group(3).strip()[:MAX_LINE_LEN],
                })
                if len(matches) >= limit:
                    truncated = True
                    break
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
    except OSError:
        return _grep_python(re.compile(re.escape(query), 0 if case_sensitive else re.IGNORECASE),
                            corpus, scope, ext, limit)

    by_file: Dict[str, List[Dict]] = {}
    for m in matches:
        by_file.setdefault(m["path"], []).append(m)
    return {
        "matches": matches,
        "match_count": len(matches),
        "file_count": len(by_file),
        "truncated": truncated,
        "files_scanned": None,   # grep eksternal tidak melaporkan jumlah file
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "query": query,
        "engine": "grep",
    }


def _grep_python(pattern, corpus: Path, scope: str, ext: str, limit: int) -> Dict:
    """Fallback iterasi Python (bila GNU grep tidak tersedia)."""
    matches: List[Dict] = []
    files_scanned = 0
    truncated = False
    started = time.monotonic()

    for f in corpus.rglob("*"):
        try:
            if not f.is_file() or f.suffix.lower() in BINARY_EXTS:
                continue
            rel = f.relative_to(corpus).as_posix()
            if scope and not rel.startswith(scope):
                continue
            if ext and f.suffix.lower() != ext:
                continue
            files_scanned += 1
            raw = f.read_bytes()
            if not looks_text(raw):
                continue
            if len(raw) > 15 * 1024 * 1024:  # file teks raksasa: skip biar grep ga beku
                continue
            for i, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
                if pattern.search(line):
                    matches.append({
                        "path": rel,
                        "line_no": i,
                        "line_text": _match_snippet(line, pattern),
                    })
                    if len(matches) >= limit:
                        truncated = True
                        break
        except OSError:
            continue
        if truncated:
            break

    # Group per file untuk UI
    by_file: Dict[str, List[Dict]] = {}
    for m in matches:
        by_file.setdefault(m["path"], []).append(m)

    return {
        "matches": matches,
        "match_count": len(matches),
        "file_count": len(by_file),
        "truncated": truncated,
        "files_scanned": files_scanned,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "query": "",
        "engine": "python",
    }

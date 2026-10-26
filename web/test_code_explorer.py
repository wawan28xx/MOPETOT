"""Unit test code_explorer — corpus dummy, tanpa server & tanpa DB asli."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import py_compile

py_compile.compile("code_explorer.py", doraise=True)
print("[1] py_compile OK: code_explorer.py")

import code_explorer as ce

# --- corpus dummy ---
tmp = Path(tempfile.mkdtemp())
corpus = tmp / "corpus"
(corpus / "sources_java/com/app").mkdir(parents=True)
(corpus / "assets/www").mkdir(parents=True)

java = corpus / "sources_java/com/app/ApiClient.java"
java.write_text(
    "public class ApiClient {\n"
    "    private static final String BASE_URL = \"https://api.stockbit.com/\";\n"
    "    private static final String TOKEN = \"tok_dev_abc123\";\n"
    "}\n",
    encoding="utf-8",
)
js = corpus / "assets/www/app.js"
js.write_text(
    "var host = 'https://api.stockbit.com/v2';\n"
    "// api.stockbit.com production\n",
    encoding="utf-8",
)
(corpus / "assets/logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00binary")
(corpus / "assets/blob.bin").write_bytes(b"\x00\x01\x02binarynull")

# --- list_dir: lazy per-direktori, binary ter-skip ---
root = ce.list_dir(corpus)
assert root["dirs"] == ["assets", "sources_java"], root["dirs"]
assert root["total_files"] == 0  # root tidak punya file langsung

sub = ce.list_dir(corpus, "sources_java/com/app")
assert {f["name"] for f in sub["files"]} == {"ApiClient.java"}, sub
assert sub["truncated"] is False

assets_dir = ce.list_dir(corpus, "assets")
assert "logo.png" not in [f["name"] for f in assets_dir["files"]], "png harus ter-skip"
assert assets_dir["dirs"] == ["www"], assets_dir
try:
    ce.list_dir(corpus, "../keluar")
    raise AssertionError("traversal list_dir harus ditolak")
except ce.ExplorerError:
    pass
print("[2] list_dir OK (lazy, binary skip, traversal ditolak)")

# --- safe_resolve: traversal ditolak ---
try:
    ce.safe_resolve(corpus, "../../etc/passwd")
    raise AssertionError("traversal harus ditolak")
except ce.ExplorerError:
    pass
try:
    ce.safe_resolve(corpus, "assets/../../secrets.txt")
    raise AssertionError("traversal harus ditolak")
except ce.ExplorerError:
    pass
print("[3] safe_resolve OK (traversal ditolak)")

# --- normalize_rel_path: absolut -> relatif ---
abs_path = str(corpus / "assets/www/app.js").replace("\\", "/")
assert ce.normalize_rel_path(corpus, abs_path) == "assets/www/app.js"
assert ce.normalize_rel_path(corpus, "assets/www/app.js") == "assets/www/app.js"
print("[4] normalize_rel_path OK")

# --- read_file: paging + binary ditolak ---
page = ce.read_file(corpus, "sources_java/com/app/ApiClient.java")
assert page["total_lines"] == 4 and len(page["lines"]) == 4
assert page["next_offset"] is None
page2 = ce.read_file(corpus, "sources_java/com/app/ApiClient.java", offset=0, limit=2)
assert page2["next_offset"] == 2 and len(page2["lines"]) == 2
try:
    ce.read_file(corpus, "assets/logo.png")
    raise AssertionError("png harus ditolak")
except ce.ExplorerError:
    pass
try:
    ce.read_file(corpus, "assets/blob.bin")
    raise AssertionError("binary-null harus ditolak")
except ce.ExplorerError:
    pass
try:
    ce.read_file(corpus, "tidak/ada.java")
    raise AssertionError("file hilang harus ditolak")
except ce.ExplorerError:
    pass
print("[5] read_file OK (paging + binary + missing file)")

# --- grep: literal, case-insensitive, regex, scope, ext, limit ---
r = ce.grep(corpus, "api.stockbit.com")
assert r["match_count"] == 3, r  # 2 di java + 1 di js
assert r["file_count"] == 2
assert {m["path"] for m in r["matches"]} == {"sources_java/com/app/ApiClient.java", "assets/www/app.js"}
assert r["matches"][0]["line_no"] >= 1

r = ce.grep(corpus, "API.STOCKBIT.COM", case_sensitive=True)
assert r["match_count"] == 0

r = ce.grep(corpus, "API.STOCKBIT.COM", case_sensitive=False)
assert r["match_count"] == 3

r = ce.grep(corpus, r"tok_dev_\w+", regex_mode=True)
assert r["match_count"] == 1 and "TOKEN" in r["matches"][0]["line_text"]

r = ce.grep(corpus, "api.stockbit.com", scope="assets")
assert r["match_count"] == 2, r  # 2 match di app.js (host + comment)
assert all(m["path"] == "assets/www/app.js" for m in r["matches"])

r = ce.grep(corpus, "api.stockbit.com", ext=".js")
assert r["match_count"] == 2, r
if r["engine"] == "python":
    assert r["files_scanned"] == 1
else:
    assert r["files_scanned"] is None  # grep eksternal tidak melaporkan jumlah file

r = ce.grep(corpus, "o", limit=1)
assert r["truncated"] is True and r["match_count"] == 1
assert r["engine"] in ("ripgrep", "grep", "python"), r["engine"]
if ce._find_ripgrep():
    assert r["engine"] == "ripgrep", "ripgrep vendored/PATH -> harus pakai fast path"
    # path rel harus konsisten (bukan absolut Windows)
    assert all("\\" not in m["path"] and not m["path"].startswith("C:") for m in r["matches"]), r["matches"]

try:
    ce.grep(corpus, "[invalid(regex", regex_mode=True)
    raise AssertionError("regex invalid harus raise")
except ce.ExplorerError:
    pass
try:
    ce.grep(corpus, "   ")
    raise AssertionError("query kosong harus raise")
except ce.ExplorerError:
    pass
print("[6] grep OK (literal/case/regex/scope/ext/limit/error)")

# --- line_text cap utk minified JS satu baris ---
big = corpus / "assets/big.js"
big.write_text("x" * 1000 + "NEEDLE" + "y" * 2000, encoding="utf-8")
r = ce.grep(corpus, "NEEDLE")
assert len(r["matches"][0]["line_text"]) <= ce.MAX_LINE_LEN + 1  # +1 = prefix "…" utk match di tengah
assert "NEEDLE" in r["matches"][0]["line_text"]
assert r["matches"][0]["line_text"].startswith("…")  # match di offset 1000 -> snippet di-pusatkan di match
print("[7] line cap OK (file minified)")

print("\nALL CODE EXPLORER CHECKS PASSED")

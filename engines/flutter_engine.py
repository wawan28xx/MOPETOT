"""Flutter: libapp.so — coba blutter, fallback deep dart string extraction + symbols."""
import re
from pathlib import Path

from .common import run as run_cmd, find_tool, log, extract_strings_basic
from . import native_engine, generic_engine


def extract_flutter_dart_corpus(libapp: Path, corpus: Path):
    """Ekstraksi terstruktur string Dart, Route, URL, Class, dan Assets dari libapp.so."""
    out_dir = corpus / "flutter_dart"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = libapp.read_bytes()
        # Ekstrak string ASCII & UTF-8 panjang >= 4
        raw_strings = re.findall(rb'[\x20-\x7E]{4,}', data)
        dart_corpus = set()
        routes = set()
        urls = set()

        url_re = re.compile(r'https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._?%&=~#-]*)?')
        route_re = re.compile(r'^/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$')

        for s in raw_strings:
            try:
                t = s.decode('utf-8', errors='ignore').strip()
                if len(t) >= 4:
                    dart_corpus.add(t)
                    if url_re.match(t):
                        urls.add(t)
                    elif route_re.match(t):
                        routes.add(t)
            except Exception:
                pass

        # Tulis corpus terstruktur
        (out_dir / "dart_strings.txt").write_text('\n'.join(sorted(dart_corpus)), encoding='utf-8', errors='replace')
        if urls:
            (out_dir / "flutter_urls.txt").write_text('\n'.join(sorted(urls)), encoding='utf-8', errors='replace')
        if routes:
            (out_dir / "flutter_routes.txt").write_text('\n'.join(sorted(routes)), encoding='utf-8', errors='replace')

        log(f"Flutter Dart deep extraction: {len(dart_corpus)} strings, {len(urls)} URLs, {len(routes)} routes", "ok")
    except Exception as e:
        log(f"Flutter Dart extraction failed: {e}", "warn")


def run(libapp: Path, root: Path, corpus: Path, opts: dict):
    flutter_so = None
    for p in root.rglob("libflutter.so"):
        flutter_so = p
        break

    # Fast mode: skip blutter, langsung fallback ke string extraction
    skip_blutter = opts.get("skip_blutter", False)
    blutter = None if skip_blutter else find_tool("blutter")

    if skip_blutter:
        log("Fast mode: blutter di-skip (Dart string extraction saja)", "warn")
    elif blutter:
        outdir = corpus / "flutter_blutter"
        outdir.mkdir(parents=True, exist_ok=True)
        cmd = [str(blutter), str(libapp)]
        if flutter_so:
            cmd.append(str(flutter_so))
        cmd.append(str(outdir))
        log(f"[>] blutter: {libapp.name} -> Dart symbols (live progress di bawah)")
        rc, out, err = run_cmd(cmd, timeout=900, stream=True)
        if rc == 0:
            log(f"blutter: {libapp.name} -> Dart symbols", "ok")
            return
        log(f"blutter gagal ({err[:100]}), fallback strings", "warn")
    else:
        log("blutter binary tidak ditemukan di bin/. Menggunakan Deep Dart String & Route Extractor...", "info")

    # Fallback: deep dart string extractor
    extract_flutter_dart_corpus(libapp, corpus)

    # native strings + symbols pada libapp.so
    native_engine.run(libapp, corpus, opts)
    if flutter_so:
        native_engine.run(flutter_so, corpus, opts)

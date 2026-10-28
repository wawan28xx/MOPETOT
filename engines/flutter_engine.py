"""Flutter: libapp.so — coba blutter, fallback deep dart string extraction + symbols."""
import re
import sys
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


def _run_blutter_dir(lib_dir: Path, corpus: Path, opts: dict) -> bool:
    """Jalankan blutter pada direktori berisi libapp.so (+libflutter.so).
    Return True bila berhasil (pp.txt dihasilkan)."""
    libapp = lib_dir / "libapp.so"
    # Fast mode: skip blutter, langsung fallback ke string extraction
    skip_blutter = opts.get("skip_blutter", False)
    blutter = None if skip_blutter else find_tool("blutter")

    if skip_blutter:
        log("Fast mode: blutter di-skip (Dart string extraction saja)", "warn")
    elif blutter and lib_dir.name != "armeabi-v7a":
        # blutter hanya untuk arm64/x64; CLI: blutter_run.py <lib_dir> <outdir>
        outdir = corpus / "flutter_blutter"
        outdir.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, str(blutter), str(libapp.parent), str(outdir)]
        log(f"[>] blutter: {libapp.parent.name}/libapp.so -> Dart class dump "
            f"(build DartVM pertama kali per versi bisa lama)")
        # timeout besar: build pertama DartVM ~5-10 menit; analisis ~40 detik
        rc, out, err = run_cmd(cmd, timeout=3600, stream=True)
        if rc == 0 and (outdir / "pp.txt").exists():
            log(f"blutter: Dart class dump -> {outdir} (pp.txt, objs.txt, asm/, blutter_frida.js)", "ok")
            return True
        log(f"blutter gagal ({(err or '')[:100]}), fallback strings", "warn")
    elif blutter:
        log("blutter dilewati untuk armeabi-v7a (arm64/x64 saja), fallback strings", "warn")
    else:
        log("blutter binary tidak ditemukan di bin/. Menggunakan Deep Dart String & Route Extractor...", "info")

    # Fallback: deep dart string extractor
    extract_flutter_dart_corpus(libapp, corpus)
    return False


def run(libapp: Path, root: Path, corpus: Path, opts: dict):
    return _run_blutter_dir(libapp.parent, corpus, opts)


def run_ios(app_dir: Path, workdir: Path, corpus: Path, opts: dict):
    """Flutter iOS: Dart AOT ada di Frameworks/App.framework/App.
    Stage copy dengan nama libapp.so/libflutter.so (konvensi blutter),
    lalu dump via blutter (TARGET_OS diambil dari snapshot flags)."""
    app_fw = app_dir / "Frameworks" / "App.framework" / "App"
    flutter_fw = None
    for cand in (app_dir / "Frameworks" / "Flutter.framework").rglob("*"):
        if cand.is_file() and cand.name == "Flutter":
            flutter_fw = cand
            break
    if not app_fw.exists() or flutter_fw is None:
        return False

    log("Flutter iOS terdeteksi (App.framework) — staging untuk blutter", "ok")
    stage = Path(workdir) / "flutter_ios_stage"
    stage.mkdir(parents=True, exist_ok=True)
    import shutil as _sh
    _sh.copy2(app_fw, stage / "libapp.so")
    _sh.copy2(flutter_fw, stage / "libflutter.so")
    return _run_blutter_dir(stage, corpus, opts)

    # native strings + symbols pada libapp.so
    native_engine.run(libapp, corpus, opts)
    if flutter_so:
        native_engine.run(flutter_so, corpus, opts)

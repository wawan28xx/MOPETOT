"""Ekstraksi APK/AAB: bongkar zip, sortir artefak, dispatch ke engine per-format."""
import zipfile
from pathlib import Path

from .common import run as run_cmd, find_tool, log, extract_strings_basic
from . import dex_engine, native_engine, flutter_engine, unity_engine, generic_engine, plist_engine


def unpack_apk(target: Path, workdir: Path, opts: dict):
    log(f"Bongkar APK/AAB: {target.name} ({target.stat().st_size / 1048576:.1f} MB)")
    root = workdir / "apk_root"
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        log(f"Zip entries: {len(infos)} file — mengekstrak...")
        for info in infos:
            try:
                zf.extract(info, root)
            except Exception:
                pass
    log("Ekstraksi zip selesai", "ok")
    dispatch_extracted(target, root, workdir, opts)
    return root


def dispatch_extracted(target: Path, root: Path, workdir: Path, opts: dict):
    corpus = workdir / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)

    # DEX -> jadx / apktool
    dex_files = sorted(root.rglob("*.dex"))
    if dex_files:
        log(f"[>] DEX: {len(dex_files)} file")
        dex_engine.run(dex_files, corpus / "sources_java", opts)
    else:
        log("[>] Tidak ada DEX (non-Android atau sudah diproses)")

    # manifest & resources -> apktool decode (XML readable).
    # Decode APK asli (bukan folder hasil extract) supaya apktool bekerja andal.
    apktool_decode(target, corpus / "decoded_res", opts)

    # Native libs
    so_list = sorted(root.rglob("*.so"))
    if so_list:
        log(f"[>] Native libs: {len(so_list)} file")
    for so in so_list:
        if so.name.lower() == "libapp.so" and any(p.name.lower().startswith("libflutter") for p in root.rglob("*.so")):
            flutter_engine.run(so, root, corpus, opts)
        elif so.name.lower() == "libil2cpp.so":
            unity_engine.run(so, root, corpus, opts)
        else:
            native_engine.run(so, corpus, opts)

    # Assets / JS / JSON / config — copy untuk scanning teks
    scan_exts = {".js", ".json", ".xml", ".txt", ".properties", ".yml", ".yaml", ".ini",
                 ".html", ".htm", ".css", ".conf", ".cfg", ".env", ".plist", ".ts", ".php", ".py", ".rb", ".md"}
    copied = 0
    for f in root.rglob("*"):
        if f.is_file() and f.suffix.lower() in scan_exts:
            rel = f.relative_to(root)
            dst = corpus / "assets" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                dst.write_bytes(f.read_bytes())
                copied += 1
            except OSError:
                pass
    if copied:
        log(f"[>] Assets teks disalin: {copied} file (js/json/xml/dll)")

    # Strings untuk binary tak dikenal
    scanned = 0
    for f in root.rglob("*"):
        if f.is_file() and f.stat().st_size < 20 * 1024 * 1024:
            if f.suffix.lower() in (".so", ".bin", ".dat", ".ttf", ".png", ".jpg"):
                continue  # sudah ditangani/oleh engine lain / bukan teks
            if f.suffix.lower() in scan_exts:
                continue
            kind = sniff_binary(f)
            if kind in ("unknown", "axml", "dex"):
                generic_engine.run(f, corpus / "strings_other", opts)
                scanned += 1
    if scanned:
        log(f"[>] String extraction biner: {scanned} file -> strings_other")

    # Signing cert
    for mf in sorted((root / "META-INF").glob("*.RSA")) if (root / "META-INF").exists() else []:
        signer_info(mf, corpus / "signing.txt")


def sniff_binary(path: Path):
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return "unknown"
    for name, sig in {
        "elf": b"\x7fELF", "pe": b"MZ", "dex": b"dex\n",
        "zip": b"PK\x03\x04", "hbc": b"\x1f\xbc\x0c\x00",
    }.items():
        if head.startswith(sig):
            return name
    return "unknown"


def apktool_decode(apk_file: Path, outdir: Path, opts: dict):
    apktool = find_tool("apktool")
    if not apktool:
        log("apktool tidak ditemukan, manifest dilewati", "warn")
        return
    java = "java"
    outdir.mkdir(parents=True, exist_ok=True)
    log("[>] apktool decode: manifest + resources (live progress di bawah)")
    rc, out, err = run_cmd([java, "-jar", str(apktool), "d", "-f", "-o", str(outdir), str(apk_file)],
                       timeout=900, stream=True)
    if rc != 0:
        log(f"apktool decode gagal: {err[:200]}", "warn")
    elif not (outdir / "AndroidManifest.xml").exists():
        log("apktool selesai tapi manifest tidak ditemukan", "warn")


def signer_info(rsa_file: Path, outfile: Path):
    """Ekstrak subject dari sertifikat signing APK (META-INF/*.RSA)."""
    try:
        import subprocess
        import os
        from cryptography.x509 import load_der_x509_certificate
        from cryptography.hazmat.primitives.serialization import Encoding
        # fallback: keytool -printcert -jarfile
        jarfile = None
        # find the apk in rsa_file parents
        outfile.parent.mkdir(parents=True, exist_ok=True)
        with open(outfile, "a", encoding="utf-8") as f:
            f.write(f"# signing: {rsa_file.name}\n")
    except Exception:
        pass

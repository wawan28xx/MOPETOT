#!/usr/bin/env python3
"""mobile_audit.py — otomasi reverse engineering + secret scanning untuk target mobile/binari.

Alur: IDENTIFY -> UNPACK -> SCAN -> REPORT

Target yang didukung:
  .apk / .aab / .xapk / .apks    Android package
  .ipa                           iOS package
  .jar                           Java archive
  .dex / .smali                  Dalvik bytecode
  .so / .dll / .exe / Mach-O     native / .NET binaries
  .hbc / .bundle                 Hermes / React Native
  <dir>                          direktori sudah diekstrak (APK/asset)
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Console cp1252 sering crash saat print byte non-UTF8 (rabin2, strings biner).
# Paksa stdout/stderr ke UTF-8 + replace supaya scan tidak mati di tengah jalan.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from engines.common import log, find_tool
from engines import apk_engine, ipa_engine, dex_engine, native_engine, dotnet_engine
from engines import hermes_engine, flutter_engine, unity_engine, generic_engine, plist_engine
from engines.fingerprint import sniff_file, detect_framework, FRAMEWORK_NAMES, rabin2_identity
from secret_scanner import load_rules, scan_corpus, summarize
from engines import manifest_analyzer, endpoint_analyzer

BASE = Path(__file__).resolve().parent


def classify(target: Path):
    ext = target.suffix.lower()
    if target.is_dir():
        ct, fw = detect_framework(target)
        return "dir", fw
    kind, _ = sniff_file(target)
    if ext in (".apk",):
        return "apk", None
    if ext in (".aab", ".xapk", ".apks", ".apkm", ".zip"):
        return "zip", None
    if ext == ".ipa":
        return "ipa", None
    if ext == ".jar" or kind == "jar":
        return "jar", None
    if kind == "dex":
        return "dex", None
    if ext in (".so",) or kind == "elf":
        return "elf", None
    if ext in (".dll", ".exe") or kind == "pe":
        return "pe", None
    if ext in (".hbc",) or kind == "hbc":
        return "hbc", None
    if kind == "mach_o":
        return "macho", None
    if kind == "axml":
        return "axml", None
    return "unknown", None


def unpack(target: Path, workdir: Path, opts: dict):
    ctype, _ = classify(target)
    root = None
    if ctype in ("apk", "zip") or ctype == "apk":
        root = apk_engine.unpack_apk(target, workdir, opts)
    elif ctype == "ipa":
        root = ipa_engine.unpack_ipa(target, workdir, opts)
    elif ctype == "jar":
        _unpack_jar(target, workdir)
    elif ctype == "dex":
        dex_engine.run([target], workdir / "corpus" / "sources_java", opts)
    elif ctype == "elf":
        native_engine.run(target, workdir / "corpus", opts)
    elif ctype == "pe":
        if _is_dotnet(target):
            dotnet_engine.run(target, workdir / "corpus", opts)
        else:
            native_engine.run(target, workdir / "corpus", opts)
    elif ctype == "hbc":
        hermes_engine.run(target, workdir / "corpus", opts)
    elif ctype == "macho":
        native_engine.run(target, workdir / "corpus", opts)
    elif ctype == "axml":
        _dump_axml(target, workdir)
    elif ctype == "dir":
        # sudah diekstrak — rerun fingerprint untuk dispatch engine spesifik
        ct2, fw = detect_framework(target)
        _dispatch_dir(target, workdir, opts)
    else:
        generic_engine.run(target, workdir / "corpus" / "strings_other", opts)
    return ctype, root


def _is_dotnet(path: Path) -> bool:
    try:
        head = path.read_bytes()[:4 * 1024 * 1024]
    except OSError:
        return False
    # Penanda definitif CLI metadata: header dimulai 'BSJB'
    if b"BSJB" in head:
        return True
    if head[:2] == b"MZ":
        if b"mscoree" in head.lower() or b"_CorDllMain" in head or b"_CorExeMain" in head:
            return True
    return False


def _unpack_jar(target: Path, workdir: Path):
    import zipfile
    root = workdir / "jar_root"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(target) as zf:
            zf.extractall(root)
    except Exception as e:
        log(f"jar extract gagal: {e}", "warn")
    classes = sorted(root.rglob("*.class"))
    if classes:
        jadx = find_tool("jadx")
        if jadx:
            out = workdir / "corpus" / "sources_java"
            rc, o, e = _run([str(jadx), "--no-res", "-d", str(out), str(target)], 900)
            log("jadx: jar -> Java source", "ok" if rc == 0 else "warn")


def _dump_axml(target: Path, workdir: Path):
    """Binary XML -> readable XML via androguard."""
    try:
        from androguard.core.axml import AXMLPrinter
        data = target.read_bytes()
        x = AXMLPrinter(data)
        outdir = workdir / "corpus" / "decoded_axml"
        outdir.mkdir(parents=True, exist_ok=True)
        out = outdir / (target.name + ".xml")
        out.write_bytes(x.get_xml())
        log(f"AXML decoded: {target.name}", "ok")
    except Exception as e:
        log(f"AXML decode gagal: {e}", "warn")


def _dispatch_dir(target: Path, workdir: Path, opts: dict):
    from engines.fingerprint import detect_framework as df
    ct, fw = df(target)
    apk_engine.dispatch_extracted(target, target, workdir, opts)


def _run(cmd, timeout):
    from engines.common import run
    return run(cmd, timeout=timeout)


APKID_WRAPPER = BASE / "apkid_wrapper.py"

# Python 3.13 + yara-python-dex (APKiD butuh dex module; tidak ada di 3.14).
PY313_CANDIDATES = [
    r"C:\Users\Administrator_DEIT\AppData\Local\Programs\Python\Python313\python.exe",
    r"C:\Program Files\Python313\python.exe",
    r"C:\Python313\python.exe",
]


def _py313():
    import shutil
    launcher = shutil.which("py")
    if launcher:
        try:
            out = subprocess.run([launcher, "-3.13", "-c", "import sys; print(sys.executable)"],
                                 capture_output=True, text=True, timeout=20,
                                 creationflags=0x08000000).stdout.strip()
            if out and Path(out).exists():
                return out
        except Exception:
            pass
    for p in PY313_CANDIDATES:
        if Path(p).exists():
            return p
    return None


def run_apkid(target: Path):
    """APKiD fingerprint -> dict {packers, protectors, obfuscators, compilers, anti_*}."""
    py313 = _py313()
    if not py313 or not APKID_WRAPPER.exists():
        log("APKiD: python 3.13 tidak ditemukan, TECH STACK di-skip", "warn")
        return {}
    try:
        rc, out, err = _run([py313, str(APKID_WRAPPER), str(target)], timeout=600)
        if rc != 0 or not out:
            log(f"APKiD gagal (rc={rc})", "warn")
            return {}
        data = json.loads(out.strip().splitlines()[-1])
        if data.get("error"):
            log(f"APKiD error: {data['error']}", "warn")
            return {}
    except Exception as e:
        log(f"APKiD exception: {e}", "warn")
        return {}
    merged = {}
    for f in data.get("files", []):
        for cat, rules in (f.get("matches") or {}).items():
            merged.setdefault(cat, []).extend(rules)
    merged = {k: sorted(set(v)) for k, v in merged.items()}
    return merged


def detect_split_apks(target: Path):
    """SPLIT APKS: cek zip (apks/xapk/apkm) berisi banyak .apk, atau sibling
    split_config.*.apk di direktori yang sama dengan base APK."""
    ext = target.suffix.lower()
    if ext in (".apks", ".xapk", ".apkm", ".zip"):
        try:
            import zipfile
            with zipfile.ZipFile(target) as zf:
                apks = [n for n in zf.namelist() if n.lower().endswith(".apk")]
            if apks:
                splits = [a for a in apks if "split_config" in a.lower() or a.lower().endswith("config." + "apk")]
                if len(apks) > 1:
                    detail = f"{len(apks)} ({len(splits)} config splits — no additional dex/manifest content beyond the base APK)" if splits else f"{len(apks)} (multi-APK bundle)"
                    return detail
        except Exception:
            pass
    if ext == ".apk":
        siblings = sorted(target.parent.glob("split_config.*.apk"))
        if siblings:
            return f"{1 + len(siblings)} (config splits — no additional dex/manifest content beyond the base APK)"
    return None


_PACKER_NAMES = {
    "dexguard": "DexGuard",
    "bangcle": "Bangcle",
    "tencent": "Tencent Legu",
    "kiwisec": "KiwiSec",
    "ijiami": "ijiami",
    "sangfor": "Sangfor",
    "appsealing": "AppSealing",
    "jiagu": "360 Jiagu",
    "medusah": "MedusaH",
    "appguard": "AppGuard",
    "apkguard": "APKGuard",
    "protectt": "Protectt",
    "nhn": "NHN AppGuard",
    "dpt": "DPT",
    "gpresto": "Gpresto",
    "gaoxor": "Gaoxor",
    "cryptoshell": "CryptoShell",
    "whitecryption": "WhiteCryption",
    "appdome": "Appdome",
    "insidesecure": "InsideSecure",
    "appiron": "AppIron",
    "appdefence": "AppDefence",
    "vguard": "V-Guard",
    "build38": "Build38",
    "ahope": "Ahop AppShield",
}


def _friendly(names, known):
    out = []
    for n in names:
        l = n.lower()
        hit = next((v for k, v in known.items() if k in l), None)
        out.append(hit or n)
    return sorted(set(out))


def build_tech_stack(apkid: dict, ctype: str, fw: dict, target: Path):
    """Kalimat TECH STACK dari hasil APKiD + deteksi framework."""
    parts = []
    packers = _friendly(apkid.get("packer", []), _PACKER_NAMES)
    protectors = _friendly(apkid.get("protector", []), _PACKER_NAMES)
    compilers = apkid.get("compiler", [])
    obfuscators = apkid.get("obfuscator", [])
    anti_vm = apkid.get("anti_vm", [])
    anti_debug = apkid.get("anti_debug", [])

    fw_keys = list(fw.keys()) if isinstance(fw, dict) else []
    cross_platform = any(k in fw_keys for k in ("flutter", "react_native_hermes", "react_native_js",
                                                "unity_il2cpp", "unity_mono", "cordova", "capacitor", "xamarin"))
    fw_label = ", ".join(fw.values()) if isinstance(fw, dict) else "-"
    parts.append(f"Tipe: {ctype.upper()}")
    parts.append(f"Framework: {fw_label or 'native'}")
    parts.append(f"Cross-platform signature: {'YA (' + ', '.join(k for k in fw_keys if k not in ('unknown',)) + ')' if cross_platform else 'TIDAK (native)'}")

    dex_count = 0
    import zipfile
    if ctype in ("apk", "zip") and target.exists():
        try:
            with zipfile.ZipFile(target) as zf:
                dex_count = sum(1 for n in zf.namelist() if n.lower().endswith(".dex"))
        except Exception:
            dex_count = 0
        parts.append(f"DEX: {dex_count} file")
    elif ctype == "ipa" and target.exists():
        macho = 0
        dylibs = 0
        frameworks = 0
        try:
            with zipfile.ZipFile(target) as zf:
                names = zf.namelist()
                for n in names:
                    ln = n.lower()
                    if ln.endswith(".dylib"):
                        dylibs += 1
                # executable utama: file tanpa ekstensi di root .app
                app_root_names = set()
                for n in names:
                    segs = n.split("/")
                    if len(segs) >= 3 and segs[0] == "Payload" and segs[1].endswith(".app") and len(segs) == 3:
                        app_root_names.add(segs[2])
                main_bin = sum(1 for n in app_root_names
                               if n and "." not in n and n not in ("embedded.mobileprovision", "PkgInfo"))
                macho = main_bin
                # framework bundle: .../Frameworks/X.framework/ berisi biner Mach-O
                frameworks = len({n.split("/")[3] for n in names
                                  if "/frameworks/" in n.lower() and len(n.split("/")) > 3
                                  and n.split("/")[3].endswith(".framework")})
        except Exception:
            pass
        parts.append(f"Mach-O: {macho} executable + {dylibs} dylib + {frameworks} framework")
    if compilers:
        parts.append(f"Compiler: {', '.join(sorted(set(compilers)))}")
    if packers:
        parts.append(f"Packer: {'method-nativized oleh ' + ', '.join(packers) + ' (komersial)' if packers else '-'}")
    if protectors:
        parts.append(f"Protector: {'runtime self-protection komersial: ' + ', '.join(protectors)}")
    if obfuscators:
        parts.append(f"Obfuscator: {', '.join(sorted(set(obfuscators)))}")
    if anti_vm:
        parts.append(f"Anti-VM: {len(anti_vm)} indikator (emulator/device tampering check)")
    if anti_debug:
        parts.append(f"Anti-Debug: {len(anti_debug)} indikator")
    return "; ".join(parts) if parts else "-"


def build_rasp(apkid: dict, corpus_dir: Path = None, apk_root: Path = None):
    """RASP (Runtime Application Self-Protection) — yang paling penting.
    Prioritas: protector komersial (APKiD) > packer (APKiD) > library RASP
    terdeteksi dari corpus/native lib (RootBeer, DexGuard, dll) > in-app check."""
    packers = _friendly(apkid.get("packer", []), _PACKER_NAMES)
    protectors = _friendly(apkid.get("protector", []), _PACKER_NAMES)
    anti_debug = apkid.get("anti_debug", [])
    anti_vm = apkid.get("anti_vm", [])
    anti_root = apkid.get("anti_root", [])

    if protectors:
        return f"TERDETEKSI (runtime protection komersial): {', '.join(protectors)}"
    if packers:
        return f"TERDETEKSI (packer — kode di-enkripsi/dinative-kan): {', '.join(packers)}"

    # Deteksi library RASP yang lolos APKiD (obfuscated/renamed/native-only):
    # scan nama path + nama native lib hasil unpack.
    lib_hits = _detect_rasp_libs(corpus_dir, apk_root)
    if lib_hits:
        # dedup label yang sama
        uniq = {}
        for label in sorted(lib_hits):
            uniq.setdefault(label.split(" (", 1)[0], label)
        return f"TERDETEKSI (library anti-tamper/root-detection: {', '.join(sorted(uniq.values()))})"

    checks = []
    if anti_debug:
        checks.append(f"anti-debug ({len(anti_debug)})")
    if anti_vm:
        checks.append(f"anti-VM ({len(anti_vm)})")
    if anti_root:
        checks.append(f"anti-root ({len(anti_root)})")
    if checks:
        return "SEBAGIAN (in-app security check: " + ", ".join(checks) + ")"
    return "TIDAK TERDETEKSI (tidak ada indikasi runtime protection)"


# Penanda library RASP: (substring path/class, substring native lib, label)
_RASP_LIB_SIGNATURES = [
    (r"com/scottyab/rootbeer", r"rootbeer", "RootBeer (root detection)"),
    (r"com/scottyab/rootbeer", r"toolchecker", "RootBeer (root detection, native lib renamed)"),
    (r"rootbeernative", r"", "RootBeer (root detection)"),
    (r"com/topjohnwu/magisk", r"magisk", "Magisk (root environment)"),
    (r"saurik/substrate", r"substrate", "Substrate (jailbreak/root hook)"),
    (r"com/appsealing", r"appsealing", "AppSealing (RASP)"),
    (r"promon", r"shieldsdk", "Promon Shield (RASP)"),
    (r"com/guardsquare", r"dexguard", "DexGuard (RASP/packer)"),
    (r"dexguard", r"", "DexGuard (RASP/packer)"),
    (r"appguard", r"", "AppGuard (RASP)"),
    (r"com/cresting", r"", "AppGuard/Cresting (RASP)"),
    (r"bangcle", r"libprotect", "Bangcle/SecNeo (packer/RASP)"),
    (r"secneo", r"", "SecNeo/Bangcle (packer/RASP)"),
    (r"libdexhelper", r"dexhelper", "Tencent Legu (packer)"),
    (r"libjiagu", r"jiagu", "Qihoo 360 Jiagu (packer)"),
    (r"libshell", r"libshell", "Shell packer"),
    (r"libavmp", r"avmp", "Obfuscator-LLVM (native obfuscation)"),
    (r"libobfus", r"obfus", "Native obfuscation"),
    (r"com/qq/e", r"libegis", "Tencent soter/Egis (integrity)"),
    (r"com/baidu/protect", r"", "Baidu Protect (RASP)"),
    (r"com/aliyun/security", r"libsecurity", "Alibaba Security (RASP)"),
    (r"whitecryption", r"", "WhiteCryption (code protection)"),
    (r"appdome", r"", "Appdome (RASP/on-device protection)"),
    (r"vguard", r"", "V-Guard (RASP)"),
    (r"free_rasp", r"", "Free RASP (root/jailbreak detection)"),
    (r"ljx/mobilert", r"", "MobileRT (RASP)"),
]


def _detect_rasp_libs(corpus_dir: Path = None, apk_root: Path = None):
    """Cari penanda library RASP dari nama path/class + nama native lib."""
    roots = []
    for d in (corpus_dir, apk_root, (corpus_dir / "..") if corpus_dir else None):
        if d is not None:
            p = Path(d)
            if p.exists():
                roots.append(p)
    if not roots:
        return set()
    found = set()
    # scan file/dir names (path-based, tidak perlu baca isi)
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            low = dirpath.lower().replace("\\", "/")
            for cl, lib, label in _RASP_LIB_SIGNATURES:
                if cl and cl.lower() in low:
                    found.add(label)
            for f in files:
                fl = f.lower()
                for cl, lib, label in _RASP_LIB_SIGNATURES:
                    if lib and lib in fl:
                        found.add(label)
                    elif cl and cl.lower() in fl:
                        found.add(label)
    return found


def write_report(outdir: Path, target: Path, ctype, frameworks, findings, stats, tool_map,
                 endpoints=None, manifest=None, meta=None):
    outdir.mkdir(parents=True, exist_ok=True)
    sev = summarize(findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    meta = meta or {}

    md = []
    md.append(f"# Mobile Audit Report — {target.name}\n")
    md.append(f"- Target: `{target}`")
    md.append(f"- Tipe: `{ctype}`")
    md.append(f"- Framework: {', '.join(frameworks.values()) if isinstance(frameworks, dict) else frameworks}")
    if frameworks and isinstance(frameworks, dict):
        md.append(f"- Deteksi: {', '.join(frameworks.keys()) or '-'}")
    md.append(f"- File discan: {stats['files']}, baris: {stats['lines']}")

    # ===== Header informasi aplikasi (PACKAGE / SHA-256 / TECH STACK / SOURCE / SPLIT APKS / RASP) =====
    package = (manifest or {}).get("package") or meta.get("package") or "-"
    md.append(f"- PACKAGE: `{package}`")
    sha256 = meta.get("sha256")
    if sha256:
        md.append(f"- SHA-256: `{sha256}`")
    md.append(f"- TECH STACK: {meta.get('tech_stack') or '-'}")
    md.append(f"- SOURCE: {meta.get('source') or '-'}")
    md.append(f"- SPLIT APKS: {meta.get('split_apks') or '-'}")
    md.append(f"- RASP: {meta.get('rasp') or '-'}")
    md.append("")

    md.append("## Ringkasan")
    md.append("")
    md.append("| Severity | Jumlah |")
    md.append("|---|---|")
    for s in order:
        md.append(f"| {s.capitalize()} | {sev['by_severity'].get(s, 0)} |")
    md.append("")
    md.append("| Kategori | Jumlah |")
    md.append("|---|---|")
    for cat, n in sorted(sev["by_category"].items(), key=lambda x: -x[1]):
        md.append(f"| {cat} | {n} |")
    md.append("")

    md.append("## Tooling terpasang")
    md.append("")
    md.append("| Tool | Status |")
    md.append("|---|---|")
    for name, path in tool_map.items():
        md.append(f"| {name} | {path or 'TIDAK ADA'} |")
    md.append("")

    if endpoints:
        md.append("## Attack Surface — Endpoint")
        md.append("")
        md.extend(endpoint_analyzer.endpoints_to_markdown(endpoints))
        md.append("")

    md.append("## Manifest / Komponen")
    md.append("")
    md.extend(manifest_analyzer.manifest_to_markdown(manifest))
    md.append("")

    md.append("## Temuan")
    md.append("")
    findings_sorted = sorted(findings, key=lambda f: order.get(f.rule.severity, 9))
    by_id = {}
    for f in findings_sorted:
        by_id.setdefault(f.rule.id, []).append(f)
    md.append("### Detail per rule")
    md.append("")
    for rid in sorted(by_id, key=lambda r: order.get(by_id[r][0].rule.severity, 9)):
        fs = by_id[rid]
        first = fs[0]
        md.append(f"#### `{rid}` — {first.rule.severity.upper()} ({first.rule.category})")
        md.append("")
        md.append(f"{first.rule.description}")
        md.append("")
        md.append(f"Total: **{len(fs)}** lokasi")
        md.append("")
        md.append("```")
        for f in fs[:20]:
            md.append(f"{f.filepath}:{f.line}  :: {f.match.strip()[:160]}")
        if len(fs) > 20:
            md.append(f"... dan {len(fs) - 20} lagi")
        md.append("```")
        md.append("")

    (outdir / "report.md").write_text("\n".join(md), encoding="utf-8")

    jdata = {
        "target": str(target),
        "type": ctype,
        "frameworks": list(frameworks.keys()) if isinstance(frameworks, dict) else frameworks,
        "stats": stats,
        "summary": sev,
        "endpoints": endpoints,
        "manifest": manifest,
        "meta": meta,
        "findings": [f.to_dict() for f in findings_sorted],
    }
    (outdir / "findings.json").write_text(json.dumps(jdata, indent=2), encoding="utf-8")
    return outdir / "report.md"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mobile_audit", description="Otomasi RE + secret scan untuk target mobile/binari")
    ap.add_argument("target", help="APK/AAB/IPA/JAR/DEX/SO/DLL/EXE/HBC atau direktori")
    ap.add_argument("-o", "--out", default=None, help="Direktori output (default: reports/<target>)")
    ap.add_argument("--rules", default=None, help="File rules JSON custom (default: rules/secrets.json)")
    ap.add_argument("--no-unpack", action="store_true", help="Lewati unpack, scan file yang sudah ada")
    ap.add_argument("--quiet", action="store_true", help="Kurangi log")
    ap.add_argument("--keep", action="store_true", help="Pertahankan artefak unpack")
    ap.add_argument("--skip-jadx", action="store_true",
                    help="Fast mode: lewati dekompilasi jadx (smali+assets saja, jauh lebih cepat)")
    ap.add_argument("--skip-blutter", action="store_true",
                    help="Fast mode: lewati dekompilasi blutter (Dart string extraction saja)")
    args = ap.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        log(f"Target tidak ditemukan: {target}", "err")
        sys.exit(2)

    rules = load_rules(args.rules)

    if args.out:
        outdir = Path(args.out)
    else:
        outdir = BASE / "reports" / target.name.replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    tool_map = {t: str(find_tool(t)) if find_tool(t) else None
                for t in ("jadx", "apktool", "rabin2", "ghidra", "ilspycmd", "il2cppdumper", "blutter")}

    t_start = time.time()
    log("=== Phase 1: IDENTIFY ===")
    ctype, fw = classify(target)
    if fw is None and ctype == "dir":
        _, fw = detect_framework(target)
    log(f"Tipe: {ctype}")
    if fw:
        for k, v in fw.items():
            log(f"Framework: {v}")

    if not args.no_unpack:
        log("=== Phase 2: UNPACK ===")
        if args.skip_jadx:
            log("Fast mode: jadx di-skip (smali + assets + strings saja)", "warn")
        if args.skip_blutter:
            log("Fast mode: blutter di-skip (Dart string extraction saja)", "warn")
        t_unpack = time.time()
        try:
            ctype, root = unpack(target, workdir, {"quiet": args.quiet, "skip_jadx": args.skip_jadx, "skip_blutter": args.skip_blutter})
        except Exception as e:
            log(f"Unpack error: {e}", "err")
            import traceback
            traceback.print_exc()
        log(f"Unpack selesai ({time.time() - t_unpack:.1f}s)", "ok")
        # deteksi framework dari hasil ekstraksi
        from engines.fingerprint import detect_framework as df2
        _, fw = df2(workdir)
        log(f"Framework: {', '.join(fw.values())}" if fw else "Framework: -")
    else:
        root = target

    corpus = workdir / "corpus"
    if not corpus.exists():
        corpus = workdir
    if not corpus.exists():
        log("Tidak ada corpus untuk discan", "err")
        sys.exit(1)

    corpus_files = sum(1 for _ in corpus.rglob("*") if _.is_file())
    log(f"=== Phase 3: SCAN ===")
    log(f"Rules dimuat: {len(rules)}")
    log(f"Corpus: {corpus_files} file, target: {target.name}")
    t_scan = time.time()
    findings, stats = scan_corpus(corpus, rules, quiet=args.quiet)
    log(f"Scan selesai ({time.time() - t_scan:.1f}s, {stats['files']} file, {stats['lines']} baris)", "ok")
    log(f"Temuan mentah: {len(findings)}", "ok" if findings else "info")

    log("=== Phase 4: REPORT ===")
    t_report = time.time()

    # Metadata aplikasi: SHA-256 target, APKiD fingerprint (TECH STACK/RASP), split APKs
    meta = {"source": "Operator-supplied APK"}
    log("SHA-256 target...", "info")
    try:
        h = hashlib.sha256()
        with open(target, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        meta["sha256"] = h.hexdigest()
        log(f"SHA-256: {meta['sha256'][:16]}...", "ok")
    except Exception as e:
        log(f"SHA-256 gagal: {e}", "warn")

    apkid = run_apkid(target)
    if apkid:
        meta["tech_stack"] = build_tech_stack(apkid, ctype, fw or {}, target)
        meta["rasp"] = build_rasp(apkid, corpus, workdir / "apk_root")
        log(f"RASP: {meta['rasp']}", "ok" if "TERDETEKSI" in meta["rasp"] or "SEBAGIAN" in meta["rasp"] else "info")
    else:
        meta["tech_stack"] = build_tech_stack({}, ctype, fw or {}, target)
        meta["rasp"] = build_rasp({}, corpus, workdir / "apk_root")

    split_apks = detect_split_apks(target)
    if split_apks:
        meta["split_apks"] = split_apks
        log(f"SPLIT APKS: {split_apks}", "ok")
    endpoints = endpoint_analyzer.analyze_endpoints(corpus, workdir / "corpus" / "decoded_res",
                                                    workdir / "apk_root")
    if ctype == "ipa":
        manifest = manifest_analyzer.analyze_ipa_manifest(corpus, workdir / "ipa_root")
    else:
        manifest = manifest_analyzer.analyze_manifest(corpus, workdir / "corpus" / "decoded_res",
                                                      workdir / "apk_root")
    if manifest:
        meta["package"] = manifest.get("package")

    rep = write_report(outdir, target, ctype, fw or {}, findings, stats, tool_map,
                       endpoints=endpoints, manifest=manifest, meta=meta)
    log(f"Laporan: {rep}")
    log(f"JSON: {outdir / 'findings.json'}")
    log(f"Total waktu: {time.time() - t_start:.1f}s", "ok")

    if not args.keep and workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

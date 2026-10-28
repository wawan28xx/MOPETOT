"""Ekstraksi IPA (iOS): Payload/*.app — Mach-O utama, dylibs, framework, plist."""
import json
import zipfile
from pathlib import Path

from .common import run, log
from . import native_engine, plist_engine, generic_engine


"""Ekstraksi IPA (iOS): Payload/*.app — Mach-O utama, dylibs, framework, plist, Objective-C/Swift class-dump."""
import re
import zipfile
from pathlib import Path

from .common import run, find_tool, log, extract_strings_basic
from . import native_engine, plist_engine, generic_engine


def extract_objc_swift_symbols(macho_path: Path, corpus: Path):
    """Ekstraksi terstruktur Objective-C & Swift Class Hierarchy / Method Signatures (Class-Dump equivalent).

    Urutan strategi:
    1. Parser ObjC runtime pure-Python (engines/objc_dump.py) — class-dump penuh
       (class/super/protocols/methods/ivars/properties/kategori). rabin2 6.x di
       Windows tidak bisa dipakai (flag -C berubah & plugin ObjC rusak: "UnnamedClass").
    2. Fallback lief: symbol table tidak ikut terenkripsi FairPlay, jadi tetap berguna
       untuk binary cryptid-encrypted; symbol Swift `_$s` di-demangle parsial.
    """
    out_dir = corpus / "sources_ios_symbols"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{macho_path.name}_classes.h"

    banner = ["// ====================================================================",
              f"// MOPETOT iOS Class-Dump: {macho_path.name}",
              "// ===================================================================="]

    # 1. Class-dump runtime ObjC via parser internal
    dump_note = None
    try:
        from .objc_dump import dump_binary, swift_demangle_partial
        r = dump_binary(macho_path)
        if r.get("ok"):
            swift_syms = _swift_symbols_lief(macho_path, swift_demangle_partial)
            recovered = 0
            if r.get("partial"):
                # FairPlay partial: symbol table di __LINKEDIT tetap plaintext —
                # framework pihak-3 sering keep `-[Class sel:]` debug symbols.
                # Merge nama selector hasilnya ke inventory class.
                sym_methods = _lief_objc_methods(macho_path)
                for c in r.get("classes") or []:
                    sm = sym_methods.get(c.get("name") or "")
                    if not sm:
                        continue
                    c["methods"] = sorted(set(sm["m"]))[:200]
                    c["class_methods"] = sorted(set(sm["cm"]))[:100]
                    if c["methods"] or c["class_methods"]:
                        recovered += 1
                r["stats"]["methods"] = sum(
                    len(c.get("methods") or []) + len(c.get("class_methods") or [])
                    for c in r.get("classes") or []) or r["stats"].get("methods", 0)
                if recovered:
                    r["recovered_classes"] = recovered
            lines = list(banner)
            lines.append(f"// arch: {r['arch']} | classes: {r['stats']['classes']} | "
                         f"methods: {r['stats']['methods']} | categories: {r['stats']['categories']}")
            lines += ["", r["header"]]
            if r.get("partial"):
                rec = [c for c in (r.get("classes") or [])
                       if (c.get("methods") or c.get("class_methods"))]
                if rec:
                    lines += ["", "// --- Methods recovered dari symbol table (plaintext __LINKEDIT) ---"]
                    for c in rec[:400]:
                        for sel in (c.get("class_methods") or [])[:40]:
                            lines.append(f"+ ({c['name']}) {sel};")
                        for sel in (c.get("methods") or [])[:80]:
                            lines.append(f"- ({c['name']}) {sel};")
            if swift_syms:
                lines += ["", "// --- Swift symbols (demangled parsial) ---", *swift_syms]
            out_file.write_text("\n".join(lines), encoding="utf-8", errors="replace")
            # struktur JSON untuk Hook Generator / iOS Inspector
            (out_dir / f"{macho_path.name}_classes.json").write_text(
                json.dumps({"binary": macho_path.name, "arch": r["arch"], "stats": r["stats"],
                            "partial": bool(r.get("partial")), "encrypted": bool(r.get("encrypted")),
                            "classes": r["classes"], "categories": r["categories"]},
                           indent=1, ensure_ascii=False),
                encoding="utf-8", errors="replace")
            mode = "PARTIAL FairPlay" if r.get("partial") else "runtime parser"
            if r.get("recovered_classes"):
                mode += f" +{r['recovered_classes']} class via symtab"
            log(f"iOS Class-Dump ({mode}): {macho_path.name} -> "
                f"{r['stats']['classes']} classes / {r['stats']['methods']} methods", "ok")
            return
        dump_note = r.get("error")
        if r.get("encrypted"):
            dump_note = "FairPlay/cryptid ENCRYPTED"
    except Exception as e:
        dump_note = f"parser error: {e}"

    # 2. Fallback: symbol table via lief (tetap jalan untuk binary encrypted)
    try:
        from .objc_dump import swift_demangle_partial
    except Exception:
        def swift_demangle_partial(_s):
            return None
    classes_found = set()
    methods_found = set()
    swift_found = set()
    try:
        import lief
        binary = lief.parse(str(macho_path))
        if binary:
            for s in binary.symbols:
                name = s.name or ""
                if "_OBJC_CLASS_$_" in name:
                    cname = name.split("_OBJC_CLASS_$_")[-1]
                    classes_found.add(f"@interface {cname} : NSObject")
                elif (name.startswith("-[") or name.startswith("+[")) and name.endswith("]"):
                    methods_found.add(name)
                elif name.startswith("_$s") or name.startswith("$s"):
                    swift_found.add(swift_demangle_partial(name) or f"// Swift Symbol: {name}")
    except Exception:
        pass

    content = list(banner)
    if dump_note:
        content.append(f"// NOTE: {dump_note} — dump dari runtime ObjC tidak tersedia;")
        content.append("//       section di bawah adalah hasil fallback symbol table (parsial).")
        if dump_note.startswith("FairPlay"):
            content.append("//       Untuk class-dump penuh, dump binary ter-dekripsi dari device jailbroken.")
    content += ["", "// --- Classes ---"]
    content.extend(sorted(classes_found))
    content += ["", "// --- Methods / Selectors ---"]
    content.extend(sorted(methods_found))
    if swift_found:
        content += ["", "// --- Swift Symbols ---"]
        content.extend(sorted(swift_found))
    if len(content) > len(banner) + 5:
        out_file.write_text("\n".join(content), encoding="utf-8", errors="replace")
        log(f"iOS Class-Dump (fallback symbols): {macho_path.name} "
            f"({len(classes_found)} classes, {len(methods_found)} methods, {len(swift_found)} swift)", "ok")


def _lief_objc_methods(macho_path: Path) -> dict:
    """Symbol ObjC dari symtab (linkedit tidak ikut terenkripsi FairPlay).

    Framework pihak-3 (Realm, Alamofire, dll.) biasanya keep symbol debug
    `-[Class selector:]` -> bisa dipakai untuk isi nama method yang di partial
    dump milik binary FairPlay-encrypted.
    Return {class: {"m": [selector...], "cm": [selector...]}}.
    """
    out = {}
    try:
        import lief
        b = lief.parse(str(macho_path))
        if not b:
            return out
        for s in b.symbols:
            nm = s.name or ""
            if not (nm.startswith("-[") or nm.startswith("+[")) or not nm.endswith("]"):
                continue
            inner = nm[2:-1]
            if " " not in inner:
                continue
            cls, sel = inner.split(" ", 1)
            entry = out.setdefault(cls, {"m": [], "cm": []})
            (entry["cm"] if nm.startswith("+[") else entry["m"]).append(sel)
    except Exception:
        pass
    return out


def _swift_symbols_lief(macho_path: Path, demangler) -> list:
    """Ambil symbol Swift dari symtab via lief dan demangle parsial (maks 400 baris)."""
    out = []
    try:
        import lief
        binary = lief.parse(str(macho_path))
        if not binary:
            return out
        for s in binary.symbols:
            name = s.name or ""
            if name.startswith("_$s") or name.startswith("$s"):
                dm = None
                try:
                    dm = demangler(name)
                except Exception:
                    pass
                out.append(f"{dm or name}")
                if len(out) >= 400:
                    break
    except Exception:
        pass
    return out


def unpack_ipa(target: Path, workdir: Path, opts: dict):
    log(f"Bongkar IPA: {target.name}")
    root = workdir / "ipa_root"
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                zf.extract(info, root)
            except Exception:
                pass

    corpus = workdir / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)

    apps = sorted(root.rglob("*.app")) if (root / "Payload").exists() else []
    app_dir = apps[0] if apps else None
    if not app_dir:
        app_dir = root

    # Mach-O utama (file executable di root .app tanpa ekstensi yang BENAR-BENAR
    # Mach-O — jangan menerima PkgInfo dsb. yang kebetulan tanpa ekstensi)
    main_bin = None
    for f in sorted(app_dir.iterdir()):
        if f.is_file() and f.suffix == "" and f.name not in ("embedded.mobileprovision",) and _is_macho(f):
            main_bin = f
            break
    if main_bin:
        native_engine.run(main_bin, corpus, opts)
        extract_objc_swift_symbols(main_bin, corpus)
        log(f"Mach-O utama: {main_bin.name}", "ok")

    # Flutter iOS: Dart AOT snapshot di Frameworks/App.framework/App
    if (app_dir / "Frameworks" / "App.framework" / "App").exists():
        from . import flutter_engine
        flutter_engine.run_ios(app_dir, workdir, corpus, opts)

    # Semua biner Mach-O lain (dylib, framework biner, executable tools)
    macho_glob = list(app_dir.rglob("*.dylib")) + [p for p in app_dir.rglob("*") if p.is_file() and _is_macho(p)]
    seen = {main_bin} if main_bin else set()
    for b in macho_glob:
        if b in seen:
            continue
        seen.add(b)
        native_engine.run(b, corpus, opts)
        # Ekstrak simbol class untuk dynamic framework biner
        if b.suffix == ".dylib" or "framework" in str(b).lower():
            extract_objc_swift_symbols(b, corpus)

    # Deteksi FairPlay encryption (cryptid) pada semua biner Mach-O
    analyze_ipa_encryption(app_dir, corpus, [b for b in seen if b])

    # Plist -> XML. Nama unik per path relatif supaya Info.plist antar-bundle
    # tidak saling menimpa; Info.plist utama app disimpan tetap sebagai
    # `Info.plist` agar manifest_analyzer bisa menemukannya.
    plist_out = corpus / "plist_decoded"
    plist_out.mkdir(parents=True, exist_ok=True)
    plists = list(app_dir.rglob("*.plist")) + list(app_dir.rglob("*.mobileprovision"))
    main_plist = app_dir / "Info.plist"
    for p in plists:
        if p == main_plist:
            name = "Info.plist"
        else:
            rel = p.relative_to(app_dir)
            name = "__".join(rel.parts[:-1] + (rel.stem,)) if len(rel.parts) > 1 else rel.stem
        if plist_engine.run(p, plist_out, opts, name=name):
            log(f"plist: {p.name}", "ok")

    # Bundle JS / JSON / aset teks
    scan_exts = {".js", ".json", ".xml", ".txt", ".properties", ".yml", ".yaml", ".ini",
                 ".html", ".htm", ".css", ".conf", ".cfg", ".env", ".ts", ".php", ".py", ".rb", ".md"}
    for f in app_dir.rglob("*"):
        if f.is_file() and f.suffix.lower() in scan_exts:
            rel = f.relative_to(app_dir)
            dst = corpus / "assets" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                dst.write_bytes(f.read_bytes())
            except OSError:
                pass

    # Entitlements / provisioning profile (XML plist) sudah ter-decode di plist_out
    return root


def _is_macho(path: Path):
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe")


# ------------------ FairPlay encryption (cryptid) detection ------------------

import struct

# Magic Mach-O
MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
FAT_MAGIC_BE = 0xCAFEBABE  # fat/universal (big-endian)

# Load command
LC_ENCRYPTION_INFO = 0x21      # 32-bit
LC_ENCRYPTION_INFO_64 = 0x2C   # 64-bit

_CPU_TYPES = {
    12: "arm", 0x0100000C: "arm64",
    7: "x86", 0x01000007: "x86_64",
    5: "powerpc", 0x01000012: "ppc64",
}


def _parse_mach_slice(data: bytes, offset: int) -> dict:
    """Parse satu slice Mach-O -> {ncmds, cryptid, cryptoff, cryptsize} atau None."""
    if offset + 32 > len(data):
        return None
    # Magic bisa little- atau big-endian tergantung platform
    magic_le = struct.unpack_from("<I", data, offset)[0]
    magic_be = struct.unpack_from(">I", data, offset)[0]
    little = None
    if magic_le in (MH_MAGIC_64, MH_MAGIC):
        little = True
    elif magic_be in (MH_MAGIC_64, MH_MAGIC):
        little = False
    else:
        return None
    endianness = "<" if little else ">"
    # mach_header{32}: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
    # (+reserved utk 64-bit) — layout sama hingga ncmds
    cputype = struct.unpack_from(endianness + "I", data, offset + 4)[0]
    ncmds = struct.unpack_from(endianness + "I", data, offset + 16)[0]
    is64 = (magic_le if little else magic_be) == MH_MAGIC_64
    cursor = offset + 32 if is64 else offset + 28  # header 64-bit punya reserved
    result = {"cryptid": 0, "cryptoff": 0, "cryptsize": 0, "arch": _CPU_TYPES.get(cputype, f"cpu:{cputype}"), "ncmds": ncmds}
    for _ in range(ncmds):
        if cursor + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endianness + "II", data, cursor)
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # encryption_info: cmd, cmdsize, cryptoff, cryptsize, cryptid
            if cursor + 20 <= len(data):
                cryptoff, cryptsize, cryptid = struct.unpack_from(endianness + "III", data, cursor + 8)
                if cryptid:
                    result.update({"cryptid": cryptid, "cryptoff": cryptoff, "cryptsize": cryptsize})
        cursor += cmdsize
        if cmdsize == 0:
            break
    return result


def check_macho_encryption(path: Path) -> list:
    """Deteksi FairPlay encryption (cryptid) per-slice Mach-O. Pure Python, tanpa dep baru.

    Return list[{arch, cryptid, cryptoff, cryptsize, encrypted}].
    Fat/universal binary menghasilkan >1 entry.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return []
    slices = []
    fat_magic = struct.unpack_from(">I", data, 0)[0]
    if fat_magic == FAT_MAGIC_BE:
        # universal binary: nfat_arch, lalu {cputype, cpusubtype, offset, size, align}
        nfat = struct.unpack_from(">I", data, 4)[0]
        for i in range(min(nfat, 16)):
            base = 8 + i * 20
            if base + 20 > len(data):
                break
            cputype, _, off, size, _ = struct.unpack_from(">IIIII", data, base)
            slices.append((off, _CPU_TYPES.get(cputype, f"cpu:{cputype}")))
    else:
        slices.append((0, None))

    results = []
    for off, forced_arch in slices:
        info = _parse_mach_slice(data, off)
        if not info:
            continue
        if forced_arch:
            info["arch"] = forced_arch
        info["encrypted"] = bool(info.get("cryptid"))
        results.append(info)
    return results


def analyze_ipa_encryption(app_dir: Path, corpus: Path, binaries: list):
    """Cek semua binary Mach-O dalam .app; hasil disimpan ke corpus/ios_crypto.json."""
    report = {"binaries": [], "any_encrypted": False}
    for b in binaries:
        if not b or not Path(b).exists():
            continue
        slices = check_macho_encryption(Path(b))
        if not slices:
            continue
        rel = str(b.relative_to(app_dir)) if b.is_relative_to(app_dir) else b.name
        for s in slices:
            entry = {
                "file": rel, "arch": s["arch"],
                "cryptid": s["cryptid"], "cryptoff": s["cryptoff"], "cryptsize": s["cryptsize"],
                "encrypted": s["encrypted"],
            }
            report["binaries"].append(entry)
            if s["encrypted"]:
                report["any_encrypted"] = True
                log(f"🔒 FairPlay ENCRYPTED: {rel} [{s['arch']}] cryptid={s['cryptid']} "
                    f"(offset {s['cryptoff']:#x}, size {s['cryptsize']}) — strings/symbols TIDAK lengkap, "
                    f"butuh dump decrypted dari device jailbroken", "warn")
            else:
                log(f"cryptid=0 OK: {rel} [{s['arch']}] binary tidak terenkripsi", "ok")
    try:
        (corpus / "ios_crypto.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError:
        pass
    return report

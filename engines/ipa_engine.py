"""Ekstraksi IPA (iOS): Payload/*.app — Mach-O utama, dylibs, framework, plist."""
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
    """Ekstraksi terstruktur Objective-C & Swift Class Hierarchy / Method Signatures (Class-Dump equivalent)."""
    r2 = find_tool("rabin2")
    out_dir = corpus / "sources_ios_symbols"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{macho_path.name}_classes.h"

    classes_found = set()
    methods_found = set()
    protocols_found = set()

    # 1. Gunakan rabin2 -C (Objective-C Classes & Methods dump) jika tersedia
    if r2:
        rc, out, err = run([str(r2), "-C", "-qq", str(macho_path)], timeout=180, stream=False)
        if rc == 0 and out and ("class " in out or "method " in out or "@interface" in out or "objc" in out.lower()):
            out_file.write_text(out, encoding="utf-8", errors="replace")
            log(f"iOS Class-Dump (rabin2 -C): {macho_path.name} -> {out_file.name}", "ok")
            return

    # 2. Fallback: Ekstraksi via lief / symbol demangling untuk Swift & Obj-C
    try:
        import lief
        binary = lief.parse(str(macho_path))
        if binary:
            for s in binary.symbols:
                name = s.name or ""
                # ObjC Class: _OBJC_CLASS_$_MyClass
                if "_OBJC_CLASS_$_" in name:
                    cname = name.split("_OBJC_CLASS_$_")[-1]
                    classes_found.add(f"@interface {cname} : NSObject")
                # ObjC Method: -[MyClass myMethod:] or +[MyClass myMethod:]
                elif (name.startswith("-[") or name.startswith("+[")) and name.endswith("]"):
                    methods_found.add(name)
                # Swift Mangled Symbols: _$s... / $s...
                elif name.startswith("_$s") or name.startswith("$s"):
                    classes_found.add(f"// Swift Symbol: {name}")
    except Exception:
        pass

    # 3. Fallback: Scan raw binary untuk Objective-C selector & class strings
    if not classes_found and not methods_found:
        try:
            data = macho_path.read_bytes()
            # Cari pola Obj-C selector
            objc_methods = re.findall(rb'[-+][\w\(\)\s\*]+\[[\w]+\s+[\w:]+\]', data)
            for m in objc_methods:
                try:
                    methods_found.add(m.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
        except Exception:
            pass

    if classes_found or methods_found:
        content = ["// ============================================================================",
                   f"// iOS Objective-C & Swift Class-Dump (Extracted from {macho_path.name})",
                   "// ============================================================================",
                   "",
                   "// --- Classes ---"]
        content.extend(sorted(classes_found))
        content.extend(["", "// --- Methods / Selectors ---"])
        content.extend(sorted(methods_found))
        out_file.write_text("\n".join(content), encoding="utf-8", errors="replace")
        log(f"iOS Class-Dump: {macho_path.name} ({len(classes_found)} classes, {len(methods_found)} methods)", "ok")


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

    # Mach-O utama (file executable di root .app tanpa ekstensi)
    main_bin = None
    for f in sorted(app_dir.iterdir()):
        if f.is_file() and f.suffix == "" and f.name not in ("embedded.mobileprovision",):
            main_bin = f
            break
    if main_bin:
        native_engine.run(main_bin, corpus, opts)
        extract_objc_swift_symbols(main_bin, corpus)
        log(f"Mach-O utama: {main_bin.name}", "ok")

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

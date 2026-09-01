"""Native binary (ELF .so / Mach-O / PE): ekstrak strings + symbols (rabin2 + lief)."""
from pathlib import Path

from .common import run as run_cmd
from .common import find_tool, log, extract_strings_basic
from . import generic_engine


"""Native binary (ELF .so / Mach-O / PE): ekstrak strings + symbols (rabin2 + lief + Ghidra Decompiler)."""
import os
import shutil
import tempfile
from pathlib import Path

from .common import run as run_cmd
from .common import find_tool, log, extract_strings_basic
from . import generic_engine


def run_ghidra_decompiler(path: Path, corpus: Path, opts: dict):
    """Jalankan Ghidra Headless Analyzer untuk dekompilasi C/C++ fungsi JNI dan native."""
    ghidra_headless = find_tool("ghidra")
    if not ghidra_headless:
        return

    # Hanya dekompilasi library aplikasi utama / JNI (jangan semua library sistem pihak ketiga untuk efisiensi)
    # File berukuran < 30MB
    try:
        if path.stat().st_size > 30 * 1024 * 1024:
            return
    except OSError:
        return

    out_c_dir = corpus / "sources_c_decompiled"
    out_c_dir.mkdir(parents=True, exist_ok=True)
    c_outfile = out_c_dir / f"{path.name}.c"
    if c_outfile.exists():
        return

    # Buat script Ghidra headless python export sederhana
    with tempfile.TemporaryDirectory() as tmp_proj_dir:
        script_dir = Path(tmp_proj_dir) / "scripts"
        script_dir.mkdir(parents=True, exist_ok=True)
        export_script = script_dir / "ExportC.java"

        # Java headless export script
        export_script.write_text(f"""
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;
import java.io.File;

public class ExportC extends GhidraScript {{
    @Override
    public void run() throws Exception {{
        File outFile = new File("{str(c_outfile).replace('\\', '/')}");
        PrintWriter writer = new PrintWriter(outFile);
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        FunctionIterator iter = currentProgram.getListing().getFunctions(true);
        while (iter.hasNext()) {{
            Function f = iter.next();
            // Prioritas fungsi JNI atau fungsi custom aplikasi
            String fname = f.getName();
            if (fname.startsWith("Java_") || fname.startsWith("jni") || !fname.startsWith("FUN_")) {{
                DecompileResults res = decomp.decompileFunction(f, 30, monitor);
                if (res != null && res.getDecompiledFunction() != null) {{
                    writer.println("// Function: " + fname);
                    writer.println(res.getDecompiledFunction().getC());
                    writer.println();
                }}
            }}
        }}
        writer.close();
        decomp.dispose();
    }}
}}
""", encoding="utf-8")

        cmd = [
            str(ghidra_headless),
            tmp_proj_dir,
            "TempProj",
            "-import", str(path),
            "-scriptPath", str(script_dir),
            "-postScript", "ExportC.java",
            "-deleteProject"
        ]

        log(f"[>] Ghidra Headless: decompile JNI C/C++ {path.name}")
        rc, out, err = run_cmd(cmd, timeout=300, stream=False)
        if rc == 0 and c_outfile.exists() and c_outfile.stat().st_size > 0:
            log(f"Ghidra decompiled: {path.name} -> {c_outfile.name}", "ok")
        else:
            # Jika timeout atau gagal, fallback silent
            if c_outfile.exists() and c_outfile.stat().st_size == 0:
                c_outfile.unlink(missing_ok=True)


def run(path: Path, corpus: Path, opts: dict):
    kind = _kind(path)
    rel_dir = corpus / "strings_native"
    rel_dir.mkdir(parents=True, exist_ok=True)

    outfile = rel_dir / (path.name + ".strings")
    # rabin2 -z (strings) cepat untuk ELF/Mach-O/PE
    r2 = find_tool("rabin2")
    written = False
    if r2:
        log(f"[>] rabin2: strings {path.name}")
        rc, out, err = run_cmd([str(r2), "-z", "-qq", str(path)], timeout=300, stream=False)
        if rc == 0 and out:
            outfile.write_text(out, encoding="utf-8", errors="replace")
            written = True
        elif rc == 0 and not out:
            pass
        else:
            log(f"rabin2 -z gagal untuk {path.name}: {err[:100]}", "warn")
    if not written:
        try:
            data = path.read_bytes()
            strings = extract_strings_basic(data, min_len=6)
            if strings:
                outfile.write_text("\n".join(strings), encoding="utf-8", errors="replace")
                written = True
        except OSError:
            pass

    if written:
        log(f"strings: {path.name}", "ok")

    # Symbols (function names, imports) via lief
    has_jni_function = False
    try:
        import lief
        binary = lief.parse(str(path))
        if binary is not None:
            syms = []
            for s in binary.symbols:
                try:
                    if s.name:
                        syms.append(s.name)
                        if s.name.startswith("Java_"):
                            has_jni_function = True
                except Exception:
                    pass
            try:
                for imp in getattr(binary, "imports", []) or []:
                    syms.append(f"import {imp.name}")
            except Exception:
                pass
            if syms:
                symfile = corpus / "symbols_native" / (path.name + ".symbols")
                symfile.parent.mkdir(parents=True, exist_ok=True)
                symfile.write_text("\n".join(sorted(set(syms))), encoding="utf-8", errors="replace")
                log(f"symbols: {path.name} ({len(syms)})", "ok")
    except ImportError:
        pass
    except Exception as e:
        log(f"lief parse {path.name}: {e}", "warn")

    # Jalankan Ghidra Decompiler untuk library ELF/JNI yang relevan
    if kind == "elf" and (has_jni_function or path.name.startswith("libapp") or "native" in path.name.lower()):
        run_ghidra_decompiler(path, corpus, opts)


def _kind(path: Path):
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return "?"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return "macho"
    return "?"

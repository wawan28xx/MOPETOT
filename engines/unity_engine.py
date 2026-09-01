"""Unity IL2CPP: libil2cpp.so + global-metadata.dat -> dump.cs (class/method/field)."""
from pathlib import Path

from .common import run as run_cmd, find_tool, log
from . import native_engine


def run(libil2cpp: Path, root: Path, corpus: Path, opts: dict):
    metadata = None
    for p in root.rglob("global-metadata.dat"):
        metadata = p
        break
    dumper = find_tool("il2cppdumper")
    if dumper and metadata:
        outdir = corpus / "unity_il2cpp"
        outdir.mkdir(parents=True, exist_ok=True)
        log(f"[>] Il2CppDumper: {libil2cpp.name} + global-metadata.dat")
        rc, out, err = run_cmd([str(dumper), str(libil2cpp), str(metadata), str(outdir)], timeout=600, stream=True)
        dump_cs = outdir / "dump.cs"
        if rc == 0 and dump_cs.exists():
            log(f"Il2CppDumper: {len(dump_cs.read_text(encoding='utf-8', errors='replace').splitlines())} baris dump.cs", "ok")
            return
        log(f"Il2CppDumper gagal ({err[:120]}), fallback strings", "warn")
    elif not metadata:
        log("global-metadata.dat tidak ditemukan", "warn")
    else:
        log("Il2CppDumper tidak ditemukan", "warn")

    native_engine.run(libil2cpp, corpus, opts)

"""DEX -> Java source (jadx) atau Smali (apktool/baksmali)."""
import shutil
from pathlib import Path

from .common import run as run_cmd
from .common import find_tool, log


def _has_output(outdir: Path) -> bool:
    if not outdir.exists():
        return False
    return any(outdir.rglob("*.java")) or any(outdir.rglob("*.smali"))


def run(dex_files, outdir: Path, opts: dict):
    if not dex_files:
        return
    if opts.get("skip_jadx"):
        log("jadx di-skip (fast mode) — cukup smali dari apktool decode", "warn")
        return
    jadx = find_tool("jadx")
    if jadx:
        log(f"jadx: dekompilasi {len(dex_files)} DEX -> {outdir.name} (bisa lama, live progress di bawah)")
        rc, out, err = run_cmd(
            [str(jadx), "--no-res", "--no-debug-info", "-d", str(outdir), *[str(d) for d in dex_files]],
            timeout=900,
            stream=True,
        )
        if rc == 0 or _has_output(outdir):
            count = sum(1 for _ in outdir.rglob("*.java")) if outdir.exists() else 0
            log(f"jadx: {len(dex_files)} DEX -> {count} file Java", "ok")
            return
        log(f"jadx gagal (rc={rc}, {err[:120]}), fallback smali", "warn")
    else:
        log("jadx tidak ditemukan", "warn")

    # Fallback smali via apktool
    apktool = find_tool("apktool")
    if apktool and dex_files:
        smali_out = outdir.parent / "smali"
        smali_out.mkdir(parents=True, exist_ok=True)
        rc, out, err = run_cmd(["java", "-jar", str(apktool), "d", "-f", "-s", "-o", str(smali_out), str(dex_files[0].parent)],
                           timeout=600, stream=True)
        if rc == 0:
            log("apktool: smali assembly dihasilkan", "ok")
        else:
            log(f"smali fallback gagal: {err[:120]}", "warn")

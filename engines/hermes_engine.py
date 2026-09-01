"""Hermes bytecode (.hbc / index.android.bundle) -> assembly (hbctool)."""
from pathlib import Path

from .common import run as run_cmd
from .common import log


def run(path: Path, corpus: Path, opts: dict):
    outdir = corpus / "hermes_asm"
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / (path.name + ".hbcasm")

    from shutil import which
    exe = which("hbctool")
    rc = 1
    log(f"[>] hbctool: disasm {path.name}")
    if exe:
        rc, out, err = run_cmd([exe, "disasm", str(path), str(outfile)], timeout=300, stream=True)
    else:
        try:
            rc, out, err = run_cmd(
                ["python", "-m", "hbctool", "disasm", str(path), str(outfile)], timeout=300, stream=True
            )
        except FileNotFoundError:
            rc = 1

    if rc == 0 and outfile.exists():
        log(f"hbctool: {path.name} -> Hermes asm", "ok")
        return

    log(f"hbctool tidak tersedia/bisa untuk {path.name}, fallback strings", "warn")
    from .generic_engine import run as gen_run
    gen_run(path, corpus / "strings_other", opts)

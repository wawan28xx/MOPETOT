"""Generic binary -> dump strings (untuk format tak dikenal)."""
from pathlib import Path

from .common import extract_strings_basic, log


def run(path: Path, outdir: Path, opts: dict):
    try:
        if path.stat().st_size > 30 * 1024 * 1024:
            return
        data = path.read_bytes()
    except OSError:
        return
    strings = extract_strings_basic(data, min_len=6)
    if not strings:
        return
    outdir.mkdir(parents=True, exist_ok=True)
    outfile = outdir / (path.name + ".strings")
    outfile.write_text("\n".join(strings), encoding="utf-8", errors="replace")
    log(f"strings manual: {path.name}", "ok")

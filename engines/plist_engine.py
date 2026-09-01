"""Plist (biner/XML) -> XML teks via plistlib."""
import plistlib
from pathlib import Path


def run(path: Path, outdir: Path, opts: dict, name: str = None):
    """Decode plist -> XML teks. `name` opsional (tanpa .xml) supaya beberapa
    Info.plist dari bundle berbeda tidak saling menimpa di outdir."""
    outdir.mkdir(parents=True, exist_ok=True)
    out_name = (name or path.name) + ".xml"
    try:
        data = path.read_bytes()
        if data[:6] == b"bplist":
            obj = plistlib.loads(data)
            outfile = outdir / out_name
            outfile.write_text(plistlib.dumps(obj, fmt=plistlib.FMT_XML).decode("utf-8"), encoding="utf-8")
            return True
        else:
            # plain XML plist — copy langsung
            dst = outdir / out_name
            dst.write_bytes(data)
            return True
    except Exception:
        return False

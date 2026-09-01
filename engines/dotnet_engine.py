""".NET assembly (.dll/.exe) -> C# source via ilspycmd."""
from pathlib import Path

from .common import run as run_cmd, find_tool, log


def run(path: Path, corpus: Path, opts: dict):
    ilspy = find_tool("ilspycmd")
    if not ilspy:
        log("ilspycmd tidak ditemukan, .NET dilewati", "warn")
        return
    outdir = corpus / "sources_dotnet" / path.name.replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    log(f"[>] ilspycmd: decompile {path.name}")
    rc, out, err = run_cmd([str(ilspy), "-p", "-o", str(outdir), str(path)], timeout=600, stream=True)
    if rc == 0:
        log(f"ilspycmd: {path.name} -> C#", "ok")
    else:
        # fallback single-file dump
        rc2, out2, err2 = run_cmd([str(ilspy), "-o", str(outdir / (path.stem + ".cs")), str(path)], timeout=600, stream=True)
        if rc2 == 0:
            log(f"ilspycmd (single): {path.name}", "ok")
        else:
            log(f"ilspycmd gagal {path.name}: {err[:120]}", "warn")

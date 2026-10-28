# -*- coding: utf-8 -*-
"""Wrapper blutter untuk MOPETOT (Windows).

Pemakaian: python bin/blutter_run.py <lib_dir_berisi_libapp.so> <outdir>

Melakukan:
1. Set env MSVC (vcvarsall) + CMake + Ninja + DLL ICU (bin/blutter_src/bin)
2. Jalankan blutter.py <lib_dir> <outdir>
   - otomatis fetch SDK Dart sesuai versi target (cache di dartsdk/)
   - build DartVM per versi (cache di build/) — sekali per versi Dart
   - dump class/function/offset -> pp.txt, objs.txt, asm/, blutter_frida.js

Dipanggil oleh engines/flutter_engine.py saat framework Flutter terdeteksi.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent      # repo mobile/
BLUTTER_SRC = ROOT / "bin" / "blutter_src"

VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
CMAKE_BIN = r"C:\Program Files\CMake\bin"
NINJA_DIR = (r"C:\Users\Administrator_DEIT\AppData\Local\Microsoft\WinGet\Packages"
             r"\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe")


def build_env():
    """Env dengan compiler MSVC + CMake + Ninja + DLL runtime ICU/capstone."""
    out = subprocess.check_output(
        f'"{VCVARS}" x64 >nul 2>&1 && set', shell=True, text=True,
        errors="replace")
    env = {}
    for line in out.splitlines():
        if "=" in line and not line.startswith("!"):
            k, _, v = line.partition("=")
            env[k] = v
    paths = [
        str(BLUTTER_SRC / "bin"),                          # blutter exe + DLL runtime
        str(BLUTTER_SRC / "external" / "icu-windows" / "bin64"),
        CMAKE_BIN, NINJA_DIR,
    ]
    env["PATH"] = ";".join(paths) + ";" + env.get("PATH", "")
    return env


def main():
    if len(sys.argv) < 3:
        print("usage: blutter_run.py <lib_dir> <outdir>", file=sys.stderr)
        return 2
    lib_dir = Path(sys.argv[1]).resolve()
    outdir = Path(sys.argv[2]).resolve()
    if not (lib_dir / "libapp.so").exists():
        print(f"[blutter] libapp.so tidak ada di {lib_dir}", file=sys.stderr)
        return 3
    outdir.mkdir(parents=True, exist_ok=True)

    env = build_env()
    os.chdir(BLUTTER_SRC)
    p = subprocess.run(
        [sys.executable, "-X", "utf8", "blutter.py", str(lib_dir), str(outdir)],
        env=env)
    return p.returncode


if __name__ == "__main__":
    sys.exit(main())

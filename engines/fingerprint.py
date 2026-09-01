"""Deteksi framework / jenis arsip dari target (APK, IPA, AAB, biner, dll)."""
import json
import os
import re
import zipfile
from pathlib import Path

from .common import run as run_cmd, find_tool, extract_strings_basic, run, is_installed, log

MAGIC = {
    "elf": b"\x7fELF",
    "mach_o": b"\xfe\xed\xfa\xcf",  # 64-bit big endian
    "mach_o_le": b"\xcf\xfa\xed\xfe",  # 64-bit little endian
    "mach_o_32": b"\xfe\xed\xfa\xce",
    "mach_o_32_le": b"\xce\xfa\xed\xfe",
    "pe": b"MZ",
    "zip": b"PK\x03\x04",
    "jar": b"PK\x03\x04",
    "dex": b"dex\n",
    "hbc": b"\x1f\xbc\x0c\x00",
    "class": b"\xca\xfe\xba\xbe",
    "arsc": b"\x02\x00\x0c\x00",
    "gzip": b"\x1f\x8b",
}

FRAMEWORK_NAMES = {
    "flutter": "Flutter (Dart compiled)",
    "react_native_hermes": "React Native (Hermes bytecode)",
    "react_native_js": "React Native (plain JS bundle)",
    "unity_il2cpp": "Unity (IL2CPP native)",
    "unity_mono": "Unity (Mono / managed)",
    "cordova": "Cordova/Ionic/Capacitor (WebView)",
    "xamarin": "Xamarin (.NET on Android)",
    "dotnet": ".NET managed assembly",
    "native": "Native binary (C/C++)",
    "unknown": "Unknown",
}


def sniff_file(path: Path):
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return "unknown", None
    for name, sig in MAGIC.items():
        if head.startswith(sig):
            return name, None
    # AXML / binary XML heuristics
    if head.startswith(b"\x03\x00\x08\x00") or head.startswith(b"\x01\x03\x00\x08"):
        return "axml", None
    return "unknown", None


def sniff_zip_member(zf: zipfile.ZipFile, name):
    try:
        data = zf.read(name)[:8]
    except Exception:
        return None
    for m, sig in MAGIC.items():
        if data.startswith(sig):
            return m
    return None


def detect_framework(unpacked_dir: Path, container_type=None):
    """Cari penanda framework dalam direktori hasil ekstraksi."""
    markers = {}
    paths = list(unpacked_dir.rglob("*")) if unpacked_dir.exists() else []

    lower = {}
    for p in paths:
        if p.is_file():
            lower[p.name.lower()] = p

    if any(p.suffix.lower() == ".apk" for p in paths) or (
        "classes.dex" in lower or any(p.name.lower().startswith("classes") and p.suffix.lower() == ".dex" for p in paths)
    ):
        container_type = "apk"

    # Flutter
    if any(p.name.lower() == "libapp.so" for p in paths) and any(
        p.name.lower().startswith("libflutter") for p in paths
    ):
        markers["flutter"] = FRAMEWORK_NAMES["flutter"]
    # Unity IL2CPP
    il2cpp = any(p.name.lower() == "libil2cpp.so" for p in paths)
    metadata = any(p.name.lower() == "global-metadata.dat" for p in paths)
    if il2cpp and metadata:
        markers["unity_il2cpp"] = FRAMEWORK_NAMES["unity_il2cpp"]
    elif il2cpp:
        markers["unity_il2cpp"] = FRAMEWORK_NAMES["unity_il2cpp"] + " (metadata tidak ditemukan)"
    # Unity Mono
    if any(p.name.lower() == "assembly-csharp.dll" for p in paths):
        markers["unity_mono"] = FRAMEWORK_NAMES["unity_mono"]
    # React Native
    for p in paths:
        n = p.name.lower()
        if n == "index.android.bundle":
            if p.suffix.lower() == ".hbc" or "hbc" in n:
                markers["react_native_hermes"] = FRAMEWORK_NAMES["react_native_hermes"]
            else:
                # cek binary hbc magic
                if p.stat().st_size > 4:
                    with open(p, "rb") as f:
                        if f.read(4) == b"\x1f\xbc\x0c\x00":
                            markers["react_native_hermes"] = FRAMEWORK_NAMES["react_native_hermes"]
                        else:
                            markers["react_native_js"] = FRAMEWORK_NAMES["react_native_js"]
    if any(p.name.lower().endswith(".hbc") for p in paths) and not markers.get("react_native_hermes"):
        markers["react_native_hermes"] = FRAMEWORK_NAMES["react_native_hermes"]
    # Cordova
    if any(str(p).replace("\\", "/").endswith("assets/www/index.html") for p in paths):
        markers["cordova"] = FRAMEWORK_NAMES["cordova"]
    # Capacitor (framework WebView modern; penanda capacitor.config.json + native-bridge.js)
    cap_config = any(p.name.lower() == "capacitor.config.json" for p in paths)
    cap_bridge = any(p.name.lower() in ("native-bridge.js", "capacitor.js") for p in paths)
    if cap_config:
        markers["capacitor"] = "Capacitor (Ionic WebView)"
        if markers.get("cordova"):
            markers["cordova"] = FRAMEWORK_NAMES["cordova"]
    elif cap_bridge and "cordova" not in markers:
        markers["capacitor"] = "Capacitor (Ionic WebView)"
    if cap_bridge and markers.get("capacitor"):
        markers["cordova"] = FRAMEWORK_NAMES["cordova"]
    # Xamarin
    if any(p.name.lower() in ("libmonodroid.so", "libmono.so") for p in paths):
        markers["xamarin"] = FRAMEWORK_NAMES["xamarin"]
    # .NET
    for p in paths:
        if p.suffix.lower() in (".dll", ".exe") and p.name.lower() != "libil2cpp.so":
            if "lib/arm" not in str(p).replace("\\", "/") or "assemblies" in str(p).replace("\\", "/"):
                markers.setdefault("dotnet", FRAMEWORK_NAMES["dotnet"])

    if not markers:
        markers["unknown"] = FRAMEWORK_NAMES["unknown"]

    return container_type, markers


def analyze_single_binary(path: Path):
    """Analisis satu file biner untuk keperluan report metadata."""
    info = {"path": str(path), "size": path.stat().st_size}
    kind, _ = sniff_file(path)
    info["type"] = kind
    if kind == "pe":
        info["machine"] = pe_machine(path)
    return info


def pe_machine(path: Path):
    try:
        data = path.read_bytes()[:4096]
        if data[:2] != b"MZ":
            return "?"
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        if pe_off + 6 > len(data):
            return "?"
        machine = int.from_bytes(data[pe_off + 4:pe_off + 6], "little")
        return {
            0x8664: "x86-64",
            0x014C: "x86",
            0xAA64: "ARM64",
            0x01C4: "ARM32",
        }.get(machine, hex(machine))
    except Exception:
        return "?"


def rabin2_identity(path: Path):
    """Identifikasi arsitektur via rabin2 (fallback `file`)."""
    r2 = find_tool("rabin2")
    if r2:
        rc, out, err = run_cmd([r2, "-I", str(path)])
        if rc == 0 and out:
            return out.strip()
    return None

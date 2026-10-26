"""Unit test: deteksi FairPlay encryption (cryptid) — engines/ipa_engine.py.
Bangun Mach-O sintetis via struct (encrypted, decrypted, fat/universal) & validasi parser.
"""
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import py_compile

py_compile.compile("engines/ipa_engine.py", doraise=True)
print("[0] py_compile OK: engines/ipa_engine.py")

from engines.ipa_engine import check_macho_encryption

LC_ENCRYPTION_INFO_64 = 0x2C
LC_ENCRYPTION_INFO = 0x21


def make_macho64(cryptid=0, cryptoff=0x4000, cryptsize=0x10000):
    """Mach-O 64-bit LE: header + 2 load commands (LC_ENCRYPTION_INFO_64 + LC_SEGMENT dummy)."""
    header = struct.pack("<IIIIIIII",
                         0xFEEDFACF,          # magic
                         0x0100000C,          # cputype arm64
                         0,                   # cpusubtype
                         2,                   # filetype MH_EXECUTE
                         2,                   # ncmds
                         32 + 20 + 24,        # sizeofcmds
                         0,                   # flags
                         0)                   # reserved
    enc = struct.pack("<IIIII", LC_ENCRYPTION_INFO_64, 20, cryptoff, cryptsize, cryptid)
    dummy = struct.pack("<IIIIII", 0x19, 24, 0, 0, 0, 0)  # LC_SEGMENT_64 minimal
    return header + enc + dummy


def make_fat(slices):
    """Universal binary: {cputype, blob} -> FAT container."""
    n = len(slices)
    out = struct.pack(">II", 0xCAFEBABE, n)
    offset = 8 + n * 20
    entries = []
    blobs = b""
    for cputype, blob in slices:
        out += struct.pack(">IIIII", cputype, 0, offset, len(blob), 12) if False else b""
        entries.append((cputype, offset, len(blob)))
        offset += len(blob)
        blobs += blob
    # bangun header dengan offset final
    hdr = struct.pack(">II", 0xCAFEBABE, n)
    for cputype, off, size in entries:
        hdr += struct.pack(">IIIII", cputype, 3, off, size, 12)
    return hdr + blobs


tmp = Path(tempfile.mkdtemp())

# --- 1. Mach-O 64-bit ENCRYPTED (cryptid=1) ---
enc_file = tmp / "encrypted_bin"
enc_file.write_bytes(make_macho64(cryptid=1))
res = check_macho_encryption(enc_file)
assert len(res) == 1, res
assert res[0]["encrypted"] is True and res[0]["cryptid"] == 1
assert res[0]["arch"] == "arm64"
assert res[0]["cryptoff"] == 0x4000 and res[0]["cryptsize"] == 0x10000
print("[1] Mach-O 64-bit ENCRYPTED terdeteksi:", res[0])

# --- 2. Mach-O 64-bit decrypted (cryptid=0) ---
ok_file = tmp / "plain_bin"
ok_file.write_bytes(make_macho64(cryptid=0))
res = check_macho_encryption(ok_file)
assert len(res) == 1 and res[0]["encrypted"] is False and res[0]["cryptid"] == 0
print("[2] Mach-O 64-bit decrypted (cryptid=0) OK:", res[0])

# --- 3. Fat/universal: arm64 encrypted + armv7 plain ---
arm64_blob = make_macho64(cryptid=1)
# armv7 (32-bit, magic 0xFEEDFACE LE, header 28 bytes, LC_ENCRYPTION_INFO 32-bit)
hdr32 = struct.pack("<IIIIIII", 0xFEEDFACE, 12, 0, 2, 1, 28 + 20, 0)
enc32 = struct.pack("<IIIII", LC_ENCRYPTION_INFO, 20, 0x4000, 0x8000, 0)
armv7_blob = hdr32 + enc32
fat_file = tmp / "universal_bin"
fat_file.write_bytes(make_fat([(0x0100000C, arm64_blob), (12, armv7_blob)]))
res = check_macho_encryption(fat_file)
assert len(res) == 2, res
by_arch = {r["arch"]: r for r in res}
assert by_arch["arm64"]["encrypted"] is True, by_arch
assert by_arch["arm"]["encrypted"] is False, by_arch
print("[3] Fat/universal 2-slice OK:", [(r["arch"], r["encrypted"]) for r in res])

# --- 4. File bukan Mach-O -> [] ---
junk = tmp / "junk.bin"
junk.write_bytes(b"\x00" * 128 + b"MZ" + b"\x00" * 64)
assert check_macho_encryption(junk) == []
print("[4] Non-Mach-O -> kosong OK")

# --- 5. Mach-O big-endian (iOS device binary lama) ---
hdr_be = struct.pack(">IIIIIII", 0xFEEDFACE, 12, 0, 2, 1, 28 + 20, 0)
enc_be = struct.pack(">IIIII", LC_ENCRYPTION_INFO, 20, 0x4000, 0x8000, 1)
be_file = tmp / "be_bin"
be_file.write_bytes(hdr_be + enc_be)
res = check_macho_encryption(be_file)
assert len(res) == 1 and res[0]["encrypted"] is True and res[0]["arch"] == "arm", res
print("[5] Mach-O big-endian encrypted OK:", res[0])

print("\nALL CRYPTID DETECTOR CHECKS PASSED")

"""ObjC Class-Dump pure-Python untuk Mach-O (arm64/x86_64) — tanpa rabin2/lief.

Membaca struktur runtime Objective-C langsung dari file:
  __objc_classlist -> class_t -> class_ro_t -> name / method_list / ivars / props
  __objc_catlist   -> category_t -> instance/class methods
Method list modern (relative / "small" method list) didukung.
Chained fixups (iOS 15+) di-decode saat membaca pointer.

Output: pseudo-header ObjC ala class-dump, siap dipakai oleh Hook Generator.
"""
import struct
from pathlib import Path

# ---- Konstanta Mach-O ----
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO_64 = 0x2C
LC_ENCRYPTION_INFO = 0x21

FAST_DATA_MASK = 0x00007FFFFFFFFFF8  # mask bits -> ro/rw pointer
FAST_IS_SWIFT = 0x1

RELATIVE_METHOD_FLAG = 0x80000000  # entsizeAndFlags -> small/relative method list

# class_ro_t flags (untuk info tambahan)
RO_META = 0x2
RO_ROOT = 0x8
RO_HIDDEN = 0x10
RO_EXCEPTION = 0x20

# chained fixup (arm64, non-e): bit63 set => target = value & 0x7FFFFFFFFFFF
REBASE_FLAG = 0x8000000000000000
REBASE_TARGET_MASK = 0x00007FFFFFFFFFFF


def _read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


class MachOImage:
    """Representasi minimal satu slice Mach-O 64-bit + mapping vmaddr->file offset."""

    def __init__(self, data: bytes, offset: int = 0, arch: str = "arm64"):
        self.data = data
        self.base = offset
        self.arch = arch
        self.sections = {}   # (segname, sectname) -> (vmaddr, size, fileoff)
        self.encrypted = False
        self.crypt_range = None  # (file_lo, file_hi) range FairPlay
        self.parse()

    # ---------- primitives ----------
    def fo(self, addr: int):
        """vmaddr -> file offset (None bila di luar mapping)."""
        for (vmaddr, size, fileoff) in self.sections.values():
            if vmaddr <= addr < vmaddr + size:
                off = fileoff + (addr - vmaddr)
                if off < len(self.data):
                    return off
        return None

    def u64(self, addr):
        off = self.fo(addr)
        if off is None:
            return None
        return _read_u64(self.data, off)

    def ptr(self, addr):
        """Baca pointer & decode chained-fixup rebase encoding."""
        v = self.u64(addr)
        if v is None:
            return None
        if v & REBASE_FLAG:
            v &= REBASE_TARGET_MASK
        return v

    def cstr(self, addr, maxlen=600):
        off = self.fo(addr)
        if off is None:
            return None
        # string di dalam range FairPlay = ciphertext, jangan kembalikan garbage
        if self.crypt_range and self.crypt_range[0] <= off < self.crypt_range[1]:
            return None
        end = self.data.find(b"\x00", off, off + maxlen)
        if end == -1:
            end = off + maxlen
        try:
            s = self.data[off:end].decode("utf-8", errors="replace")
        except Exception:
            return None
        return s if s else None

    # ---------- parsing ----------
    def parse(self):
        data, base = self.data, self.base
        magic = _read_u32(data, base)
        if magic != MH_MAGIC_64:
            raise ValueError("bukan Mach-O 64-bit LE")
        cputype = struct.unpack_from("<i", data, base + 4)[0]
        if cputype == 0x0100000C:
            self.arch = "arm64"
        elif cputype == 0x01000007:
            self.arch = "x86_64"
        ncmds = _read_u32(data, base + 16)
        cursor = base + 32
        for _ in range(ncmds):
            if cursor + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from("<II", data, cursor)
            if cmd == LC_SEGMENT_64:
                if cursor + 72 <= len(data):
                    segname = data[cursor + 8:cursor + 24].split(b"\x00")[0].decode(errors="replace")
                    vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, cursor + 24)
                    nsects = _read_u32(data, cursor + 64)
                    sc = cursor + 72
                    for _s in range(min(nsects, 255)):
                        if sc + 80 > len(data):
                            break
                        sect = data[sc:sc + 16].split(b"\x00")[0].decode(errors="replace")
                        addr, size = struct.unpack_from("<QQ", data, sc + 32)
                        off = _read_u32(data, sc + 48)
                        self.sections[(segname, sect)] = (addr, size, off)
                        sc += 80
            elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                if cursor + 20 <= len(data):
                    cryptoff, cryptsize, cryptid = struct.unpack_from("<III", data, cursor + 8)
                    if cryptid:
                        self.encrypted = True
                        self.crypt_range = (cryptoff, cryptoff + cryptsize)
            cursor += cmdsize
            if cmdsize == 0:
                break

    # ---------- ObjC runtime parsing ----------
    # ---------- symtab (tidak ikut terenkripsi FairPlay) ----------
    def symtab_objc_classes(self):
        """Parse LC_SYMTAB -> {vmaddr: ClassName} untuk simbol _OBJC_CLASS_$_X."""
        out = {}
        cur = self.base + 32
        ncmds = _read_u32(self.data, self.base + 16)
        stroff = strsize = symoff = nsyms = None
        for _ in range(ncmds):
            if cur + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from("<II", self.data, cur)
            if cmd == 0x2:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", self.data, cur + 8)
                break
            cur += cmdsize
            if cmdsize == 0:
                break
        if not nsyms:
            return out
        for i in range(min(nsyms, 300000)):
            eo = self.base + symoff + i * 16
            if eo + 16 > len(self.data):
                break
            strx, typ = struct.unpack_from("<IB", self.data, eo)
            value, = struct.unpack_from("<Q", self.data, eo + 8)
            if (typ & 0x3e) == 0x0e or (typ & 0x3e) == 0x0f:  # N_SECT | N_EXT
                so = self.base + stroff + strx
                if so >= len(self.data):
                    continue
                name_end = self.data.find(b"\x00", so, so + 300)
                if name_end == -1:
                    continue
                try:
                    name = self.data[so:name_end].decode("utf-8", "replace")
                except Exception:
                    continue
                if name.startswith("_OBJC_CLASS_$_") and value:
                    out[value] = name[len("_OBJC_CLASS_$_"):]
        return out

    # ---------- partial dump untuk binary FairPlay-encrypted ----------
    def partial_classlist(self, sym_names):
        """Classlist + nama dari symtab + jumlah method/ivar/prop dari __objc_const.

        Range FairPlay hanya menutup __TEXT (termasuk __objc_methname/__objc_classname),
        sedangkan __objc_classlist/__objc_const/__objc_data tetap plaintext —
        struktur masih bisa dihitung meski nama selector terenkripsi.
        """
        classes = []
        for cls in self._section_addrs("__objc_classlist"):
            name = sym_names.get(cls)
            bits = self.u64(cls + 0x20)
            if bits is None:
                continue
            ro = bits & FAST_DATA_MASK
            if not ro:
                continue
            entry = {"name": name, "super": "", "swift": False,
                     "methods": [], "class_methods": [], "ivars": [], "props": [],
                     "protocols": [], "meta": False,
                     "names_encrypted": True, "method_count": 0,
                     "ivar_count": 0, "prop_count": 0}
            # hitung method/ivar/prop dari header list (plaintext di __objc_const)
            ml = self.ptr(ro + 32)
            if ml:
                first = self.u64(ml)
                if first is not None:
                    entry["method_count"] = min(first >> 32, 100000)
            il = self.ptr(ro + 48)
            if il:
                first = self.u64(il)
                if first is not None:
                    entry["ivar_count"] = min(first >> 32, 100000)
            pl = self.ptr(ro + 64)
            if pl:
                first = self.u64(pl)
                if first is not None:
                    entry["prop_count"] = min(first >> 32, 100000)
            isa = self.ptr(cls)
            if isa and isa != cls:
                mbits = self.u64(isa + 0x20)
                if mbits is not None:
                    mro = mbits & FAST_DATA_MASK
                    if mro:
                        mml = self.ptr(mro + 32)
                        if mml:
                            mf = self.u64(mml)
                            if mf is not None:
                                entry["method_count"] += min(mf >> 32, 100000)
            classes.append(entry)
        return classes

    def _section_addrs(self, sectname):
        out = []
        for (seg, sect), (addr, size, _off) in self.sections.items():
            if sect == sectname and size and seg.startswith("__"):
                n = size // 8
                out.extend(self.ptr(addr + i * 8) for i in range(min(n, 200000)))
        return [a for a in out if a]

    def _method_list(self, addr, out_methods, seen_lists):
        """Parse method_list_t (legacy 24-byte & relative 12-byte) -> out_methods."""
        if not addr or addr in seen_lists:
            return
        seen_lists.add(addr)
        entsize_flags = self.u64(addr)  # baca dulu; u32 bawah = flags? layout: [entsizeAndFlags:u32][count:u32]
        if entsize_flags is None:
            return
        low = _read_u32(self.data, self.fo(addr)) if self.fo(addr) is not None else None
        if low is None:
            return
        entsize = low & 0xFFFF
        flags = low & 0xFFFF0000
        # entsizeAndFlags nyata di 4 byte pertama; bit31 = relative methods
        first4 = entsize
        count = self.u64(addr) >> 32  # [0]=entsize_flags u32, [4]=count u32
        if count is None or count > 100000:
            return
        relative = bool(first4 & 0x80000000)
        esize = first4 & 0x3FFFFFFF
        entry_off = self.fo(addr + 8)
        if entry_off is None:
            return
        for i in range(count):
            if relative:
                eo = entry_off + i * 12
                if eo + 12 > len(self.data):
                    break
                name_rel, types_rel = struct.unpack_from("<ii", self.data, eo)
                name_addr = addr + 8 + i * 12 + name_rel
                types_addr = addr + 8 + i * 12 + 4 + types_rel
                nm = self.cstr(name_addr)
                ty = self.cstr(types_addr)
                if nm:
                    out_methods.append((nm, ty or ""))
            else:
                step = esize or 24
                eo = entry_off + i * step
                if eo + 24 > len(self.data):
                    break
                naddr, taddr = struct.unpack_from("<QQ", self.data, eo)
                nm = self.cstr(naddr)
                ty = self.cstr(taddr)
                if nm:
                    out_methods.append((nm, ty or ""))
        # flag sanity check: gunakan 'flags' agar pyflakes tenang
        _ = flags

    def _ivar_list(self, addr, out_ivars):
        if not addr:
            return
        first = self.u64(addr)
        if first is None:
            return
        entsize = first & 0xFFFFFFFF
        count = first >> 32
        if count > 10000 or (entsize or 32) > 64:
            return
        entry_off = self.fo(addr + 8)
        if entry_off is None:
            return
        for i in range(count):
            eo = entry_off + i * entsize
            if eo + 32 > len(self.data):
                break
            off_ptr, naddr, taddr = struct.unpack_from("<QQQ", self.data, eo)
            nm = self.cstr(naddr)
            ty = self.cstr(taddr)
            if nm:
                out_ivars.append((nm, ty or ""))

    def _property_list(self, addr, out_props):
        if not addr:
            return
        first = self.u64(addr)
        if first is None:
            return
        entsize = first & 0xFFFFFFFF
        count = first >> 32
        if count > 10000 or entsize not in (16, 24):
            return
        entry_off = self.fo(addr + 8)
        if entry_off is None:
            return
        for i in range(count):
            eo = entry_off + i * 16
            if eo + 16 > len(self.data):
                break
            naddr, aaddr = struct.unpack_from("<QQ", self.data, eo)
            nm = self.cstr(naddr)
            attrs = self.cstr(aaddr)
            if nm:
                out_props.append((nm, attrs or ""))

    def _protocol_list(self, addr, out_protocols):
        if not addr:
            return
        cnt = self.u64(addr)
        if cnt is None or cnt > 1000:
            return
        for i in range(cnt):
            p = self.ptr(addr + 8 + i * 8)
            if not p:
                continue
            # protocol_t: isa@0, name@8, protolist@0x10, ...
            nm = self.cstr(self.ptr(p + 8) or 0)
            if nm:
                out_protocols.append(nm)

    def _class_info(self, cls_ptr, is_meta=False):
        """Parse class_t -> dict berisi nama, super, methods, ivars, props, protocols."""
        info = {"name": None, "super": None, "methods": [], "class_methods": [],
                "ivars": [], "props": [], "protocols": [], "meta": is_meta, "swift": False}
        if not cls_ptr:
            return None
        isa = self.ptr(cls_ptr)
        bits = self.u64(cls_ptr + 0x20)
        if bits is None:
            return None
        if bits & FAST_IS_SWIFT:
            info["swift"] = True
        ro_ptr = bits & FAST_DATA_MASK
        if not ro_ptr:
            return None
        name_addr = self.ptr(ro_ptr + 24)
        if not name_addr:
            return None
        info["name"] = self.cstr(name_addr)
        if not info["name"] or not info["name"][0].isalpha() and not info["name"].startswith("_"):
            return None
        ro_flags = self.u64(ro_ptr)
        if ro_flags is not None and ro_flags & (1 << 31):  # RO_EXCEPTION sanity
            return None
        super_ptr = self.ptr(cls_ptr + 8)
        if super_ptr:
            sbits = self.u64(super_ptr + 0x20)
            if sbits is not None:
                sro = sbits & FAST_DATA_MASK
                if sro:
                    sname = self.cstr(self.ptr(sro + 24) or 0)
                    info["super"] = sname
        self._method_list(self.ptr(ro_ptr + 32), info["methods"], set())
        self._protocol_list(self.ptr(ro_ptr + 40), info["protocols"])
        self._ivar_list(self.ptr(ro_ptr + 48), info["ivars"])
        self._property_list(self.ptr(ro_ptr + 64), info["props"])
        if isa and isa != cls_ptr:
            try:
                meta_bits = self.u64(isa + 0x20)
                if meta_bits is not None:
                    meta_ro = meta_bits & FAST_DATA_MASK
                    if meta_ro and self.cstr(self.ptr(meta_ro + 24) or 0) == info["name"]:
                        self._method_list(self.ptr(meta_ro + 32), info["class_methods"], set())
            except Exception:
                pass
        return info

    def class_dump(self):
        """Dump semua class + category. Return (header_text, stats)."""
        classes = []
        seen = set()
        classlist = self._section_addrs("__objc_classlist")
        for cls in classlist:
            if cls in seen:
                continue
            seen.add(cls)
            info = self._class_info(cls)
            if info:
                classes.append(info)
        # category
        categories = []
        for cat in self._section_addrs("__objc_catlist"):
            try:
                name = self.cstr(self.ptr(cat) or 0)
                cls_ptr = self.ptr(cat + 8)
                cls_name = None
                if cls_ptr:
                    info = self._class_info(cls_ptr)
                    cls_name = info["name"] if info else None
                inst_m, cls_m = [], []
                self._method_list(self.ptr(cat + 16), inst_m, set())
                self._method_list(self.ptr(cat + 24), cls_m, set())
                if inst_m or cls_m:
                    categories.append({"name": name, "class": cls_name,
                                       "methods": inst_m, "class_methods": cls_m})
            except Exception:
                continue
        stats = {
            "classes": len(classes),
            "methods": sum(len(c["methods"]) + len(c["class_methods"]) for c in classes),
            "categories": len(categories),
            "ivars": sum(len(c["ivars"]) for c in classes),
        }
        return _render_header(classes, categories), stats, classes, categories


def _types_readable(types: str) -> str:
    """Encode ObjC type signature -> signature C kasar (id, void, BOOL, dll)."""
    if not types:
        return "id"
    t = types.split("{")[0].strip()
    mapping = {"@": "id", "v": "void", "B": "BOOL", "i": "int", "l": "long",
               "q": "long long", "f": "float", "d": "double", "c": "char",
               "s": "short", "^": "void *", "#": "Class", ":": "SEL", "*": "char *"}
    return mapping.get(t, "id")


def _render_header(classes, categories):
    lines = []
    for c in sorted(classes, key=lambda x: (x["swift"], x["name"] or "")):
        proto = "<" + ", ".join(c["protocols"]) + ">" if c["protocols"] else ""
        sw = " (Swift)" if c["swift"] else ""
        sup = c["super"] or "NSObject"
        lines.append(f"@interface {c['name']} : {sup}{proto}{sw}")
        for (nm, ty) in c["ivars"]:
            lines.append(f"    {{ {_types_readable(ty)} {_nm_sanitize(nm)}; }}")
        for (nm, attrs) in c["props"]:
            lines.append(f"    @property {attrs}".rstrip() + f" // {nm}")
        for (nm, ty) in c["class_methods"]:
            lines.append(f"    + ({_types_readable(ty)}) {nm};")
        for (nm, ty) in c["methods"]:
            lines.append(f"    - ({_types_readable(ty)}) {nm};")
        lines.append("@end")
        lines.append("")
    for cat in categories:
        lines.append(f"@interface {cat['class'] or '?'} ({cat['name']})")
        for (nm, ty) in cat.get("class_methods", []):
            lines.append(f"    + ({_types_readable(ty)}) {nm};")
        for (nm, ty) in cat.get("methods", []):
            lines.append(f"    - ({_types_readable(ty)}) {nm};")
        lines.append("@end")
        lines.append("")
    return "\n".join(lines)


def _nm_sanitize(n):
    return n.strip().replace(" ", "_")


def _render_partial_header(classes):
    """Render inventory untuk binary FairPlay-encrypted (nama selector tak tersedia)."""
    lines = ["// NOTE: FairPlay ENCRYPTED — nama selector terenkripsi.",
             "//       Kolom di bawah = nama class (symtab) + jumlah method/ivar/prop",
             "//       hasil parse struktur runtime di __objc_const (plaintext)."]
    for c in sorted(classes, key=lambda x: -(x["method_count"])):
        nm = c["name"] or f"<class@{c.get('addr', '?')}>"
        lines.append(f"@interface {nm}  // methods: {c['method_count']} "
                     f"(terenkripsi), ivars: {c['ivar_count']}, props: {c['prop_count']}")
    lines.append("")
    return "\n".join(lines)


# ---------------- Swift demangling pragmatis ----------------

def swift_demangle_partial(sym: str):
    """Demangle parsial symbol Swift (_$s / $s): ambil modul.kelas.fungsi yang readable.

    Bukan demangler lengkap — cukup untuk menelusuri nama fungsi menarik
    (login, token, key, dsb.) dari symbol Swift mentah.
    """
    s = sym
    for pfx in ("_$s", "$s", "_$S"):
        if s.startswith(pfx):
            s = s[len(pfx):]
            break
    else:
        return None
    words = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch.isdigit():
            # dua digit pertama: <ndigits><len> utk identifier panjang
            if i + 1 < n and s[i + 1].isdigit() and (i + 2 < n) and s[i + 2].isdigit() is False:
                pass
            j = i
            digits = ""
            while j < n and s[j].isdigit() and len(digits) < 3:
                digits += s[j]
                j += 1
            # coba interpretasi: [d1 d2 ...] -> d2 adalah jumlah digit panjang asli
            if len(digits) >= 2 and digits[0] != "1" and digits[0] > digits[1] and j < n:
                ln = int(digits[1:])
                i = j
            else:
                ln = int(digits)
                i = j
            if ln <= 0 or i + ln > n:
                break
            word = s[i:i + ln]
            i += ln
            if word and all(c.isalpha() or c in "_$" for c in word):
                words.append(word.replace("$", "_"))
            continue
        # marker struktural Swift: C=class, c=class member, V/O/P=pemisah tipe, F=fungsi
        if ch in "CcVvOoPpFf":
            i += 1
            continue
        i += 1
    if not words:
        return None
    out = []
    for w in words:
        if w == "·":
            continue
        out.append(w)
    return ".".join(out) if out else None


def dump_binary(macho_path: Path):
    """Entry point: dump class ObjC satu binary Mach-O.

    Return dict: {ok, encrypted, arch, header, stats, error}
    """
    try:
        data = macho_path.read_bytes()
    except OSError as e:
        return {"ok": False, "error": f"read: {e}"}

    # Fat/universal: pilih slice arm64, jika tidak ada slice pertama yang 64-bit
    slices = []
    magic = struct.unpack_from(">I", data, 0)[0] if len(data) >= 4 else 0
    if magic == FAT_MAGIC:
        nfat = struct.unpack_from(">I", data, 4)[0]
        for i in range(min(nfat, 16)):
            base = 8 + i * 20
            cputype, _, off, size, _ = struct.unpack_from(">IIIII", data, base)
            slices.append((cputype, off, size))
    else:
        slices = [(None, 0, len(data))]

    chosen = None
    for (cputype, off, size) in slices:
        if cputype == 0x0100000C:
            chosen = (off, size, "arm64")
            break
    if chosen is None and slices:
        cputype, off, size = slices[0]
        chosen = (off, size, "arm64" if cputype == 0x0100000C else "arm")

    off, size, arch = chosen
    try:
        img = MachOImage(data[:off + size] if off else data, offset=off, arch=arch)
    except (ValueError, struct.error) as e:
        return {"ok": False, "error": f"parse macho: {e}", "arch": arch}
    if img.encrypted:
        # FairPlay: nama selector/class terenkripsi, tapi symtab + struktur
        # __objc_classlist/__objc_const tetap plaintext -> partial dump
        try:
            sym_names = img.symtab_objc_classes()
            classes = img.partial_classlist(sym_names)
        except struct.error:
            classes = []
        named = [c for c in classes if c["name"]]
        stats = {"classes": len(classes),
                 "methods": sum(c["method_count"] for c in classes),
                 "categories": 0, "ivars": sum(c["ivar_count"] for c in classes)}
        if classes:
            header = _render_partial_header(classes)
            return {"ok": True, "partial": True, "encrypted": True, "arch": img.arch,
                    "header": header, "stats": stats, "classes": classes,
                    "categories": [],
                    "note": "FairPlay/cryptid ENCRYPTED — nama selector terenkripsi; "
                            "inventory class + jumlah method dari symtab+__objc_const. "
                            "Untuk nama method penuh: dump binary dari device jailbroken."}
        return {"ok": False, "encrypted": True, "arch": img.arch,
                "error": "FairPlay/cryptid encrypted — tidak ada classlist yang bisa diparse; "
                         "butuh binary ter-dekripsi dari device jailbroken"}
    if not img.sections:
        return {"ok": False, "error": "tidak ada section", "arch": img.arch}
    try:
        header, stats, classes, categories = img.class_dump()
    except struct.error as e:
        return {"ok": False, "error": f"dump: {e}", "arch": img.arch}
    if not stats["classes"] and not stats["categories"]:
        return {"ok": False, "error": "tidak ada class ObjC terdeteksi", "arch": img.arch,
                "stats": stats}
    return {"ok": True, "arch": img.arch, "header": header, "stats": stats,
            "classes": classes, "categories": categories}

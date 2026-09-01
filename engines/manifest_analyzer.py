"""manifest_analyzer.py — analisis AndroidManifest.xml (decoded) untuk komponen,
permission, provider, dan deep link (skema+host). Jatuh ke scan biner bila
manifest belum ter-decode apktool.
"""
import re
from pathlib import Path

COMPONENT_TAGS = ("activity", "service", "receiver", "provider")

# Tag pembuka komponen — di-scan iteratif agar self-closing (`/>`) tidak menelan
# blok berikutnya. Body ditutup oleh `</tag>`.
_TAG_RE = re.compile(r"<(%s)\b([^>]*)>" % "|".join(COMPONENT_TAGS), re.I)

_ENV_HINTS = ("dev", "staging", "stg", "sandbox", "test", "qa", "uat", "beta", "preprod", "preview")


def _iter_blocks(text: str):
    for m in _TAG_RE.finditer(text):
        tag, attrs = m.group(1), m.group(2)
        if attrs.rstrip().endswith("/"):
            yield tag, attrs, ""
            continue
        end = re.search(r"</%s\s*>" % re.escape(tag), text[m.end():], re.I | re.S)
        if end:
            body = text[m.end():m.end() + end.start()]
            yield tag, attrs, body


def _find_manifest(corpus_dir: Path, decoded_dir: Path, apk_root: Path):
    for d in (decoded_dir, apk_root):
        if d is not None:
            m = d / "AndroidManifest.xml"
            if m.exists():
                return m
    if corpus_dir is not None and corpus_dir.exists():
        hits = sorted(corpus_dir.rglob("AndroidManifest.xml"))
        if hits:
            return hits[0]
    return None


def _attr(tag: str, name: str):
    m = re.search(r'%s\s*=\s*"([^"]*)"' % re.escape(name), tag)
    return m.group(1) if m else None


def _parse_block(tag: str, attrs: str, body: str, result: dict):
    name = _attr(attrs, "android:name") or _attr(attrs, "name")
    if not name:
        return
    kind = tag.lower()
    exported = _attr(attrs, "android:exported")
    comp = {
        "type": kind,
        "name": name,
        "exported": exported,
        "permission": _attr(attrs, "android:permission"),
        "authority": _attr(attrs, "android:authority"),
        "data": [],
    }
    # intent-filter <data .../> — kumpulkan skema/host untuk deep link
    for dm in re.finditer(r"<data\b[^>]*/>", body):
        dtag = dm.group(0)
        scheme = _attr(dtag, "android:scheme")
        host = _attr(dtag, "android:host")
        if scheme or host:
            comp["data"].append({"scheme": scheme, "host": host})
    result["components"].append(comp)


def parse_manifest_xml(text: str):
    result = {
        "package": None,
        "version": None,
        "min_sdk": None,
        "target_sdk": None,
        "application": {},
        "permissions": [],
        "components": [],
        "deep_links": [],  # (scheme, host) unik
    }
    m = re.search(r'package="([^"]+)"', text)
    result["package"] = m.group(1) if m else None
    m = re.search(r'android:versionName="([^"]*)"', text)
    result["version"] = m.group(1) if m else None
    m = re.search(r'<uses-sdk\b[^>]*?android:minSdkVersion="(\d+)"', text)
    result["min_sdk"] = m.group(1) if m else None
    m = re.search(r'<uses-sdk\b[^>]*?android:targetSdkVersion="(\d+)"', text)
    result["target_sdk"] = m.group(1) if m else None

    app = re.search(r"<application\b(.*?)>", text, re.S)
    if app:
        at = app.group(1)
        for k in ("allowBackup", "usesCleartextTraffic", "debuggable", "networkSecurityConfig",
                  "label", "name"):
            v = _attr(at, "android:" + k)
            if v is not None:
                result["application"][k] = v

    result["permissions"] = sorted(set(
        re.findall(r'<uses-permission\b[^>]*?android:name="([^"]+)"', text)
    ))

    for tag, attrs, body in _iter_blocks(text):
        _parse_block(tag, attrs, body, result)

    seen = set()
    for c in result["components"]:
        for d in c["data"]:
            key = (d.get("scheme"), d.get("host"))
            if key not in seen:
                seen.add(key)
                result["deep_links"].append(key)

    return result


def analyze_manifest(corpus_dir: Path = None, decoded_dir: Path = None, apk_root: Path = None):
    """Cari + parse manifest. Return dict atau None."""
    manifest = _find_manifest(corpus_dir, decoded_dir, apk_root)
    if manifest is None:
        return None
    text = manifest.read_text(encoding="utf-8", errors="replace")
    try:
        return parse_manifest_xml(text)
    except Exception:
        return None


# ===== IPA: manifest dari Info.plist =====

_SENSITIVE_NS = ("camera", "location", "microphone", "photo", "motion",
                 "faceid", "tracking", "bluetooth", "contacts", "calendar")


def _find_ipa_plist(corpus_dir: Path, ipa_root: Path = None):
    if ipa_root is not None:
        apps = sorted(ipa_root.rglob("*.app")) if (ipa_root / "Payload").exists() else []
        if apps:
            m = apps[0] / "Info.plist"
            if m.exists():
                return m
    if corpus_dir is not None and corpus_dir.exists():
        hits = sorted(corpus_dir.rglob("Info.plist.xml"))
        if hits:
            return hits[0]
    return None


def _plist_val(d, key, default=None):
    v = d.get(key, default)
    return v


def parse_ipa_plist_text(text: str):
    """Parse Info.plist (XML) -> dict manifest bergaya Android agar report
    konsisten: package/version/min_sdk/permissions/components/deep_links."""
    import plistlib
    try:
        data = plistlib.loads(text.encode("utf-8"))
    except Exception:
        # fallback: mungkin XML biasa yang tidak bisa di-plistlib (mobileprovision)
        data = {}
    result = {
        "platform": "ios",
        "package": None,
        "version": None,
        "min_sdk": None,
        "target_sdk": None,
        "application": {},
        "permissions": [],
        "components": [],
        "deep_links": [],
    }
    result["package"] = _plist_val(data, "CFBundleIdentifier")
    sv = _plist_val(data, "CFBundleShortVersionString")
    bv = _plist_val(data, "CFBundleVersion")
    result["version"] = f"{sv} (build {bv})" if sv and bv and bv != sv else (sv or bv)
    result["min_sdk"] = _plist_val(data, "MinimumOSVersion")
    result["application"] = {
        "display_name": _plist_val(data, "CFBundleDisplayName") or _plist_val(data, "CFBundleName"),
        "ats": _plist_val(data, "NSAppTransportSecurity"),
        "non_exempt_encryption": _plist_val(data, "ITSAppUsesNonExemptEncryption"),
        "required_capabilities": _plist_val(data, "UIRequiredDeviceCapabilities"),
        "min_os": result["min_sdk"],
    }
    # NS* usage descriptions = permission iOS
    for k, v in data.items():
        if k.startswith("NS") and isinstance(v, str):
            result["permissions"].append({"name": k, "description": v})
    result["permissions"].sort(key=lambda x: x["name"])
    # URL types -> deep link + komponen
    for ut in data.get("CFBundleURLTypes") or []:
        schemes = ut.get("CFBundleURLSchemes") or []
        host = ut.get("CFBundleURLHost", ut.get("CFBundleURLName"))
        for s in schemes:
            result["deep_links"].append((s, host))
            result["components"].append({
                "type": "url_scheme",
                "name": s,
                "exported": "true",
                "permission": None,
                "authority": None,
                "data": [{"scheme": s, "host": host}],
            })
    # LSApplicationQueriesSchemes — scheme yang di-query (dipakai deep link antar-app)
    for s in data.get("LSApplicationQueriesSchemes") or []:
        result["deep_links"].append((s, None))
    seen = set()
    dl = []
    for scheme, host in result["deep_links"]:
        if (scheme, host) not in seen:
            seen.add((scheme, host))
            dl.append((scheme, host))
    result["deep_links"] = dl
    return result


def analyze_ipa_manifest(corpus_dir: Path = None, ipa_root: Path = None):
    """Cari + parse Info.plist app utama. Return dict bergaya Android."""
    plist = _find_ipa_plist(corpus_dir, ipa_root)
    if plist is None:
        return None
    text = plist.read_text(encoding="utf-8", errors="replace")
    try:
        return parse_ipa_plist_text(text)
    except Exception:
        return None


def manifest_to_markdown(m: dict) -> list:
    if not m:
        return ["(manifest tidak ditemukan / gagal di-decode)"]
    if m.get("platform") == "ios":
        return _ipa_manifest_to_markdown(m)
    out = []
    out.append(f"- Package: `{m['package']}`  |  Version: `{m['version'] or '-'}`  |  "
               f"minSdk: `{m['min_sdk'] or '-'}`  |  targetSdk: `{m['target_sdk'] or '-'}`")
    app = m["application"]
    if app:
        flags = []
        for k in ("allowBackup", "debuggable", "usesCleartextTraffic"):
            if k in app:
                flags.append(f"{k}={app[k]}")
        if flags:
            out.append(f"- Aplikasi: {', '.join(flags)}")
    if m["permissions"]:
        sensitive = [p for p in m["permissions"] if any(
            k in p.lower() for k in ("camera", "location", "sms", "contacts", "record_audio",
                                     "read_phone", "storage", "biometric", "account"))]
        out.append(f"- Permission: {len(m['permissions'])} total "
                   f"({len(sensitive)} sensitif: {', '.join(p.rsplit('.', 1)[-1] for p in sensitive[:12])})")

    exported = [c for c in m["components"] if c["exported"] == "true"]
    out.append("")
    out.append(f"### Komponen exported: {len(exported)}")
    out.append("")
    if exported:
        out.append("| Tipe | Komponen | Permission |")
        out.append("|---|---|---|")
        for c in exported[:30]:
            out.append(f"| {c['type']} | `{c['name']}` | {c.get('permission') or '-'} |")
    else:
        out.append("Tidak ada komponen exported eksplisit.")

    if m["deep_links"]:
        out.append("")
        out.append("### Deep link (scheme/host)")
        out.append("")
        for scheme, host in sorted(m["deep_links"], key=lambda x: (x[1] or "", x[0] or "")):
            out.append(f"- `{scheme}://{host}`")
    return out


def _ipa_manifest_to_markdown(m: dict) -> list:
    out = []
    out.append(f"- Bundle ID: `{m['package']}`  |  Version: `{m['version'] or '-'}`  |  "
               f"MinimumOS: `{m['min_sdk'] or '-'}`")
    app = m["application"]
    if app:
        flags = []
        if app.get("display_name"):
            flags.append(f"name={app['display_name']}")
        ats = app.get("ats")
        if ats:
            arbitrary = "true" if str(ats).lower() in ("1", "true", "yes") else (
                str(ats.get("NSAllowsArbitraryLoads")).lower() if isinstance(ats, dict) else str(ats))
            flags.append(f"ATS allowsArbitraryLoads={arbitrary}")
        enc = app.get("non_exempt_encryption")
        if enc is not None:
            flags.append(f"usesNonExemptEncryption={enc}")
        caps = app.get("required_capabilities")
        if caps:
            flags.append(f"capabilities={','.join(caps) if isinstance(caps, list) else caps}")
        if flags:
            out.append(f"- Aplikasi: {', '.join(flags)}")
    if m["permissions"]:
        sensitive = [p for p in m["permissions"] if any(
            k in p["name"].lower() for k in _SENSITIVE_NS)]
        out.append(f"- Permission: {len(m['permissions'])} total "
                   f"({len(sensitive)} sensitif: {', '.join(p['name'] for p in sensitive[:12])})")
        out.append("")
        out.append("### Izin iOS (usage description)")
        out.append("")
        for p in m["permissions"]:
            desc = (p.get("description") or "").strip()
            if desc:
                out.append(f"- `{p['name']}` — {desc[:180]}")
            else:
                out.append(f"- `{p['name']}`")

    if m["components"]:
        out.append("")
        out.append("### URL scheme (deep link)")
        out.append("")
        for c in m["components"]:
            s = c["name"]
            host = (c["data"][0].get("host") if c["data"] else None)
            out.append(f"- `{s}://{host}`" if host else f"- `{s}://`")

    if m["deep_links"]:
        extra = [x for x in m["deep_links"] if x[1] is None]
        if extra:
            out.append("")
            out.append("### Query scheme")
            out.append("")
            for scheme, _ in sorted(extra):
                out.append(f"- `{scheme}://`")
    return out

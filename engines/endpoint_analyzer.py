"""endpoint_analyzer.py — ekstraksi attack surface dari corpus:
host/domain (dengan klasifikasi env dev/staging/prod), deep-link scheme, dan
metadata config (capacitor.config.json, google-services.json, build.gradle, .env).
"""
import json
import re
from pathlib import Path

from .common import is_library_source

URL_RE = re.compile(r"\bhttps?://([A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])(:[0-9]{2,5})?(/[A-Za-z0-9._~:/?#@!$&()*+,;=%\[\]-]*)?")
# Skema custom harus mulai di token boundary (hindari artefak string extraction spt "xhttps://").
# Skema tanpa titik (mis. sunfishgo) dan host harus punya label TLD alfa (mis. gdhr.app).
SCHEME_HOST_RE = re.compile(r"(?<![A-Za-z0-9_.-])([a-zA-Z][a-zA-Z0-9+-]{1,30})://([A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])")
TLD_ALPHA = re.compile(r"\.[a-z]{2,}$")
IP_PORT_RE = re.compile(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::([0-9]{2,5}))?")

# Skema yang bukan deep link aplikasi target (framework/OS/library)
NOISE_SCHEMES = {
    "android-app", "gap", "zxing", "mobilemanager", "cap", "capacitor", "capacitor-deeplinking",
    "ionic", "cordova", "node", "js", "intent", "chrome", "chrome-extension", "javascript",
    "about", "blob", "mailto", "sms", "tel", "geo", "market", "content", "file", "ftp",
    "http", "https", "ws", "wss", "tg", "whatsapp", "viber", "line", "skype", "zoommtg",
    "path", "xpath", "xhttps", "shttps", "xhttp",
}

# Domain 3rd-party yang sering muncul (library, CDN, iklan, docs) — bukan surface target
THIRD_PARTY = {
    "google.com", "googleapis.com", "gstatic.com", "googlesyndication.com", "google-analytics.com",
    "android.com", "androidx.com", "googleusercontent.com", "firebaseio.com", "firebase.com",
    "github.com", "githubusercontent.com", "apache.org", "mozilla.org", "w3.org", "json-schema.org",
    "facebook.com", "fbcdn.net", "twitter.com", "twimg.com", "x.com", "instagram.com",
    "whatsapp.com", "apple.com", "icloud.com", "microsoft.com", "windows.com", "azure.com",
    "office.com", "linkedin.com", "npmjs.com", "pypi.org", "rubygems.org", "maven.org",
    "jquery.com", "angular.io", "ionicframework.com", "capacitorjs.com", "cordova.apache.org",
    "stackoverflow.com", "stackexchange.com", "wikipedia.org", "wikimedia.org", "youtube.com",
    "youtu.be", "reddit.com", "medium.com", "cloudflare.com", "cloudflareinsights.com",
    "amazonaws.com", "amazon.com", "aws.amazon.com", "digitalocean.com", "herokuapp.com",
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "jsdelivr.net", "unpkg.com",
    "cdnjs.cloudflare.com", "bootstrapcdn.com", "mapbox.com", "openstreetmap.org",
    "osm.org", "here.com", "tomtom.com", "qrserver.com", "flagsapi.com", "cermati.com",
    "fontello.com", "tfhub.dev", "mediapipe.dev",
    "googleadservices.com", "googletagmanager.com", "doubleclick.net", "googletagservices.com",
    "analytics.google.com", "googletagmanager.com", "google-analytics.com",
    "example.com", "example.org", "example.net", "foo.bar", "foo.com", "foo.org", "foobar.com",
    "test.com", "test.org", "test.net", "localhost", "invalid", "domain.com", "yourdomain.com",
    "sample.com", "placeholder.com", "dummy.com", "mydomain.com", "example.co.id", "acme.com",
    "schema.org", "ietf.org", "gnu.org", "opensource.org", "apache.org", "eclipse.org", "mozilla.org",
    "mapboxusercontent.com", "mixpanel.com", "segment.com", "amplitude.com", "sentry.io",
    "bugsnag.com", "crashlytics.com", "fabric.io", "branch.io", "adjust.com", "kochava.com",
    "onesignal.com", "pusher.com", "socket.io", "discord.com", "telegram.org", "t.me",
    "slack.com", "stripe.com", "paypal.com", "midtrans.com", "veritrans.co.id", "xendit.co",
    "adyen.com", "boku.com", "firebasedatabase.app", "supabase.co", "browserstack.com",
    "chrome.com", "chromium.org", "w3schools.com", "gmpg.org", "creativecommons.org",
    "android.googlesource.com", "webrtc.org", "ffmpeg.org", "libpng.org", "zlib.net",
}

ENV_LABELS = ("dev", "staging", "stg", "sandbox", "test", "qa", "uat", "beta", "preprod", "preview", "canary")
ENV_PATH = ("dev", "staging", "stg", "sandbox", "test", "qa", "uat", "preprod")


def _env_for_host(host: str):
    labels = host.lower().split(".")
    for lab in labels:
        base = lab.split("-")[0] if "-" in lab else lab
        if lab in ENV_LABELS:
            return lab if lab in ("dev",) else ("staging" if lab in ("staging", "stg") else lab)
        if lab.endswith("-dev") or lab.endswith("-staging") or lab.endswith("-stg"):
            return "dev" if lab.endswith("-dev") else "staging"
    if host.lower().endswith(".dev"):
        return "dev"
    return None


def _env_for_path(path: str):
    if not path:
        return None
    seg = path.strip("/").split("/")
    if seg and seg[0].lower() in ENV_PATH:
        return "staging" if seg[0].lower() in ("staging", "stg") else seg[0].lower()
    return None


def _is_third_party(host: str):
    h = host.lower()
    for d in THIRD_PARTY:
        if h == d or h.endswith("." + d):
            return True
    return False


def _is_library_source(parts):
    return is_library_source(parts)


def _scan_texts(corpus_dir: Path):
    """Yield (path_rel, text) untuk file teks relevan dengan ukuran masuk akal.

    Lewati format biner & blob tanpa URL; untuk dir hasil-dekompilasi hanya ambil
    kode milik aplikasi sendiri (bukan library/framework).
    """
    if not corpus_dir.exists():
        return
    skip_parts = ("sources_kotlin", "sources_js", "jd-cli", "javap",
                  "strings_other", "strings_wasm", "strings_dx", "strings_js")
    for p in sorted(corpus_dir.rglob("*")):
        if not p.is_file():
            continue
        parts = p.relative_to(corpus_dir).parts
        if any(sp in parts for sp in skip_parts):
            continue
        if _is_library_source(parts):
            continue
        if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".ttf", ".otf",
                                ".woff", ".woff2", ".so", ".dylib", ".dll", ".dex", ".arsc", ".hbc"):
            continue
        try:
            if p.stat().st_size > 12 * 1024 * 1024:
                continue
            raw = p.read_bytes()
        except OSError:
            continue
        text = None
        for enc in ("utf-8", "latin-1"):
            try:
                text = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if text is None or "\x00" in text[:2000]:
            continue
        # File teks/script ikut discan semua (minified JS berisi banyak URL);
        # yang di-skip hanya format biner & blob data tanpa URL.
        yield str(p).replace("\\", "/"), text


def analyze_endpoints(corpus_dir: Path, decoded_dir: Path = None, apk_root: Path = None):
    hosts = {}
    deep_links = {}
    configs = []

    for rel, text in _scan_texts(corpus_dir):
        # host per URL
        for m in URL_RE.finditer(text):
            host = m.group(1).lower()
            if "." not in host and host not in ("localhost",):
                continue  # host tanpa titik (go, goto, host) = artefak ekstraksi
            if _is_third_party(host):
                continue
            port = m.group(2) or ""
            path = m.group(3) or ""
            h = host + port
            if h not in hosts:
                hosts[h] = {"host": host, "port": (m.group(2) or "").lstrip(":"),
                            "env": _env_for_host(host), "path_env": _env_for_path(path),
                            "files": set(), "paths": set(), "urls": []}
            hosts[h]["files"].add(rel)
            if path:
                hosts[h]["paths"].add(path[:120])
            if len(hosts[h]["urls"]) < 3:
                hosts[h]["urls"].append((m.group(0)[:160]))
        # scheme://host custom
        for m in SCHEME_HOST_RE.finditer(text):
            scheme = m.group(1).lower()
            host = m.group(2).lower()
            if scheme in NOISE_SCHEMES:
                continue
            if "android" in scheme:  # jandroid-app:// artefak string extraction
                continue
            if "." not in host or not TLD_ALPHA.search(host):
                continue  # host bukan domain (path://m-11.39, gap://ready, dll)
            if _is_third_party(host):
                continue
            key = f"{scheme}://{host}"
            if key not in deep_links:
                deep_links[key] = {"scheme": scheme, "host": host, "files": set()}
            deep_links[key]["files"].add(rel)

    # metadata config terstruktur
    for name, fn in (("capacitor.config.json", _cap_cfg), ("google-services.json", _google_services),
                     ("package.json", _package_json)):
        hit = _find_config(corpus_dir, name)
        if hit:
            cfg = fn(hit[1])
            if cfg:
                cfg["file"] = hit[0]
                configs.append(cfg)

    # build.gradle signing + .env
    for rel, text in _scan_texts(corpus_dir):
        low = rel.lower()
        if low.endswith("build.gradle") or low.endswith("build.gradle.kts"):
            sig = re.findall(r"(?i)(storePassword|keyPassword)\s*['\"]([^'\"]{4,})['\"]", text)
            if sig:
                configs.append({"type": "signing", "file": rel, "values": [f"{k}:{v}" for k, v in sig]})
        if low.endswith(".env") or low.endswith(".env.example") or "environment" in low and low.endswith(".json"):
            for k, v in re.findall(r"(?im)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{3,})\s*=\s*['\"]?([^'\"\r\n]+)", text):
                if not re.fullmatch(r"\$?\{(?:.*?)\}|your_|<.*>|__.*__", v):
                    configs.append({"type": "env", "file": rel, "key": k, "value": v[:120]})

    hosts_out = sorted(hosts.values(), key=lambda h: (h["env"] or "zz", h["host"]))
    for h in hosts_out:
        h["files"] = sorted(h["files"])
        h["paths"] = sorted(h["paths"])
    for d in deep_links.values():
        d["files"] = sorted(d["files"])
    return {
        "hosts": hosts_out,
        "deep_links": sorted(deep_links.values(), key=lambda d: d["host"]),
        "configs": configs,
    }


def _find_config(corpus_dir: Path, name: str):
    if not corpus_dir.exists():
        return None
    for p in sorted(corpus_dir.rglob(name)):
        try:
            return str(p).replace("\\", "/"), p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return None


def _cap_cfg(text: str):
    try:
        d = json.loads(text)
    except Exception:
        return None
    out = {"type": "capacitor"}
    for k in ("appId", "appName"):
        if d.get(k):
            out[k] = d[k]
    if isinstance(d.get("server"), dict) and d["server"].get("url"):
        out["server_url"] = d["server"]["url"]
    if isinstance(d.get("server"), dict) and d["server"].get("androidScheme"):
        out["androidScheme"] = d["server"]["androidScheme"]
    plugins = d.get("plugins")
    if isinstance(plugins, dict):
        ga = plugins.get("GoogleAuth")
        if isinstance(ga, dict) and ga.get("serverClientId"):
            out["google_server_client_id"] = ga["serverClientId"]
    return out


def _google_services(text: str):
    try:
        d = json.loads(text)
    except Exception:
        return None
    pi = d.get("project_info") or {}
    out = {"type": "google_services", "project_id": pi.get("project_id"),
           "project_number": pi.get("project_number")}
    keys = []
    for c in d.get("client", []) or []:
        for ak in (c.get("api_key") or []):
            if ak.get("current_key"):
                keys.append(ak["current_key"])
        ci = (c.get("oauth_client") or [])
        for oc in ci:
            if oc.get("client_id", "").endswith("apps.googleusercontent.com"):
                out.setdefault("oauth_client_ids", []).append(oc["client_id"])
    if keys:
        out["api_keys"] = keys
    return out if (out.get("project_id") or out.get("api_keys")) else None


def _package_json(text: str):
    try:
        d = json.loads(text)
    except Exception:
        return None
    return {"type": "package", "name": d.get("name"), "version": d.get("version"),
            "dependencies": sorted((d.get("dependencies") or {}).keys())}


def endpoints_to_markdown(ep: dict) -> list:
    if not ep or not ep.get("hosts"):
        return ["(tidak ada endpoint terdeteksi)"]
    out = []
    env_count = {}
    for h in ep["hosts"]:
        env = h.get("path_env") or h.get("env") or "prod"
        env_count[env] = env_count.get(env, 0) + 1
    out.append(f"Total host unik (non-3rd-party): **{len(ep['hosts'])}** — " +
               ", ".join(f"{k}: {v}" for k, v in sorted(env_count.items())))
    out.append("")

    interesting = [h for h in ep["hosts"] if (h.get("path_env") or h.get("env")) and
                   (h.get("path_env") or h.get("env")) != "prod"]
    if interesting:
        out.append("### Host berenv dev/staging (potensi info-leak env)")
        out.append("")
        out.append("| Host | Env | Path env | Contoh URL |")
        out.append("|---|---|---|---|")
        for h in interesting[:25]:
            example = ""
            if h["urls"]:
                example = h["urls"][0]
            out.append(f"| `{h['host']}` | {h.get('env') or '-'} | {h.get('path_env') or '-'} | {example[:90]} |")
        out.append("")

    out.append("### Semua host")
    out.append("")
    out.append("| Host | Port | Env | File |")
    out.append("|---|---|---|---|")
    for h in ep["hosts"][:60]:
        files = ", ".join(sorted(f.split("/corpus/")[-1] for f in list(h["files"])[:2]))
        out.append(f"| `{h['host']}` | {h['port'] or '-'} | {h.get('path_env') or h.get('env') or 'prod'} | {files[:70]} |")
    if len(ep["hosts"]) > 60:
        out.append(f"| ... {len(ep['hosts']) - 60} lagi |")
    out.append("")

    if ep.get("deep_links"):
        out.append("### Custom scheme / deep link")
        out.append("")
        out.append("| Scheme://Host | File |")
        out.append("|---|---|")
        for d in ep["deep_links"][:30]:
            files = ", ".join(f.split("/corpus/")[-1] for f in sorted(d["files"])[:1])
            out.append(f"| `{d['scheme']}://{d['host']}` | {files[:70]} |")
        out.append("")

    if ep.get("configs"):
        out.append("### Konfigurasi terstruktur")
        out.append("")
        for c in ep["configs"][:40]:
            vals = ", ".join(f"{k}={v}" for k, v in c.items() if k not in ("type", "file"))
            out.append(f"- **{c['type']}** `{c['file']}`: {vals[:200]}")
        out.append("")
    return out

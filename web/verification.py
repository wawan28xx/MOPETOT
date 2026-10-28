import socket
import json
import ipaddress
import re
import requests
import urllib3
import hashlib
import hmac
import datetime
from typing import Dict, Any, List

# Disable InsecureRequestWarning when probing dev/staging servers with self-signed SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8"
}

def check_ip_details(ip_str: str) -> Dict[str, Any]:
    """Cek tipe IP (Private vs Public), reverse DNS, open ports, dan GeoIP."""
    ip_str = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"error": "Format IP tidak valid", "ip": ip_str, "is_private": False, "alive": False}

    is_priv = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    result = {
        "ip": ip_str,
        "is_private": is_priv,
        "type": "Private (RFC 1918 / Local)" if is_priv else "Public IPv4",
        "alive": False,
        "hostname": "",
        "open_ports": [],
        "geo": {},
        "message": ""
    }

    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        result["hostname"] = host
    except Exception:
        pass

    if is_priv:
        result["message"] = "Alamat IP Internal / Private (Hanya dapat diakses dari jaringan lokal / intranet)."
        return result

    # Public IP: Cek port
    common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 22]
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            r = s.connect_ex((ip_str, port))
            if r == 0:
                result["open_ports"].append(port)
                result["alive"] = True
        except Exception:
            pass
        finally:
            s.close()

    # GeoIP lookup via ip-api.com
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip_str}?fields=status,country,regionName,city,isp,org,as",
            headers=HEADERS,
            timeout=4.0
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result["geo"] = {
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "region": data.get("regionName", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "as": data.get("as", "")
                }
    except Exception:
        pass

    if result["alive"]:
        ports_str = ", ".join(str(p) for p in result["open_ports"])
        geo_info = result["geo"].get("country", "")
        if result["geo"].get("isp"):
            geo_info += f" ({result['geo']['isp']})"
        result["message"] = f"Host AKTIF! Port terbuka: {ports_str}." + (f" Lokasi: {geo_info}" if geo_info else "")
    else:
        result["message"] = "Host tidak merespon pada port umum (Tertutup / Firewall / Timeout)."

    return result


def check_firebase_crud(url_str: str) -> Dict[str, Any]:
    """Test permission Firebase Realtime Database: Read & Write (CRUD test)."""
    url = url_str.strip()
    if not url.startswith("http"):
        url = "https://" + url

    base_url = url.split("?")[0].rstrip("/")
    if ".firebaseio.com" in base_url:
        idx = base_url.find(".firebaseio.com") + len(".firebaseio.com")
        base_url = base_url[:idx]

    test_read_url = f"{base_url}/.json?shallow=true"
    test_write_url = f"{base_url}/audit_probe_test.json"

    read_open = False
    write_open = False
    details = []
    response_body = ""

    # 1. Test Read
    try:
        r = requests.get(test_read_url, headers=HEADERS, timeout=6.0, verify=False)
        response_body = r.text[:800]
        if r.status_code == 200 and r.text.strip() != "null":
            read_open = True
            details.append("Read: OPEN (HTTP 200 - Data publik dapat dibaca tanpa Auth)")
        elif r.status_code == 200:
            read_open = True
            details.append("Read: OPEN (HTTP 200 - Root JSON kosong / null)")
        elif r.status_code in (401, 403):
            details.append(f"Read: PROTECTED (HTTP {r.status_code} Permission Denied / Auth Required)")
        else:
            details.append(f"Read: Respon HTTP {r.status_code}")
    except Exception as e:
        details.append(f"Read Gagal: {str(e)}")

    # 2. Test Write
    try:
        test_payload = {"audit_probe": "security_test", "author": "mobile_audit_tool"}
        r = requests.put(test_write_url, json=test_payload, headers=HEADERS, timeout=6.0, verify=False)
        if r.status_code == 200:
            write_open = True
            details.append("Write: OPEN (HTTP 200 - Data uji coba berhasil ditulis tanpa Auth!)")
            try:
                requests.delete(test_write_url, headers=HEADERS, timeout=4.0, verify=False)
            except Exception:
                pass
        elif r.status_code in (401, 403):
            details.append(f"Write: PROTECTED (HTTP {r.status_code} Permission Denied)")
        else:
            details.append(f"Write: Respon HTTP {r.status_code}")
    except Exception as e:
        details.append(f"Write Gagal: {str(e)}")

    if read_open and write_open:
        verdict = "CRITICAL_OPEN_RW"
        summary = "CRITICAL: Database Firebase terbuka PENUH (Bisa Read & Write tanpa Auth)!"
    elif read_open:
        verdict = "HIGH_OPEN_READ"
        summary = "HIGH: Database Firebase terbuka READ (Data publik bocor tanpa Auth)!"
    elif write_open:
        verdict = "CRITICAL_OPEN_WRITE"
        summary = "CRITICAL: Database Firebase terbuka WRITE!"
    else:
        verdict = "SECURE"
        summary = "SECURE: Database Firebase terproteksi dengan aturan Auth (Rules aman)."

    return {
        "url": base_url,
        "test_read_url": test_read_url,
        "verdict": verdict,
        "read_open": read_open,
        "write_open": write_open,
        "summary": summary,
        "details": details,
        "raw_response": response_body
    }


_GAPI_DENIAL_PATTERNS = [
    ("api key not valid", "INVALID_KEY", "DENIED — INVALID KEY", False,
     "API key tidak valid / sudah dihapus"),
    ("invalid api key", "INVALID_KEY", "DENIED — INVALID KEY", False,
     "API key tidak valid / sudah dihapus"),
    ("api key is invalid", "INVALID_KEY", "DENIED — INVALID KEY", False,
     "API key tidak valid / sudah dihapus"),
    ("api keys are not supported by this api", "OAUTH_ONLY", "API WAJIB OAUTH (KEY TAK TERUJI)", None,
     "API ini menolak API key (hanya OAuth) — tidak membuktikan validitas key"),
    ("this ip, site or mobile application is not authorized to use this api key",
     "IP_RESTRICTED", "DENIED — IP/REFERER RESTRICTED", True,
     "Key valid, di-restrict ke IP/referer tertentu (attacker butuh IP/referrer yang cocok)"),
    ("this api key is not authorized to use this service or api",
     "API_RESTRICTED", "DENIED — API RESTRICTION", True,
     "Key valid, API ini tidak ada di allowlist API restriction key"),
    ("not activated on your api project", "NOT_ACTIVATED", "DENIED — API NONAKTIF", True,
     "Key valid; API tidak di-activate di project GCP"),
    ("not activated on the project", "NOT_ACTIVATED", "DENIED — API NONAKTIF", True,
     "Key valid; API tidak di-activate di project GCP"),
    ("has not been used in project", "NOT_ACTIVATED", "DENIED — API NONAKTIF", True,
     "Key valid; API belum pernah dipakai / disabled di project GCP"),
    ("it is disabled", "NOT_ACTIVATED", "DENIED — API NONAKTIF", True,
     "Key valid; API disabled di project GCP — aktifkan via console untuk jadi attack surface"),
    ("from referer", "REF_RESTRICTED", "DENIED — REFERER RESTRICTED", True,
     "Key valid, di-restrict ke HTTP referer tertentu — attacker butuh referer yang cocok"),
    ("client application", "CLIENT_RESTRICTED", "DENIED — CLIENT/PACKAGE RESTRICTED", True,
     "Key valid, di-restrict ke package/bundle ID aplikasi tertentu (khas mobile key)"),
    ("bundle id", "CLIENT_RESTRICTED", "DENIED — CLIENT/PACKAGE RESTRICTED", True,
     "Key valid, di-restrict ke package/bundle ID aplikasi tertentu (khas mobile key)"),
    ("referernotallowed", "REF_RESTRICTED", "DENIED — REFERER RESTRICTED", True,
     "Key valid tapi dibatasi HTTP referer"),
    ("quota", "QUOTA", "DENIED — KUOTA HABIS", True,
     "Key valid tapi kuota habis / rate limited (billing abuse pernah/terjadi)"),
    ("rate limit", "QUOTA", "DENIED — KUOTA HABIS", True,
     "Key valid tapi kuota habis / rate limited (billing abuse pernah/terjadi)"),
    ("requests from this", "OTHER_RESTRICTED", "DENIED — RESTRICTED", True,
     "Key valid tapi request dari klien ini ditolak (restriction aktif)"),
    ("calling a legacy api", "NOT_ACTIVATED", "DENIED — API NONAKTIF (legacy)", True,
     "Key valid; API legacy tidak di-enable di project (migrasi ke API baru, Places API dsb.)"),
    ("referer restrictions cannot be used with this api", "REF_RESTRICTED",
     "DENIED — REFERER RESTRICTED", True,
     "Key valid, di-restrict ke HTTP referer tertentu ( Maps web service menolak)"),
]


def _gapi_classify(text: str):
    """Klasifikasi pesan error Google -> (status_label, vulnerable, key_valid, detail)."""
    tl = (text or "").lower()
    for pat, _kind, label, kv, detail in _GAPI_DENIAL_PATTERNS:
        if pat in tl:
            return label, False, kv, detail
    return None


def _gapi_probe_image(name: str, category: str, url: str, attempts: int = 2) -> dict:
    """Probe endpoint image (Static Maps / Embed) dengan retry.

    Google kadang balas transient 429/403 karena rate limit ketika 24 probe
    berjalan paralel — scope yang sebenarnya aktif bisa salah terbaca DENIED.
    Retry sekali (jeda 1.2s) bila attempt pertama bukan image-render sukses.
    """
    import time as _time
    out = None
    for i in range(attempts):
        out = _gapi_probe(name, category, "GET", url)
        if out.get("vulnerable"):
            return out
        if i < attempts - 1:
            _time.sleep(1.2)
    return out


def _gapi_probe(name: str, category: str, method: str, url: str, body=None, headers=None) -> dict:
    """Satu probe API Google + klasifikasi berbasis BODY respons (bukan HTTP code!).

    Google Maps web services sering balas HTTP 200 padahal body JSON-nya
    REQUEST_DENIED (error_message terisi) — jadi status_code 200 TIDAK berarti
    aktif. Urutan pengecekan:
      1. JSON `status` == OK/ZERO_RESULTS tanpa error_message -> benar-benar ACTIVE
      2. JSON `error_message` / `status` REQUEST_DENIED -> classify pesannya
      3. JSON `error` (Cloud API style) -> classify message-nya
      4. Non-JSON: content-type image + 200 -> ACTIVE (Static Maps render)
         sisanya -> classify teks mentah (keyword denial)
    """
    import requests as _rq
    out = {"api": name, "category": category, "url": url, "method": method,
           "status": "Error", "vulnerable": False, "key_valid": None, "detail": ""}
    try:
        hdrs = dict(HEADERS)
        if headers:
            hdrs.update(headers)
        if method == "POST":
            r = _rq.post(url, json=body, headers=hdrs, timeout=6.0, verify=False)
        else:
            r = _rq.get(url, headers=hdrs, timeout=6.0, verify=False)

        data = None
        try:
            data = r.json()
        except Exception:
            data = None
        raw = (r.text or "")[:2000]
        ctype = (r.headers.get("content-type") or "").lower()

        # --- 1) JSON Maps-style: status + error_message itu ground truth ---
        if isinstance(data, dict):
            st = data.get("status")
            err_msg = str(data.get("error_message") or data.get("errorMessage") or "")
            # Cloud API error style: {"error": {"code":..,"message":..,"errors":[..]}}
            cloud_err = data.get("error")
            cloud_msg = ""
            if isinstance(cloud_err, dict):
                cloud_msg = str(cloud_err.get("message") or "")
                for e in (cloud_err.get("errors") or [])[:3]:
                    cloud_msg += " " + str(e.get("message") or "")
                    if e.get("reason"):
                        cloud_msg += " " + str(e.get("reason"))

            if st in ("OK", "ZERO_RESULTS") and not err_msg:
                out.update(status="ACTIVE / ALLOWED", vulnerable=True, key_valid=True,
                           detail=f"Status {st} - endpoint aktif & key diterima")
                return out
            if err_msg:
                # HTTP 200 + error_message = DENIED di dalam body
                res = _gapi_classify(err_msg) or (f"HTTP {r.status_code}", False, None,
                                                  err_msg[:140])
                out.update(status=res[0], vulnerable=res[1], key_valid=res[2], detail=res[3])
                return out
            if st and st not in ("OK", "ZERO_RESULTS", None):
                # status REQUEST_DENIED / OVER_QUERY_LIMIT / dst (error_message bisa kosong)
                res = _gapi_classify(err_msg + " " + str(st) + " " + raw)
                if res:
                    out.update(status=res[0], vulnerable=res[1], key_valid=res[2], detail=res[3])
                else:
                    out.update(status=f"DENIED — {st}", vulnerable=False, key_valid=None,
                               detail=f"Maps status: {st}" + (f" | {str(data)[:100]}" if not err_msg else ""))
                return out
            if cloud_msg:
                res = _gapi_classify(cloud_msg) or (f"HTTP {r.status_code}", False, None,
                                                    cloud_msg[:140])
                out.update(status=res[0], vulnerable=res[1], key_valid=res[2], detail=res[3])
                return out
            # 200 JSON tanpa status/error -> sukses generik (mis. Gemini models list)
            if r.status_code == 200 and "models" in data:
                out.update(status="ACTIVE / ALLOWED", vulnerable=True, key_valid=True,
                           detail="HTTP 200 - daftar model diterima (Gemini API aktif)")
                return out
            if r.status_code == 200:
                out.update(status="ACTIVE / ALLOWED", vulnerable=True, key_valid=True,
                           detail="HTTP 200 - endpoint merespons data sukses")
                return out
            out.update(status=f"HTTP {r.status_code}", key_valid=None, detail=raw[:120])
            return out

        # --- 2) Non-JSON: image = Static Maps render sukses ---
        if ctype.startswith("image") and r.status_code == 200:
            out.update(status="ACTIVE / ALLOWED", vulnerable=True, key_valid=True,
                       detail="Gambar berhasil dirender (billing/kuota aktif)")
            return out

        # --- 3) teks/HTML/plain: klasifikasi keyword denial di body ---
        res = _gapi_classify(raw)
        if res:
            out.update(status=res[0], vulnerable=res[1], key_valid=res[2], detail=res[3])
        elif r.status_code == 200 and "html" not in ctype:
            out.update(status="ACTIVE / ALLOWED", vulnerable=True, key_valid=True,
                       detail="HTTP 200 - resource sukses")
        else:
            out.update(status=f"HTTP {r.status_code}", key_valid=None, detail=raw[:140])
    except Exception as e:
        out.update(status="Error", detail=str(e))
    return out


def check_google_api_key(key_str: str) -> Dict[str, Any]:
    """Suite tester Google API key: 24 scope dalam 4 kategori (paralel).

    Kategori:
      1. Maps Core      — 10 endpoint klasik (Geocoding, Directions, Places, dst.)
      2. Maps Extended  — Street View, Nearby Search, Roads, Geolocation, Embed, Address Validation
      3. Cloud AI/Data   — YouTube, Gemini (Generative Language), Translation, Vision, TTS, NL
      4. Key Intel       — Drive/Calendar (API wajib OAuth): pesan error-nya membuktikan key valid/mati

    Seluruh probe read-only & ringan (1 request per scope). Eksekusi paralel
    sehingga total waktu ~6-10 detik berapa pun jumlah scope-nya.
    """
    m = re.search(r'AIza[0-9A-Za-z_-]{35}', key_str)
    key = m.group(0) if m else key_str.strip()

    probes = []

    def g(name, url, category="Maps Core", headers=None):
        probes.append((name, category, "GET", url, None, headers))

    def p_(name, url, body, category="Cloud AI / Data", headers=None):
        probes.append((name, category, "POST", url, body, headers))

    # --- 1. Maps Core (10) ---
    g("Geocoding API", f"https://maps.googleapis.com/maps/api/geocode/json?address=Jakarta&key={key}")
    g("Reverse Geocoding", f"https://maps.googleapis.com/maps/api/geocode/json?latlng=-6.200000,106.816666&key={key}")
    g("Directions API", f"https://maps.googleapis.com/maps/api/directions/json?origin=Jakarta&destination=Bandung&key={key}")
    g("Distance Matrix API", f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=Jakarta&destinations=Bandung&key={key}")
    g("Places Text Search", f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurant+in+Jakarta&key={key}")
    g("Place Details", f"https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJnUvjRenzaS4R4p8G5Ssk6kE&key={key}")
    g("Place Autocomplete", f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Jakarta&key={key}")
    g("Time Zone API", f"https://maps.googleapis.com/maps/api/timezone/json?location=-6.200000,106.816666&timestamp=1458000000&key={key}")
    g("Elevation API", f"https://maps.googleapis.com/maps/api/elevation/json?locations=-6.200000,106.816666&key={key}")
    g("Static Maps API", f"https://maps.googleapis.com/maps/api/staticmap?center=Surabaya&zoom=10&size=400x400&key={key}")

    # --- 2. Maps Extended (6) ---
    g("Street View Metadata", f"https://maps.googleapis.com/maps/api/streetview/metadata?location=-6.2088,106.8456&key={key}", "Maps Extended")
    g("Places Nearby Search", f"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-6.200000,106.816666&radius=500&key={key}", "Maps Extended")
    g("Roads API (nearestRoads)", f"https://roads.googleapis.com/v1/nearestRoads?points=-6.200000,106.816666&key={key}", "Maps Extended")
    p_("Geolocation API", f"https://www.googleapis.com/geolocation/v1/geolocate?key={key}", {}, "Maps Extended")
    g("Maps Embed API", f"https://www.google.com/maps/embed/v1/view?key={key}&center=-6.200000,106.816666&zoom=10&maptype=roadmap", "Maps Extended")
    p_("Address Validation API", f"https://addressvalidation.googleapis.com/v1:validateAddress?key={key}",
       {"address": {"regionCode": "ID"}}, "Maps Extended")

    # --- 3. Cloud AI / Data (6) — vektor billing abuse paling mahal ---
    g("YouTube Data API v3", f"https://www.googleapis.com/youtube/v3/videos?part=snippet&chart=mostPopular&maxResults=1&key={key}", "Cloud AI / Data")
    g("Generative Language (Gemini)", f"https://generativelanguage.googleapis.com/v1beta/models?key={key}", "Cloud AI / Data")
    p_("Cloud Translation API", f"https://translation.googleapis.com/language/translate/v2?key={key}",
       {"q": "hello", "target": "id", "format": "text"})
    p_("Cloud Vision API", f"https://vision.googleapis.com/v1/images:annotate?key={key}",
       {"requests": [{"image": {"source": {"imageUri": "https://www.gstatic.com/webp/gallery3/1.jpg"}},
                      "features": [{"type": "LABEL_DETECTION", "maxResults": 1}]}]})
    p_("Text-to-Speech API", f"https://texttospeech.googleapis.com/v1/text:synthesize?key={key}",
       {"input": {"text": "hi"}, "voice": {"languageCode": "en-US"}, "audioConfig": {"audioEncoding": "MP3"}})
    p_("Natural Language API", f"https://language.googleapis.com/v1/documents:analyzeSentiment?key={key}",
       {"document": {"content": "hello", "type": "PLAIN_TEXT"}})

    # --- 3b. Hasil validasi manual: arah migrasi Google + endpoint image kedua ---
    g("Street View Image", f"https://maps.googleapis.com/maps/api/streetview?location=-6.2088,106.8456&size=400x400&key={key}", "Maps Extended")
    p_("Places API (New) — searchText", "https://places.googleapis.com/v1/places:searchText",
       {"textQuery": "restaurant in Jakarta"}, "Maps Extended",
       {"X-Goog-Api-Key": key, "X-Goog-FieldMask": "places.displayName"})
    p_("Places API (New) — autocomplete", "https://places.googleapis.com/v1/places:autocomplete",
       {"input": "Jakarta"}, "Maps Extended",
       {"X-Goog-Api-Key": key, "Content-Type": "application/json"})
    p_("Roads snapToRoads (POST)", f"https://roads.googleapis.com/v1/snapToRoads?path=-6.200000,106.816666|-6.210000,106.826666&interpolate=false&key={key}",
       {}, "Maps Extended")
    g("Custom Search JSON API", f"https://www.googleapis.com/customsearch/v1?key={key}&cx=017576662512468239146:omuauf_lfve&q=lectures", "Cloud AI / Data")

    # --- 4. Key Intel (2) — API wajib OAuth, error-nya membuktikan key hidup/mati ---
    g("Drive API (key intel)", f"https://www.googleapis.com/drive/v3/about?fields=user&key={key}", "Key Intel (OAuth-only)")
    g("Calendar API (key intel)", f"https://www.googleapis.com/calendar/v3/users/me/calendarList?key={key}", "Key Intel (OAuth-only)")

    # eksekusi paralel (read-only, 1 request per scope)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for (name, cat, method, url, body, headers) in probes:
            if "staticmap" in url or "/maps/embed/" in url or "/maps/api/streetview?" in url:
                # endpoint image: retry bila transient rate-limit (aktif salah DENIED)
                futures.append(pool.submit(_gapi_probe_image, name, cat, url))
            else:
                futures.append(pool.submit(_gapi_probe, name, cat, method, url, body, headers))
        scopes = [f.result() for f in futures]

    active_count = sum(1 for s in scopes if s.get("vulnerable"))
    is_vulnerable = active_count > 0
    # validitas key = bukti terkuat dari semua respons (False lebih kuat dari None)
    key_validity = None
    for s in scopes:
        if s.get("key_valid") is False:
            key_validity = False
            break
        if s.get("key_valid") is True:
            key_validity = True

    if active_count >= 5:
        verdict = "CRITICAL_UNRESTRICTED"
        summary = f"CRITICAL: Google API Key tidak dibatasi (Unrestricted)! {active_count} dari {len(scopes)} API aktif bebas dipakai publik."
    elif active_count > 0:
        verdict = "HIGH_PARTIAL_ALLOWED"
        summary = f"HIGH: {active_count} dari {len(scopes)} Google API aktif tanpa Referer/IP restriction."
    elif key_validity is False:
        verdict = "DEAD_KEY"
        summary = f"INFO: Key tidak valid / sudah dihapus (0/{len(scopes)} scope aktif, probe mengindikasikan invalid key)."
    else:
        verdict = "SECURE_RESTRICTED"
        extra = ""
        if key_validity is True:
            extra = " (key valid tapi semua scope dibatasi/nonaktif)"
        summary = f"SECURE: Kunci Google dibatasi — 0/{len(scopes)} scope aktif{extra}."

    return {
        "key": key[:10] + "..." + key[-4:] if len(key) > 14 else key,
        "full_key": key,
        "active_scopes_count": active_count,
        "total_tested": len(scopes),
        "key_valid": key_validity,
        "is_vulnerable": is_vulnerable,
        "verdict": verdict,
        "summary": summary,
        "scopes": scopes
    }


def check_aws_sts_identity(access_key: str, secret_key: str = "", session_token: str = "") -> Dict[str, Any]:
    """Cek keaktifan AWS Access Key langsung via AWS STS GetCallerIdentity API."""
    ak = access_key.strip()
    sk = secret_key.strip()
    st = session_token.strip()

    if not ak.startswith("AKIA") and not ak.startswith("ASIA"):
        m = re.search(r'\b(AKIA|ASIA)[0-9A-Z]{16}\b', ak)
        if m:
            ak = m.group(0)

    if not sk:
        # Jika secret key belum ada (hanya Access Key ID yang terdeteksi)
        return {
            "access_key": ak,
            "has_secret": False,
            "verdict": "INFO_KEY_ONLY",
            "summary": f"Access Key ID ({ak}) ditemukan. Butuh Secret Access Key untuk menjalankan GetCallerIdentity.",
            "caller_identity": {},
            "raw_response": "Access Key terdeteksi tanpa pasangan Secret Key di string yang sama."
        }

    # Generate SigV4
    host = 'sts.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://sts.amazonaws.com/'
    request_parameters = 'Action=GetCallerIdentity&Version=2011-06-15'

    t = datetime.datetime.now(datetime.timezone.utc)
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')

    canonical_uri = '/'
    canonical_querystring = ''
    canonical_headers = f'content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:{host}\nx-amz-date:{amzdate}\n'
    if st:
        canonical_headers += f'x-amz-security-token:{st}\n'
        signed_headers = 'content-type;host;x-amz-date;x-amz-security-token'
    else:
        signed_headers = 'content-type;host;x-amz-date'

    payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()
    canonical_request = f"POST\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{datestamp}/{region}/sts/aws4_request"
    string_to_sign = f"{algorithm}\n{amzdate}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign(key_bytes, msg):
        return hmac.new(key_bytes, msg.encode('utf-8'), hashlib.sha256).digest()

    kDate = sign(('AWS4' + sk).encode('utf-8'), datestamp)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, 'sts')
    kSigning = sign(kService, 'aws4_request')
    signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    auth_header = f"{algorithm} Credential={ak}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    req_headers = {
        'Host': host,
        'x-amz-date': amzdate,
        'Authorization': auth_header,
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'User-Agent': 'MobileAuditTool/2.0'
    }
    if st:
        req_headers['x-amz-security-token'] = st

    try:
        r = requests.post(endpoint, data=request_parameters, headers=req_headers, timeout=5.0)
        resp_text = r.text
        if r.status_code == 200:
            # Parse XML identity
            account = re.search(r'<Account>([^<]+)</Account>', resp_text)
            arn = re.search(r'<Arn>([^<]+)</Arn>', resp_text)
            user_id = re.search(r'<UserId>([^<]+)</UserId>', resp_text)
            acc_val = account.group(1) if account else "—"
            arn_val = arn.group(1) if arn else "—"
            user_val = user_id.group(1) if user_id else "—"

            return {
                "access_key": ak,
                "has_secret": True,
                "is_active": True,
                "verdict": "CRITICAL_VALID_CREDENTIALS",
                "summary": f"🚨 CRITICAL: Kunci AWS AKTIF! ARN: {arn_val} (Account: {acc_val})",
                "caller_identity": {
                    "account": acc_val,
                    "arn": arn_val,
                    "user_id": user_val
                },
                "raw_response": resp_text
            }
        else:
            code_m = re.search(r'<Code>([^<]+)</Code>', resp_text)
            msg_m = re.search(r'<Message>([^<]+)</Message>', resp_text)
            err_code = code_m.group(1) if code_m else f"HTTP {r.status_code}"
            err_msg = msg_m.group(1) if msg_m else resp_text[:120]
            return {
                "access_key": ak,
                "has_secret": True,
                "is_active": False,
                "verdict": "SECURE_INVALID_OR_REVOKED",
                "summary": f"Kunci AWS Tidak Aktif / Ditolak ({err_code}): {err_msg}",
                "caller_identity": {},
                "raw_response": resp_text
            }
    except Exception as e:
        return {
            "access_key": ak,
            "has_secret": True,
            "is_active": False,
            "verdict": "ERROR_CONNECTION",
            "summary": f"Gagal menghubungi AWS STS: {str(e)}",
            "caller_identity": {},
            "raw_response": str(e)
        }


def check_stripe_key(key_str: str) -> Dict[str, Any]:
    """Cek format dan live status Stripe Key (Publishable vs Secret Key)."""
    key = key_str.strip()
    m = re.search(r'\b(pk_live_|sk_live_|pk_test_|sk_test_)[0-9a-zA-Z]{24,}\b', key)
    if m:
        key = m.group(0)

    is_secret = key.startswith("sk_live_") or key.startswith("sk_test_")
    is_live = key.startswith("sk_live_") or key.startswith("pk_live_")
    key_type = "Secret Key (sk_)" if is_secret else "Publishable Key (pk_)"
    env_type = "LIVE Production" if is_live else "TEST Mode"

    result = {
        "key": key[:12] + "..." + key[-4:] if len(key) > 16 else key,
        "full_key": key,
        "is_secret": is_secret,
        "is_live": is_live,
        "key_type": key_type,
        "env_type": env_type,
        "active": False,
        "verdict": "",
        "summary": "",
        "account_info": {},
        "raw_response": ""
    }

    if is_secret:
        # Test ke Stripe API /v1/balance
        try:
            r = requests.get("https://api.stripe.com/v1/balance", headers={"Authorization": f"Bearer {key}"}, timeout=5.0)
            result["raw_response"] = r.text[:800]
            if r.status_code == 200:
                result["active"] = True
                result["verdict"] = "CRITICAL_STRIPE_SK_LIVE" if is_live else "HIGH_STRIPE_SK_TEST"
                result["summary"] = f"🚨 {'CRITICAL' if is_live else 'HIGH'}: Stripe Secret Key AKTIF! Akses penuh ke API pembayaran Stripe."
                result["account_info"] = r.json()
            else:
                result["verdict"] = "REVOKED_STRIPE_KEY"
                result["summary"] = f"Stripe Secret Key Tidak Aktif (HTTP {r.status_code})"
        except Exception as e:
            result["summary"] = f"Gagal cek Stripe API: {e}"
    else:
        # Publishable key
        result["verdict"] = "INFO_STRIPE_PK"
        result["summary"] = f"Stripe {key_type} ({env_type}) - Dirancang untuk client-side, risiko rendah kecuali ada miskonfigurasi."

    return result


def check_webhook_status(webhook_url: str) -> Dict[str, Any]:
    """Cek keaktifan Slack atau Discord Webhook URL."""
    url = webhook_url.strip()
    is_slack = "hooks.slack.com" in url
    is_discord = "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url

    hook_type = "Slack Webhook" if is_slack else ("Discord Webhook" if is_discord else "Generic Webhook")

    result = {
        "url": url[:30] + "..." + url[-10:] if len(url) > 40 else url,
        "full_url": url,
        "hook_type": hook_type,
        "active": False,
        "verdict": "",
        "summary": "",
        "raw_response": ""
    }

    try:
        if is_slack:
            # Slack: GET request mengembalikan pesan error tertentu jika webhook valid (mis. "invalid_payload")
            # Jika webhook revoked -> HTTP 404 "channel_not_found" / "token_revoked"
            r = requests.get(url, headers=HEADERS, timeout=5.0)
            result["raw_response"] = r.text
            if r.status_code == 400 and "invalid_payload" in r.text:
                result["active"] = True
                result["verdict"] = "HIGH_ACTIVE_WEBHOOK"
                result["summary"] = "🚨 HIGH: Slack Webhook AKTIF! Attacker dapat mengirim pesan notifikasi palsu / spam ke channel internal."
            elif r.status_code == 200:
                result["active"] = True
                result["verdict"] = "HIGH_ACTIVE_WEBHOOK"
                result["summary"] = "🚨 HIGH: Slack Webhook AKTIF (HTTP 200)!"
            else:
                result["verdict"] = "INACTIVE_WEBHOOK"
                result["summary"] = f"Slack Webhook Tidak Aktif / Revoked (HTTP {r.status_code})"
        elif is_discord:
            # Discord: GET request ke webhook URL mengembalikan JSON metadata channel/guild tanpa mengeksekusi post
            r = requests.get(url, headers=HEADERS, timeout=5.0)
            result["raw_response"] = r.text
            if r.status_code == 200:
                data = r.json()
                guild_id = data.get("guild_id", "—")
                channel_id = data.get("channel_id", "—")
                name = data.get("name", "—")
                result["active"] = True
                result["verdict"] = "HIGH_ACTIVE_WEBHOOK"
                result["summary"] = f"🚨 HIGH: Discord Webhook AKTIF! Nama: '{name}', Guild: {guild_id}, Channel: {channel_id}"
            else:
                result["verdict"] = "INACTIVE_WEBHOOK"
                result["summary"] = f"Discord Webhook Tidak Aktif / Revoked (HTTP {r.status_code})"
        else:
            r = requests.head(url, headers=HEADERS, timeout=5.0)
            result["active"] = r.status_code < 400
            result["summary"] = f"Webhook merespon HTTP {r.status_code}"
    except Exception as e:
        result["summary"] = f"Gagal menghubungi Webhook: {e}"

    return result


def check_generic_endpoint(url_str: str) -> Dict[str, Any]:
    """Test HTTP status code, response headers, dan body snippet dari endpoint."""
    url = url_str.strip()
    if not url.startswith("http"):
        url = "https://" + url

    try:
        r = requests.get(url, headers=HEADERS, timeout=6.0, verify=False, allow_redirects=True)
        headers = dict(r.headers)
        return {
            "url": url,
            "alive": True,
            "status_code": r.status_code,
            "server": headers.get("Server", headers.get("server", "—")),
            "content_type": headers.get("Content-Type", headers.get("content-type", "—")),
            "headers": {k: v for k, v in list(headers.items())[:15]},
            "body_preview": r.text[:800],
            "message": f"Endpoint AKTIF (HTTP {r.status_code})"
        }
    except requests.exceptions.HTTPError as e:
        r = e.response
        headers = dict(r.headers) if r else {}
        return {
            "url": url,
            "alive": True,
            "status_code": r.status_code if r else 0,
            "server": headers.get("Server", headers.get("server", "—")),
            "content_type": headers.get("Content-Type", headers.get("content-type", "—")),
            "headers": {k: v for k, v in list(headers.items())[:15]},
            "body_preview": r.text[:500] if r else "",
            "message": f"Endpoint merespon HTTP {r.status_code}" if r else f"HTTP Error: {e}"
        }
    except Exception as e:
        return {
            "url": url,
            "alive": False,
            "status_code": 0,
            "server": "—",
            "content_type": "—",
            "headers": {},
            "body_preview": "",
            "message": f"Koneksi gagal / Timeout ({str(e)[:60]})"
        }


def check_credential_login(url_str: str, username: str, password: str,
                           timeout: float = 10.0) -> Dict[str, Any]:
    """Uji login hardcoded credential secara NON-DESTRUKTIF (read-only setelah auth).

    Coba 3 meta umum (JSON POST / form POST / Basic auth GET) dan nilai hasilnya:
      - VALID_LOGIN    : 2xx + token/session di respons (access_token, eyJ, Set-Cookie)
      - LIKELY_VALID  : 2xx dengan respons berbeda dari baseline tanpa auth
      - INVALID       : 401/403 di semua metode
      - INCONCLUSIVE  : 2xx tapi respons identik baseline (halaman sama, tanpa token)
      - ERROR         : koneksi gagal / bukan http(s)
    Tidak ada operasi write/CRUD data — hanya endpoint login itu sendiri.
    """
    url = (url_str or "").strip()
    username = (username or "").strip()
    password = (password or "").strip()

    result = {
        "url": url,
        "username": username,
        "verdict": "",
        "summary": "",
        "attempts": [],
        "baseline_len": None,
        "evidence": "",
        "raw_response": "",
    }

    if not url.startswith(("http://", "https://")):
        result["verdict"] = "ERROR"
        result["summary"] = "URL harus diawali http:// atau https://"
        return result
    if not username or not password:
        result["verdict"] = "ERROR"
        result["summary"] = "Username dan password wajib diisi."
        return result

    def _try(label: str, http_method: str, req_kwargs: dict) -> Dict[str, Any]:
        att = {"method": label, "status": None, "ok": False, "detail": ""}
        try:
            r = requests.request(http_method, url, timeout=timeout, verify=False, **req_kwargs)
            att["status"] = r.status_code
            body = r.text or ""
            att["ok"] = 200 <= r.status_code < 300
            set_cookie = r.headers.get("Set-Cookie", "")
            token_hit = any(marker in body.lower() for marker in
                            ("access_token", "id_token", "refresh_token", "\"token\"",
                             "authorization", "bearer ", "eyj"))
            cookie_hit = any(m in set_cookie.lower() for m in
                             ("session", "token", "auth", "sid"))
            att["token_hit"] = token_hit or cookie_hit
            att["body_len"] = len(body)
            att["body_head"] = body[:300]
            return att
        except requests.exceptions.Timeout:
            att["detail"] = "timeout"
            return att
        except requests.exceptions.SSLError as e:
            att["detail"] = f"ssl: {str(e)[:80]}"
            return att
        except requests.exceptions.ConnectionError as e:
            att["detail"] = f"connection: {str(e)[:100]}"
            return att
        except Exception as e:
            att["detail"] = f"error: {str(e)[:100]}"
            return att

    # baseline tanpa kredensial (GET) — pembanding respons
    base = _try("GET-baseline", "GET", {"headers": HEADERS})
    result["baseline_len"] = base.get("body_len")

    attempts = []
    # 1. JSON POST (username / email variants)
    for key in ("username", "email", "user"):
        att = _try(f"json:{key}", "POST", {
            "headers": {**HEADERS, "Content-Type": "application/json"},
            "data": json.dumps({key: username, "password": password}),
        })
        att["cred_key"] = key
        attempts.append(att)
        if att.get("status") in (200, 201) and att.get("token_hit"):
            break
    # 2. Form POST
    attempts.append(_try("form", "POST", {
        "headers": {**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        "data": f"username={username}&password={password}",
    }))
    # 3. Basic auth GET
    import base64 as _b64
    basic = _b64.b64encode(f"{username}:{password}".encode()).decode()
    attempts.append(_try("basic", "GET", {
        "headers": {**HEADERS, "Authorization": "Basic " + basic},
    }))
    result["attempts"] = [{k: v for k, v in a.items() if k not in ("body_head",)}
                          for a in attempts]

    def _fmt(a):
        return f"{a['method']} -> HTTP {a.get('status')}{(' [' + a['detail'] + ']') if a.get('detail') else ''}"

    # nilai verdict
    base_status = base.get("status")
    reached = [a for a in attempts if a.get("status") is not None]
    ok2xx = [a for a in attempts if a.get("ok")]

    # VALID #1: respons 2xx mengandung token/session
    valid = next((a for a in ok2xx if a.get("token_hit")), None)
    # VALID #2: endpoint terproteksi auth (baseline 401/403) tapi 2xx DENGAN kredensial
    if not valid and base_status in (401, 403):
        valid = next((a for a in ok2xx if a.get("status") in (200, 201)), None)
    # LIKELY: 2xx dan respons jelas beda dari baseline 2xx
    likely = next((a for a in ok2xx
                   if base_status not in (401, 403)
                   and a.get("body_len") is not None
                   and base.get("body_len") is not None
                   and abs(a["body_len"] - base["body_len"]) > 50), None)
    # INVALID: tidak ada 2xx sama sekali dan ada 401/403 eksplisit
    invalid_all = (not ok2xx) and any(a.get("status") in (401, 403) for a in reached)

    if valid:
        result["verdict"] = "VALID_LOGIN"
        result["summary"] = f"🚨 CRITICAL: Login BERHASIL via {valid['method']} — kredensial aktif (token/session terdeteksi)."
        result["raw_response"] = valid.get("body_head", "")
        result["evidence"] = "; ".join(_fmt(a) for a in attempts)
    elif likely:
        result["verdict"] = "LIKELY_VALID"
        result["summary"] = f"⚠️ Kredensial KEMUNGKINAN valid via {likely['method']} — respons beda dari baseline, tapi tanpa token eksplisit. Cek manual."
        result["raw_response"] = likely.get("body_head", "")
        result["evidence"] = "; ".join(_fmt(a) for a in attempts)
    elif invalid_all:
        result["verdict"] = "INVALID"
        result["summary"] = ("🔒 Kredensial DITOLAK (401/403 diterima, tidak ada yang lolos) — invalid/revoked/akun disabled. "
                          "Catatan: 405 = endpoint dengan method berbeda — cek apakah ini endpoint login yang benar.")
        result["evidence"] = "; ".join(_fmt(a) for a in attempts)
    else:
        ok_any = next((a for a in attempts if a.get("ok")), None)
        if ok_any:
            result["verdict"] = "INCONCLUSIVE"
            result["summary"] = (f"Endpoint merespons 2xx via {ok_any['method']} tapi respons mirip baseline "
                                  "(tanpa token/session terdeteksi). Bukan endpoint login, atau login via mekanisme lain (OTP/dynamic fields).")
            result["raw_response"] = ok_any.get("body_head", "")
            result["evidence"] = "; ".join(_fmt(a) for a in attempts)
        else:
            statuses = sorted({a.get("status") for a in attempts if a.get("status")})
            if not statuses:
                result["verdict"] = "ERROR"
                result["summary"] = "Endpoint tidak dapat dijangkau (timeout/koneksi gagal)."
                result["evidence"] = "; ".join(_fmt(a) for a in attempts)
            else:
                result["verdict"] = "INCONCLUSIVE"
                result["summary"] = f"Respons tidak meyakinkan (status: {statuses}). Cek endpoint & format payload manual."
                result["evidence"] = "; ".join(_fmt(a) for a in attempts)
    return result

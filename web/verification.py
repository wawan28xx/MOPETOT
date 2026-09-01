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


def check_google_api_key(key_str: str) -> Dict[str, Any]:
    """Test lengkap seluruh Google Maps & Cloud API endpoints (10+ API endpoints)."""
    m = re.search(r'AIza[0-9A-Za-z_-]{35}', key_str)
    key = m.group(0) if m else key_str.strip()

    tests = {
        "Geocoding API": f"https://maps.googleapis.com/maps/api/geocode/json?address=Jakarta&key={key}",
        "Reverse Geocoding": f"https://maps.googleapis.com/maps/api/geocode/json?latlng=-6.200000,106.816666&key={key}",
        "Directions API": f"https://maps.googleapis.com/maps/api/directions/json?origin=Jakarta&destination=Bandung&key={key}",
        "Distance Matrix API": f"https://maps.googleapis.com/maps/api/distancematrix/json?origins=Jakarta&destinations=Bandung&key={key}",
        "Places Text Search API": f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurant+in+Jakarta&key={key}",
        "Place Details API": f"https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJnUvjRenzaS4R4p8G5Ssk6kE&key={key}",
        "Place Autocomplete API": f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Jakarta&key={key}",
        "Time Zone API": f"https://maps.googleapis.com/maps/api/timezone/json?location=-6.200000,106.816666&timestamp=1458000000&key={key}",
        "Elevation API": f"https://maps.googleapis.com/maps/api/elevation/json?locations=-6.200000,106.816666&key={key}",
        "Static Maps API": f"https://maps.googleapis.com/maps/api/staticmap?center=Surabaya&zoom=10&size=400x400&key={key}",
    }

    scopes = []

    for name, test_url in tests.items():
        try:
            r = requests.get(test_url, headers=HEADERS, timeout=5.0, verify=False)
            if "staticmap" in test_url:
                if r.status_code == 200:
                    scopes.append({
                        "api": name,
                        "url": test_url,
                        "status": "ACTIVE / ALLOWED",
                        "vulnerable": True,
                        "detail": "Gambar Static Map 400x400 berhasil di-render (Billing / Kuota aktif)"
                    })
                else:
                    scopes.append({
                        "api": name,
                        "url": test_url,
                        "status": f"HTTP {r.status_code}",
                        "vulnerable": False,
                        "detail": "Status respon bukan 200 OK"
                    })
            else:
                try:
                    data = r.json()
                    st = data.get("status")
                    if st in ("OK", "ZERO_RESULTS"):
                        scopes.append({
                            "api": name,
                            "url": test_url,
                            "status": "ACTIVE / ALLOWED",
                            "vulnerable": True,
                            "detail": f"Status: {st} - Endpoint memberikan data sukses"
                        })
                    elif st == "REQUEST_DENIED":
                        err_msg = data.get("error_message", "Request Denied")
                        scopes.append({
                            "api": name,
                            "url": test_url,
                            "status": "DENIED",
                            "vulnerable": False,
                            "detail": err_msg
                        })
                    else:
                        scopes.append({
                            "api": name,
                            "url": test_url,
                            "status": st or f"HTTP {r.status_code}",
                            "vulnerable": False,
                            "detail": str(data)[:80]
                        })
                except Exception:
                    scopes.append({
                        "api": name,
                        "url": test_url,
                        "status": f"HTTP {r.status_code}",
                        "vulnerable": False,
                        "detail": r.text[:80]
                    })
        except Exception as e:
            scopes.append({
                "api": name,
                "url": test_url,
                "status": "Error",
                "vulnerable": False,
                "detail": str(e)
            })

    active_count = sum(1 for s in scopes if s.get("vulnerable"))
    is_vulnerable = active_count > 0

    if active_count >= 5:
        verdict = "CRITICAL_UNRESTRICTED"
        summary = f"CRITICAL: Google API Key tidak dibatasi (Unrestricted)! {active_count} dari {len(scopes)} API aktif bebas dipakai publik."
    elif active_count > 0:
        verdict = "HIGH_PARTIAL_ALLOWED"
        summary = f"HIGH: {active_count} dari {len(scopes)} Google API aktif tanpa Referer/IP restriction."
    else:
        verdict = "SECURE_RESTRICTED"
        summary = "SECURE: Kunci Google dibatasi (Restricted / API Scope dinonaktifkan)."

    return {
        "key": key[:10] + "..." + key[-4:] if len(key) > 14 else key,
        "full_key": key,
        "active_scopes_count": active_count,
        "total_tested": len(scopes),
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

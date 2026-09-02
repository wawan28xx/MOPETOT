import os
import sys
import json
import uuid
import asyncio
import contextlib
import logging
import re
import shutil
import time
import markdown as md_lib
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from database.db import (
    init_db, get_db, insert_scan, update_scan_status, complete_scan,
    insert_finding, insert_endpoint, insert_secret, insert_manifest,
    insert_log, get_scan, get_scans, query_scans, get_findings, get_endpoints,
    get_secrets, get_manifest, get_logs, get_stats, search_findings,
    delete_scan, upsert_verification_cache, get_verification_cache,
    upsert_poc_cache, get_poc_cache, request_scan, claim_next_queued_scan,
    fail_interrupted_scans
)

from verification import (
    check_ip_details, check_firebase_crud, check_google_api_key, check_generic_endpoint,
    check_aws_sts_identity, check_stripe_key, check_webhook_status
)

from poc_engine import PoCEngine

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = Path(
    os.environ.get("MOPETOT_UPLOAD_DIR", os.environ.get("UPLOAD_DIR", BASE_DIR / "uploads"))
).expanduser()
RESULTS_DIR = Path(
    os.environ.get("MOPETOT_RESULTS_DIR", os.environ.get("RESULTS_DIR", BASE_DIR / "results"))
).expanduser()
MOBILE_AUDIT_DIR = BASE_DIR.parent
DEFAULT_MAX_UPLOAD_BYTES = 500 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024


def _positive_int_env(*names, default):
    for name in names:
        raw = os.environ.get(name)
        if raw is not None:
            try:
                value = int(raw)
                if value > 0:
                    return value
            except ValueError:
                pass
    return default


MAX_UPLOAD_BYTES = _positive_int_env(
    "MOPETOT_MAX_UPLOAD_BYTES", "MAX_UPLOAD_BYTES", default=DEFAULT_MAX_UPLOAD_BYTES
)

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Mobile Audit Tool", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

SCAN_PROGRESS = {}
QUEUE_TASK = None
QUEUE_WAKEUP = None
ACTIVE_PROCESS = None
SHUTTING_DOWN = False

@app.on_event("startup")
async def startup():
    global QUEUE_TASK, QUEUE_WAKEUP, SHUTTING_DOWN
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    await init_db()
    db = await get_db()
    try:
        await fail_interrupted_scans(db)
    finally:
        await db.close()
    SHUTTING_DOWN = False
    QUEUE_WAKEUP = asyncio.Event()
    QUEUE_TASK = asyncio.create_task(queue_worker(), name="scan-queue-worker")


@app.on_event("shutdown")
async def shutdown():
    global QUEUE_TASK, QUEUE_WAKEUP, SHUTTING_DOWN
    SHUTTING_DOWN = True
    if QUEUE_WAKEUP:
        QUEUE_WAKEUP.set()
    if ACTIVE_PROCESS and ACTIVE_PROCESS.returncode is None:
        await terminate_process(ACTIVE_PROCESS)
    if QUEUE_TASK:
        QUEUE_TASK.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await QUEUE_TASK
    QUEUE_TASK = None
    QUEUE_WAKEUP = None


async def terminate_process(proc, timeout=10):
    if not proc or proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


async def queue_worker():
    while not SHUTTING_DOWN:
        QUEUE_WAKEUP.clear()
        try:
            db = await get_db()
            try:
                scan = await claim_next_queued_scan(db)
            finally:
                await db.close()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scan queue could not claim the next item")
            await asyncio.sleep(1)
            continue

        if scan:
            try:
                await run_scan(
                    scan["id"],
                    scan["file_path"],
                    scan["file_type"],
                    scan["platform"],
                    fast_mode=bool(scan["fast_mode"]),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                failure_db = None
                try:
                    failure_db = await get_db()
                    await update_scan_status(
                        failure_db,
                        scan["id"],
                        "failed",
                        error=f"Queue worker error: {exc}",
                    )
                except Exception:
                    logger.exception(
                        "Could not persist queue worker failure for scan %s",
                        scan["id"],
                    )
                finally:
                    if failure_db:
                        await failure_db.close()
                await asyncio.sleep(1)
            continue

        await QUEUE_WAKEUP.wait()

def classify_file(filename):
    name = filename.lower()
    if name.endswith(".apk") or name.endswith(".aab") or name.endswith(".xapk"):
        return "apk", "android"
    elif name.endswith(".ipa"):
        return "ipa", "ios"
    elif name.endswith(".jar"):
        return "jar", "java"
    elif name.endswith(".dex") or name.endswith(".smali"):
        return "dex", "android"
    elif name.endswith(".so"):
        return "elf", "native"
    elif name.endswith(".dll") or name.endswith(".exe"):
        return "pe", "dotnet"
    elif name.endswith(".hbc"):
        return "hbc", "hermes"
    elif name.endswith(".zip"):
        return "zip", "unknown"
    else:
        return "unknown", "unknown"

def count_lines_in_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)
    except:
        return 0


def corpus_rel_path(full_path, scan_id):
    """Strip prefix hasil-dir/work/corpus sehingga tersisa path relatif app
    (mis. ...\\corpus\\assets\\x.js -> \\assets\\x.js)."""
    corpus = str(RESULTS_DIR / str(scan_id) / "work" / "corpus")
    p = str(full_path)
    for prefix in (corpus, corpus.replace("\\", "/")):
        if p.startswith(prefix) and len(p) > len(prefix):
            return p[len(prefix):]
    return p


def enhance_report_html(html, scan_id):
    """Buat '... N lagi' jadi clickable + table host row."""
    # 1. Row tabel endpoint: | ... 62 lagi | (td pertama, sisa cell kosong)
    html = re.sub(
        r'(<td[^>]*>)(\.\.\. \d+ lagi)(</td>)',
        rf'\1<a class="more-link" data-scan="{scan_id}" data-section="hosts" href="#">\2</a>\3',
        html,
        count=1
    )
    # 2. Baris '... dan N lagi' di dalam code block per-rule
    def _code_repl(m):
        inner = m.group(1)
        mm = re.search(r'\.\.\. dan (\d+) lagi(\s*)$', inner)
        if not mm:
            return m.group(0)
        before = html[:m.start()]
        h4s = re.findall(r'<h4><code>([^<]+)</code>', before)
        rid = h4s[-1] if h4s else ""
        anchor = (f'<a class="more-link" data-scan="{scan_id}" data-rule="{rid}" href="#">'
                  f'... dan {mm.group(1)} lagi</a>')
        inner2 = re.sub(r'\.\.\. dan \d+ lagi(\s*)$', anchor + r'\1', inner)
        return f'<pre><code>{inner2}</code></pre>'
    return re.sub(r'<pre><code>(.*?)</code></pre>', _code_repl, html, flags=re.DOTALL)

async def run_scan(scan_id: int, file_path: str, file_type: str, platform: str, fast_mode: bool = False):
    global ACTIVE_PROCESS
    from database.db import get_db
    db = await get_db()
    proc = None
    output_tasks = []
    heartbeat_task = None
    try:
        await update_scan_status(db, scan_id, "running", 5, "init")
        await insert_log(db, scan_id, "info", f"Starting scan for {file_path}")

        result_dir = RESULTS_DIR / str(scan_id)
        result_dir.mkdir(exist_ok=True)
        corpus_dir = result_dir / "corpus"
        corpus_dir.mkdir(exist_ok=True)

        SCAN_PROGRESS[scan_id] = {"status": "running", "progress": 5, "phase": "init"}

        await insert_log(db, scan_id, "info", f"File type: {file_type}, Platform: {platform}")
        if fast_mode:
            await insert_log(db, scan_id, "info", "FAST MODE: jadx + blutter decompile di-skip (smali + assets + strings)")

        scan_script = MOBILE_AUDIT_DIR / "mobile_audit.py"
        cmd = [
            sys.executable, str(scan_script),
            file_path,
            "-o", str(result_dir),
            "--keep"
        ]
        if fast_mode:
            cmd.append("--skip-jadx")
            cmd.append("--skip-blutter")

        await update_scan_status(db, scan_id, "running", 10, "decompile")
        SCAN_PROGRESS[scan_id] = {"status": "running", "progress": 10, "phase": "decompile"}
        await insert_log(db, scan_id, "info", "Phase: DECOMPILE (jadx/apktool)")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        ACTIVE_PROCESS = proc

        last_line_time = time.monotonic()
        scan_started = time.monotonic()

        async def _stream_output(stream, stderr=False):
            nonlocal last_line_time
            async for line in stream:
                text = line.decode(errors="ignore").strip()
                if not text:
                    continue
                last_line_time = time.monotonic()
                if stderr:
                    await insert_log(db, scan_id, "warning", f"STDERR: {text}")
                    continue

                level = "info"
                if text.startswith("[-]"): level = "error"
                elif text.startswith("[!]"): level = "warning"
                await insert_log(db, scan_id, level, text)
                m = re.search(r"=== Phase (\d): ([A-Z]+) ===", text)
                if m:
                    phase_no = int(m.group(1))
                    phase_name = m.group(2).lower()
                    prog_map = {1: 5, 2: 10, 3: 70, 4: 90}
                    prog = prog_map.get(phase_no, 10)
                    await update_scan_status(db, scan_id, "running", prog, phase_name)
                    SCAN_PROGRESS[scan_id] = {"status": "running", "progress": prog, "phase": phase_name}
                elif text.startswith("[+] Temuan mentah:"):
                    await update_scan_status(db, scan_id, "running", 85, "analyze")
                    SCAN_PROGRESS[scan_id] = {"status": "running", "progress": 85, "phase": "analyze"}

        async def _heartbeat():
            """Log kalau tools diam >45 detik, supaya user tau masih jalan / macet."""
            nonlocal last_line_time
            while True:
                await asyncio.sleep(45)
                if proc.returncode is not None:
                    return
                silent = time.monotonic() - last_line_time
                if silent >= 45:
                    elapsed = int(time.monotonic() - scan_started)
                    await insert_log(db, scan_id, "warning",
                                     f"[!] Tidak ada output {int(silent)}s — tools masih berjalan (elapsed {elapsed}s), "
                                     f"cek PID {proc.pid}...")
                    last_line_time = time.monotonic()

        output_tasks = [
            asyncio.create_task(_stream_output(proc.stdout)),
            asyncio.create_task(_stream_output(proc.stderr, stderr=True)),
        ]
        heartbeat_task = asyncio.create_task(_heartbeat())
        returncode = await proc.wait()
        await asyncio.gather(*output_tasks)
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat_task

        if returncode != 0:
            await update_scan_status(db, scan_id, "failed", error="mobile_audit.py exited with code " + str(returncode))
            await insert_log(db, scan_id, "error", f"Scan failed: exit code {returncode}")
            SCAN_PROGRESS[scan_id] = {"status": "failed", "error": f"exit code {returncode}"}
            return

        await update_scan_status(db, scan_id, "running", 85, "analyze")
        SCAN_PROGRESS[scan_id] = {"status": "running", "progress": 85, "phase": "analyze"}
        await insert_log(db, scan_id, "info", "Phase: ANALYZE (parsing results)")

        findings_file = result_dir / "findings.json"
        if findings_file.exists():
            await parse_findings(db, scan_id, findings_file)
            await parse_secrets(db, scan_id, findings_file)
            await parse_endpoints(db, scan_id, findings_file)

        manifest_path = corpus_dir / "AndroidManifest.xml"
        if manifest_path.exists() and not findings_file.exists():
            await parse_manifest(db, scan_id, manifest_path)

        # Sync package_name dari manifest_info ke scans (history page)
        mf = await get_manifest(db, scan_id)
        pkg = mf["package_name"] if mf else None
        ver = (mf["version_name"] or "") if mf else None
        if pkg:
            await db.execute("UPDATE scans SET package_name=?, version=? WHERE id=?",
                             (pkg, ver, scan_id))

        await update_scan_status(db, scan_id, "running", 95, "report")
        SCAN_PROGRESS[scan_id] = {"status": "running", "progress": 95, "phase": "report"}
        await insert_log(db, scan_id, "info", "Phase: REPORT")

        await complete_scan(db, scan_id)
        await insert_log(db, scan_id, "info", "Scan completed successfully")
        SCAN_PROGRESS[scan_id] = {"status": "completed", "progress": 100}

    except asyncio.CancelledError:
        await terminate_process(proc)
        with contextlib.suppress(Exception):
            await update_scan_status(
                db, scan_id, "failed", error="Scan interrupted: server shutdown"
            )
            await insert_log(db, scan_id, "error", "Scan interrupted: server shutdown")
        SCAN_PROGRESS[scan_id] = {
            "status": "failed",
            "error": "Scan interrupted: server shutdown",
        }
        raise
    except Exception as e:
        await update_scan_status(db, scan_id, "failed", error=str(e))
        await insert_log(db, scan_id, "error", f"Exception: {str(e)}")
        SCAN_PROGRESS[scan_id] = {"status": "failed", "error": str(e)}
    finally:
        for task in output_tasks:
            if not task.done():
                task.cancel()
        if output_tasks:
            await asyncio.gather(*output_tasks, return_exceptions=True)
        if heartbeat_task and not heartbeat_task.done():
            heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat_task
        await terminate_process(proc)
        if ACTIVE_PROCESS is proc:
            ACTIVE_PROCESS = None
        await db.close()

async def parse_manifest(db, scan_id, manifest_path):
    try:
        content = manifest_path.read_text(encoding="utf-8", errors="ignore")
        package = ""
        version_name = ""
        version_code = ""
        min_sdk = ""
        target_sdk = ""

        import re
        pkg_match = re.search(r'package="([^"]+)"', content)
        if pkg_match:
            package = pkg_match.group(1)

        vname_match = re.search(r'android:versionName="([^"]+)"', content)
        if vname_match:
            version_name = vname_match.group(1)

        vcode_match = re.search(r'android:versionCode="([^"]+)"', content)
        if vcode_match:
            version_code = vcode_match.group(1)

        min_match = re.search(r'android:minSdkVersion="([^"]+)"', content)
        if min_match:
            min_sdk = min_match.group(1)

        target_match = re.search(r'android:targetSdkVersion="([^"]+)"', content)
        if target_match:
            target_sdk = target_match.group(1)

        permissions = []
        for perm_match in re.finditer(r'android\.permission\.[A-Z_]+', content):
            permissions.append(perm_match.group(0))

        deep_links = []
        for scheme_match in re.finditer(r'android:scheme="([^"]+)"', content):
            deep_links.append(scheme_match.group(1))

        await insert_manifest(db, scan_id, package, version_name, version_code,
                            min_sdk, target_sdk, json.dumps(permissions), "[]", json.dumps(deep_links))
    except Exception as e:
        await insert_log(db, scan_id, "warning", f"Manifest parse error: {e}")

async def parse_findings(db, scan_id, findings_file):
    try:
        content = findings_file.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)

        findings_list = []
        if isinstance(data, dict):
            findings_list = data.get("findings", [])
            manifest = data.get("manifest", {})
            if manifest:
                if manifest.get("platform") == "ios":
                    await insert_manifest(db, scan_id,
                        manifest.get("package", ""),
                        manifest.get("version", ""),
                        "",
                        manifest.get("min_sdk", ""),
                        "",
                        json.dumps([p.get("name") for p in manifest.get("permissions", []) if isinstance(p, dict)]),
                        json.dumps(manifest.get("components", [])),
                        json.dumps([list(dl) for dl in manifest.get("deep_links", [])]))
                else:
                    await insert_manifest(db, scan_id,
                        manifest.get("package_name", manifest.get("package", "")),
                        manifest.get("version_name", ""),
                        manifest.get("version_code", ""),
                        manifest.get("min_sdk", ""),
                        manifest.get("target_sdk", ""),
                        json.dumps(manifest.get("permissions", [])),
                        json.dumps(manifest.get("components", {})),
                        json.dumps(manifest.get("deep_links", [])))
        elif isinstance(data, list):
            findings_list = data

        for f in findings_list:
            await insert_finding(db, scan_id,
                f.get("category", "unknown"),
                f.get("severity", "info"),
                f.get("title", f.get("description", f.get("match", "")))[:200],
                f.get("description", ""),
                f.get("context", f.get("match", "")),
                f.get("file", f.get("file_path", "")),
                f.get("line"))
    except Exception as e:
        await insert_log(db, scan_id, "warning", f"Findings parse error: {e}")

async def parse_secrets(db, scan_id, secrets_file):
    try:
        if not secrets_file.exists():
            return
        content = secrets_file.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        items = data if isinstance(data, list) else data.get("secrets", data.get("findings", []))
        for s in items:
            if s.get("category") in ("Credentials", "GCP", "Firebase", "API Keys", "Crypto", "PII"):
                await insert_secret(db, scan_id,
                    s.get("rule", s.get("rule_id", "")),
                    s.get("category", "unknown"),
                    s.get("severity", "info"),
                    s.get("file", s.get("file_path", "")),
                    s.get("line", s.get("line_number")),
                    s.get("match", s.get("value", ""))[:200],
                    s.get("context", ""))
    except Exception as e:
        await insert_log(db, scan_id, "warning", f"Secrets parse error: {e}")

async def parse_endpoints(db, scan_id, endpoints_file):
    try:
        if not endpoints_file.exists():
            return
        content = endpoints_file.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        endpoints_data = data.get("endpoints", data) if isinstance(data, dict) else None

        if isinstance(endpoints_data, dict):
            hosts = endpoints_data.get("hosts", [])
            for host_info in hosts:
                if isinstance(host_info, dict):
                    host = host_info.get("host", "")
                    urls = host_info.get("urls", [])
                    paths = host_info.get("paths", [])
                    for url in urls:
                        await insert_endpoint(db, scan_id, url, host,
                            host_info.get("port"), host_info.get("scheme", "https"),
                            "", host_info.get("env", "unknown"))
            deep_links = endpoints_data.get("deep_links", [])
            for dl in deep_links:
                if isinstance(dl, dict):
                    await insert_endpoint(db, scan_id, dl.get("url", ""), "",
                        None, dl.get("scheme", ""), dl.get("path", ""), "")
                elif isinstance(dl, str):
                    await insert_endpoint(db, scan_id, dl, "", None, "", "", "")
        elif isinstance(endpoints_data, dict):
            for host, info in endpoints_data.items():
                if isinstance(info, dict):
                    for url in info.get("urls", []):
                        await insert_endpoint(db, scan_id, url, host,
                            info.get("port"), info.get("scheme"),
                            info.get("path"), info.get("env", "unknown"))
    except Exception as e:
        await insert_log(db, scan_id, "warning", f"Endpoints parse error: {e}")


def safe_upload_filename(filename):
    normalized = filename.replace("\\", "/")
    basename = Path(normalized).name
    if not basename or basename in (".", "..") or "\x00" in basename:
        raise HTTPException(400, "Invalid filename")
    return basename


def path_is_within(path, root):
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
        return True
    except ValueError:
        return False


def check_directory_writable(directory):
    directory.mkdir(parents=True, exist_ok=True)
    probe = directory / f".healthz-{uuid.uuid4().hex}"
    try:
        with open(probe, "xb") as handle:
            handle.write(b"ok")
    finally:
        with contextlib.suppress(FileNotFoundError):
            probe.unlink()


@app.get("/healthz")
async def healthz():
    checks = {"database": "ok", "uploads": "ok", "results": "ok"}
    errors = {}

    db = None
    try:
        db = await get_db()
        cursor = await db.execute("SELECT 1")
        await cursor.fetchone()
    except Exception as exc:
        checks["database"] = "error"
        errors["database"] = "unavailable"
        logger.warning("Database health check failed: %s", exc)
    finally:
        if db:
            await db.close()

    for name, directory in (("uploads", UPLOAD_DIR), ("results", RESULTS_DIR)):
        try:
            check_directory_writable(directory)
        except Exception as exc:
            checks[name] = "error"
            errors[name] = "unavailable"
            logger.warning("%s directory health check failed: %s", name, exc)

    healthy = not errors
    payload = {"status": "ok" if healthy else "error", "checks": checks}
    if errors:
        payload["errors"] = errors
    return JSONResponse(payload, status_code=200 if healthy else 503)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, page: int = 1, per_page: int = 10, search: str = "", platform: str = "all", status: str = "all"):
    db = await get_db()
    try:
        stats = await get_stats(db)
        per_page = max(5, min(per_page, 100))
        page = max(1, page)
        offset = (page - 1) * per_page

        scans, total = await query_scans(
            db,
            search=search or None,
            platform=platform or None,
            status=status or None,
            limit=per_page,
            offset=offset,
        )
        total_pages = max(1, (total + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages
            offset = (page - 1) * per_page
            scans, total = await query_scans(
                db,
                search=search or None,
                platform=platform or None,
                status=status or None,
                limit=per_page,
                offset=offset,
            )

        return templates.TemplateResponse(request, "index.html", {
            "stats": stats,
            "scans": scans,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_scans": total,
            "search": search,
            "platform": platform,
            "status": status
        })
    finally:
        await db.close()

@app.get("/api/scans")
async def api_scans(page: int = 1, per_page: int = 10, search: str = "", platform: str = "all", status: str = "all"):
    db = await get_db()
    try:
        per_page = max(5, min(per_page, 100))
        page = max(1, page)
        offset = (page - 1) * per_page

        scans, total = await query_scans(
            db,
            search=search or None,
            platform=platform or None,
            status=status or None,
            limit=per_page,
            offset=offset,
        )
        total_pages = max(1, (total + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages
            offset = (page - 1) * per_page
            scans, total = await query_scans(
                db,
                search=search or None,
                platform=platform or None,
                status=status or None,
                limit=per_page,
                offset=offset,
            )

        stats = await get_stats(db)

        return JSONResponse({
            "scans": [dict(s) for s in scans],
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "stats": stats
        })
    finally:
        await db.close()

@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(request, "upload.html")

@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...), fast: str = Form("")):
    if not file.filename:
        raise HTTPException(400, "No file selected")

    filename = safe_upload_filename(file.filename)
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if file_ext not in ["apk", "aab", "ipa", "jar", "dex", "smali", "so", "dll", "exe", "hbc", "zip", "xapk", "apks", "apkm"]:
        raise HTTPException(400, f"Unsupported file type: .{file_ext}")

    scan_id = uuid.uuid4().hex
    upload_path = UPLOAD_DIR / f"{scan_id}_{filename}"
    file_size = 0
    file_created = False
    stored = False
    fast_mode = fast.lower() in ("1", "true", "yes", "on")

    try:
        with open(upload_path, "xb") as output:
            file_created = True
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                file_size += len(chunk)
                if file_size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        413,
                        f"Upload exceeds maximum size of {MAX_UPLOAD_BYTES} bytes",
                    )
                output.write(chunk)

        file_type, platform = classify_file(filename)
        db = await get_db()
        try:
            db_id = await insert_scan(
                db, filename, str(upload_path), file_size, file_type, platform,
                fast_mode=fast_mode,
            )
            stored = True
        finally:
            await db.close()
    finally:
        await file.close()
        if file_created and not stored:
            with contextlib.suppress(FileNotFoundError):
                upload_path.unlink()

    return JSONResponse({"scan_id": db_id, "status": "pending", "filename": filename, "fast": fast_mode})

@app.post("/api/scan/{scan_id}/start")
async def start_scan(scan_id: int):
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        if scan["status"] != "pending":
            raise HTTPException(400, f"Scan status is {scan['status']}, only pending scans can be started")
        if not await request_scan(db, scan_id):
            raise HTTPException(409, "Scan was already requested")
        if QUEUE_WAKEUP:
            QUEUE_WAKEUP.set()
        return JSONResponse({"status": "started", "queue_status": "queued"})
    finally:
        await db.close()

@app.get("/scan/{scan_id}")
async def scan_page(request: Request, scan_id: int):
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        logs = await get_logs(db, scan_id)
        scan_view = dict(scan)
        if scan_view["status"] == "queued":
            scan_view["status"] = "running"
            scan_view["phase"] = "queued"
        return templates.TemplateResponse(
            request, "scan.html", {"scan": scan_view, "logs": logs}
        )
    finally:
        await db.close()

@app.get("/api/scan/{scan_id}/status")
async def scan_status(scan_id: int):
    progress = SCAN_PROGRESS.get(scan_id, {"status": "unknown", "progress": 0})
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if scan:
            progress["status"] = scan["status"]
            progress["progress"] = scan["progress"]
            progress["phase"] = scan["phase"]
        return JSONResponse(progress)
    finally:
        await db.close()

@app.get("/api/scan/{scan_id}/logs")
async def scan_logs_api(scan_id: int, after: int = 0):
    db = await get_db()
    try:
        logs = await get_logs(db, scan_id, after=after)
        return JSONResponse({"logs": [dict(l) for l in logs]})
    finally:
        await db.close()

@app.get("/results/{scan_id}")
async def results_page(request: Request, scan_id: int):
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")

        report_html = ""
        result_dir = RESULTS_DIR / str(scan_id)
        report_file = result_dir / "report.md"
        if report_file.exists():
            report_content = report_file.read_text(encoding="utf-8", errors="ignore")
            # Sembunyikan full Windows path -> path relatif corpus app
            corpus_full = str(result_dir / "work" / "corpus")
            report_content = report_content.replace(corpus_full, "")
            report_content = report_content.replace(corpus_full.replace("\\", "/"), "")
            report_html = md_lib.markdown(report_content, extensions=["tables", "fenced_code"])
            report_html = enhance_report_html(report_html, scan_id)

        logs = await get_logs(db, scan_id)

        return templates.TemplateResponse(request, "results.html", {
            "scan": scan,
            "report_html": report_html,
            "logs": logs
        })
    finally:
        await db.close()

@app.get("/report/{scan_id}")
async def download_report(scan_id: int):
    result_dir = RESULTS_DIR / str(scan_id)
    report_file = result_dir / "report.md"
    if not report_file.exists():
        raise HTTPException(404, "Report not found")
    content = report_file.read_text(encoding="utf-8", errors="ignore")
    return PlainTextResponse(content, headers={
        "Content-Disposition": f'attachment; filename="report_{scan_id}.md"'
    })

@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    db = await get_db()
    try:
        scans = await get_scans(db, limit=100)
        stats = await get_stats(db)
        return templates.TemplateResponse(request, "history.html", {
            "scans": scans,
            "stats": stats
        })
    finally:
        await db.close()

@app.get("/api/history")
async def api_history():
    db = await get_db()
    try:
        scans = await get_scans(db, limit=100)
        return JSONResponse([dict(s) for s in scans])
    finally:
        await db.close()

def extract_report_metadata(report_file: Path) -> dict:
    meta = {}
    if not report_file.exists():
        return meta
    content = report_file.read_text(encoding="utf-8", errors="ignore")
    
    patterns = {
        "target": r"- Target:\s*`?([^`\r\n]+)`?",
        "file_type": r"- Tipe:\s*`?([^`\r\n]+)`?",
        "framework": r"- Framework:\s*([^\r\n]+)",
        "detection": r"- Deteksi:\s*([^\r\n]+)",
        "scan_stats": r"- File discan:\s*(\d+),\s*baris:\s*(\d+)",
        "package_name": r"- PACKAGE:\s*`?([^`\r\n]+)`?",
        "sha256": r"- SHA-256:\s*`?([^`\r\n]+)`?",
        "tech_stack": r"- TECH STACK:\s*([^\r\n]+)",
        "source": r"- SOURCE:\s*([^\r\n]+)",
        "split_apks": r"- SPLIT APKS:\s*([^\r\n]+)",
        "rasp": r"- RASP:\s*([^\r\n]+)"
    }
    
    for key, pat in patterns.items():
        m = re.search(pat, content, re.I)
        if m:
            if key == "scan_stats":
                meta["files_scanned"] = int(m.group(1))
                meta["lines_scanned"] = int(m.group(2))
            else:
                meta[key] = m.group(1).strip()
    return meta


def build_pocs_payload(scan_obj: dict, manifest_obj: dict, corpus_dir: Path) -> dict:
    """CPU and filesystem-heavy PoC extraction moved off event-loop thread."""
    poc_engine = PoCEngine(corpus_dir=corpus_dir if corpus_dir and corpus_dir.exists() else None)
    pkg_name = (manifest_obj or {}).get("package_name") or scan_obj.get("package_name") or "com.target.app"

    comps_raw = []
    deeplinks_raw = []
    if manifest_obj:
        try:
            comps_raw = json.loads(manifest_obj.get("components") or "[]")
        except Exception:
            comps_raw = []
        try:
            deeplinks_raw = json.loads(manifest_obj.get("deep_links") or "[]")
        except Exception:
            deeplinks_raw = []

    component_pocs = []
    if isinstance(comps_raw, list):
        for c in comps_raw:
            if isinstance(c, dict) and (c.get("exported") in (True, "true", "True")):
                component_pocs.append(poc_engine.generate_component_poc(pkg_name, c))

    deeplink_pocs = []
    for dl in deeplinks_raw:
        dl_str = dl if isinstance(dl, str) else ("://".join(dl) if isinstance(dl, list) else str(dl))
        deeplink_pocs.append(poc_engine.generate_deeplink_poc(pkg_name, dl_str))

    return {
        "package_name": pkg_name,
        "component_pocs": component_pocs,
        "deeplink_pocs": deeplink_pocs,
        "total_pocs": len(component_pocs) + len(deeplink_pocs),
    }


@app.get("/api/scan/{scan_id}")
async def api_scan_detail(scan_id: int):
    """Return scan details + manifest_info, findings summary, secrets summary, report metadata."""
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        manifest = await get_manifest(db, scan_id)
        findings = await get_findings(db, scan_id)
        secrets = await get_secrets(db, scan_id)
        result = dict(scan)
        result["manifest_info"] = dict(manifest) if manifest else {}
        result["findings"] = [dict(f) for f in findings]
        result["secrets"] = [dict(s) for s in secrets]
        
        # Extract rich metadata from report.md
        report_file = RESULTS_DIR / str(scan_id) / "report.md"
        result["meta"] = extract_report_metadata(report_file)
        return JSONResponse(result)
    finally:
        await db.close()


@app.get("/api/scan/{scan_id}/findings")
async def api_findings(scan_id: int, severity: str = None):
    db = await get_db()
    try:
        findings = await get_findings(db, scan_id, severity)
        return JSONResponse([dict(f) for f in findings])
    finally:
        await db.close()

@app.get("/api/scan/{scan_id}/secrets")
async def api_secrets(scan_id: int, severity: str = None):
    db = await get_db()
    try:
        secrets = await get_secrets(db, scan_id, severity)
        return JSONResponse([dict(s) for s in secrets])
    finally:
        await db.close()

@app.get("/api/scan/{scan_id}/endpoints")
async def api_endpoints(scan_id: int):
    db = await get_db()
    try:
        endpoints = await get_endpoints(db, scan_id)
        return JSONResponse([dict(e) for e in endpoints])
    finally:
        await db.close()

@app.get("/api/scan/{scan_id}/rule/{rule_id}")
async def api_rule_findings(scan_id: int, rule_id: str):
    """Semua temuan untuk satu rule (dari findings.json), path relatif corpus."""
    result_dir = RESULTS_DIR / str(scan_id)
    fj = result_dir / "findings.json"
    if not fj.exists():
        raise HTTPException(404, "findings.json not found")
    try:
        data = json.loads(fj.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(500, "findings.json corrupt")
    fs = [f for f in data.get("findings", []) if f.get("rule") == rule_id]
    for f in fs:
        f["file"] = corpus_rel_path(f.get("file", ""), scan_id)
        f["match"] = (f.get("match") or "")[:200]
        f["context"] = (f.get("context") or "")[:300]
    return JSONResponse({"rule": rule_id, "total": len(fs), "findings": fs})

@app.get("/api/scan/{scan_id}/source-context")
async def api_source_context(scan_id: int, file: str = "", line: int = 0, match: str = "", radius: int = 5):
    """Return ±radius lines around the given line number from a corpus file.
    'file' can be a relative path (from corpus root) or absolute path.
    Falls back to searching in results/findings.json context field."""
    result_dir = RESULTS_DIR / str(scan_id)
    corpus_root = result_dir / "work" / "corpus"

    # Resolve file path
    candidate = Path(file.lstrip("/\\"))
    abs_paths = [
        corpus_root / candidate,
        Path(file) if Path(file).is_absolute() else None,
    ]
    found_path = None
    for p in abs_paths:
        if p and p.exists() and p.is_file():
            found_path = p
            break

    if found_path and line > 0:
        try:
            all_lines = found_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            start = max(0, line - radius - 1)
            end = min(len(all_lines), line + radius)
            result_lines = [{"no": start + i + 1, "text": all_lines[start + i]} for i in range(end - start)]
            return JSONResponse({"lines": result_lines, "target_line": line, "file": str(found_path)})
        except Exception as e:
            pass

    # Fallback: search findings.json for context of this file+line
    fj = result_dir / "findings.json"
    if fj.exists():
        try:
            data = json.loads(fj.read_text(encoding="utf-8", errors="ignore"))
            findings = data.get("findings", []) if isinstance(data, dict) else []
            secrets = data.get("secrets", findings)
            for s in (findings + secrets):
                fpath = s.get("file", s.get("file_path", ""))
                fline = s.get("line", s.get("line_number"))
                ctx = s.get("context", "")
                if ctx and (file in fpath or fpath in file) and (not line or str(fline) == str(line)):
                    lines = ctx.splitlines()
                    base = (line or 1) - len(lines) // 2
                    result_lines = [{"no": max(1, base + i), "text": l} for i, l in enumerate(lines)]
                    return JSONResponse({"lines": result_lines, "target_line": line or base + len(lines)//2, "file": fpath})
        except Exception:
            pass

    return JSONResponse({"lines": [], "target_line": line, "file": file})


@app.get("/api/scan/{scan_id}/verify-cache")
async def api_get_verify_cache(scan_id: int):
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")

        rows = await get_verification_cache(db, scan_id)
        out = {}
        for row in rows:
            modal_raw = row["modal_json"] or "{}"
            try:
                modal_obj = json.loads(modal_raw)
            except Exception:
                modal_obj = {}

            out[row["row_id"]] = {
                "module": row["module"],
                "target": row["target"],
                "button_text": row["button_text"],
                "result_html": row["result_html"],
                "modal": modal_obj,
                "updated_at": row["updated_at"],
            }
        return JSONResponse({"scan_id": scan_id, "cache": out})
    finally:
        await db.close()


@app.post("/api/scan/{scan_id}/verify-cache")
async def api_upsert_verify_cache(scan_id: int, request: Request):
    payload = await request.json()
    row_id = (payload.get("row_id") or "").strip()
    if not row_id:
        raise HTTPException(400, "row_id is required")

    modal_obj = payload.get("modal") or {}
    if not isinstance(modal_obj, dict):
        modal_obj = {}

    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")

        await upsert_verification_cache(
            db=db,
            scan_id=scan_id,
            row_id=row_id,
            module=(payload.get("module") or "").strip(),
            target=(payload.get("target") or "").strip(),
            button_text=(payload.get("button_text") or "").strip(),
            result_html=payload.get("result_html") or "",
            modal_json=json.dumps(modal_obj),
        )
        return JSONResponse({"status": "ok", "row_id": row_id})
    finally:
        await db.close()


@app.post("/api/scan/{scan_id}/verify/firebase")
async def api_verify_firebase(scan_id: int, request: Request):
    data = await request.json()
    url = data.get("url", "")
    if not url:
        raise HTTPException(400, "URL is required")
    result = await asyncio.to_thread(check_firebase_crud, url)
    return JSONResponse(result)


@app.post("/api/scan/{scan_id}/verify/ip")
async def api_verify_ip(scan_id: int, request: Request):
    data = await request.json()
    ip = data.get("ip", "")
    if not ip:
        raise HTTPException(400, "IP address is required")
    result = await asyncio.to_thread(check_ip_details, ip)
    return JSONResponse(result)


@app.post("/api/scan/{scan_id}/verify/google-api")
async def api_verify_google_api(scan_id: int, request: Request):
    data = await request.json()
    key = data.get("key", "")
    if not key:
        raise HTTPException(400, "API key is required")
    result = await asyncio.to_thread(check_google_api_key, key)
    return JSONResponse(result)


@app.post("/api/scan/{scan_id}/verify/endpoint")
async def api_verify_endpoint(scan_id: int, request: Request):
    data = await request.json()
    url = data.get("url", "")
    if not url:
        raise HTTPException(400, "URL is required")
    result = await asyncio.to_thread(check_generic_endpoint, url)
    return JSONResponse(result)


@app.post("/api/scan/{scan_id}/verify/aws")
async def api_verify_aws(scan_id: int, request: Request):
    data = await request.json()
    ak = data.get("access_key", "")
    sk = data.get("secret_key", "")
    token = data.get("session_token", "")
    if not ak:
        raise HTTPException(400, "Access Key is required")
    result = await asyncio.to_thread(check_aws_sts_identity, ak, sk, token)
    return JSONResponse(result)


@app.post("/api/scan/{scan_id}/verify/stripe")
async def api_verify_stripe(scan_id: int, request: Request):
    data = await request.json()
    key = data.get("key", "")
    if not key:
        raise HTTPException(400, "Stripe Key is required")
    result = await asyncio.to_thread(check_stripe_key, key)
    return JSONResponse(result)


@app.post("/api/scan/{scan_id}/verify/webhook")
async def api_verify_webhook(scan_id: int, request: Request):
    data = await request.json()
    url = data.get("url", "")
    if not url:
        raise HTTPException(400, "Webhook URL is required")
    result = await asyncio.to_thread(check_webhook_status, url)
    return JSONResponse(result)


@app.get("/api/scan/{scan_id}/pocs")
async def api_get_pocs(scan_id: int, force: int = 0, lazy: int = 0):
    """Generate comprehensive deterministic PoCs (ADB Intent extras, DeepLinks, HTML, Python)."""
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")

        if force != 1:
            cached = await get_poc_cache(db, scan_id)
            if cached and cached["payload_json"]:
                try:
                    payload = json.loads(cached["payload_json"])
                    payload["from_cache"] = True
                    payload["cached_at"] = cached["updated_at"]
                    return JSONResponse(payload)
                except Exception:
                    pass

        if lazy == 1 and force != 1:
            return JSONResponse({
                "package_name": scan["package_name"] or "com.target.app",
                "component_pocs": [],
                "deeplink_pocs": [],
                "total_pocs": 0,
                "from_cache": False,
                "needs_generation": True,
            })

        manifest = await get_manifest(db, scan_id)

        result_dir = RESULTS_DIR / str(scan_id)
        corpus_dir = result_dir / "work" / "corpus"
        scan_obj = dict(scan)
        manifest_obj = dict(manifest) if manifest else {}
        payload = await asyncio.to_thread(build_pocs_payload, scan_obj, manifest_obj, corpus_dir)
        await upsert_poc_cache(db, scan_id, json.dumps(payload))
        payload["from_cache"] = False
        return JSONResponse(payload)
    finally:
        await db.close()


@app.get("/api/scan/{scan_id}/frida-script")
async def api_get_frida_script(scan_id: int):
    """Generate comprehensive Frida hook bypass script for this scanned target."""
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        manifest = await get_manifest(db, scan_id)
        findings = await get_findings(db, scan_id)
        
        pkg_name = (manifest and manifest["package_name"]) or scan["package_name"] or "com.target.app"
        rasp_info = scan["rasp"] or "" if "rasp" in scan.keys() else ""
        
        poc_engine = PoCEngine()
        frida_code = poc_engine.generate_frida_bypass_script(pkg_name, [dict(f) for f in findings], rasp_info)
        
        return PlainTextResponse(frida_code, headers={
            "Content-Disposition": f'attachment; filename="bypass_hooks_{scan_id}.js"'
        })
    finally:
        await db.close()


@app.get("/api/scan/{scan_id}/hosts")
async def api_all_hosts(scan_id: int):
    """Semua host endpoint (non-truncated), path relatif corpus."""
    result_dir = RESULTS_DIR / str(scan_id)
    fj = result_dir / "findings.json"
    if not fj.exists():
        raise HTTPException(404, "findings.json not found")
    try:
        data = json.loads(fj.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(500, "findings.json corrupt")
    ep = data.get("endpoints") or {}
    hosts = ep.get("hosts") or []
    for h in hosts:
        h["files"] = [corpus_rel_path(f, scan_id) for f in h.get("files", [])]
        h["paths"] = h.get("paths") or []
    return JSONResponse({"total": len(hosts), "hosts": hosts})

@app.delete("/api/scan/{scan_id}")
async def api_delete_scan(scan_id: int):
    db = await get_db()
    try:
        scan = await get_scan(db, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        upload_path = Path(scan["file_path"])
        if path_is_within(upload_path, UPLOAD_DIR):
            with contextlib.suppress(FileNotFoundError):
                upload_path.unlink()
        else:
            raise HTTPException(500, "Stored upload path is outside upload directory")

        scan_dir = RESULTS_DIR / str(scan_id)
        if not path_is_within(scan_dir, RESULTS_DIR):
            raise HTTPException(500, "Stored result path is outside result directory")
        if scan_dir.exists():
            shutil.rmtree(scan_dir)
        await delete_scan(db, scan_id)
        return JSONResponse({"status": "deleted"})
    finally:
        await db.close()

@app.get("/api/search")
async def api_search(q: str = ""):
    if not q:
        return JSONResponse([])
    db = await get_db()
    try:
        results = await search_findings(db, q)
        return JSONResponse([dict(r) for r in results])
    finally:
        await db.close()

@app.get("/compare", response_class=HTMLResponse)
async def compare_page(request: Request):
    db = await get_db()
    try:
        scans = await get_scans(db, limit=100)
        return templates.TemplateResponse(request, "compare.html", {
            "scans": scans
        })
    finally:
        await db.close()

@app.get("/api/compare/{scan_id_1}/{scan_id_2}")
async def api_compare(scan_id_1: int, scan_id_2: int):
    db = await get_db()
    try:
        scan1 = await get_scan(db, scan_id_1)
        scan2 = await get_scan(db, scan_id_2)
        if not scan1 or not scan2:
            raise HTTPException(404, "One or both scans not found")

        findings1 = await get_findings(db, scan_id_1)
        findings2 = await get_findings(db, scan_id_2)

        secrets1 = await get_secrets(db, scan_id_1)
        secrets2 = await get_secrets(db, scan_id_2)

        endpoints1 = await get_endpoints(db, scan_id_1)
        endpoints2 = await get_endpoints(db, scan_id_2)

        return JSONResponse({
            "scan1": dict(scan1),
            "scan2": dict(scan2),
            "findings1": [dict(f) for f in findings1],
            "findings2": [dict(f) for f in findings2],
            "secrets1": [dict(s) for s in secrets1],
            "secrets2": [dict(s) for s in secrets2],
            "endpoints1": [dict(e) for e in endpoints1],
            "endpoints2": [dict(e) for e in endpoints2]
        })
    finally:
        await db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8089)

# Mobile Audit Tool v1

Automated mobile reverse engineering and secret scanning toolkit with a web GUI.

This project has two main parts:

- CLI orchestrator: `mobile_audit.py`
- Web UI + API: `web/app.py`

## Prerequisites

- Windows x64 (bundled tools are Windows binaries/scripts).
- Python 3.11+ for web and core scan pipeline.
- Optional Python 3.13 for APKiD fingerprint enrichment (`TECH STACK`).
- Java runtime is bundled in this repo at `bin/jre` (no separate Java install required).

Optional environment overrides:

- `MOBILE_AUDIT_JAVA` -> explicit path to `java.exe` to override bundled runtime.
- `MOBILE_AUDIT_PY313` -> explicit path to Python 3.13 executable for APKiD.

## Core Features (v1)

- Multi-format target support: APK, AAB, XAPK, IPA, JAR, DEX, SO, DLL, EXE, HBC, directory.
- Pipeline: Identify -> Unpack -> Scan -> Report.
- Secret detection with regex rules database (`rules/secrets.json`).
- Endpoint and manifest extraction.
- Web dashboard with scan history, filters, and pagination.
- Live Verifier modules (Firebase, Google API key scopes, endpoint, IP, AWS, Stripe, webhook).
- PoC + Frida generation from findings.
- Persistence cache:
  - verifier result cache (`verification_cache`)
  - PoC cache (`poc_cache`)

## Quick Start

### 1) Install Python dependencies

```bash
pip install -r web/requirements.txt
```

### 2) Initialize database (optional)

```bash
python web/init_db.py
```

Catatan: `web/app.py` juga otomatis inisialisasi database saat startup.

### 3) Run web server

```bash
python web/app.py
```

Open: `http://127.0.0.1:8089`

### 4) CLI usage (optional)

```bash
python mobile_audit.py <target_file_or_dir>
```

### 5) Quick runtime check (recommended)

```bash
bin\jre\bin\java.exe -version
```

Jika command di atas gagal, clone repo kemungkinan tidak lengkap.

## Project Layout

```text
mobile/
|- mobile_audit.py
|- secret_scanner.py
|- engines/
|- rules/
|- web/
|  |- app.py
|  |- database/db.py
|  |- templates/
|  |- static/
|  `- requirements.txt
`- reports/ (local runtime output)
```

## Release v1 Notes

- PoC generation now supports cache-first loading and manual regenerate.
- Live Verifier results are persisted and restored after tab switch/reopen.
- Fast mode policy:
  - ON: skip JADX + skip Blutter
  - OFF: try full analysis (Blutter fallback if unavailable)

## Important Security and Privacy Notes

- Do not commit scan artifacts from real client binaries.
- Keep `web/uploads/`, `web/results/`, and `web/database/mobile_audit.db` out of Git.
- Review `LAUNCH_V1_GITHUB_GUIDE.md` before first public push.

## Troubleshooting

- Scan Android langsung `failed`:
  - Pastikan `bin/jre/bin/java.exe` ada.
  - Jalankan `bin\\jre\\bin\\java.exe -version`.
- `TECH STACK` atau APKiD kosong/skip:
  - Install Python 3.13, atau set `MOBILE_AUDIT_PY313` ke path Python 3.13.
- Port `8089` bentrok:
  - Ubah port di `web/app.py` pada `uvicorn.run(...)`.

## Additional Docs

- Full technical docs: `DOKUMENTASI_MOBILE_AUDIT.md`
- Web module docs: `web/README.md`
- Launch checklist and upload scope: `LAUNCH_V1_GITHUB_GUIDE.md`
- Changelog: `CHANGELOG.md`

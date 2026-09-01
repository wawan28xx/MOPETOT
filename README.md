# Mobile Audit Tool v1

Automated mobile reverse engineering and secret scanning toolkit with a web GUI.

This project has two main parts:

- CLI orchestrator: `mobile_audit.py`
- Web UI + API: `web/app.py`

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
cd web
pip install -r requirements.txt
```

### 2) Initialize database

```bash
python init_db.py
```

### 3) Run web server

```bash
python app.py
```

Open: `http://127.0.0.1:8089`

### 4) CLI usage (optional)

```bash
python mobile_audit.py <target_file_or_dir>
```

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

## Additional Docs

- Full technical docs: `DOKUMENTASI_MOBILE_AUDIT.md`
- Web module docs: `web/README.md`
- Launch checklist and upload scope: `LAUNCH_V1_GITHUB_GUIDE.md`
- Changelog: `CHANGELOG.md`

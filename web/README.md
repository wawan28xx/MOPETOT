# Mobile Audit Tool — Web GUI

Web-based interface untuk mobile application security audit. Upload APK/IPA, auto-scan, lihat hasil dalam dashboard.

## Quick Start

### 1. Install Dependencies

```bash
cd C:\platform-tools\AGENT\tools\mobile\web
pip install -r requirements.txt
```

### 2. Start Server

**Windows (double-click):**
```
run.bat
```

**Command line:**
```bash
python app.py
```

**Background (silent):**
```bash
cscript //nologo run_silent.vbs
```

### 3. Buka Browser

```
http://localhost:8089
```

### 4. Stop Server

```bash
taskkill /f /im python.exe
```

---

## Fitur

### Dashboard (`/`)
- Ringkasan statistik: total scan, completed, running, failed
- List 10 scan terakhir dengan status
- Quick link ke Upload

### Upload (`/upload`)
- Drag-and-drop atau click untuk pilih file
- **Fast mode** (checkbox, default ON): skip jadx decompile — scan smali + assets + strings langsung. 3-5x lebih cepat, hasil secret/endpoint tetap lengkap (jadx mode hanya menambah Java-source readability, bukan temuan baru)
- Supported formats:
  | Format | Platform |
  |--------|----------|
  | `.apk`, `.aab`, `.xapk` | Android |
  | `.ipa` | iOS |
  | `.jar` | Java |
  | `.dex`, `.smali` | Android bytecode |
  | `.so` | Native ELF |
  | `.dll`, `.exe` | .NET/PE |
  | `.hbc` | Hermes bytecode |
  | `.zip` | Generic |
- Auto-detect platform dan file type
- Upload progress bar
- Auto-redirect ke scan progress setelah upload

### Scan Progress (`/scan/{id}`)
- Real-time progress polling (setiap 2 detik)
- Phase indicator dari log scan: init → unpack → scan → analyze → report → completed
- Live log viewer
- Auto-redirect ke results saat selesai

### Results (`/results/{id}`)
Tab-based viewer:

**Tab Findings:**
- Severity (critical/high/medium/low/info)
- Category, title, file, line number
- Sortable by severity

**Tab Secrets:**
- Extracted credentials, API keys, tokens
- File location dan line number
- Truncated match value (click to expand)

**Tab Endpoints:**
- All discovered URLs/domains
- Environment classification (production/dev/staging)
- Host, path, scheme

**Tab Manifest:**
- Package name, version, SDK versions
- Permissions list
- Deep links / URL schemes

**Tab Logs:**
- Full scan execution log
- Timestamped entries

### History (`/history`)
- Full list semua scan
- Status indicator per scan
- Delete scan (with confirmation)
- Stats summary

### Compare (`/compare`)
- Pilih 2 scan untuk dibandingkan
- Side-by-side: findings, secrets, endpoints
- Diff view: menunjukkan findings yang hanya ada di salah satu scan
- Berguna untuk: Android vs iOS, versi lama vs baru

### Search
- Global search bar di navbar
- Search across all findings
- HTMX-powered instant results

---

## Cara Kerja

### Pipeline

```
Upload APK/IPA
      │
      ▼
┌─────────────┐
│  IDENTIFY   │  Classify file type, detect platform
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   UNPACK    │  Extract archive, run jadx/apktool/blutter/etc
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    SCAN     │  Run secret_scanner.py (87 regex rules)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   ANALYZE   │  Parse manifest, findings, secrets, endpoints
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   REPORT    │  Store results in SQLite, serve via web
└─────────────┘
```

### Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.14 + FastAPI |
| Frontend | Jinja2 templates + HTMX |
| Database | SQLite (aiosqlite) |
| Styling | Custom CSS (dark theme) |
| Real-time | HTTP polling (HTMX) |
| Scan engine | mobile_audit.py (existing CLI tool) |
| Secret detection | secret_scanner.py (87 regex rules) |

### Database Schema

```
scans
├── id (PK)
├── filename, file_path, file_size
├── file_type, platform
├── package_name, version
├── status (pending/running/completed/failed)
├── progress (0-100)
├── phase, error
└── created_at, started_at, completed_at

findings
├── id (PK), scan_id (FK)
├── category, severity, title
├── description, evidence
└── file_path, line_number

secrets
├── id (PK), scan_id (FK)
├── rule_id, category, severity
├── file_path, line_number
└── match, context

endpoints
├── id (PK), scan_id (FK)
├── url, host, port, scheme
├── path, env, method
└── depth

verification_cache
├── id (PK), scan_id (FK)
├── row_id (unique per scan)
├── module, target
├── button_text, result_html
├── modal_json
└── updated_at

poc_cache
├── id (PK), scan_id (FK unique)
├── payload_json
└── updated_at

manifest_info
├── id (PK), scan_id (FK)
├── package_name, version_name, version_code
├── min_sdk, target_sdk
├── permissions (JSON), components (JSON)
└── deep_links (JSON)
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| GET | `/upload` | Upload page |
| POST | `/upload` | Upload file & start scan |
| GET | `/scan/{id}` | Scan progress page |
| GET | `/results/{id}` | Results page |
| GET | `/history` | History page |
| GET | `/compare` | Compare page |
| GET | `/api/scan/{id}/status` | Scan status (JSON) |
| GET | `/api/scan/{id}/verify-cache` | Live verifier cached results |
| POST | `/api/scan/{id}/verify-cache` | Save/update verifier row cache |
| GET | `/api/scan/{id}/pocs?lazy=1` | Cache-first PoC fetch (non-blocking) |
| GET | `/api/scan/{id}/pocs?force=1` | Force regenerate PoC payload |
| GET | `/api/scan/{id}/findings` | Findings (JSON) |
| GET | `/api/scan/{id}/secrets` | Secrets (JSON) |
| GET | `/api/scan/{id}/endpoints` | Endpoints (JSON) |
| GET | `/api/history` | All scans (JSON) |
| GET | `/api/search?q=` | Search findings |
| GET | `/api/compare/{id1}/{id2}` | Compare 2 scans |
| DELETE | `/api/scan/{id}` | Delete scan |

---

## File Structure

```
tools/mobile/web/
├── app.py                  # FastAPI application
├── run.bat                 # Windows launcher
├── run_silent.vbs          # Silent background launcher
├── requirements.txt        # Python dependencies
│
├── database/
│   └── db.py              # Database models & queries
│   └── mobile_audit.db    # SQLite database (auto-created)
│
├── templates/
│   ├── base.html           # Base template (navbar, footer)
│   ├── index.html          # Dashboard
│   ├── upload.html         # Upload page
│   ├── scan.html           # Scan progress
│   ├── results.html        # Results viewer
│   ├── history.html        # Scan history
│   └── compare.html        # Compare scans
│
├── static/
│   ├── css/style.css       # Dark theme CSS
│   └── js/app.js           # Frontend utilities
│
├── uploads/                # Uploaded APK/IPA files
└── results/                # Scan results per scan ID
    └── {id}/
        ├── corpus/         # Extracted files
        ├── findings.json
        ├── secrets.json
        └── endpoints.json
```

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+U` | Go to Upload |
| `/` | Focus search bar |

---

## Configuration

Default port: **8089**

Untuk mengganti port, edit `app.py` baris terakhir:
```python
uvicorn.run(app, host="0.0.0.0", port=8089)  # change port here
```

---

## Troubleshooting

**Port sudah dipakai:**
```bash
netstat -ano | findstr ":8089"
taskkill /f /pid {PID}
```

**Database corrupt:**
```bash
del database\mobile_audit.db
# Restart server, DB will be recreated
```

**Dependencies missing:**
```bash
pip install -r requirements.txt
```

**Upload gagal / scan timeout:**
- File terlalu besar (>200MB) — belum didukung
- mobile_audit.py error — cek tab Logs di results page

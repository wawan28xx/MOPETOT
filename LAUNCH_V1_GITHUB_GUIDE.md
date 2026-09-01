# Launch v1 - GitHub Upload Guide

Panduan ini untuk menyiapkan repo publik/private GitHub dengan aman sebelum launching v1.

## 1. Tujuan

- Memastikan hanya source code dan dokumentasi yang naik ke GitHub.
- Mencegah kebocoran sample APK/IPA, hasil scan, atau kredensial.
- Menyiapkan struktur release yang rapi untuk v1.

## 2. Yang Wajib Di-upload

### Root

- `README.md`
- `CHANGELOG.md`
- `LAUNCH_V1_GITHUB_GUIDE.md`
- `DOKUMENTASI_MOBILE_AUDIT.md`
- `mobile_audit.py`
- `secret_scanner.py`
- `apkid_wrapper.py`
- `.gitignore`
- `rules/secrets.json`

### Engines

- `engines/*.py`

### Web App

- `web/app.py`
- `web/poc_engine.py`
- `web/verification.py`
- `web/requirements.txt`
- `web/init_db.py`
- `web/README.md`
- `web/templates/*.html`
- `web/static/css/style.css`
- `web/database/db.py`

## 3. Yang Jangan Di-upload

### Runtime and Sensitive Data

- `web/uploads/`
- `web/results/`
- `reports/`
- `web/database/mobile_audit.db`
- `*.log`, `web/server.log`

### Caches

- `__pycache__/`
- `*.pyc`

### Bundled Heavy Binary Toolchains (untuk source release v1)

- `bin/ghidra_12.1.2_PUBLIC/`
- `bin/dotnet-sdk/`
- `bin/radare2/`
- `bin/jadx/`
- `bin/vcpkg/`
- `bin/icu/`
- `bin/blutter_out/`
- `bin/blutter_src/build/`

Catatan: `bin/apktool.jar` boleh dipisah jadi langkah install manual agar repo ringan.

## 4. Checklist Pre-Push

Jalankan dari folder `tools/mobile`:

```bash
python -m py_compile mobile_audit.py secret_scanner.py web/app.py web/database/db.py web/poc_engine.py web/verification.py
```

Lalu cek file yang akan di-commit:

```bash
git status
git add .
git status
```

Review staged diff:

```bash
git diff --staged
```

Pastikan tidak ada path berikut di staged:

- `web/uploads/*`
- `web/results/*`
- `reports/*`
- `web/database/mobile_audit.db`
- file `.apk`, `.ipa`, `.aab`, `.xapk`, `.apks`

## 5. Suggested First Tags

- Tag: `v1.0.0`
- Title: `Mobile Audit Tool v1.0.0`
- Description ringkas:
  - Initial release
  - Web GUI + Live Verifier
  - PoC and Frida generator
  - Verifier and PoC caching

## 6. Suggested Release Structure

Untuk rilis berikutnya:

- `v1.0.x` = bugfix/stability
- `v1.1.x` = minor features (AI assist optional, richer analyzers)
- `v2.0.0` = breaking changes arsitektur/API

## 7. Operational Notes

- Setelah clone fresh, jalankan `python web/init_db.py` sebelum `python web/app.py`.
- Untuk environment production internal, pertimbangkan:
  - reverse proxy
  - auth layer
  - database backup policy
  - folder isolation for uploads/results

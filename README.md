# MOPENOT — Mobile Audit Tool

MOPENOT adalah toolkit reverse-engineering dan secret scanning untuk aplikasi mobile serta binary terkait. Proyek ini menyediakan dua entry point:

- `mobile_audit.py`: CLI untuk menjalankan pipeline audit dan menghasilkan laporan JSON/HTML.
- `web/app.py`: dashboard FastAPI untuk upload target, memantau scan, melihat temuan, dan menjalankan verifier.

## Fitur utama

- Mendukung APK, AAB, XAPK/APKS/APKM, IPA, JAR, DEX/SMALI, SO, DLL/EXE, HBC, ZIP, dan direktori hasil ekstraksi.
- Pipeline empat tahap: **Identify → Unpack → Scan → Report**.
- Secret scanning berbasis regex dari `rules/secrets.json`.
- Ekstraksi endpoint, manifest, framework, metadata SHA-256, tech stack, dan indikasi RASP.
- Dashboard dengan riwayat scan, filter, pagination, perbandingan dua scan, log realtime, serta pembuatan PoC.
- Verifier untuk Firebase, Google API key, endpoint, IP, AWS STS, Stripe, dan webhook.
- Cache SQLite untuk hasil verifier dan PoC.

## Persyaratan

Untuk menjalankan seluruh kode proyek, gunakan Python **3.13 atau lebih baru**. Versi ini diperlukan oleh sintaks Python yang dipakai engine native dan juga mendukung jalur APKiD opsional.

Kebutuhan tambahan:

- Java 17 atau lebih baru untuk APKTool dan proses berbasis Java.
- Windows x64: beberapa binary bundled di `bin/` adalah tool Windows dan memberi dukungan analisis paling lengkap.
- Linux/Docker: aplikasi web tetap dapat berjalan; tool Windows-only dapat dilewati dan engine menggunakan fallback yang tersedia.

Variabel lingkungan opsional:

- `MOBILE_AUDIT_JAVA`: path executable Java yang ingin digunakan.
- `MOBILE_AUDIT_PY313`: path Python 3.13 untuk enrichment APKiD.

## Instalasi lokal

```bash
python3.13 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r web/requirements.txt
```

Database akan dibuat otomatis ketika aplikasi web start. Inisialisasi manual juga tersedia:

```bash
python web/init_db.py
```

## Menjalankan aplikasi web

Dari root repository:

```bash
python web/app.py
```

Atau jalankan Uvicorn secara eksplisit:

```bash
python -m uvicorn app:app --app-dir web --host 0.0.0.0 --port 8089
```

Buka `http://127.0.0.1:8089`. Direktori runtime berikut dibuat otomatis:

- `web/uploads/`: file yang di-upload.
- `web/results/`: corpus, log, dan hasil scan.
- `web/database/mobile_audit.db`: database SQLite.

Jangan memasukkan ketiga lokasi tersebut ke version control karena dapat berisi binary aplikasi dan temuan sensitif.

## Menjalankan CLI

```bash
python mobile_audit.py <target>
```

Contoh:

```bash
python mobile_audit.py sample.apk --out reports/sample --keep
python mobile_audit.py sample.apk --skip-jadx --skip-blutter --quiet
python mobile_audit.py extracted_app/ --no-unpack --rules rules/secrets.json
```

Opsi yang tersedia:

| Opsi | Keterangan |
|---|---|
| `-o`, `--out DIR` | Direktori output; default `reports/<nama_target_dengan_titik_menjadi_underscore>` |
| `--rules FILE` | File rules JSON custom |
| `--no-unpack` | Scan direktori/file yang sudah diekstrak |
| `--quiet` | Kurangi output log |
| `--keep` | Pertahankan artefak unpack di `work/` |
| `--skip-jadx` | Fast mode tanpa dekompilasi JADX |
| `--skip-blutter` | Fast mode tanpa dekompilasi Blutter |

Hasil utama CLI adalah `findings.json` dan laporan HTML pada direktori output. Jika `--keep` digunakan, artefak intermediate disimpan di `<output>/work/`.

## API penting

Dashboard menggunakan endpoint berikut:

| Method | Endpoint | Fungsi |
|---|---|---|
| `GET` | `/api/scans` | Daftar scan dan statistik |
| `POST` | `/upload` | Upload target baru |
| `POST` | `/api/scan/{id}/start` | Memulai scan pending |
| `GET` | `/api/scan/{id}/status` | Status dan progress |
| `GET` | `/api/scan/{id}/logs` | Log scan |
| `GET` | `/api/scan/{id}/findings` | Temuan keamanan |
| `GET` | `/api/scan/{id}/secrets` | Secret yang terdeteksi |
| `GET` | `/api/scan/{id}/endpoints` | Endpoint yang ditemukan |
| `GET` | `/api/compare/{id1}/{id2}` | Perbandingan dua scan |

Endpoint verifier tersedia pada prefix `/api/scan/{id}/verify/` untuk modul `firebase`, `google-api`, `endpoint`, `ip`, `aws`, `stripe`, dan `webhook`. Dokumentasi interaktif FastAPI tersedia di `/docs` ketika server berjalan.

## Docker

Image memakai Python 3.13, Java, `binutils`, dan `file`, berjalan sebagai user non-root, serta memiliki health check pada port `8089`.

```bash
docker build -t mopenot:local .
docker run --rm -p 8089:8089 \
  -v mopenot-uploads:/app/web/uploads \
  -v mopenot-results:/app/web/results \
  -v mopenot-db:/app/web/database \
  mopenot:local
```

Tool Windows-only yang ada di checkout lokal sengaja tidak disertakan dalam image Linux. Untuk deployment, gunakan volume persisten pada `web/uploads`, `web/results`, dan `web/database`.

## CI/CD

- `.github/workflows/ci-cd.yml` menjalankan compile check, smoke test FastAPI, build/health check Docker, lalu publish ke `ghcr.io/<owner>/<repository>` pada push ke `main`/`master` atau tag `v*`. Pull request menjalankan tahap validasi tanpa publish.
- `Jenkinsfile` menjalankan tahap yang sama. Publish dikendalikan parameter `PUBLISH_IMAGE`; konfigurasi default memakai credential Jenkins `docker-registry-credentials`, registry Docker Hub, dan image `mopenot/mopenot`.

Workflow GitHub menggunakan `GITHUB_TOKEN`, sehingga repository harus mengizinkan Actions menulis package pada GHCR. Jenkins agent harus memiliki Python 3.13+, Docker CLI/daemon, dan credential username/password untuk registry.

## Struktur repository

```text
.
├── mobile_audit.py          # CLI orchestrator
├── secret_scanner.py        # Scanner rules-based
├── engines/                 # Engine unpacking dan analisis per format
├── rules/secrets.json       # Rule secret scanning
├── web/app.py               # FastAPI web UI/API
├── web/database/            # SQLite access dan schema
├── web/templates/           # Template dashboard
├── web/static/              # CSS dan JavaScript
├── web/requirements.txt     # Dependency Python
├── Dockerfile
├── Jenkinsfile
└── .github/workflows/ci-cd.yml
```

Dokumentasi tambahan tersedia di [web/README.md](web/README.md), [DOKUMENTASI_MOBILE_AUDIT.md](DOKUMENTASI_MOBILE_AUDIT.md), dan [CHANGELOG.md](CHANGELOG.md).

## Validasi lokal

Perintah yang digunakan CI untuk pemeriksaan sintaks:

```bash
python -m compileall -q mobile_audit.py apkid_wrapper.py secret_scanner.py engines web
```

Smoke test web dapat dilakukan dengan menjalankan server lalu membuka `/api/scans?per_page=5` atau `/docs`.

## Keamanan dan privasi

- Hanya audit aplikasi/binary yang Anda miliki atau memiliki izin untuk mengujinya.
- Perlakukan upload, corpus, laporan, secret, dan hasil verifier sebagai data sensitif.
- Jangan commit `web/uploads/`, `web/results/`, database SQLite, atau laporan klien ke repository publik.
- Verifier melakukan request jaringan ke target yang diberikan; gunakan hanya pada target yang berwenang.

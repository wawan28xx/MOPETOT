# MOPETOT — Mobile Penetration Testing Otomation

**MOPETOT** adalah singkatan dari **Mo**bile **Pe**netration **T**esting **O**tomation —
toolkit reverse-engineering dan secret scanning untuk aplikasi
mobile serta binary terkait. Proyek ini menyediakan dua entry point:

- `mobile_audit.py`: CLI untuk menjalankan pipeline audit dan menghasilkan laporan JSON/HTML.
- `web/app.py`: dashboard FastAPI untuk upload target, memantau scan, melihat temuan, dan menjalankan verifier.

## Fitur utama

- **Multi-format**: APK, AAB, XAPK/APKS/APKM, IPA, JAR, DEX/SMALI, SO, DLL/EXE (.NET via ilspycmd), HBC (Hermes), ZIP, dan direktori hasil ekstraksi.
- **Pipeline empat tahap**: Identify → Unpack → Scan → Report.
- **Secret scanning** berbasis regex dari `rules/secrets.json` (rule PEM mensyaratkan body base64 — header tanpa isi tidak dilaporkan).
- **iOS**: deteksi binary terenkripsi FairPlay (`cryptid`) — hasil strings/symbol pada binary terenkripsi ditandai sebagai partial.
- **Code Explorer**: browser corpus hasil decompile ala VS Code (syntax highlighting, grep ripgrep, find-in-file ala jadx-gui).
- **Verification Assistant**: AI chatbox via vibe CLI lokal — secret selalu ter-mask sebelum dikirim ke model.
- **Login auth**: seluruh halaman & API diproteksi session cookie.
- **Live Verifier**: Firebase, Google API key scopes, endpoint, IP, AWS STS, Stripe, webhook.
- **PoC generator**: ADB intent extras, deep link trigger, Frida bypass script, HTML exploit builder.
- **Ekstraksi endpoint, manifest, framework, metadata SHA-256, tech stack, indikasi RASP.**
- Dashboard dengan riwayat scan, filter, pagination, perbandingan dua scan, log realtime.
- Cache SQLite untuk hasil verifier dan PoC.

## Persyaratan

| Kebutuhan | Wajib? | Keterangan |
|---|---|---|
| Python **3.13+** | Wajib | Sintaks engine native butuh 3.13; 3.14 teruji |
| `pip install -r web/requirements.txt` | Wajib | Termasuk pin `starlette<0.41` (jangan di-upgrade) |
| Java 17+ | Wajib (APK) | Repo membawa JRE portable di `bin/jre` — tidak perlu install terpisah |
| **vibe CLI** (mistral-vibe) | Opsional | Untuk fitur Verification Assistant. Tanpa vibe, fitur lain tetap jalan; chip AI menunjukkan OFFLINE |
| Node.js 22+ | Opsional | Hanya jika memakai jalur REA/JS analysis (lihat `SARAN PENGEMBANGAN...txt`) |
| Windows x64 | Disarankan | Binary bundled di `bin/` adalah tool Windows; Linux/Docker tetap bisa jalan dengan fallback |

**Kredensial login default: `mopetot` / `P@petot`** — ganti segera via env
`MOPETOT_USER` / `MOPETOT_PASS`, terutama untuk deployment publik.

## Variabel lingkungan

**Server & data:**
- `MOPETOT_USER` / `MOPETOT_PASS`: kredensial login (default `mopetot` / `P@petot`).
- `MOPETOT_DB_PATH`: path database SQLite; default `web/database/mobile_audit.db`.
- `MOPETOT_UPLOAD_DIR`: direktori upload; default `web/uploads`.
- `MOPETOT_RESULTS_DIR`: direktori hasil; default `web/results`.
- `MOPETOT_MAX_UPLOAD_BYTES`: batas upload; image production memakai 500 MiB.
- `MOPETOT_MAX_CONCURRENT_SCANS`: jumlah scan aktif; production memakai `1`.

**Tool & engine:**
- `MOBILE_AUDIT_JAVA`: path executable Java (override JRE bundled).
- `MOBILE_AUDIT_PY313`: path Python 3.13 untuk enrichment APKiD.
- `MOBILE_AUDIT_VIBE_CMD`: path executable vibe bila tidak ada di PATH.

**Verification Assistant (AI):**
- Default: vibe CLI lokal, model via `VIBE_ACTIVE_MODEL` (alias model di config vibe, mis. `glm-5-3`).
- Fallback provider HTTP (opsional): `MOBILE_AUDIT_LLM_PROVIDER` = `mistral` | `opencode` | `custom`, plus `MOBILE_AUDIT_LLM_BASE_URL` / `MOBILE_AUDIT_LLM_API_KEY` / `MOBILE_AUDIT_LLM_MODEL`. Detail: [web/README.md](web/README.md).

## Instalasi lokal (Windows / Linux)

```bash
python -m venv .venv
.venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r web/requirements.txt
```

Fitur AI (opsional):

```bash
pip install mistral-vibe      # atau: uv tool install mistral-vibe
# set API key di ~/.vibe/.env sesuai instruksi vibe
```

Database dibuat otomatis saat aplikasi web start. Inisialisasi manual juga tersedia:

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

Buka `http://127.0.0.1:8089`, login dengan kredensial default, lalu upload target.
Direktori runtime berikut dibuat otomatis:

- `web/uploads/`: file yang di-upload.
- `web/results/`: corpus, log, dan hasil scan.
- `web/database/mobile_audit.db`: database SQLite.

Jangan memasukkan ketiga lokasi tersebut ke version control karena dapat berisi
binary aplikasi dan temuan sensitif.

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

Hasil utama CLI adalah `findings.json` dan laporan pada direktori output.
Jika `--keep` digunakan, artefak intermediate disimpan di `<output>/work/`.

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
| `GET` | `/api/scan/{id}/tree` | File tree corpus (Code Explorer) |
| `GET` | `/api/scan/{id}/search` | Grep corpus (ripgrep) |
| `GET` | `/api/scan/{id}/file` | Isi file corpus (viewer) |
| `POST` | `/api/scan/{id}/chat` | Verification Assistant (AI) |
| `GET` | `/api/compare/{id1}/{id2}` | Perbandingan dua scan |

Endpoint verifier tersedia pada prefix `/api/scan/{id}/verify/` untuk modul
`firebase`, `google-api`, `endpoint`, `ip`, `aws`, `stripe`, dan `webhook`.
Dokumentasi interaktif FastAPI tersedia di `/docs` ketika server berjalan.

## Docker

Image memakai Python 3.13, Java, `binutils`, dan `file`, berjalan sebagai user
non-root, serta memiliki health check pada port `8089`.

```bash
docker build -t mopetot:local .
docker run --rm -p 8089:8089 \
  -v mopetot-data:/data \
  mopetot:local
```

Tool Windows-only yang ada di checkout lokal sengaja tidak disertakan dalam
image Linux. Image menyimpan upload, hasil, dan SQLite di `/data`; gunakan satu
volume persisten untuk direktori tersebut. Endpoint health tersedia di `/healthz`.

## CI/CD

Jenkins adalah satu-satunya CI/CD production. Push ke branch `master`
menjalankan compile/test, build dan health check image, import immutable image
ke containerd k3s, rollout Deployment dan CronJob, lalu memverifikasi
`https://mopetot.pentest.web.id/healthz`. Rollout dikembalikan ke image
sebelumnya bila validasi deployment gagal.

Jenkins job memakai repository public `wawan28xx/MOPETOT`, trigger webhook
GitHub, dan polling lima-menit sebagai fallback. Agent
`k3s-platform-prod-kubeconfig` harus memiliki Docker, izin import image
melalui `sudo -n k3s ctr`, serta kubeconfig terbatas
`/home/deit/.kube/mopetot-config`.

Webhook repository menggunakan event **push** dengan Payload URL
`https://jenkins.pentest.web.id/github-webhook/` dan content type
`application/json`. Jika webhook belum dipasang, polling SCM tetap mendeteksi
perubahan `master` paling lambat sekitar lima menit.

Manifest production dan script provisioning berada di `/home/deit/defendit-k8s`:

- `platform-prod/mopetot-prod.yaml`
- `cicd/jenkins-mopetot-rbac.yaml`
- `cicd/jenkins-mopetot-job.yaml`
- `scripts/setup-mopetot-jenkins.sh`
- `scripts/activate-mopetot-tunnel.sh`

Production memakai satu replica karena SQLite, antrean in-process, dan PVC
`ReadWriteOnce`. PVC Longhorn berukuran 50 GiB. CronJob menghapus scan
completed/failed yang lebih lama dari 30 hari; jalankan dry-run sebelum aktivasi:

```bash
docker run --rm -v mopetot-data:/data --workdir /app/web mopetot:local \
  python -m maintenance.retention --days 30 --dry-run
```

## Struktur repository

```text
.
├── mobile_audit.py          # CLI orchestrator
├── secret_scanner.py        # Scanner rules-based
├── engines/                 # Engine unpacking dan analisis per format
├── rules/secrets.json       # Rule secret scanning
├── web/app.py               # FastAPI web UI/API
├── web/auth.py              # Login & session auth
├── web/chat.py              # Verification Assistant (AI, vibe CLI)
├── web/code_explorer.py     # Code Explorer (browse + grep corpus)
├── web/database/            # SQLite access dan schema
├── web/templates/           # Template dashboard (tema cyberpunk)
├── web/static/              # CSS, JS, fonts, audio
├── web/requirements.txt     # Dependency Python
├── bin/                     # Tool vendored (jre, jadx, apktool, ripgrep, ...)
├── Dockerfile
├── Jenkinsfile
└── .github/workflows/ci-cd.yml
```

Dokumentasi tambahan tersedia di [web/README.md](web/README.md),
[DOKUMENTASI_MOBILE_AUDIT.md](DOKUMENTASI_MOBILE_AUDIT.md), dan
[CHANGELOG.md](CHANGELOG.md).

## Validasi lokal

Perintah yang digunakan CI untuk pemeriksaan sintaks:

```bash
python -m compileall -q mobile_audit.py apkid_wrapper.py secret_scanner.py engines web
```

Test suite regresi yang tersedia:

```bash
python test_cryptid.py          # deteksi FairPlay (cryptid)
python test_pem_rules.py        # rule PEM (base64 body)
cd web
python test_auth.py             # login & session
python test_chat_assistant.py   # Verification Assistant (mock)
python test_code_explorer.py    # Code Explorer backend
python test_node_syntax.py      # syntax JS template results.html
node test_hljs_pipeline.js      # pipeline syntax highlighting
node test_syntax_highlight.js   # fallback tokenizer
```

Smoke test web dapat dilakukan dengan menjalankan server lalu membuka `/healthz`
atau `/docs`.

## Troubleshooting

- **Startup crash `Router.__init__() got an unexpected keyword argument 'on_startup'`**:
  versi starlette terlalu baru. Jalankan
  `pip install "starlette>=0.37.2,<0.41"` (pin sudah ada di requirements.txt).
- **`sqlite3.OperationalError: near ">>"` saat startup**: gunakan versi repo
  terbaru (fixed di commit `8f11c74`); hapus database lama yang rusak.
- **Port 8089 bentrok**: `netstat -ano | findstr :8089` lalu `taskkill /f /pid <PID>`,
  atau jalankan `python -m uvicorn app:app --app-dir web --port 8089`.
- **Chip AI OFFLINE**: vibe CLI tidak ditemukan — `pip install mistral-vibe`
  atau set `MOBILE_AUDIT_VIBE_CMD` ke path vibe.
- **TECH STACK / APKiD kosong**: set `MOBILE_AUDIT_PY313` ke Python 3.13.
- **Font logo "Cyberpunk" (Lyon ArtZ)**: free for personal use — cek lisensi
  sebelum distribusi komersial.

## Keamanan dan privasi

- Hanya audit aplikasi/binary yang Anda miliki atau memiliki izin untuk mengujinya.
- Perlakukan upload, corpus, laporan, secret, dan hasil verifier sebagai data sensitif.
- Jangan commit `web/uploads/`, `web/results/`, database SQLite, atau laporan
  klien ke repository publik.
- Verifier melakukan request jaringan ke target yang diberikan; gunakan hanya
  pada target yang berwenang.
- Default login `mopetot`/`P@petot` wajib diganti (env `MOPETOT_USER`/`MOPETOT_PASS`)
  untuk deployment di luar localhost.

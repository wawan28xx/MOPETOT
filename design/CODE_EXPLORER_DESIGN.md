# Design Doc — Code Explorer (Mobile Audit Tool)

> Status: PROPOSAL — belum ada implementasi. Mockup interaktif: `design/code_explorer_mockup.html`
> Prinsip: 100% offline, tanpa dependency eksternal baru, corpus sudah ada di `web/results/<scan_id>/work/corpus/`.

## 1. Problem

Hasil scan nunjukin `file + line`, tapi untuk menganalisis konteks kode, hunter harus
keluar dari tools dan grep corpus manual di editor/terminal. Semua hasil decompile
(jadx, smali, apktool, blutter, rabin2 strings) sebenarnya sudah ada di disk —
tinggal dibuat bisa dijelajahi dari Web UI.

## 2. UX — Tab baru "🔍 Code Explorer" di halaman results

Layout 3 panel:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ [🔍 regex..(api\.stockbit\.com)..☑regex ☑Aa] [Cari] [scope▾] [tipe file▾]│  ← toolbar grep
├───────────┬──────────────────┬──────────────────────────────────────────┤
│ FILE TREE │ HASIL GREP       │ CODE VIEWER                              │
│ (corpus)  │ per file + baris │ monospace + line number + highlight      │
│ + filter  │ klik → buka file │ match emas, snippet ⚠, tombol:           │
│           │ & scroll ke baris│ 📋 Copy | 🤖 Tanya AI | load more       │
├───────────┴──────────────────┴──────────────────────────────────────────┤
│ status: N file teks · X match · waktu grep · Enter = match berikutnya   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Interaksi kunci
| Aksi | Behavior |
|---|---|
| grep corpus | regex Python (`re`) opsional / literal, case-sensitive toggle, scope filter (folder corpus), filter ekstensi. Limit 500 match + counter "dipotak". Jalankan via `asyncio.to_thread`. |
| klik file di tree | load isi file (paging per baris, default 500 baris / 64KB), badge tipe file |
| klik hasil grep | buka file + scroll ke baris + highlight match (emas), counter "match i/n di file ini", Enter = next match |
| dari tab Secrets/Findings | tombol "📂 Buka di Code Explorer" pada temuan → buka file & line persis (menggantikan modal ±5 baris; modal lama tetap ada sebagai quick view) |
| 🤖 Tanya AI | kirim snippet file aktif sebagai konteks chat Verification Assistant (payload tambahan `file_context`) |

### Visual
- Sama tema dark + aksen purple seperti halaman results sekarang.
- File tree: collapse/expand folder, badge jumlah file, filter cepat nama file.
- Viewer: line number, highlight match emas (reuse `.hardcoded-highlight` style),
  badge ekstensi, tombol Copy path/snippet.

## 3. API (semua lokal, di `web/app.py`)

| Endpoint | Fungsi |
|---|---|
| `GET /api/scan/{id}/tree` | Daftar file corpus: `[{path, size, ext, is_dir}]` (relatif corpus). Cache in-memory per scan_id (scan selesai → corpus immutable). |
| `GET /api/scan/{id}/file?path=&offset=0&limit=500` | Isi file teks per-baris. Reject non-text (deteksi via `\0` sniff + ekstensi), cap ukuran. |
| `GET /api/scan/{id}/search?q=&regex=0&case=0&scope=&ext=&limit=500` | Grep corpus. Return `{matches: [{path, line_no, line_text}], truncated, elapsed_ms, files_scanned}`. Threadpool. |

### Keamanan (wajib)
- **Path traversal**: `Path(corpus/path).resolve()` wajib `is_relative_to(corpus_root.resolve())`, else 400.
- Hanya scan `status == completed` (corpus dijamin ada).
- File binary ditolak (sniff `\x00` di 1024 byte pertama) supaya tidak memuntahkan junk ke UI.
- Response line_text di-cap panjang (mis. 500 char) untuk file minified JS satu baris.

### Performa
- Corpus fast mode umumnya 5–20k file teks. Grep Python murni ±5–20 detik pertama.
  Mitigasi bertahap:
  1. **v1**: grep langsung + scope/ext filter + limit 500 + counter elapsed. Cukup.
  2. **v2 (opsional)**: cache index daftar file teks per scan (tabel `corpus_files`),
     dibangun sekali saat scan complete.
  3. **v3 (opsional)**: grep pakai `ripgrep` bila tersedia di PATH (fallback Python re).

## 4. Struktur kode (proposal)

```
web/
├── code_explorer.py        ← modul baru: walk corpus, read file, grep (pure func, testable)
├── app.py                  ← 3 endpoint tipis (validasi + delegate ke code_explorer)
├── templates/results.html  ← tab 8 "🔍 Code Explorer" + panel 3 kolom
└── static/css/style.css    ← styling tree/viewer (fallback offline, utama tetap Tailwind)
```

`code_explorer.py` sengaja dipisah dari `app.py` supaya:
- bisa di-unit-test tanpa server (pure function, input = Path corpus),
- app.py tidak makin bengkak (sekarang sudah 43KB+).

## 5. Fase implementasi

| Fase | Isi | Effort |
|---|---|---|
| 1 | Grep + hasil panel + viewer (tanpa tree) | 1–2 hari |
| 2 | File tree + filter + open-from-finding ( Secrets → Code Explorer) | 1 hari |
| 3 | 🤖 Tanya AI dari viewer + copy snippet + keyboard nav | ½ hari |
| 4 (ops) | corpus index cache / ripgrep fallback | ½ hari |

## 6. Yang TIDAK termasuk scope v1
- Editing/annotate file.
- Syntax highlighting engine berat — cukup warna sederhana per ekstensi (java/js/xml/json),
  match highlight lebih penting daripada highlighting sempurna.
- Diff antar versi corpus (sudah ada di backlog #9 terpisah).

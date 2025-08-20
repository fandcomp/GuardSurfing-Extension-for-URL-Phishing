# GuardSurfing – URL Phishing Checker (Backend + Chrome Extension)

GuardSurfing adalah solusi lokal untuk mendeteksi risiko phishing pada URL yang sedang dibuka serta memindai tautan/iklan eksternal di halaman.

## Prasyarat
- Windows + PowerShell
- Python 3.11 (disarankan) + pip
- Google Chrome (MV3)
- Opsional: Ollama (LLM lokal, untuk alasan kontekstual)

## Quick Start (Backend)
Jalankan di PowerShell dari folder repo ini:

```powershell
# 1) Virtual env
python -m venv .venv
. .\.venv\Scripts\Activate.ps1

# 2) Install deps
pip install -r back-end/requirements.txt

# 3) Jalankan server
python back-end/server.py
# Server: http://127.0.0.1:5000
```

Cek kesehatan:
```powershell
curl http://127.0.0.1:5000/health
```

## Opsional: Aktifkan LLM (Ollama)
Untuk alasan kontekstual tambahan pada hasil analisis tautan.

1) Install Ollama: https://ollama.ai
2) Pull model contoh:
```powershell
ollama pull llama3.1:8b
```
3) Set env sebelum menjalankan backend:
```powershell
$env:USE_LLM = '1'
$env:LLM_MODEL = 'llama3.1:8b'
$env:OLLAMA_URL = 'http://127.0.0.1:11434'
$env:LLM_TIMEOUT = '8'
python back-end/server.py
```
Catatan: Opsi LLM juga bisa diatur dari Extension Options (frontend akan mengirim flag ke `/analyze_page`).

## Endpoint API
- GET `/health` → `{ ok, threshold, features }`
- GET `/version` → `{ model, features, threshold, explain }`
- GET `/config` → `{ model, features, threshold, use_llm, llm_model, ollama_url, llm_timeout, version }`
- POST `/process`
  - Input: `{ url, mode?: 'balanced'|'strict'|'relaxed', fast?: boolean }`
  - Output: `{ prediction, risk, threshold, reasons, explanation }`
- POST `/analyze_page`
  - Input ringkas:
  ```json
  {
    "page_url": "https://example.com",
    "links": [ { "url": "https://...", "banner": true, "tag": "a|iframe|area|...", "text": "...", "title": "...", "context": "..." } ],
    "mode": "balanced", "fast": true, "top_k_full": 3,
    "llm": false, "llm_only_external": false, "llm_max": 10
  }
  ```
  - Output: ringkasan + `items[]` (prediction, risk, banner, external, shortener, llm_reason, ...)

## Install Chrome Extension (MV3)
1) Buka `chrome://extensions`, aktifkan Developer mode.
2) Load unpacked → pilih folder `front-end/`.
3) Buka Options untuk konfigurasi:
   - API Base: `http://127.0.0.1:5000`
   - Mode: Balanced / Strict / Relaxed
   - Fast fallback, Highlight/Block risky links
   - Allowlist (satu domain per baris)
   - LLM (enable, only external, max links)

File penting frontend:
- `front-end/manifest.json` (MV3)
- `front-end/background.js` (service worker, cache, notifikasi)
- `front-end/page_scanner.js` (koleksi link/banner/iframe/onclick)
- `front-end/popup.html`, `front-end/script.js` (UI ringkas)
- `front-end/details.html`, `front-end/details.js` (daftar flagged)
- `front-end/options.html`, `front-end/options.js` (pengaturan)
- `front-end/config.js` (API base default)

## Fitur Utama
- Skor risiko URL aktif + alasan (explainability ringkas).
- Pindai halaman: tautan/iframe/area/banner tanpa <a> (onclick/data-*).
- Deteksi shortener (t.ly, rebrand.ly, bit.ly, dll) dan banner heuristik.
- Highlight/Block klik berisiko (opsional), notifikasi, Details page, Copy/Export.
- LLM opsional untuk alasan berbasis konteks halaman.

## Packaging untuk Chrome Web Store
- Zip isi folder `front-end/` (jangan zip folder induk).
- Sertakan: manifest.json, background.js, page_scanner.js, popup.html, script.js, style.css, logo.png, options.html, options.js, details.html, details.js, config.js.
- Upload lewat Developer Dashboard.

## Git LFS (dataset besar)
`.gitattributes` telah mengaktifkan LFS untuk `*.csv` (dan `collecting_dataset/*.csv`).
- Install Git LFS: https://git-lfs.github.com
- Optional rewrite history:
```powershell
git lfs migrate import --include="collecting_dataset/*.csv"
```

## Troubleshooting
- Popup Offline / tidak konek:
  - Pastikan backend aktif (http://127.0.0.1:5000).
  - Cek firewall/port.
- Flagged links kosong:
  - Tunggu 1–2 detik; konten dinamis. Extension juga memaksa GET_LINKS saat analisis jika cache link kosong.
  - Cek Allowlist (domain di-allow dilewati).
- LLM alasan kosong:
  - Pastikan Ollama aktif + env di-set, atau aktifkan LLM dari Options.
- CRLF/LF warning Git (Windows): aman; atau:
```powershell
git config core.autocrlf true
```

## Lisensi
Tambahkan LICENSE sesuai kebutuhan (mis. MIT).

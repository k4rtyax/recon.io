# recon.io

Universal web recon framework untuk bug bounty hunting.

> **Kenapa tools ini dibuat?**  
> Tools ini dibuat karena awalnya merasa ribet dan bingung jika harus menggunakan tools recon satu per satu secara manual. Framework ini dirancang khusus dan sangat cocok untuk **pemula yang ingin terjun ke dunia perhuntingan** (Bug Bounty/Pentesting).
>
> Setelah semua laporan hasil recon keluar, pastikan untuk melakukan **review dan pentest manual** guna mencari _chain exploit_ selanjutnya. Script ini **hanya ditujukan untuk mengintai (recon)** dan mengumpulkan informasi awal mengenai target.

![recon.io banner](banner.png)

> Butuh **Python 3.10** ke atas.

---

## Sebelum mulai, baca dulu

Gunakan tools ini **hanya untuk target yang diizinkan**, milik sendiri, atau program bug bounty/pentest yang sudah memberi izin. Scan aktif (port scan, fuzzing, dll) ke target tanpa izin itu **ilegal**, dan tanggung jawab sepenuhnya ada di tangan pengguna.

Fitur AI itu **opsional** dan bisa dimatikan. Kalau dinyalakan, isi laporan (termasuk temuan) akan dikirim ke provider AI yang dipilih. Jangan aktifkan kalau program melarang data keluar ke pihak ketiga.

**Intinya: pakai izin dan akal sehat.**

---

## Instalasi

Satu script untuk semua OS, deteksi otomatis (Kali, Ubuntu, Arch, Fedora, macOS).

```bash
chmod +x install.sh && ./install.sh
```

Script akan otomatis install semua tools yang dibutuhkan. Di akhir ada pilihan untuk set provider AI (bisa dilewati, bisa diulang kapan saja).

> **Windows**: belum didukung. Gunakan [WSL2](https://docs.microsoft.com/windows/wsl/install) lalu jalankan perintah di atas.

Setelah selesai, muat ulang terminal:

```bash
source ~/.bashrc   # atau source ~/.zshrc
```

---

## Cara pakai

```bash
recon -d example.com                          # recon lengkap satu domain
recon -d example.com -A                       # pemetaan jaringan saja (subdomain, dns, port)
recon -d example.com --fase subdomain,urls    # pilih fase tertentu
recon -d example.com --recon-subs             # recon tiap subdomain yang aktif
recon -d example.com --resume                 # lanjutkan scan yang terputus
recon -d example.com --diff --notify          # tampilkan & kirim yang baru muncul
recon -f targets.txt                          # banyak target sekaligus
recon --check                                 # cek tools dan API mana yang sudah siap
```

---

## Daftar perintah

| Perintah | Keterangan |
| -------- | ---------- |
| `-d DOMAIN` | satu target domain |
| `-s SUBDOMAIN` | target subdomain spesifik (lewati fase subdomain) |
| `-f FILE` | file daftar target, satu per baris |
| `-o DIR` | folder simpan hasil (default: `./results`) |
| `-A` | pemetaan jaringan saja (subdomain, dns, port) |
| `--fase NAMA` | pilih fase, pisah koma, contoh: `subdomain,urls,js` |
| `--recon-subs` | enum subdomain dulu, lalu recon tiap subdomain aktif |
| `--scope FILE` | batasi ke target in-scope saja (file `.txt`/`.csv` HackerOne) |
| `--resume` | lanjutkan run terakhir, fase yang sudah selesai dilewati |
| `--diff` | tampilkan yang baru muncul dibanding run sebelumnya |
| `--notify` | kirim ringkasan ke Discord/Slack/Telegram |
| `--menu` | pilih target in-scope dan fase lewat menu keyboard (butuh `--scope`) |
| `--chat` | mode asisten AI interaktif |
| `--list-fase` | tampilkan semua fase yang tersedia |
| `--check` | cek status semua tools |
| `--setup-ai` | set atau ganti provider AI |

---

## Tahap recon

| # | Nama | Yang dilakukan |
| - | ---- | -------------- |
| 1 | subdomain | cari semua subdomain target |
| 2 | dns | ambil info DNS, whois, cek zone transfer |
| 3 | ports | scan port terbuka |
| 4 | fingerprint | deteksi teknologi, WAF, header HTTP |
| 5 | urls | kumpulkan semua URL dari crawling & arsip |
| 6 | js | analisis file JavaScript untuk endpoint & secret |
| 7 | params | temukan parameter tersembunyi |
| 8 | security | cek header keamanan, CORS, nuclei, subdomain takeover |
| 9 | dirbrute | brute-force direktori & file tersembunyi |
| 10 | api | cari endpoint GraphQL (cek introspeksi) & dokumen OpenAPI/Swagger |
| 11 | buckets | cari cloud storage bucket (S3, GCS, Azure, Spaces) yang terbuka |

---

## Asisten AI (opsional)

AI bisa bantu navigasi recon lewat obrolan biasa. Tanpa AI, semua fase tetap jalan normal.

```bash
recon --setup-ai   # set atau ganti provider AI kapan saja

recon --chat       # buka mode obrolan dengan AI
```

Contoh percakapan:

```
> recon admin.example.com fokus urls sama js
> ada endpoint menarik nggak dari hasil tadi?
```

Sebut targetnya langsung, AI tidak akan menanyakan scope. Kalau kamu memang punya
file scope, berikan saja dan AI otomatis memfilter target ke situ. Setiap scan tetap
butuh konfirmasi manual dari kamu.

### Privasi data

Isi laporan recon dikirim ke provider AI yang dipilih. Sebelum dikirim ke provider
cloud, secret, token, cookie, dan email otomatis disensor. Provider lokal
(Ollama / LM Studio) tidak pernah menyensor karena datanya tidak keluar mesin.

Kalau program melarang data keluar ke pihak ketiga, pakai Ollama atau LM Studio.

### Pilihan provider

| Provider | Keterangan |
| -------- | ---------- |
| **Gemini** (default) | Gratis, [ai.google.dev](https://ai.google.dev) |
| **Groq** | Gratis, cepat, [console.groq.com](https://console.groq.com) |
| **OpenRouter** | Akses banyak model, [openrouter.ai](https://openrouter.ai) |
| **OpenAI** | GPT-4o dll, [platform.openai.com](https://platform.openai.com) |
| **Mistral** | Ada tier gratis, [console.mistral.ai](https://console.mistral.ai) |
| **Together.ai** | Banyak model open-source, [api.together.xyz](https://api.together.xyz) |
| **Perplexity** | Model dengan akses web, [perplexity.ai](https://www.perplexity.ai) |
| **Ollama** | Lokal, offline, tanpa key, [ollama.ai](https://ollama.ai) |
| **LM Studio** | Lokal, pakai GUI, [lmstudio.ai](https://lmstudio.ai) |
| **Provider lain** | Apa saja yang kompatibel OpenAI, isi BASE_URL + MODEL + API_KEY |

> Provider cloud (semua kecuali Ollama & LM Studio) akan menerima isi laporan recon untuk dianalisis. Kalau data tidak boleh keluar, pakai Ollama atau LM Studio.

---

## Pengaturan lanjutan

Semua pengaturan bisa diubah lewat file `.env` tanpa perlu edit kode.

```bash
cp .env.example .env   # buat file pengaturan dari template
```

| Pengaturan | Default | Keterangan |
| ---------- | ------- | ---------- |
| `RECON_OUTPUT_DIR` | `./results` | folder simpan hasil |
| `RECON_TIMEOUT` | `300` | batas waktu per perintah (detik) |
| `RECON_TIMEOUT_<FASE>` | bervariasi | batas waktu per fase |
| `RECON_JS_LIMIT` | `50` | maks file JS yang dianalisis |
| `RECON_USER_AGENT` | Chrome UA | user agent untuk HTTP request |
| `RECON_TOOL_<NAMA>` | nama tool | path ke binary tool tertentu |
| `RECON_WORDLIST` | auto-detect | path ke wordlist untuk dirbrute |
| `RECON_BUCKET_MAX` | `400` | maks kandidat nama bucket yang dites |
| `RECON_NOTIFY_*` | kosong | webhook Discord/Slack/Telegram untuk `--notify` |
| `RECON_AI_REDACT` | `1` | sensor data sensitif sebelum dikirim ke AI cloud |

---

## API OSINT (opsional, gratis)

Fase subdomain otomatis memakai crt.sh tanpa perlu key. Kalau mau hasil lebih banyak,
isi key gratis di `.env`, yang kosong dilewati begitu saja.

| Layanan | Free tier |
| ------- | --------- |
| [crt.sh](https://crt.sh) | tanpa key |
| [Shodan InternetDB](https://internetdb.shodan.io) | tanpa key |
| [Chaos](https://chaos.projectdiscovery.io) | gratis untuk personal use |
| [Netlas](https://netlas.io) | 50 request/hari |
| [VirusTotal](https://virustotal.com) | 500 request/hari |
| [LeakIX](https://leakix.net) | gratis |
| [Censys](https://censys.io) | kredit bulanan |
| [SecurityTrails](https://securitytrails.com) | terbatas |
| [Shodan](https://shodan.io) | key gratis terbatas |

Cek mana yang sudah siap:

```bash
recon --check
```

---

## Notifikasi & pemantauan berkala

```bash
recon -d example.com --diff            # cuma tampilkan yang baru sejak run sebelumnya
recon -d example.com --diff --notify   # plus kirim ke Discord/Slack/Telegram
```

Run pertama membuat baseline. Run berikutnya membandingkan subdomain, port, URL,
endpoint, dan bucket, lalu melaporkan selisihnya saja. Untuk jalan otomatis,
panggil dari cron:

```bash
0 6 * * * cd /path/recon.io && ./recon.py -d example.com --diff --notify
```

---

## Struktur hasil

```
./results/
└── example.com/
    └── recon_03_06_2026/
        ├── subdomain/
        │   ├── all_subdomains.txt
        │   ├── alive_subdomains.txt
        │   ├── alive_subdomains_info.txt
        │   ├── osint_passive.txt            (crt.sh + API OSINT)
        │   ├── tlsx_san.txt                 (SAN dari sertifikat TLS)
        │   └── catchall_subdomains.txt      (kalau ada HTTP catch-all)
        ├── dns/
        │   ├── whois.txt
        │   ├── dns_records.txt
        │   └── zone_transfer.txt
        ├── ports/
        │   ├── nmap_top1000.txt
        │   └── open_ports.txt
        ├── fingerprint/
        │   ├── tech_stack.txt
        │   ├── waf.txt
        │   ├── headers.txt
        │   └── favicon_hash.txt             (query siap pakai utk Shodan/FOFA)
        ├── urls/
        │   ├── all_urls.txt
        │   ├── ssrf_prone.txt
        │   ├── idor_hint.txt
        │   └── exposed_tool.txt
        ├── js/
        │   ├── js_endpoints.txt
        │   └── js_secrets.txt
        ├── params/
        │   └── discovered_params.txt
        ├── security/
        │   ├── missing_headers.txt
        │   ├── nuclei_results.txt
        │   ├── takeover.txt
        │   └── cors_results.txt
        ├── dirbrute/
        │   └── found_paths.txt
        ├── api/
        │   ├── graphql_endpoints.txt
        │   ├── graphql_fingerprint.txt
        │   ├── api_docs.txt
        │   └── api_endpoints.txt
        ├── buckets/
        │   ├── found_buckets.txt
        │   └── open_buckets.txt
        └── report/
            ├── report_example.com.md
            └── report_example.com.txt
```

---

## Tools yang digunakan

recon.io menggabungkan tools open-source berikut:

[Subfinder](https://github.com/projectdiscovery/subfinder) •
[Amass](https://github.com/owasp-amass/amass) •
[AlterX](https://github.com/projectdiscovery/alterx) •
[Dnsx](https://github.com/projectdiscovery/dnsx) •
[Tlsx](https://github.com/projectdiscovery/tlsx) •
[github-subdomains](https://github.com/gwen001/github-subdomains) •
[Httpx](https://github.com/projectdiscovery/httpx) •
[Nmap](https://nmap.org) •
[Naabu](https://github.com/projectdiscovery/naabu) •
[Wafw00f](https://github.com/EnableSecurity/wafw00f) •
[Katana](https://github.com/projectdiscovery/katana) •
[Gau](https://github.com/lc/gau) •
[Waybackurls](https://github.com/tomnomnom/waybackurls) •
[Nuclei](https://github.com/projectdiscovery/nuclei) •
[Arjun](https://github.com/s0md3v/Arjun) •
[Subzy](https://github.com/PentestPad/subzy) •
[Ffuf](https://github.com/ffuf/ffuf) •
[SecLists](https://github.com/danielmiessler/SecLists)

Apresiasi besar untuk para kreator alat-alat di atas! 👏

---

Untuk teknik dan studi kasus recon lanjutan, lihat [WRITEUPS_REF.md](WRITEUPS_REF.md).

# recon.io

Universal web recon framework untuk bug bounty hunting.

> **Kenapa tools ini dibuat?**  
> Tools ini dibuat karena awalnya merasa ribet dan bingung jika harus menggunakan tools recon satu per satu secara manual. Framework ini dirancang khusus dan sangat cocok untuk **pemula yang ingin terjun ke dunia perhuntingan** (Bug Bounty/Pentesting).
>
> Setelah semua laporan hasil recon keluar, pastikan untuk melakukan **review dan pentest manual** guna mencari _chain exploit_ selanjutnya. Script ini **hanya ditujukan untuk mengintai (recon)** dan mengumpulkan informasi awal mengenai target

![recon.io banner](banner.png)

> **Kebutuhan Python**: Proyek ini memerlukan **Python 3.10+** karena menggunakan fitur *union type hinting* modern (`type | None`).


## Disclaimer (penting, baca dulu)

Tool ini cuma buat target yang **kamu boleh tes** — punya sendiri, atau program bug bounty/pentest yang udah ngasih izin. Recon di sini **scan aktif** (port scan, fuzzing, dan teman-temannya), jadi nembak target tanpa izin itu **ilegal**, dan itu **tanggung jawab kamu sepenuhnya** — bukan aku, bukan tool-nya.

Fitur AI itu **opsional**. Kalau kamu pasang API key, isi report (termasuk temuan dan secret) bakal dikirim ke Google Gemini buat dianalisis. Jangan dinyalain kalau program-mu nggak ngizinin data keluar ke pihak ketiga.

Mode chat ada cek scope + konfirmasi "saya berwenang" — itu **pagar etika dan pengingat**, bukan tameng keamanan. Bisa di-bypass, dan tetap kamu yang pegang tanggung jawab.

Intinya: **pakai pakai izin dan akal sehat. Sisanya urusanmu.**


## Penggunaan

```bash
python recon.py -d example.com
python recon.py -d example.com -A
python recon.py -f targets.txt
python recon.py -d example.com --fase subdomain,dns,ports
python recon.py -d example.com -o ~/hasil
```

Setelah instalasi selesai, Anda juga dapat menjalankan framework ini secara global dari direktori mana pun cukup dengan perintah alias `recon` (atau `recon.io`):

```bash
recon -d example.com
recon -d example.com -A
```

## Argumen

| Argumen       | Keterangan                                 |
| ------------- | ------------------------------------------ |
| `-d DOMAIN`   | satu target domain                         |
| `-s SUBDOMAIN`| target spesifik subdomain (otomatis melewati fase subdomain) |
| `-f FILE`     | file berisi daftar target (satu per baris cth subdomain.txt) |
| `-o DIR`      | folder output (default: ./results)         |
| `-A`          | jalankan fase pemetaan jaringan dasar saja (subdomain, dns, ports) |
| `--fase FASE` | pilih fase tertentu, pisah koma            |
| `--recon-subs`| enumerasi subdomain dulu, lalu recon tiap subdomain aktif (hanya dengan `-d`) |
| `--list-fase` | tampilkan daftar fase                      |
| `--check`     | cek status semua tools lalu keluar         |

## Fase

| #   | Fase        | Tools                                |
| --- | ----------- | ------------------------------------ |
| 1   | subdomain   | subfinder, amass, alterx, dnsx, httpx |
| 2   | dns         | whois, dig, dnsx                      |
| 3   | ports       | naabu, nmap                           |
| 4   | fingerprint | httpx, wafw00f, curl                  |
| 5   | urls        | katana, gau/waybackurls               |
| 6   | js          | curl + regex                          |
| 7   | params      | arjun                                 |
| 8   | security    | curl, nuclei, subzy (takeover), CORS  |
| 9   | dirbrute    | ffuf                                  |

## Konfigurasi

Semua pengaturan bisa di-override via **environment variable**. Tidak perlu edit source code.

```bash
# copy dulu template-nya
cp .env.example .env

# atau set langsung
export RECON_OUTPUT_DIR=~/hasil-recon
export RECON_TIMEOUT_PORTS=600
export RECON_TOOL_NMAP=/usr/local/bin/nmap
export RECON_WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt
```

Lihat `.env.example` untuk daftar lengkap variabel yang tersedia.

| Variable                | Default          | Keterangan                |
| ----------------------- | ---------------- | ------------------------- |
| `RECON_OUTPUT_DIR`      | `./results`      | folder output             |
| `RECON_TIMEOUT`         | `300`            | timeout global (detik)    |
| `RECON_TIMEOUT_<FASE>`  | bervariasi       | timeout per fase          |
| `RECON_JS_LIMIT`        | `50`             | maks file JS dianalisis   |
| `RECON_USER_AGENT`      | Chrome UA        | user agent string         |
| `RECON_TOOL_<NAME>`     | nama tool        | path ke binary tool       |
| `RECON_WORDLIST`        | auto-detect      | path ke wordlist dirbrute |

## Struktur output

```
./results/
└── example.com/
    └── recon_03_06_2026/
        ├── subdomain/
        │   ├── subfinder.txt
        │   ├── amass.txt
        │   ├── alterx_permutations.txt
        │   ├── resolved_permutations.txt
        │   ├── all_subdomains.txt
        │   ├── httpx_alive.json
        │   ├── alive_subdomains.txt
        │   └── alive_subdomains_info.txt
        ├── dns/
        │   ├── whois.txt
        │   ├── dns_records.txt
        │   └── zone_transfer.txt
        ├── ports/
        │   ├── naabu.txt
        │   ├── nmap_top1000.txt
        │   ├── nmap_http.txt
        │   └── open_ports.txt
        ├── fingerprint/
        │   ├── httpx_tech.json
        │   ├── waf.txt
        │   ├── headers.txt
        │   └── tech_stack.txt
        ├── urls/
        │   ├── katana.txt
        │   ├── gau.txt
        │   ├── all_urls.txt
        │   ├── params_urls.txt
        │   ├── sensitive_files.txt
        │   ├── categorized.txt
        │   ├── ssrf_prone.txt
        │   ├── idor_hint.txt
        │   ├── old_version.txt
        │   ├── exposed_tool.txt
        │   └── path_traversal.txt
        ├── js/
        │   ├── js_files.txt
        │   ├── js_endpoints.txt
        │   ├── js_secrets.txt
        │   └── js_emails.txt
        ├── params/
        │   ├── endpoints_input.txt
        │   ├── arjun_results.json
        │   └── discovered_params.txt
        ├── security/
        │   ├── all_headers.txt
        │   ├── security_analysis.txt
        │   ├── missing_headers.txt
        │   ├── insecure_cookies.txt
        │   ├── nuclei_results.txt
        │   ├── takeover.txt
        │   └── cors_results.txt
        ├── dirbrute/
        │   ├── ffuf_results.json
        │   ├── ffuf_results.txt
        │   └── found_paths.txt
        └── report/
            ├── report_example.com.md
            └── report_example.com.txt
```

## Fitur

- **Pilih fase** — tidak perlu jalankan semua, pilih dengan `--fase`
- **Multi target** — gunakan `-f` untuk recon banyak domain sekaligus
- **Summary prioritas** — bagian atas report langsung highlight temuan penting
- **Configurable** — semua setting bisa di-override via environment variable
- **Universal** — tidak terikat ke target atau sistem tertentu

## Instalasi

### 1. Install dependensi Python

```bash
pip install -r requirements.txt
```

### 2. Install semua tools recon

Pilih sesuai OS:

```bash
# Linux (Kali, Ubuntu, Debian)
chmod +x install.sh && ./install.sh

# macOS
chmod +x install-mac.sh && ./install-mac.sh
```

Script ini menginstall: nmap, subfinder, httpx, nuclei, ffuf, katana, dan tools lainnya secara otomatis. Wordlist juga diunduh otomatis jika belum ada di sistem.

```bash
# 3. Muat ulang konfigurasi shell
source ~/.bashrc  # atau source ~/.zshrc
```


## Referensi Tools

Framework ini berdiri di atas berbagai *open-source tools* hebat buatan komunitas *security research*. Berikut daftar tools yang dipanggil oleh recon.io beserta link referensinya:

*   **Subfinder**: [ProjectDiscovery](https://github.com/projectdiscovery/subfinder)
*   **Amass**: [OWASP](https://github.com/owasp-amass/amass)
*   **AlterX**: [ProjectDiscovery](https://github.com/projectdiscovery/alterx)
*   **Dnsx**: [ProjectDiscovery](https://github.com/projectdiscovery/dnsx)
*   **Httpx**: [ProjectDiscovery](https://github.com/projectdiscovery/httpx)
*   **Nmap**: [Nmap.org](https://nmap.org/)
*   **Naabu**: [ProjectDiscovery](https://github.com/projectdiscovery/naabu)
*   **Wafw00f**: [EnableSecurity](https://github.com/EnableSecurity/wafw00f)
*   **Katana**: [ProjectDiscovery](https://github.com/projectdiscovery/katana)
*   **Gau**: [lc](https://github.com/lc/gau)
*   **Waybackurls**: [tomnomnom](https://github.com/tomnomnom/waybackurls)
*   **Nuclei**: [ProjectDiscovery](https://github.com/projectdiscovery/nuclei)
*   **Arjun**: [s0md3v](https://github.com/s0md3v/Arjun)
*   **Subzy**: [PentestPad](https://github.com/PentestPad/subzy)
*   **Ffuf**: [Ffuf](https://github.com/ffuf/ffuf)
*   **SecLists (Wordlists)**: [Daniel Miessler](https://github.com/danielmiessler/SecLists)

Apresiasi besar untuk para kreator alat-alat di atas! 👏

## Referensi Writeups

Untuk mempelajari teknik dan studi kasus pengintaian (*recon*) tingkat lanjut, silakan baca dokumentasi [WRITEUPS_REF.md](WRITEUPS_REF.md).

# recon.io

Universal web recon framework untuk bug bounty hunting.

> **Kenapa tools ini dibuat?**  
> Tools ini dibuat karena awalnya merasa ribet dan bingung jika harus menggunakan tools recon satu per satu secara manual. Framework ini dirancang khusus dan sangat cocok untuk **pemula yang ingin terjun ke dunia perhuntingan** (Bug Bounty/Pentesting).
>
> Setelah semua laporan hasil recon keluar, pastikan untuk melakukan **review dan pentest manual** guna mencari _chain exploit_ selanjutnya. Script ini **hanya ditujukan untuk mengintai (recon)** dan mengumpulkan informasi awal mengenai target

![recon.io banner](banner.png)


## Penggunaan

```bash
python recon.py -t example.com
python recon.py -f targets.txt
python recon.py -t example.com --fase subdomain,dns,ports
python recon.py -t example.com -o ~/hasil
python recon.py -t example.com --no-resume
```

## Argumen

| Argumen       | Keterangan                                 |
| ------------- | ------------------------------------------ |
| `-t DOMAIN`   | satu target domain                         |
| `-f FILE`     | file berisi daftar target (satu per baris) |
| `-o DIR`      | folder output (default: ~/recon-output)    |
| `--fase FASE` | pilih fase tertentu, pisah koma            |
| `--no-resume` | mulai dari awal, abaikan checkpoint        |
| `--list-fase` | tampilkan daftar fase                      |

## Fase

| #   | Fase        | Tools                                |
| --- | ----------- | ------------------------------------ |
| 1   | subdomain   | subfinder, alterx, dnsx, httpx       |
| 2   | dns         | whois, dig                           |
| 3   | ports       | naabu, nmap                          |
| 4   | fingerprint | httpx, wafw00f, curl                 |
| 5   | urls        | gau                                  |
| 6   | js          | curl + regex (linkfinder jika ada)   |
| 7   | security    | curl, nuclei                         |
| 8   | dork        | generator (tidak butuh tools)        |
| 9   | dirbrute    | ffuf                                 |

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
| `RECON_OUTPUT_DIR`      | `~/recon-output` | folder output             |
| `RECON_TIMEOUT`         | `300`            | timeout global (detik)    |
| `RECON_TIMEOUT_<FASE>`  | bervariasi       | timeout per fase          |
| `RECON_THREADS`         | `10`             | jumlah thread             |
| `RECON_USER_AGENT`      | Chrome UA        | user agent string         |
| `RECON_TOOL_<NAME>`     | nama tool        | path ke binary tool       |
| `RECON_WORDLIST`        | auto-detect      | path ke wordlist dirbrute |
| `RECON_TOOL_LINKFINDER` | _(kosong)_       | path ke linkfinder.py     |

## Struktur output

```
~/recon-output/
└── example.com/
    └── 20250101_120000/
        ├── .checkpoint.json     <- progress resume
        ├── subdomain/
        │   ├── subfinder.txt
        │   ├── alterx_permutations.txt
        │   ├── resolved_permutations.txt
        │   ├── all_subdomains.txt
        │   └── alive_subdomains.txt
        ├── dns/
        │   ├── whois.txt
        │   ├── dns_records.txt
        │   └── zone_transfer.txt
        ├── ports/
        │   ├── nmap_top1000.txt
        │   ├── nmap_http.txt
        │   └── open_ports.txt
        ├── fingerprint/
        │   ├── httpx_tech.json
        │   ├── waf.txt
        │   ├── headers.txt
        │   └── tech_stack.txt
        ├── urls/
        │   ├── gau.txt
        │   ├── all_urls.txt
        │   ├── interesting_urls.txt
        │   ├── params_urls.txt
        │   └── sensitive_files.txt
        ├── js/
        │   ├── js_files.txt
        │   ├── js_endpoints.txt
        │   ├── js_secrets.txt
        │   └── js_emails.txt
        ├── security/
        │   ├── all_headers.txt
        │   ├── security_analysis.txt
        │   ├── missing_headers.txt
        │   ├── insecure_cookies.txt
        │   └── nuclei_results.txt
        ├── dork/
        │   ├── dork_queries.txt
        │   ├── shodan_queries.txt
        │   └── censys_queries.txt
        ├── dirbrute/
        │   ├── dirb_results.txt
        │   └── found_paths.txt
        └── report/
            ├── report_example.com.md
            └── report_example.com.txt
```

## Fitur

- **Resume/checkpoint** — kalau crash, jalankan ulang dan lanjut dari fase terakhir
- **Pilih fase** — tidak perlu jalankan semua, pilih dengan `--fase`
- **Multi target** — gunakan `-f` untuk recon banyak domain sekaligus
- **Summary prioritas** — bagian atas report langsung highlight temuan penting
- **Configurable** — semua setting bisa di-override via environment variable
- **Universal** — tidak terikat ke target atau sistem tertentu

## Instalasi tools (opsional)

```bash
# apt
sudo apt install nmap curl whois dnsutils wafw00f

# go
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest

# linkfinder (opsional)
git clone https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder
pip3 install -r /opt/linkfinder/requirements.txt
export RECON_TOOL_LINKFINDER=/opt/linkfinder/linkfinder.py
```

Tools yang tidak ada akan dilewati otomatis, recon tetap berjalan.

## Referensi Tools

Framework ini berdiri di atas berbagai *open-source tools* hebat buatan komunitas *security research*. Berikut daftar tools yang dipanggil oleh recon.io beserta link referensinya:

*   **Subfinder**: [ProjectDiscovery](https://github.com/projectdiscovery/subfinder)
*   **AlterX**: [ProjectDiscovery](https://github.com/projectdiscovery/alterx)
*   **Dnsx**: [ProjectDiscovery](https://github.com/projectdiscovery/dnsx)
*   **Httpx**: [ProjectDiscovery](https://github.com/projectdiscovery/httpx)
*   **Nmap**: [Nmap.org](https://nmap.org/)
*   **Naabu**: [ProjectDiscovery](https://github.com/projectdiscovery/naabu)
*   **Wafw00f**: [EnableSecurity](https://github.com/EnableSecurity/wafw00f)
*   **Gau**: [lc](https://github.com/lc/gau)
*   **Nuclei**: [ProjectDiscovery](https://github.com/projectdiscovery/nuclei)
*   **Ffuf**: [Ffuf](https://github.com/ffuf/ffuf)
*   **LinkFinder**: [GerbenJavado](https://github.com/GerbenJavado/LinkFinder)
*   **SecLists (Wordlists)**: [Daniel Miessler](https://github.com/danielmiessler/SecLists)

Apresiasi besar untuk para kreator alat-alat di atas! 👏

## License

MIT

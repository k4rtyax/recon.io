"""
Generate laporan recon dalam format .md dan .txt.
Bagian atas laporan berisi ringkasan temuan penting (auto-highlight).
"""

import os
from datetime import datetime
from core.utils import read_lines, count_lines


def _count(path: str) -> int:
    return count_lines(path) if os.path.exists(path) else 0


class Report:
    def __init__(self, target: str, target_dir: str):
        self.target     = target
        self.target_dir = target_dir
        self.started    = datetime.now()
        self.md_path    = os.path.join(target_dir, "report", f"report_{target}.md")
        self.txt_path   = os.path.join(target_dir, "report", f"report_{target}.txt")
        os.makedirs(os.path.dirname(self.md_path), exist_ok=True)
        self._sections_md  = []
        self._sections_txt = []

    # ── helpers ──────────────────────────────────────────────────

    def add_section(self, title: str, md_content: str, txt_content: str = ""):
        self._sections_md.append(f"## {title}\n\n{md_content}\n\n---\n")
        self._sections_txt.append(
            f"\n{'='*56}\n{title}\n{'='*56}\n{txt_content or md_content}\n"
        )

    def _read_head(self, path: str, n: int = 30) -> str:
        lines = read_lines(path)
        if not lines:
            return "tidak ada hasil"
        block = "\n".join(lines[:n])
        if len(lines) > n:
            block += f"\n... ({len(lines) - n} baris lagi)"
        return block

    # ── header + ringkasan prioritas ─────────────────────────────

    def get_stats(self) -> dict:
        d = self.target_dir
        cors_findings = 0
        cors_file = f"{d}/security/cors_results.txt"
        if os.path.exists(cors_file):
            with open(cors_file) as f:
                lines = [l for l in f.read().splitlines() if l.strip() and "no cors" not in l.lower()]
            cors_findings = len(lines)
        return {
            "alive_sub":    _count(f"{d}/subdomain/alive_subdomains.txt"),
            "total_sub":    _count(f"{d}/subdomain/all_subdomains.txt"),
            "open_ports":   _count(f"{d}/ports/open_ports.txt"),
            "total_urls":   _count(f"{d}/urls/all_urls.txt"),
            "categorized":  _count(f"{d}/urls/categorized.txt"),
            "params_urls":  _count(f"{d}/urls/params_urls.txt"),
            "js_ep":        _count(f"{d}/js/js_endpoints.txt"),
            "secrets":      _count(f"{d}/js/js_secrets.txt"),
            "missing_hdrs": _count(f"{d}/security/missing_headers.txt"),
            "cookies_bad":  _count(f"{d}/security/insecure_cookies.txt"),
            "takeover":     _count(f"{d}/security/takeover.txt"),
            "disc_params":  _count(f"{d}/params/discovered_params.txt"),
            "cors":         cors_findings,
        }

    def _build_summary(self) -> tuple[str, str]:
        s            = self.get_stats()
        alive_sub    = s["alive_sub"]
        total_sub    = s["total_sub"]
        open_ports   = s["open_ports"]
        total_urls   = s["total_urls"]
        categorized  = s["categorized"]
        params_urls  = s["params_urls"]
        js_ep        = s["js_ep"]
        secrets      = s["secrets"]
        missing_hdrs = s["missing_hdrs"]
        cookies_bad  = s["cookies_bad"]
        takeover     = s["takeover"]
        disc_params  = s["disc_params"]
        cors_findings = s["cors"]

        # tentukan prioritas temuan
        findings = []
        if secrets > 0:
            findings.append(f"[!] Potential secrets ditemukan : {secrets}")
        if takeover > 0:
            findings.append(f"[!] Subdomain takeover candidate: {takeover}")
        if cors_findings > 0:
            findings.append(f"[!] CORS misconfiguration       : {cors_findings}")
        if disc_params > 0:
            findings.append(f"[!] Hidden params ditemukan     : {disc_params}")
        if categorized > 0:
            findings.append(f"[i] URL terkategorisasi         : {categorized}")
        if params_urls > 0:
            findings.append(f"[i] URL berparameter            : {params_urls}")
        if js_ep > 0:
            findings.append(f"[i] JS endpoints                : {js_ep}")
        if missing_hdrs > 0:
            findings.append(f"[i] Missing security headers    : {missing_hdrs}")
        if cookies_bad > 0:
            findings.append(f"[i] Insecure cookies            : {cookies_bad}")
        if open_ports > 0:
            findings.append(f"[i] Open ports                  : {open_ports}")

        findings_text = "\n".join(findings) if findings else "tidak ada temuan menonjol"

        md = f"""# Recon Report — {self.target}

**Target**   : `{self.target}`
**Tanggal**  : {self.started.strftime('%Y-%m-%d %H:%M')}

### Ringkasan metrik

| Metrik | Nilai |
|--------|------:|
| Subdomain ditemukan | {total_sub} |
| Subdomain aktif | {alive_sub} |
| Open ports | {open_ports} |
| Total URLs | {total_urls} |
| URL terkategorisasi | {categorized} |
| URL berparameter | {params_urls} |
| JS endpoints | {js_ep} |
| Potential secrets | {secrets} |
| Hidden params | {disc_params} |
| Takeover candidates | {takeover} |
| CORS issues | {cors_findings} |
| Missing headers | {missing_hdrs} |
| Insecure cookies | {cookies_bad} |

### Temuan prioritas

```
{findings_text}
```

---

"""

        txt_findings = "\n".join(findings) if findings else "  tidak ada temuan menonjol"

        txt = f"""
{'='*56}
RECON REPORT — {self.target}
{'='*56}
Target   : {self.target}
Tanggal  : {self.started.strftime('%Y-%m-%d %H:%M')}

RINGKASAN METRIK
  Subdomain ditemukan : {total_sub}
  Subdomain aktif     : {alive_sub}
  Open ports          : {open_ports}
  Total URLs          : {total_urls}
  URL terkategorisasi : {categorized}
  URL berparameter    : {params_urls}
  JS endpoints        : {js_ep}
  Potential secrets   : {secrets}
  Hidden params       : {disc_params}
  Takeover candidates : {takeover}
  CORS issues         : {cors_findings}
  Missing headers     : {missing_hdrs}
  Insecure cookies    : {cookies_bad}

TEMUAN PRIORITAS
{txt_findings}

"""
        return md, txt

    # ── fase-fase laporan ─────────────────────────────────────────

    def fase_subdomain(self):
        d = self.target_dir
        # Gunakan info file jika ada, fallback ke clean domain file
        info_file = f"{d}/subdomain/alive_subdomains_info.txt"
        if os.path.exists(info_file) and _count(info_file) > 0:
            alive = self._read_head(info_file)
        else:
            alive = self._read_head(f"{d}/subdomain/alive_subdomains.txt")
            
        md  = f"**Alive subdomains**\n\n```\n{alive}\n```\n"
        self.add_section("Fase 1: Subdomain Enumeration", md)

    def fase_dns(self):
        d = self.target_dir
        records = self._read_head(f"{d}/dns/dns_records.txt")
        md  = f"```\n{records}\n```\n"
        self.add_section("Fase 2: DNS Records", md)

    def fase_ports(self):
        d = self.target_dir
        ports = self._read_head(f"{d}/ports/open_ports.txt")
        md  = f"```\n{ports}\n```\n"
        self.add_section("Fase 3: Port Scan", md)

    def fase_fingerprint(self):
        d = self.target_dir
        waf = self._read_head(f"{d}/fingerprint/waf.txt", 10)
        tech = self._read_head(f"{d}/fingerprint/tech_stack.txt", 20)
        md = f"**WAF**\n\n```\n{waf}\n```\n\n**Tech stack**\n\n```\n{tech}\n```\n"
        self.add_section("Fase 4: Fingerprinting", md)

    def fase_urls(self):
        d = self.target_dir
        categorized = self._read_head(f"{d}/urls/categorized.txt", 40)
        params      = self._read_head(f"{d}/urls/params_urls.txt")
        sensitive   = self._read_head(f"{d}/urls/sensitive_files.txt", 20)
        md = (
            f"**URL terkategorisasi**\n\n```\n{categorized}\n```\n\n"
            f"**URLs berparameter**\n\n```\n{params}\n```\n\n"
            f"**File sensitif**\n\n```\n{sensitive}\n```\n"
        )
        self.add_section("Fase 5: URL Gathering", md)

    def fase_js(self):
        d = self.target_dir
        endpoints = self._read_head(f"{d}/js/js_endpoints.txt")
        secrets   = self._read_head(f"{d}/js/js_secrets.txt")
        md = (
            f"**Endpoints ditemukan**\n\n```\n{endpoints}\n```\n\n"
            f"**Potential secrets**\n\n```\n{secrets}\n```\n"
        )
        self.add_section("Fase 6: JS Analysis", md)

    def fase_security(self):
        d = self.target_dir
        missing  = self._read_head(f"{d}/security/missing_headers.txt")
        cookies  = self._read_head(f"{d}/security/insecure_cookies.txt")

        md = (
            f"**Missing security headers**\n\n```\n{missing}\n```\n\n"
            f"**Insecure cookies**\n\n```\n{cookies}\n```\n"
        )

        nuclei_file = f"{d}/security/nuclei_results.txt"
        if os.path.exists(nuclei_file):
            vulns = self._read_head(nuclei_file, 50)
            md += f"\n**Vulnerabilities (Nuclei)**\n\n```\n{vulns}\n```\n"

        takeover_file = f"{d}/security/takeover.txt"
        if os.path.exists(takeover_file):
            takeover = self._read_head(takeover_file, 20)
            md += f"\n**Subdomain Takeover candidates**\n\n```\n{takeover}\n```\n"

        cors_file = f"{d}/security/cors_results.txt"
        if os.path.exists(cors_file):
            cors = self._read_head(cors_file, 20)
            md += f"\n**CORS Misconfiguration**\n\n```\n{cors}\n```\n"

        self.add_section("Fase 7: Security Headers & Vuln Scan", md)

    def fase_params(self):
        d = self.target_dir
        params  = self._read_head(f"{d}/params/discovered_params.txt")
        md = f"**Hidden parameters ditemukan**\n\n```\n{params}\n```\n"
        self.add_section("Fase 7b: Parameter Discovery", md)

    def fase_dirbrute(self):
        d = self.target_dir
        found = self._read_head(f"{d}/dirbrute/ffuf_results.txt")
        md = f"```\n{found}\n```\n"
        self.add_section("Fase 8: Directory Bruteforce", md)

    # ── tulis ke disk ─────────────────────────────────────────────

    def save(self):
        summary_md, summary_txt = self._build_summary()

        with open(self.md_path, "w") as f:
            f.write(summary_md)
            for s in self._sections_md:
                f.write(s)
            f.write(
                f"\n---\n*dibuat otomatis oleh recon.io "
                f"— {datetime.now().strftime('%Y-%m-%d %H:%M')}*\n"
                f"*wajib verifikasi manual sebelum submit*\n"
            )

        with open(self.txt_path, "w") as f:
            f.write(summary_txt)
            for s in self._sections_txt:
                f.write(s)
            f.write(
                f"\n{'='*56}\n"
                f"dibuat: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                f"wajib verifikasi manual sebelum submit\n"
            )

        return self.md_path, self.txt_path

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

    def _build_summary(self) -> tuple[str, str]:
        d = self.target_dir

        alive_sub   = _count(f"{d}/subdomain/alive_subdomains.txt")
        total_sub   = _count(f"{d}/subdomain/all_subdomains.txt")
        open_ports  = _count(f"{d}/ports/open_ports.txt")
        interesting = _count(f"{d}/urls/interesting_urls.txt")
        params      = _count(f"{d}/urls/params_urls.txt")
        js_ep       = _count(f"{d}/js/js_endpoints.txt")
        secrets     = _count(f"{d}/js/js_secrets.txt")
        missing_hdrs= _count(f"{d}/security/missing_headers.txt")
        cookies_bad = _count(f"{d}/security/insecure_cookies.txt")
        total_urls  = _count(f"{d}/urls/all_urls.txt")

        # tentukan prioritas temuan
        findings = []
        if secrets > 0:
            findings.append(f"[!] Potential secrets ditemukan : {secrets}")
        if params > 0:
            findings.append(f"[!] URL dengan parameter        : {params}")
        if interesting > 0:
            findings.append(f"[!] Interesting URLs            : {interesting}")
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
| Interesting URLs | {interesting} |
| URL berparameter | {params} |
| JS endpoints | {js_ep} |
| Potential secrets | {secrets} |
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
  Interesting URLs    : {interesting}
  URL berparameter    : {params}
  JS endpoints        : {js_ep}
  Potential secrets   : {secrets}
  Missing headers     : {missing_hdrs}
  Insecure cookies    : {cookies_bad}

TEMUAN PRIORITAS
{txt_findings}

"""
        return md, txt

    # ── fase-fase laporan ─────────────────────────────────────────

    def fase_subdomain(self):
        d = self.target_dir
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
        interesting = self._read_head(f"{d}/urls/interesting_urls.txt")
        params      = self._read_head(f"{d}/urls/params_urls.txt")
        md = (
            f"**Interesting URLs**\n\n```\n{interesting}\n```\n\n"
            f"**URLs berparameter**\n\n```\n{params}\n```\n"
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
        self.add_section("Fase 7: Security Headers", md)

    def fase_dork(self):
        d = self.target_dir
        dorks = self._read_head(f"{d}/dork/dork_queries.txt")
        md = f"```\n{dorks}\n```\n"
        self.add_section("Fase 8: Google Dork", md)

    def fase_dirbrute(self):
        d = self.target_dir
        found = self._read_head(f"{d}/dirbrute/dirb_results.txt")
        md = f"```\n{found}\n```\n"
        self.add_section("Fase 9: Directory Bruteforce", md)

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

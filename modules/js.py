"""
Fase 6: JS Analysis
Ambil file JS dari URL list, ekstrak endpoint dan potential secrets.
"""

import os
import re
from urllib.parse import urlparse
from core.utils import info, warn, run as exec_cmd, read_lines, write_lines, tool_available
from config import SECRET_PATTERNS, DEFAULT_USER_AGENT, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out      = os.path.join(target_dir, "js")
    urls_dir = os.path.join(target_dir, "urls")
    all_urls = read_lines(os.path.join(urls_dir, "all_urls.txt"))
    t = TIMEOUTS["js"]

    # ── ambil semua URL .js ───────────────────────────────────────
    js_urls = [u for u in all_urls if urlparse(u).path.endswith(".js")]
    js_urls_file = os.path.join(out, "js_files.txt")
    write_lines(js_urls_file, js_urls)
    info(f"JS files ditemukan: {len(js_urls)}")

    endpoints_all = []
    secrets_all   = []
    emails_all    = []

    endpoint_re = re.compile(
        r"""(?:path|endpoint|api|href|action)\s*[:=]\s*['"]([/][^'"]{2,})['"]""",
        re.IGNORECASE,
    )
    email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    secret_res = [re.compile(p, re.IGNORECASE) for p in SECRET_PATTERNS]

    # ── download & analisis tiap file JS ─────────────────────────
    for js_url in js_urls[:50]:  # batasi 50 file
        code, content, _ = exec_cmd(
            ["curl", "-sL", "-A", DEFAULT_USER_AGENT,
             "--max-time", "15", js_url],
            timeout=t,
        )
        if code != 0 or not content:
            continue

        # endpoints
        for m in endpoint_re.finditer(content):
            endpoints_all.append(m.group(1))

        # emails
        for m in email_re.finditer(content):
            emails_all.append(m.group(0))

        # secrets
        for srx in secret_res:
            for m in srx.finditer(content):
                snippet = content[max(0, m.start()-20):m.end()+20].strip()
                secrets_all.append(f"[{js_url}] {snippet}")

    # ── simpan hasil ─────────────────────────────────────────────
    write_lines(os.path.join(out, "js_endpoints.txt"), sorted(set(endpoints_all)))
    write_lines(os.path.join(out, "js_secrets.txt"),   sorted(set(secrets_all)))
    write_lines(os.path.join(out, "js_emails.txt"),    sorted(set(emails_all)))

    info(f"endpoints: {len(set(endpoints_all))}")
    info(f"potential secrets: {len(set(secrets_all))}")
    info(f"emails: {len(set(emails_all))}")

    # ── linkfinder (opsi) ─────────────────────────────────────
    lf_path = TOOLS["linkfinder"]
    if lf_path and os.path.exists(lf_path) and js_urls:
        lf_out = os.path.join(out, "linkfinder.txt")
        lf_results = []
        for js_url in js_urls[:20]:
            code, stdout, _ = exec_cmd(
                ["python3", lf_path, "-i", js_url, "-o", "cli"],
                timeout=t,
            )
            if stdout:
                lf_results.append(f"=== {js_url} ===\n{stdout}")
        if lf_results:
            with open(lf_out, "w") as f:
                f.write("\n".join(lf_results) + "\n")
        info("linkfinder selesai")

"""
Fase 6: JS Analysis
Ambil file JS dari URL list, ekstrak endpoint dan potential secrets.
"""

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from core.utils import info, warn, run as exec_cmd, read_lines, write_lines, tool_available, get_working_url
from config import SECRET_PATTERNS, DEFAULT_USER_AGENT, TIMEOUTS, TOOLS

_JS_WORKERS = 10


def run(target: str, target_dir: str):
    out      = os.path.join(target_dir, "js")
    urls_dir = os.path.join(target_dir, "urls")
    all_urls_path = os.path.join(urls_dir, "all_urls.txt")
    t = TIMEOUTS["js"]

    if not os.path.exists(all_urls_path):
        warn("all_urls.txt tidak ditemukan — jalankan fase 'urls' terlebih dahulu")
        return

    all_urls = read_lines(all_urls_path)

    # ── ambil semua URL .js (filter in-scope & resolusi URL relatif) ──
    base_url = get_working_url(target)
    js_urls = []
    target_domain = target.lower()

    for u in all_urls:
        u = u.strip()
        if not u:
            continue
        try:
            parsed = urlparse(u)
            # Jika relatif, gabungkan dengan base_url
            if not parsed.scheme:
                if u.startswith("/"):
                    js_url = f"{base_url}{u}"
                else:
                    js_url = f"{base_url}/{u}"
                parsed = urlparse(js_url)
            else:
                js_url = u
                
            if parsed.path.endswith(".js"):
                hostname = parsed.netloc.lower()
                if ":" in hostname:
                    hostname = hostname.split(":")[0]
                if hostname == target_domain or hostname.endswith("." + target_domain):
                    js_urls.append(js_url)
        except Exception:
            pass

    js_urls = sorted(set(js_urls))
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

    # ── download & analisis tiap file JS (paralel) ───────────────
    def _fetch_and_parse(js_url: str):
        code, content, _ = exec_cmd(
            ["curl", "-sfL", "-A", DEFAULT_USER_AGENT, "--max-time", "15", js_url],
            timeout=t,
        )
        if code != 0 or not content:
            return [], [], []
        eps  = [m.group(1) for m in endpoint_re.finditer(content)]
        ems  = [m.group(0) for m in email_re.finditer(content)]
        secs = []
        for srx in secret_res:
            for m in srx.finditer(content):
                snippet = content[max(0, m.start()-20):m.end()+20].strip()
                secs.append(f"[{js_url}] {snippet}")
        return eps, ems, secs

    with ThreadPoolExecutor(max_workers=_JS_WORKERS) as executor:
        futures = {executor.submit(_fetch_and_parse, u): u for u in js_urls[:50]}
        for future in as_completed(futures):
            eps, ems, secs = future.result()
            endpoints_all.extend(eps)
            emails_all.extend(ems)
            secrets_all.extend(secs)

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

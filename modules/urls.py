"""
Fase 5: URL Gathering
Menggunakan Katana untuk perayapan aktif (crawling) dan pemetaan endpoint API/JS.
"""

import os
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines
from config import INTERESTING_PATTERNS, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "urls")
    all_file  = os.path.join(out, "all_urls.txt")
    t = TIMEOUTS["urls"]

    # ── katana ───────────────────────────────────────────────────
    if tool_available(TOOLS["katana"]):
        kat_out = os.path.join(out, "katana.txt")
        exec_cmd(
            [
                TOOLS["katana"], "-u", f"https://{target}",
                "-silent", "-jc", "-o", kat_out
            ],
            timeout=t,
        )
        info("katana crawling selesai")
    else:
        warn("katana tidak ditemukan, URL gathering dilewati")
        warn("install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return

    # ── ambil & deduplikat hasil ───────────────────────────────────
    all_urls = []
    if os.path.exists(kat_out):
        all_urls = read_lines(kat_out)

    all_urls = sorted(set(all_urls))
    write_lines(all_file, all_urls)
    info(f"total URLs: {len(all_urls)}")

    # ── filter: interesting ───────────────────────────────────────
    interesting_file = os.path.join(out, "interesting_urls.txt")
    interesting = [
        u for u in all_urls
        if any(p in u.lower() for p in INTERESTING_PATTERNS)
    ]
    write_lines(interesting_file, interesting)
    info(f"interesting URLs: {len(interesting)}")

    # ── filter: berparameter ─────────────────────────────────────
    params_file = os.path.join(out, "params_urls.txt")
    params = [u for u in all_urls if "?" in u and "=" in u]
    write_lines(params_file, params)
    info(f"URLs berparameter: {len(params)}")

    # ── filter: sensitive files ───────────────────────────────────
    sens_file = os.path.join(out, "sensitive_files.txt")
    sens_exts = [".sql", ".bak", ".zip", ".tar", ".gz", ".env",
                 ".git", ".log", ".conf", ".config", ".xml", ".json"]
    sensitive = [u for u in all_urls if any(u.endswith(e) for e in sens_exts)]
    write_lines(sens_file, sensitive)
    info(f"sensitive files: {len(sensitive)}")

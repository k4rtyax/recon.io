"""
Fase 5: URL Gathering
gau + waybackurls, lalu filter interesting & berparameter.
"""

import os
import shlex
from core.utils import info, warn, run as exec_cmd, run_shell as exec_shell, tool_available, read_lines, write_lines, dedupe_file
from config import INTERESTING_PATTERNS, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "urls")
    all_file  = os.path.join(out, "all_urls.txt")
    t = TIMEOUTS["urls"]

    # ── gau ──────────────────────────────────────────────────────
    if tool_available(TOOLS["gau"]):
        gau_out = os.path.join(out, "gau.txt")
        safe_target = shlex.quote(target)
        safe_out = shlex.quote(gau_out)
        exec_shell(f"{TOOLS['gau']} {safe_target} > {safe_out} 2>/dev/null", timeout=t)
        info("gau selesai")
    else:
        warn("gau tidak ditemukan, dilewati")

    # ── waybackurls ──────────────────────────────────────────────
    if tool_available(TOOLS["waybackurls"]):
        wb_out = os.path.join(out, "wayback.txt")
        safe_target = shlex.quote(target)
        safe_out = shlex.quote(wb_out)
        exec_shell(f"echo {safe_target} | {TOOLS['waybackurls']} > {safe_out} 2>/dev/null", timeout=t)
        info("waybackurls selesai")
    else:
        warn("waybackurls tidak ditemukan, dilewati")

    # ── gabungkan + deduplikat ───────────────────────────────────
    sources = ["gau.txt", "wayback.txt"]
    all_urls = []
    for src in sources:
        path = os.path.join(out, src)
        if os.path.exists(path):
            all_urls += read_lines(path)

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

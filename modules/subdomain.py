"""
Fase 1: Subdomain Enumeration
Menggunakan subfinder untuk pencarian pasif, diikuti httpx untuk probe keaktifan host.
"""

import os
from core.utils import info, warn, run as exec_cmd, run_shell as exec_shell, dedupe_file, tool_available
from config import TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "subdomain")
    all_file   = os.path.join(out, "all_subdomains.txt")
    alive_file = os.path.join(out, "alive_subdomains.txt")
    t = TIMEOUTS["subdomain"]

    # ── subfinder ────────────────────────────────────────────────
    if tool_available(TOOLS["subfinder"]):
        sf_out = os.path.join(out, "subfinder.txt")
        exec_cmd([TOOLS["subfinder"], "-d", target, "-silent", "-o", sf_out], timeout=t)
        info("subfinder selesai")
    else:
        warn("subfinder tidak ditemukan, subdomain enumeration dilewati")
        warn("install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return

    # ── ambil & deduplikat hasil ───────────────────────────────────
    lines = []
    if os.path.exists(sf_out):
        with open(sf_out) as f:
            lines = [l.strip() for l in f if l.strip()]

    with open(all_file, "w") as f:
        for line in sorted(set(lines)):
            f.write(line + "\n")

    # ── httpx: cek yang aktif ─────────────────────────────────────
    if tool_available(TOOLS["httpx"]) and os.path.exists(all_file):
        exec_cmd(
            [
                TOOLS["httpx"], "-l", all_file,
                "-silent", "-title", "-status-code", "-tech-detect",
                "-o", alive_file,
            ],
            timeout=t,
        )
        info("httpx probe selesai")
    else:
        warn("httpx tidak ditemukan, alive check dilewati")

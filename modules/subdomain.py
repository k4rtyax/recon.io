"""
Fase 1: Subdomain Enumeration
Menggunakan subfinder, assetfinder, amass.
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
        warn("subfinder tidak ditemukan, dilewati")

    # ── assetfinder ──────────────────────────────────────────────
    if tool_available(TOOLS["assetfinder"]):
        af_out = os.path.join(out, "assetfinder.txt")
        code, stdout, _ = exec_cmd([TOOLS["assetfinder"], "--subs-only", target], timeout=t)
        if code == 0 and stdout:
            with open(af_out, "w") as f:
                f.write(stdout)
        info("assetfinder selesai")
    else:
        warn("assetfinder tidak ditemukan, dilewati")

    # ── amass (passive saja, cepat) ───────────────────────────────
    if tool_available(TOOLS["amass"]):
        am_out = os.path.join(out, "amass.txt")
        exec_cmd(
            [TOOLS["amass"], "enum", "-passive", "-d", target, "-o", am_out],
            timeout=t,
        )
        info("amass selesai")
    else:
        warn("amass tidak ditemukan, dilewati")

    # ── gabungkan + deduplikat ───────────────────────────────────
    sources = ["subfinder.txt", "assetfinder.txt", "amass.txt"]
    lines = []
    for src in sources:
        path = os.path.join(out, src)
        if os.path.exists(path):
            with open(path) as f:
                lines += [l.strip() for l in f if l.strip()]

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

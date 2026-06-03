"""
Fase 1: Subdomain Enumeration
Menggunakan subfinder untuk pencarian pasif, diikuti AlterX untuk pembuatan tebakan permutasi,
dnsx untuk resolusi DNS, dan httpx untuk probe keaktifan host.
"""

import os
import json
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines
from config import TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "subdomain")
    all_file   = os.path.join(out, "all_subdomains.txt")
    alive_file = os.path.join(out, "alive_subdomains.txt")
    t = TIMEOUTS["subdomain"]

    # ── 1. subfinder (Pencarian Pasif) ────────────────────────────
    sf_out = os.path.join(out, "subfinder.txt")
    if tool_available(TOOLS["subfinder"]):
        exec_cmd([TOOLS["subfinder"], "-d", target, "-silent", "-o", sf_out], timeout=t)
        info("subfinder selesai")
    else:
        warn("subfinder tidak ditemukan, subdomain enumeration dilewati")
        warn("install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return

    # ── 2. alterx & dnsx (Pembuatan Permutasi & Resolusi DNS) ──────
    alterx_available = tool_available(TOOLS["alterx"])
    dnsx_available   = tool_available(TOOLS["dnsx"])

    resolved_file = os.path.join(out, "resolved_permutations.txt")
    
    if alterx_available and dnsx_available:
        info("menjalankan AlterX untuk tebakan permutasi subdomain...")
        alt_out = os.path.join(out, "alterx_permutations.txt")
        exec_cmd(
            [
                TOOLS["alterx"], "-l", sf_out,
                "-silent", "-o", alt_out
            ],
            timeout=t
        )
        info("AlterX selesai")

        info("menjalankan dnsx untuk resolusi DNS aktif...")
        exec_cmd(
            [
                TOOLS["dnsx"], "-l", alt_out,
                "-silent", "-o", resolved_file
            ],
            timeout=t
        )
        info("dnsx selesai")
    else:
        if not alterx_available:
            warn("alterx tidak ditemukan, melewati tahap permutasi")
            warn("install: go install github.com/projectdiscovery/alterx/cmd/alterx@latest")
        if not dnsx_available:
            warn("dnsx tidak ditemukan, melewati tahap resolusi DNS aktif")
            warn("install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")

    # ── 3. Penggabungan & Deduplikasi ──────────────────────────────
    subdomains = []
    
    # Ambil hasil pasif subfinder
    if os.path.exists(sf_out):
        subdomains += read_lines(sf_out)
        
    # Ambil hasil aktif permutasi (jika ada)
    if os.path.exists(resolved_file):
        subdomains += read_lines(resolved_file)

    subdomains = sorted(set(subdomains))
    write_lines(all_file, subdomains)
    info(f"total subdomain ditemukan (pasif + permutasi): {len(subdomains)}")

    # ── 4. httpx (Cek Keaktifan Web) ───────────────────────────────
    if tool_available(TOOLS["httpx"]) and os.path.exists(all_file):
        httpx_json = os.path.join(out, "httpx_alive.json")
        alive_info = os.path.join(out, "alive_subdomains_info.txt")
        exec_cmd(
            [
                TOOLS["httpx"], "-l", all_file,
                "-silent", "-title", "-status-code", "-tech-detect",
                "-json", "-o", httpx_json,
            ],
            timeout=t,
        )
        
        # Parse JSON untuk pisahkan clean domain & metadata
        clean_domains = []
        info_lines = []
        if os.path.exists(httpx_json):
            with open(httpx_json) as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url:
                            clean_domains.append(url)
                            status = data.get("status_code", 0)
                            title = data.get("title", "")
                            tech = ",".join(data.get("technologies", data.get("tech", [])))
                            info_lines.append(f"{url} [{status}] [{title}] [{tech}]")
                    except Exception:
                        pass
        
        write_lines(alive_file, clean_domains)
        write_lines(alive_info, info_lines)
        info(f"httpx probe selesai, alive: {len(clean_domains)}")
    else:
        warn("httpx tidak ditemukan, alive check dilewati")

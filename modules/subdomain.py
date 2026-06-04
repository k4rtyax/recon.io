"""
Fase 1: Subdomain Enumeration
Menggunakan subfinder untuk pencarian pasif, diikuti AlterX untuk pembuatan tebakan permutasi,
dnsx untuk resolusi DNS, dan httpx untuk probe keaktifan host.
"""

import os
import re
import json
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines
from config import TIMEOUTS, TOOLS


def _amass_major_version() -> int | None:
    """Deteksi major version amass dari `amass -version`. None bila gagal dibaca."""
    _, out, errout = exec_cmd([TOOLS["amass"], "-version"], timeout=10)
    m = re.search(r"v?(\d+)\.\d+", f"{out}\n{errout}")
    return int(m.group(1)) if m else None


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "subdomain")
    all_file   = os.path.join(out, "all_subdomains.txt")
    alive_file = os.path.join(out, "alive_subdomains.txt")
    t = TIMEOUTS["subdomain"]

    # ── 1a. subfinder (Pencarian Pasif) ──────────────────────────
    sf_out = os.path.join(out, "subfinder.txt")
    if tool_available(TOOLS["subfinder"]):
        exec_cmd([TOOLS["subfinder"], "-d", target, "-silent", "-o", sf_out], timeout=t)
        info("subfinder selesai")
    else:
        warn("subfinder tidak ditemukan, subdomain enumeration dilewati")
        return

    # ── 1b. amass (Pasif) ────────────────────────────────────────
    # Universal lintas-versi: amass v5+ memakai arsitektur engine/database
    # (subcommand engine/enum/subs) dan akan menggantung pada invokasi
    # one-shot gaya v4 — itu dilewati (subfinder sudah cover passive enum).
    # Timeout amass dibatasi agar tak pernah menghabiskan jatah fase.
    amass_out = os.path.join(out, "amass.txt")
    if tool_available(TOOLS["amass"]):
        major = _amass_major_version()
        if major is not None and major >= 5:
            warn(f"amass v{major} memakai arsitektur engine (bukan one-shot), dilewati — passive enum dicover subfinder")
        else:
            exec_cmd(
                [TOOLS["amass"], "enum", "-passive", "-d", target, "-o", amass_out],
                timeout=min(t, 180),
            )
            info("amass selesai")
    else:
        warn("amass tidak ditemukan, passive enum tambahan dilewati")

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
                "-wd", target,
                "-wt", "5",
                "-silent", "-o", resolved_file
            ],
            timeout=t
        )
        info("dnsx selesai")
    else:
        if not alterx_available:
            warn("alterx tidak ditemukan, melewati tahap permutasi")
        if not dnsx_available:
            warn("dnsx tidak ditemukan, melewati tahap resolusi DNS aktif")

    # ── 3. Penggabungan & Deduplikasi ──────────────────────────────
    subdomains = []

    for src in [sf_out, amass_out, resolved_file]:
        if os.path.exists(src):
            subdomains += read_lines(src)

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
                            tech_list = data.get("technologies") or data.get("tech") or []
                            tech = ",".join(tech_list)
                            info_lines.append(f"{url} [{status}] [{title}] [{tech}]")
                    except Exception as e:
                        warn(f"gagal parse baris httpx JSON: {e}")
        
        write_lines(alive_file, clean_domains)
        write_lines(alive_info, info_lines)
        info(f"httpx probe selesai, alive: {len(clean_domains)}")
    else:
        warn("httpx tidak ditemukan, alive check dilewati")

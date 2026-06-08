"""
Fase 1: Subdomain Enumeration
Subfinder (pasif) → AlterX (permutasi) → dnsx (resolusi) → httpx (alive probe).
Wildcard DNS dan HTTP catch-all dideteksi dan dipisah secara otomatis.
"""

import os
import re
import json
import socket
import random
import string
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines
from config import TIMEOUTS, TOOLS


def _amass_major_version() -> int | None:
    """Deteksi major version amass dari `amass -version`. None bila gagal dibaca."""
    _, out, errout = exec_cmd([TOOLS["amass"], "-version"], timeout=10)
    m = re.search(r"v?(\d+)\.\d+", f"{out}\n{errout}")
    return int(m.group(1)) if m else None


def _wildcard_ips(target: str) -> set[str]:
    """Probe subdomain acak untuk mendeteksi wildcard DNS. Return set IP, kosong jika tidak ada."""
    probe = "wc-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "." + target
    try:
        return {r[4][0] for r in socket.getaddrinfo(probe, None)}
    except OSError:
        return set()


def _filter_dns_wildcards(hosts: list[str], wc_ips: set[str]) -> tuple[list[str], int]:
    """Hapus host yang hanya resolve ke wildcard IP. Pakai thread pool untuk kecepatan."""
    if not wc_ips:
        return hosts, 0

    def _is_wildcard(host: str) -> bool:
        try:
            ips = {r[4][0] for r in socket.getaddrinfo(host, None)}
            return bool(ips) and ips.issubset(wc_ips)
        except OSError:
            # NXDOMAIN atau timeout → bukan wildcard yang confirm, tetap simpan
            return False

    kept, dropped = [], 0
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_is_wildcard, h): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                if fut.result():
                    dropped += 1
                else:
                    kept.append(host)
            except Exception:
                kept.append(host)
    return kept, dropped


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

    # ── 2. alterx & dnsx (Permutasi & Resolusi DNS) ──────────────
    alterx_available = tool_available(TOOLS["alterx"])
    dnsx_available   = tool_available(TOOLS["dnsx"])
    resolved_file = os.path.join(out, "resolved_permutations.txt")

    if alterx_available and dnsx_available:
        info("menjalankan AlterX untuk tebakan permutasi subdomain...")
        alt_out = os.path.join(out, "alterx_permutations.txt")
        exec_cmd(
            [TOOLS["alterx"], "-l", sf_out, "-silent", "-o", alt_out],
            timeout=t
        )
        info("AlterX selesai")

        info("menjalankan dnsx untuk resolusi DNS aktif...")
        exec_cmd(
            [TOOLS["dnsx"], "-l", alt_out, "-wd", target, "-wt", "5", "-silent", "-o", resolved_file],
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

    # ── 3a. Filter wildcard DNS ────────────────────────────────────
    wc_ips = _wildcard_ips(target)
    if wc_ips:
        warn(f"wildcard DNS terdeteksi: {target} → {', '.join(sorted(wc_ips))}")
        write_lines(
            os.path.join(out, "wildcard_dns.txt"),
            [f"# Wildcard IPs untuk {target}"] + sorted(wc_ips),
        )
        subdomains, dropped = _filter_dns_wildcards(subdomains, wc_ips)
        if dropped:
            info(f"dibuang {dropped} subdomain yang hanya resolve ke wildcard IP")

    write_lines(all_file, subdomains)
    info(f"total subdomain (pasif + permutasi): {len(subdomains)}")

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

        entries = []
        if os.path.exists(httpx_json):
            with open(httpx_json) as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception as e:
                        warn(f"gagal parse baris httpx JSON: {e}")

        # ── 4a. Deteksi HTTP catch-all vhost ──────────────────────
        if entries:
            fp_counter = Counter(
                (e.get("status_code", 0), e.get("content_length", -1), e.get("title", ""))
                for e in entries
            )
            total = len(entries)
            # fingerprint yang mendominasi >40% hasil dengan lebih dari 3 entri = catch-all
            catchall_fps = {
                fp for fp, cnt in fp_counter.items()
                if cnt > 3 and cnt / total > 0.4
            }

            if catchall_fps:
                dominated = sum(fp_counter[fp] for fp in catchall_fps)
                warn(f"HTTP catch-all terdeteksi: {dominated}/{total} host punya respons identik")
                real_entries, catchall_urls, seen_fps = [], [], set()
                for e in entries:
                    fp = (e.get("status_code", 0), e.get("content_length", -1), e.get("title", ""))
                    if fp in catchall_fps:
                        catchall_urls.append(e.get("url", ""))
                        if fp not in seen_fps:
                            seen_fps.add(fp)
                            real_entries.append(e)  # satu representatif per fingerprint
                    else:
                        real_entries.append(e)
                write_lines(
                    os.path.join(out, "catchall_subdomains.txt"),
                    [u for u in catchall_urls if u],
                )
                info(f"disimpan {len(catchall_urls)} catch-all ke catchall_subdomains.txt")
                entries = real_entries

        # Ekstrak domain bersih dan info
        clean_domains, info_lines = [], []
        for data in entries:
            url = data.get("url", "")
            if url:
                clean_domains.append(url)
                status = data.get("status_code", 0)
                title = data.get("title", "")
                tech_list = data.get("technologies") or data.get("tech") or []
                tech = ",".join(tech_list)
                info_lines.append(f"{url} [{status}] [{title}] [{tech}]")

        write_lines(alive_file, clean_domains)
        write_lines(alive_info, info_lines)
        info(f"httpx probe selesai, alive: {len(clean_domains)}")
    else:
        warn("httpx tidak ditemukan, alive check dilewati")

"""
Fase 9: Directory Bruteforce
Menggunakan dirb atau ffuf (fallback).
"""

import os
from core.utils import info, warn, run as exec_cmd, tool_available
from config import DEFAULT_USER_AGENT, TIMEOUTS, TOOLS, WORDLIST_PATHS


def _find_wordlist() -> str | None:
    for path in WORDLIST_PATHS:
        if path and os.path.exists(path):
            return path
    return None


def run(target: str, target_dir: str):
    out       = os.path.join(target_dir, "dirbrute")
    url       = f"https://{target}"
    wordlist  = _find_wordlist()
    result_file = os.path.join(out, "dirb_results.txt")
    t = TIMEOUTS["dirbrute"]

    if not wordlist:
        warn("wordlist tidak ditemukan, dirbrute dilewati")
        warn("install: apt install dirb seclists")
        warn("atau set env: RECON_WORDLIST=/path/to/wordlist.txt")
        return

    # ── coba dirb dulu ────────────────────────────────────────────
    if tool_available(TOOLS["dirb"]):
        exec_cmd(
            [
                TOOLS["dirb"], url, wordlist,
                "-o", result_file,
                "-r",           # tidak rekursif (cepat)
                "-S",           # silent (tanpa progress)
                "-a", DEFAULT_USER_AGENT,
                "-t",           # add trailing slash
            ],
            timeout=t,
        )
        info("dirb selesai")
        _extract_found(result_file, out)
        return

    # ── fallback: ffuf ────────────────────────────────────────────
    if tool_available(TOOLS["ffuf"]):
        ffuf_out = os.path.join(out, "ffuf_results.json")
        exec_cmd(
            [
                TOOLS["ffuf"],
                "-u", f"{url}/FUZZ",
                "-w", wordlist,
                "-H", f"User-Agent: {DEFAULT_USER_AGENT}",
                "-mc", "200,201,204,301,302,307,401,403",
                "-o", ffuf_out,
                "-of", "json",
                "-t", "50",
                "-timeout", "10",
            ],
            timeout=t,
        )
        info("ffuf selesai")
        return

    warn("dirb dan ffuf tidak ditemukan, dirbrute dilewati")


def _extract_found(dirb_file: str, out_dir: str):
    """Ekstrak baris CODE:200/301/302/403 dari output dirb."""
    if not os.path.exists(dirb_file):
        return
    found = []
    with open(dirb_file) as f:
        for line in f:
            if "CODE:2" in line or "CODE:3" in line or "CODE:403" in line:
                found.append(line.strip())
    with open(os.path.join(out_dir, "found_paths.txt"), "w") as f:
        f.write("\n".join(found))
    info(f"path ditemukan: {len(found)}")

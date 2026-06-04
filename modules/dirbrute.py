"""
Fase 8: Directory Bruteforce
Menggunakan ffuf (modern Go-based fuzzer) sebagai default utama.
"""

import os
import json
import urllib.request
from core.utils import info, warn, run as exec_cmd, tool_available, get_working_url
from config import DEFAULT_USER_AGENT, TIMEOUTS, TOOLS, WORDLIST_PATHS

_WORDLIST_URL     = "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt"
_WORDLIST_BUNDLED = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists", "common.txt")


def _find_wordlist() -> str | None:
    for path in WORDLIST_PATHS:
        if path and os.path.exists(path) and os.path.getsize(path) > 0:
            return path
    return _download_wordlist()


def _download_wordlist() -> str | None:
    """Download wordlist fallback ke wordlists/common.txt jika tidak ada di sistem."""
    os.makedirs(os.path.dirname(_WORDLIST_BUNDLED), exist_ok=True)
    info("wordlist tidak ditemukan, mengunduh fallback...")
    try:
        urllib.request.urlretrieve(_WORDLIST_URL, _WORDLIST_BUNDLED)
        if os.path.getsize(_WORDLIST_BUNDLED) > 0:
            info(f"wordlist diunduh ke: {_WORDLIST_BUNDLED}")
            return _WORDLIST_BUNDLED
        # file ada tapi kosong — hapus agar tidak dipakai
        os.remove(_WORDLIST_BUNDLED)
    except Exception as e:
        warn(f"gagal mengunduh wordlist: {e}")
        if os.path.exists(_WORDLIST_BUNDLED):
            os.remove(_WORDLIST_BUNDLED)
    return None


def run(target: str, target_dir: str):
    out       = os.path.join(target_dir, "dirbrute")
    url       = get_working_url(target)
    wordlist  = _find_wordlist()
    result_file = os.path.join(out, "ffuf_results.txt")
    ffuf_out  = os.path.join(out, "ffuf_results.json")
    t = TIMEOUTS["dirbrute"]

    if not wordlist:
        warn("wordlist tidak ditemukan, dirbrute dilewati")
        return

    # ── Gunakan ffuf sebagai alat utama ───────────────────────────
    if tool_available(TOOLS["ffuf"]):
        info("menjalankan ffuf directory brute-force...")
        code, stdout, stderr = exec_cmd(
            [
                TOOLS["ffuf"],
                "-u", f"{url}/FUZZ",
                "-w", wordlist,
                "-H", f"User-Agent: {DEFAULT_USER_AGENT}",
                "-mc", "200,201,204,301,302,307,401",  # dihapus 403 karena sering false positive dari WAF
                "-ac",  # auto-calibrate: otomatis deteksi & filter soft 404 / catch-all
                "-o", ffuf_out,
                "-of", "json",
                "-t", "50",
                "-timeout", "10",
            ],
            timeout=t,
        )
        info("ffuf selesai")
        _parse_ffuf_results(ffuf_out, result_file, out)
        return

    warn("ffuf tidak ditemukan, dirbrute dilewati")


def _parse_ffuf_results(json_file: str, txt_file: str, out_dir: str):
    """Ekstrak hasil dari ffuf_results.json dan tulis ke ffuf_results.txt dan found_paths.txt"""
    if not os.path.exists(json_file):
        warn("file hasil ffuf tidak ditemukan")
        return

    try:
        with open(json_file) as f:
            data = json.load(f)
    except Exception as e:
        warn(f"gagal membaca JSON hasil ffuf: {e}")
        return

    results = data.get("results", [])
    formatted_lines = []

    for r in results:
        # ambil url, status, length, redirect
        status = r.get("status")
        length = r.get("length")
        url = r.get("url")
        redirect = r.get("redirectlocation", "")
        
        line = f"[{status}] {url} (size: {length})"
        if redirect:
            line += f" -> {redirect}"
        
        formatted_lines.append(line)

    # Tulis ke ffuf_results.txt agar dibaca oleh report.py (menjaga kompatibilitas)
    with open(txt_file, "w") as f:
        f.write("\n".join(formatted_lines) + "\n")

    # Tulis ke found_paths.txt sebagai cadangan ringkas
    with open(os.path.join(out_dir, "found_paths.txt"), "w") as f:
        f.write("\n".join(formatted_lines) + "\n")

    info(f"path ditemukan: {len(formatted_lines)}")

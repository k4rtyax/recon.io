"""
Fase: Parameter Discovery
Gunakan arjun untuk menemukan hidden parameter di endpoint penting.
Input: idor_hint, exposed_tool, params_urls, ssrf_prone, path_traversal (dari fase urls)
"""

import os
import json
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines
from config import TIMEOUTS, TOOLS, DEFAULT_USER_AGENT


def run(target: str, target_dir: str):
    out      = os.path.join(target_dir, "params")
    urls_dir = os.path.join(target_dir, "urls")
    t        = TIMEOUTS["params"]

    if not tool_available(TOOLS["arjun"]):
        warn("arjun tidak ditemukan, parameter discovery dilewati")
        return

    # Kumpulkan endpoint prioritas dari output fase urls
    target_files = [
        os.path.join(urls_dir, "idor_hint.txt"),
        os.path.join(urls_dir, "exposed_tool.txt"),
        os.path.join(urls_dir, "params_urls.txt"),
        os.path.join(urls_dir, "ssrf_prone.txt"),
        os.path.join(urls_dir, "path_traversal.txt"),
    ]

    endpoints = []
    for f in target_files:
        if os.path.exists(f):
            endpoints += read_lines(f)

    # Deduplikasi & batasi jumlah endpoint
    endpoints = list(dict.fromkeys(e for e in endpoints if e.strip()))[:100]

    if not endpoints:
        warn("tidak ada endpoint untuk di-scan parameter discovery")
        info("pastikan fase 'urls' sudah dijalankan terlebih dahulu")
        return

    info(f"parameter discovery pada {len(endpoints)} endpoint...")

    all_results = []
    endpoints_input = os.path.join(out, "endpoints_input.txt")
    write_lines(endpoints_input, endpoints)

    arjun_out = os.path.join(out, "arjun_results.json")
    code, stdout, stderr = exec_cmd(
        [
            TOOLS["arjun"],
            "-i", endpoints_input,
            "-oJ", arjun_out,
            "-t", "10",
            "--headers", f"User-Agent: {DEFAULT_USER_AGENT}",
            "-q",
        ],
        timeout=t,
    )

    # Parse hasil JSON arjun
    if os.path.exists(arjun_out):
        try:
            with open(arjun_out) as f:
                data = json.load(f)
            for url, val in data.items():
                # arjun bisa mengembalikan {url: [params]} atau
                # {url: {"params": [...], "method": ...}} tergantung versi
                params = val.get("params", []) if isinstance(val, dict) else val
                for p in (params or []):
                    all_results.append(f"{url} → param: {p}")
        except Exception as e:
            warn(f"gagal parse hasil arjun: {e}")

    if not all_results and stdout.strip():
        all_results = [l for l in stdout.splitlines() if l.strip()]

    results_file = os.path.join(out, "discovered_params.txt")
    write_lines(results_file, all_results)
    info(f"parameter ditemukan: {len(all_results)}")
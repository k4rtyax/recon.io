"""
Fase 3: Port Scanning
Menggunakan nmap (top 1000 ports + service detection).
"""

import os
import re
from core.utils import info, warn, run as exec_cmd, tool_available
from config import TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "ports")
    t = TIMEOUTS["ports"]

    if not tool_available(TOOLS["nmap"]):
        warn("nmap tidak ditemukan, fase port scan dilewati")
        return

    # ── nmap top 1000 ports ───────────────────────────────────────
    nmap_out = os.path.join(out, "nmap_top1000.txt")
    exec_cmd(
        [
            TOOLS["nmap"], "-sV", "--open",
            "-T4", "--top-ports", "1000",
            "-oN", nmap_out,
            target,
        ],
        timeout=t,
    )
    info("nmap top-1000 selesai")

    # ── nmap port 80/443/8080/8443 dengan script http ─────────────
    nmap_http = os.path.join(out, "nmap_http.txt")
    exec_cmd(
        [
            TOOLS["nmap"], "-sV", "--open",
            "-p", "80,443,8080,8443,8000,3000,5000",
            "--script", "http-title,http-headers,http-methods",
            "-oN", nmap_http,
            target,
        ],
        timeout=t,
    )
    info("nmap http scan selesai")

    # ── ekstrak open ports ke file ringkas ───────────────────────
    open_ports_file = os.path.join(out, "open_ports.txt")
    _extract_open_ports(nmap_out, open_ports_file)


def _extract_open_ports(nmap_file: str, out_file: str):
    if not os.path.exists(nmap_file):
        return
    pattern = re.compile(r"^(\d+/\w+)\s+open\s+(\S+)\s*(.*)")
    lines = []
    with open(nmap_file) as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                port, service, version = m.groups()
                lines.append(f"{port:<20} {service:<20} {version.strip()}")
    with open(out_file, "w") as f:
        f.write("\n".join(lines))

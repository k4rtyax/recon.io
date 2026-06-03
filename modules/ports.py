"""
Fase 3: Port Scanning
Menggunakan Naabu (fast port scanner) + Nmap (service detection pada port terbuka).
Fallback ke Nmap murni jika Naabu tidak terinstal.
"""

import os
import re
from core.utils import info, warn, run as exec_cmd, tool_available
from config import TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "ports")
    t = TIMEOUTS["ports"]

    nmap_available  = tool_available(TOOLS["nmap"])
    naabu_available = tool_available(TOOLS["naabu"])

    if not nmap_available and not naabu_available:
        warn("nmap dan naabu tidak ditemukan, fase port scan dilewati")
        return

    nmap_out = os.path.join(out, "nmap_top1000.txt")
    nmap_http = os.path.join(out, "nmap_http.txt")
    open_ports_file = os.path.join(out, "open_ports.txt")

    # ── ALUR 1: NAABU (Fast Scan) + NMAP (Service Detection) ───────
    if naabu_available:
        info("menggunakan Naabu untuk pemindaian port cepat...")
        naabu_out = os.path.join(out, "naabu.txt")
        
        # Jalankan naabu (top 1000 ports)
        exec_cmd(
            [
                TOOLS["naabu"], "-host", target,
                "-top-ports", "1000", "-silent",
                "-o", naabu_out
            ],
            timeout=t
        )
        
        # Parse port yang terbuka
        ports = []
        if os.path.exists(naabu_out):
            with open(naabu_out) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if ":" in line:
                        parts = line.split(":")
                        port = parts[-1].strip()
                        if port.isdigit():
                            ports.append(port)
                    elif line.isdigit():
                        ports.append(line)
        
        ports = sorted(list(set(ports)), key=int)
        
        if not ports:
            info("tidak ada port terbuka yang ditemukan oleh Naabu")
            with open(open_ports_file, "w") as f:
                f.write("")
            return

        info(f"Naabu menemukan {len(ports)} port terbuka: {', '.join(ports)}")

        # Simpan list port mentah dulu sebagai cadangan ke open_ports.txt
        with open(open_ports_file, "w") as f:
            for p in ports:
                f.write(f"{p}/tcp               unknown              \n")

        # Jika nmap ada, lakukan deteksi service pada port terbuka tersebut
        if nmap_available:
            ports_str = ",".join(ports)
            info("menjalankan Nmap service detection pada port yang terbuka...")
            exec_cmd(
                [
                    TOOLS["nmap"], "-sV", "--open",
                    "-p", ports_str, "-T4",
                    "-oN", nmap_out,
                    target,
                ],
                timeout=t,
            )
            
            # Ekstrak data service ke open_ports.txt
            _extract_open_ports(nmap_out, open_ports_file)

            # Cek jika ada port HTTP yang terbuka untuk di-scan script
            http_candidate_ports = {"80", "443", "8080", "8443", "8000", "3000", "5000"}
            open_http_ports = [p for p in ports if p in http_candidate_ports]
            if open_http_ports:
                info(f"menjalankan Nmap HTTP scripts pada port: {', '.join(open_http_ports)}...")
                exec_cmd(
                    [
                        TOOLS["nmap"], "-sV", "--open",
                        "-p", ",".join(open_http_ports),
                        "--script", "http-title,http-headers,http-methods",
                        "-oN", nmap_http,
                        target,
                    ],
                    timeout=t,
                )
        else:
            warn("nmap tidak ditemukan, detail deteksi service dilewati")
        
        return

    # ── ALUR 2: FALLBACK NMAP MURNI ───────────────────────────────
    if nmap_available:
        warn("naabu tidak ditemukan, menggunakan fallback Nmap murni (lebih lambat)...")
        # nmap top 1000 ports
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

        # Parse port yang terbuka dari nmap_out untuk HTTP script scan
        ports = []
        if os.path.exists(nmap_out):
            pattern = re.compile(r"^(\d+)/tcp\s+open")
            with open(nmap_out) as f:
                for line in f:
                    m = pattern.match(line.strip())
                    if m:
                        ports.append(m.group(1))

        # Cek jika ada port HTTP yang terbuka untuk di-scan script
        http_candidate_ports = {"80", "443", "8080", "8443", "8000", "3000", "5000"}
        open_http_ports = [p for p in ports if p in http_candidate_ports]
        if open_http_ports:
            info(f"menjalankan Nmap HTTP scripts pada port: {', '.join(open_http_ports)}...")
            exec_cmd(
                [
                    TOOLS["nmap"], "-sV", "--open",
                    "-p", ",".join(open_http_ports),
                    "--script", "http-title,http-headers,http-methods",
                    "-oN", nmap_http,
                    target,
                ],
                timeout=t,
            )
            info("nmap http scan selesai")
        else:
            info("tidak ada port HTTP terbuka untuk pemindaian HTTP scripts")

        # ekstrak open ports ke file ringkas
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
    
    # Cek hasil dulu sebelum overwrite. Jika kosong, jangan timpa file yang ada.
    if lines:
        with open(out_file, "w") as f:
            f.write("\n".join(lines) + "\n")
    elif not os.path.exists(out_file):
        with open(out_file, "w") as f:
            f.write("")


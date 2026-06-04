"""
Fase 2: DNS Records
Menggunakan whois dan dig.
"""

import os
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines
from config import TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "dns")
    t = TIMEOUTS["dns"]

    if not tool_available(TOOLS["dig"]):
        warn("dig tidak ditemukan, fase DNS dilewati")
        return

    # ── whois ────────────────────────────────────────────────────
    if tool_available(TOOLS["whois"]):
        code, stdout, _ = exec_cmd([TOOLS["whois"], target], timeout=t)
        if stdout:
            with open(os.path.join(out, "whois.txt"), "w") as f:
                f.write(stdout)
        info("whois selesai")
    else:
        warn("whois tidak ditemukan, dilewati")

    # ── dig records / dnsx ────────────────────────────────────────
    records_file = os.path.join(out, "dns_records.txt")
    alive_subdomains_file = os.path.join(target_dir, "subdomain", "alive_subdomains.txt")
    
    clean_hosts = []
    if os.path.exists(alive_subdomains_file):
        for line in read_lines(alive_subdomains_file):
            host = line.replace("http://", "").replace("https://", "").split("/")[0]
            if host:
                clean_hosts.append(host)
                
    if clean_hosts and tool_available(TOOLS["dnsx"]):
        info("menjalankan dnsx untuk resolusi DNS massal subdomain...")
        temp_dns_file = os.path.join(out, "temp_dns_targets.txt")
        write_lines(temp_dns_file, clean_hosts)
        
        exec_cmd(
            [
                TOOLS["dnsx"], "-l", temp_dns_file,
                "-recon", "-resp", "-nc", "-silent",
                "-o", records_file
            ],
            timeout=t
        )
        
        if os.path.exists(temp_dns_file):
            os.remove(temp_dns_file)
        info("dnsx records selesai")
    else:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        all_records = []

        for rtype in record_types:
            code, stdout, _ = exec_cmd([TOOLS["dig"], "+short", target, rtype], timeout=t)
            if stdout.strip():
                all_records.append(f"--- {rtype} ---")
                all_records.append(stdout.strip())

        with open(records_file, "w") as f:
            f.write("\n".join(all_records))

        info("dig records selesai")

    # ── zone transfer attempt ─────────────────────────────────────
    # ambil nameserver dulu
    _, ns_out, _ = exec_cmd([TOOLS["dig"], "+short", target, "NS"], timeout=t)
    ns_list = [ns.strip().rstrip(".") for ns in ns_out.splitlines() if ns.strip()]

    axfr_file = os.path.join(out, "zone_transfer.txt")
    axfr_results = []
    for ns in ns_list:
        code, stdout, _ = exec_cmd([TOOLS["dig"], f"@{ns}", target, "AXFR"], timeout=t)
        if stdout and "Transfer failed" not in stdout:
            axfr_results.append(f"=== AXFR via {ns} ===\n{stdout}")
    if axfr_results:
        with open(axfr_file, "w") as f:
            f.write("\n".join(axfr_results) + "\n")

    info("zone transfer check selesai")

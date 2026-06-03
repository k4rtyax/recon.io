"""
Fase 2: DNS Records
Menggunakan whois dan dig.
"""

import os
from core.utils import info, warn, run as exec_cmd, tool_available
from config import TIMEOUTS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "dns")
    t = TIMEOUTS["dns"]

    # ── whois ────────────────────────────────────────────────────
    if tool_available("whois"):
        code, stdout, _ = exec_cmd(["whois", target], timeout=t)
        if stdout:
            with open(os.path.join(out, "whois.txt"), "w") as f:
                f.write(stdout)
        info("whois selesai")
    else:
        warn("whois tidak ditemukan, dilewati")

    # ── dig records ──────────────────────────────────────────────
    records_file = os.path.join(out, "dns_records.txt")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    all_records = []

    for rtype in record_types:
        code, stdout, _ = exec_cmd(["dig", "+short", target, rtype], timeout=t)
        if stdout.strip():
            all_records.append(f"--- {rtype} ---")
            all_records.append(stdout.strip())

    with open(records_file, "w") as f:
        f.write("\n".join(all_records))

    info("dig records selesai")

    # ── zone transfer attempt ─────────────────────────────────────
    # ambil nameserver dulu
    _, ns_out, _ = exec_cmd(["dig", "+short", target, "NS"], timeout=t)
    ns_list = [ns.strip().rstrip(".") for ns in ns_out.splitlines() if ns.strip()]

    axfr_file = os.path.join(out, "zone_transfer.txt")
    for ns in ns_list:
        code, stdout, _ = exec_cmd(["dig", f"@{ns}", target, "AXFR"], timeout=t)
        if stdout and "Transfer failed" not in stdout:
            with open(axfr_file, "a") as f:
                f.write(f"=== AXFR via {ns} ===\n{stdout}\n")

    info("zone transfer check selesai")

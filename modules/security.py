"""
Fase 7: Security Headers & Vulnerability Scanning
Cek header keamanan yang hilang, cookie flags, nuclei vulnerability scan.
"""

import os
from core.utils import info, warn, run as exec_cmd, write_lines, tool_available, get_working_url
from config import REQUIRED_SECURITY_HEADERS, DEFAULT_USER_AGENT, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "security")
    url = get_working_url(target)
    t = TIMEOUTS["security"]

    # ── ambil headers via curl ────────────────────────────────────
    code, stdout, _ = exec_cmd(
        ["curl", "-sI", "-L", "-A", DEFAULT_USER_AGENT,
         "--max-time", "15", url],
        timeout=t,
    )

    raw_hdrs_file = os.path.join(out, "all_headers.txt")
    with open(raw_hdrs_file, "w") as f:
        f.write(stdout)

    if code != 0 or not stdout.strip():
        warn(f"curl gagal mengambil headers (code={code}), security check dilewati")
        write_lines(os.path.join(out, "missing_headers.txt"), [])
        return

    header_names = {
        line.split(":")[0].strip().lower()
        for line in stdout.splitlines() if ":" in line
    }

    # ── cek security headers yang hilang ─────────────────────────
    missing = [h for h in REQUIRED_SECURITY_HEADERS if h.lower() not in header_names]
    missing_file = os.path.join(out, "missing_headers.txt")
    write_lines(missing_file, missing)
    info(f"missing security headers: {len(missing)}")

    # ── analisis header detail ────────────────────────────────────
    analysis = []
    for hdr in REQUIRED_SECURITY_HEADERS:
        status = "MISSING" if hdr.lower() not in header_names else "present"
        analysis.append(f"{status:<10} {hdr}")

    with open(os.path.join(out, "security_analysis.txt"), "w") as f:
        f.write("\n".join(analysis))

    # ── insecure cookies ─────────────────────────────────────────
    insecure = []
    for line in stdout.splitlines():
        if line.lower().startswith("set-cookie"):
            cookie_lower = line.lower()
            flags_missing = []
            if "httponly" not in cookie_lower:
                flags_missing.append("HttpOnly")
            if "secure" not in cookie_lower:
                flags_missing.append("Secure")
            if "samesite" not in cookie_lower:
                flags_missing.append("SameSite")
            if flags_missing:
                insecure.append(f"[missing: {', '.join(flags_missing)}] {line.strip()}")

    write_lines(os.path.join(out, "insecure_cookies.txt"), insecure)
    info(f"insecure cookies: {len(insecure)}")

    # ── nuclei ────────────────────────────────────────────────────
    if tool_available(TOOLS["nuclei"]):
        nuclei_out = os.path.join(out, "nuclei_results.txt")
        alive_file = os.path.join(target_dir, "subdomain", "alive_subdomains.txt")
        
        # Jika ada list subdomain dari Fase 1, scan semuanya sekaligus
        if os.path.exists(alive_file) and os.path.getsize(alive_file) > 0:
            info("menjalankan nuclei scan massal pada subdomain aktif...")
            nuclei_cmd = [
                TOOLS["nuclei"], "-list", alive_file,
                "-severity", "critical,high,medium",
                "-o", nuclei_out,
                "-silent"
            ]
        else:
            info("menjalankan nuclei scan pada target utama...")
            nuclei_cmd = [
                TOOLS["nuclei"], "-u", url,
                "-severity", "critical,high,medium",
                "-o", nuclei_out,
                "-silent"
            ]
            
        exec_cmd(nuclei_cmd, timeout=t)
        info("nuclei selesai")
    else:
        warn("nuclei tidak ditemukan, dilewati")

"""
Fase 7: Security Headers & Nikto
Cek header keamanan yang hilang, cookie flags, nikto scan.
"""

import os
from core.utils import info, warn, run as exec_cmd, write_lines, tool_available
from config import REQUIRED_SECURITY_HEADERS, DEFAULT_USER_AGENT, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "security")
    url = f"https://{target}"
    t = TIMEOUTS["security"]

    # ── ambil headers via curl ────────────────────────────────────
    code, stdout, _ = exec_cmd(
        ["curl", "-sI", "-A", DEFAULT_USER_AGENT,
         "--max-time", "15", url],
        timeout=t,
    )

    raw_hdrs_file = os.path.join(out, "all_headers.txt")
    with open(raw_hdrs_file, "w") as f:
        f.write(stdout)

    headers_lower = stdout.lower()

    # ── cek security headers yang hilang ─────────────────────────
    missing = [h for h in REQUIRED_SECURITY_HEADERS if h.lower() not in headers_lower]
    missing_file = os.path.join(out, "missing_headers.txt")
    write_lines(missing_file, missing)
    info(f"missing security headers: {len(missing)}")

    # ── analisis header detail ────────────────────────────────────
    analysis = []
    for hdr in REQUIRED_SECURITY_HEADERS:
        status = "MISSING" if hdr.lower() not in headers_lower else "present"
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

    # ── nikto ─────────────────────────────────────────────────────
    if tool_available(TOOLS["nikto"]):
        nikto_out = os.path.join(out, "nikto.txt")
        exec_cmd(
            [TOOLS["nikto"], "-h", url, "-o", nikto_out, "-Format", "txt",
             "-timeout", "10", "-maxtime", "300s"],
            timeout=t,
        )
        info("nikto selesai")
    else:
        warn("nikto tidak ditemukan, dilewati")

"""
Fase 7: Security Headers, Takeover, CORS & Vulnerability Scanning
"""

import os
from core.utils import info, warn, run as exec_cmd, write_lines, tool_available, get_working_url
from config import REQUIRED_SECURITY_HEADERS, DEFAULT_USER_AGENT, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "security")
    url = get_working_url(target)
    t   = TIMEOUTS["security"]

    # ── ambil headers via curl ────────────────────────────────────
    code, stdout, _ = exec_cmd(
        [TOOLS["curl"], "-sI", "-L", "-A", DEFAULT_USER_AGENT, "--max-time", "15", url],
        timeout=t,
    )

    with open(os.path.join(out, "all_headers.txt"), "w") as f:
        f.write(stdout)

    if code != 0 or not stdout.strip():
        warn(f"curl gagal mengambil headers (code={code}), security check dilewati")
        write_lines(os.path.join(out, "missing_headers.txt"), [])
        return

    header_names = {
        line.split(":")[0].strip().lower()
        for line in stdout.splitlines() if ":" in line
    }

    # ── missing security headers ──────────────────────────────────
    missing = [h for h in REQUIRED_SECURITY_HEADERS if h.lower() not in header_names]
    write_lines(os.path.join(out, "missing_headers.txt"), missing)
    info(f"missing security headers: {len(missing)}")

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

    # ── nuclei (vuln scan) ────────────────────────────────────────
    alive_file = os.path.join(target_dir, "subdomain", "alive_subdomains.txt")
    if tool_available(TOOLS["nuclei"]):
        nuclei_out = os.path.join(out, "nuclei_results.txt")
        if os.path.exists(alive_file) and os.path.getsize(alive_file) > 0:
            info("menjalankan nuclei scan massal pada subdomain aktif...")
            nuclei_cmd = [
                TOOLS["nuclei"], "-list", alive_file,
                "-severity", "critical,high,medium",
                "-o", nuclei_out, "-silent",
            ]
        else:
            info("menjalankan nuclei scan pada target utama...")
            nuclei_cmd = [
                TOOLS["nuclei"], "-u", url,
                "-severity", "critical,high,medium",
                "-o", nuclei_out, "-silent",
            ]
        exec_cmd(nuclei_cmd, timeout=t)
        info("nuclei selesai")
    else:
        warn("nuclei tidak ditemukan, dilewati")

    # ── subdomain takeover ────────────────────────────────────────
    takeover_out = os.path.join(out, "takeover.txt")
    if tool_available(TOOLS["subzy"]) and os.path.exists(alive_file):
        info("menjalankan subzy takeover check...")
        exec_cmd(
            [TOOLS["subzy"], "run", "--targets", alive_file, "--output", takeover_out],
            timeout=t,
        )
        info("subzy selesai")
    elif tool_available(TOOLS["nuclei"]) and os.path.exists(alive_file):
        info("menjalankan nuclei takeover templates...")
        exec_cmd(
            [
                TOOLS["nuclei"], "-list", alive_file,
                "-t", "http/takeovers/",
                "-o", takeover_out, "-silent",
            ],
            timeout=t,
        )
        info("nuclei takeover selesai")
    else:
        warn("takeover check dilewati — subzy tidak ada atau alive_subdomains.txt belum ada")

    # ── CORS misconfiguration ─────────────────────────────────────
    cors_out = os.path.join(out, "cors_results.txt")
    _check_cors(url, cors_out, t)


def _check_cors(url: str, out_file: str, timeout: int):
    """Test CORS dengan beberapa origin berbahaya dan refleksi null."""
    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]
    findings = []

    for origin in test_origins:
        code, stdout, _ = exec_cmd(
            [
                TOOLS["curl"], "-sI", "-A", "Mozilla/5.0",
                "-H", f"Origin: {origin}",
                "--max-time", "10", url,
            ],
            timeout=timeout,
        )
        if code != 0:
            continue

        headers_lower = stdout.lower()
        acao = ""
        acac = ""
        for line in stdout.splitlines():
            ll = line.lower()
            if ll.startswith("access-control-allow-origin"):
                acao = line.split(":", 1)[-1].strip()
            if ll.startswith("access-control-allow-credentials"):
                acac = line.split(":", 1)[-1].strip()

        if not acao:
            continue

        # Klasifikasi tingkat keparahan
        if acao == origin or acao == "*":
            severity = "CRITICAL" if acac.lower() == "true" else "MEDIUM"
            findings.append(
                f"[{severity}] Origin: {origin} → ACAO: {acao} | ACAC: {acac or 'not set'}"
            )

    if findings:
        write_lines(out_file, findings)
        info(f"CORS issues ditemukan: {len(findings)}")
        for finding in findings:
            warn(finding)
    else:
        write_lines(out_file, ["no cors issues found"])
        info("CORS: tidak ada misconfiguration terdeteksi")

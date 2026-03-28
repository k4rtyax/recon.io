"""
Fase 4: Fingerprinting
WhatWeb untuk tech stack, wafw00f untuk WAF detection.
"""

import os
from core.utils import info, warn, run as exec_cmd, tool_available
from config import DEFAULT_USER_AGENT, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "fingerprint")
    url = f"https://{target}"
    t = TIMEOUTS["fingerprint"]

    # ── whatweb ──────────────────────────────────────────────────
    if tool_available(TOOLS["whatweb"]):
        ww_out = os.path.join(out, "whatweb.txt")
        code, stdout, _ = exec_cmd(
            [TOOLS["whatweb"], "--user-agent", DEFAULT_USER_AGENT, "-a", "3",
             "--log-brief", ww_out, url],
            timeout=t,
        )
        # juga simpan tech stack
        tech_file = os.path.join(out, "tech_stack.txt")
        _parse_whatweb(ww_out, tech_file)
        info("whatweb selesai")
    else:
        warn("whatweb tidak ditemukan, dilewati")

    # ── wafw00f ──────────────────────────────────────────────────
    if tool_available(TOOLS["wafw00f"]):
        waf_out = os.path.join(out, "waf.txt")
        code, stdout, _ = exec_cmd([TOOLS["wafw00f"], url], timeout=t)
        with open(waf_out, "w") as f:
            f.write(stdout)
        info("wafw00f selesai")
    else:
        warn("wafw00f tidak ditemukan, dilewati")

    # ── headers via curl ─────────────────────────────────────────
    hdr_out = os.path.join(out, "headers.txt")
    code, stdout, _ = exec_cmd(
        ["curl", "-sI", "-A", DEFAULT_USER_AGENT,
         "--max-time", "15", url],
        timeout=t,
    )
    with open(hdr_out, "w") as f:
        f.write(stdout)
    info("headers grab selesai")


def _parse_whatweb(ww_file: str, tech_file: str):
    if not os.path.exists(ww_file):
        return
    techs = set()
    with open(ww_file) as f:
        for line in f:
            # whatweb brief format: URL [status] Tech1, Tech2[version], ...
            parts = line.split("]", 1)
            if len(parts) > 1:
                for tech in parts[1].split(","):
                    tech = tech.strip()
                    if tech:
                        techs.add(tech)
    with open(tech_file, "w") as f:
        for t in sorted(techs):
            f.write(t + "\n")

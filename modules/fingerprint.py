"""
Fase 4: Fingerprinting
httpx dengan -tech-detect untuk tech stack, wafw00f untuk WAF detection.
"""

import os
import json
from core.utils import info, warn, run as exec_cmd, tool_available
from config import DEFAULT_USER_AGENT, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "fingerprint")
    url = f"https://{target}"
    t = TIMEOUTS["fingerprint"]

    # ── httpx (technology detect) ─────────────────────────────────
    if tool_available(TOOLS["httpx"]):
        httpx_json = os.path.join(out, "httpx_tech.json")
        exec_cmd(
            [
                TOOLS["httpx"], "-u", target,
                "-silent", "-tech-detect", "-json",
                "-o", httpx_json
            ],
            timeout=t,
        )
        tech_file = os.path.join(out, "tech_stack.txt")
        _parse_httpx_tech(httpx_json, tech_file)
        info("httpx tech-detect selesai")
    else:
        warn("httpx tidak ditemukan, tech-detect dilewati")

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


def _parse_httpx_tech(json_file: str, tech_file: str):
    if not os.path.exists(json_file):
        return
    techs = set()
    try:
        with open(json_file) as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                # httpx returns a list of tech in 'tech' key
                for t in data.get("technologies", data.get("tech", [])):
                    techs.add(t)
    except Exception as e:
        warn(f"gagal membaca hasil teknologi httpx: {e}")
        
    with open(tech_file, "w") as f:
        for t in sorted(techs):
            f.write(t + "\n")

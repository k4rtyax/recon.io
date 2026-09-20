"""
Fase 4: Fingerprinting
httpx dengan -tech-detect untuk tech stack, wafw00f untuk WAF detection,
plus favicon hash (mmh3) untuk korelasi infrastruktur lewat Shodan/FOFA/ZoomEye.
"""

import os
import re
import ssl
import json
import base64
import urllib.request
from urllib.parse import urljoin
from core.utils import info, warn, run as exec_cmd, tool_available, get_working_url
from config import DEFAULT_USER_AGENT, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "fingerprint")
    url = get_working_url(target)
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
        [TOOLS["curl"], "-sI", "-L", "-A", DEFAULT_USER_AGENT,
         "--max-time", "15", url],
        timeout=t,
    )
    with open(hdr_out, "w") as f:
        f.write(stdout)
    info("headers grab selesai")

    # ── favicon hash ─────────────────────────────────────────────
    _favicon_hash(url, out)


def _ssl_ctx():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _fetch(url: str, timeout: int = 15) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return resp.read()
    except Exception:
        return None


def _favicon_url(base_url: str) -> str | None:
    """Coba /favicon.ico, kalau gagal ambil dari <link rel=icon> di homepage."""
    direct = urljoin(base_url + "/", "favicon.ico")
    if _fetch(direct):
        return direct

    html = _fetch(base_url)
    if not html:
        return None
    try:
        text = html.decode("utf-8", errors="ignore")
    except Exception:
        return None

    for tag in re.findall(r"<link\b[^>]*>", text, re.I):
        if not re.search(r"rel\s*=\s*[\"'][^\"']*icon", tag, re.I):
            continue
        href = re.search(r"href\s*=\s*[\"']([^\"']+)[\"']", tag, re.I)
        if href:
            return urljoin(base_url + "/", href.group(1))
    return None


def _favicon_hash(base_url: str, out: str):
    try:
        import mmh3
    except ImportError:
        warn("mmh3 tidak terpasang, favicon hash dilewati (pip install mmh3)")
        return

    ico_url = _favicon_url(base_url)
    if not ico_url:
        warn("favicon tidak ditemukan, hash dilewati")
        return

    data = _fetch(ico_url)
    if not data:
        warn("favicon gagal diunduh, hash dilewati")
        return

    fhash = mmh3.hash(base64.encodebytes(data))
    with open(os.path.join(out, "favicon_hash.txt"), "w") as f:
        f.write(f"favicon : {ico_url}\n")
        f.write(f"mmh3    : {fhash}\n\n")
        f.write("query untuk cari host lain dengan favicon sama:\n")
        f.write(f"  shodan : http.favicon.hash:{fhash}\n")
        f.write(f"  fofa   : icon_hash=\"{fhash}\"\n")
        f.write(f"  zoomeye: iconhash:\"{fhash}\"\n")
    info(f"favicon hash: {fhash}")


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
                for t in (data.get("technologies") or data.get("tech") or []):
                    techs.add(t)
    except Exception as e:
        warn(f"gagal membaca hasil teknologi httpx: {e}")
        
    with open(tech_file, "w") as f:
        for t in sorted(techs):
            f.write(t + "\n")

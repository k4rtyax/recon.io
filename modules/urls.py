"""
Fase 5: URL Gathering
Katana untuk crawling aktif + gau/waybackurls untuk URL historis.
Output dikategorikan: ssrf_prone, idor_hint, old_version, exposed_tool, path_traversal.
"""

import os
import re
from urllib.parse import urlparse, parse_qs
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines, get_working_url
from config import URL_CATEGORIES, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out      = os.path.join(target_dir, "urls")
    all_file = os.path.join(out, "all_urls.txt")
    t        = TIMEOUTS["urls"]

    all_urls = []

    # ── 1. katana (crawling aktif) ────────────────────────────────
    if tool_available(TOOLS["katana"]):
        kat_out = os.path.join(out, "katana.txt")
        url = get_working_url(target)
        exec_cmd(
            [TOOLS["katana"], "-u", url, "-silent", "-jc", "-o", kat_out],
            timeout=t,
        )
        if os.path.exists(kat_out):
            all_urls += read_lines(kat_out)
        info("katana selesai")
    else:
        warn("katana tidak ditemukan")

    # ── 2. gau / waybackurls (URL historis) ───────────────────────
    if tool_available(TOOLS["gau"]):
        gau_out = os.path.join(out, "gau.txt")
        exec_cmd([TOOLS["gau"], target, "--o", gau_out], timeout=t)
        if os.path.exists(gau_out):
            all_urls += read_lines(gau_out)
        info("gau selesai")
    elif tool_available(TOOLS["waybackurls"]):
        wb_out = os.path.join(out, "waybackurls.txt")
        code, stdout, _ = exec_cmd(
            ["bash", "-c", f"echo '{target}' | {TOOLS['waybackurls']}"],
            timeout=t,
        )
        if stdout.strip():
            write_lines(wb_out, stdout.splitlines())
            all_urls += stdout.splitlines()
        info("waybackurls selesai")
    else:
        warn("gau/waybackurls tidak ditemukan — URL historis dilewati")

    if not all_urls:
        warn("tidak ada URL yang berhasil dikumpulkan")
        return

    # ── 3. dedup & simpan semua ───────────────────────────────────
    all_urls = sorted(set(u.strip() for u in all_urls if u.strip()))
    write_lines(all_file, all_urls)
    info(f"total URLs (setelah dedup): {len(all_urls)}")

    # ── 4. filter lama: berparameter & sensitif ───────────────────
    params_file = os.path.join(out, "params_urls.txt")
    params = [u for u in all_urls if "?" in u and "=" in u]
    write_lines(params_file, params)
    info(f"URLs berparameter: {len(params)}")

    sens_file = os.path.join(out, "sensitive_files.txt")
    sensitive = [u for u in all_urls if _is_sensitive(u)]
    write_lines(sens_file, sensitive)
    info(f"sensitive files: {len(sensitive)}")

    # ── 5. klasifikasi multi-kategori ────────────────────────────
    categorized = _categorize(all_urls)
    all_labeled = []

    for cat, urls in categorized.items():
        cat_file = os.path.join(out, f"{cat}.txt")
        write_lines(cat_file, urls)
        info(f"[{cat}]: {len(urls)}")
        for u in urls:
            all_labeled.append(f"[{cat.upper():<14}] {u}")

    write_lines(os.path.join(out, "categorized.txt"), sorted(all_labeled))


# ── helpers ───────────────────────────────────────────────────────

def _categorize(urls: list[str]) -> dict[str, list[str]]:
    result = {cat: [] for cat in URL_CATEGORIES}
    compiled_regex = {
        cat: [re.compile(p) for p in cfg.get("path_regex", [])]
        for cat, cfg in URL_CATEGORIES.items()
    }

    for url in urls:
        try:
            parsed = urlparse(url.lower())
            path   = parsed.path
            qparams = set(parse_qs(parsed.query).keys())
        except Exception:
            continue

        for cat, cfg in URL_CATEGORIES.items():
            matched = False

            # cek query parameter
            if qparams & set(cfg.get("params", [])):
                matched = True

            # cek path segment (exact)
            if not matched and "path_segments" in cfg:
                segments = set(path.strip("/").replace("/", " ").split())
                if segments & set(cfg["path_segments"]):
                    matched = True

            # cek regex pada path
            if not matched:
                for rx in compiled_regex[cat]:
                    if rx.search(path):
                        matched = True
                        break

            if matched:
                result[cat].append(url)

    return result


_SENS_EXTS = {".sql", ".bak", ".zip", ".tar", ".gz", ".env",
              ".log", ".conf", ".config", ".pem", ".key"}

_SENS_NAMES = {
    "package.json", "composer.json", ".git/config", ".git/HEAD",
    "web.config", ".htaccess", ".htpasswd", ".dockerenv",
    "wp-config.php", "database.yml", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "shadow", "passwd",
}


def _is_sensitive(url: str) -> bool:
    try:
        path = urlparse(url.lower()).path
    except Exception:
        return False
    if any(path.endswith(ext) for ext in _SENS_EXTS):
        return True
    basename = path.rsplit("/", 1)[-1] if "/" in path else path
    if basename in _SENS_NAMES:
        return True
    if "/.git/" in path or path.endswith("/.git"):
        return True
    return False

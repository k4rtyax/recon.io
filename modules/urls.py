"""
Fase 5: URL Gathering
Menggunakan Katana untuk perayapan aktif (crawling) dan pemetaan endpoint API/JS.
"""

import os
from urllib.parse import urlparse
from core.utils import info, warn, run as exec_cmd, tool_available, read_lines, write_lines, get_working_url
from config import INTERESTING_PATTERNS, TIMEOUTS, TOOLS


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "urls")
    all_file  = os.path.join(out, "all_urls.txt")
    t = TIMEOUTS["urls"]

    # ── katana ───────────────────────────────────────────────────
    if tool_available(TOOLS["katana"]):
        kat_out = os.path.join(out, "katana.txt")
        url = get_working_url(target)
        exec_cmd(
            [
                TOOLS["katana"], "-u", url,
                "-silent", "-jc", "-o", kat_out
            ],
            timeout=t,
        )
        info("katana crawling selesai")
    else:
        warn("katana tidak ditemukan, URL gathering dilewati")
        warn("install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return

    # ── ambil & deduplikat hasil ───────────────────────────────────
    all_urls = []
    if os.path.exists(kat_out):
        all_urls = read_lines(kat_out)

    all_urls = sorted(set(all_urls))
    write_lines(all_file, all_urls)
    info(f"total URLs: {len(all_urls)}")

    # ── filter: interesting (path segment matching) ───────────────
    interesting_file = os.path.join(out, "interesting_urls.txt")
    interesting = [u for u in all_urls if _is_interesting(u)]
    write_lines(interesting_file, interesting)
    info(f"interesting URLs: {len(interesting)}")

    # ── filter: berparameter ─────────────────────────────────────
    params_file = os.path.join(out, "params_urls.txt")
    params = [u for u in all_urls if "?" in u and "=" in u]
    write_lines(params_file, params)
    info(f"URLs berparameter: {len(params)}")

    # ── filter: sensitive files ───────────────────────────────────
    sens_file = os.path.join(out, "sensitive_files.txt")
    sensitive = [u for u in all_urls if _is_sensitive(u)]
    write_lines(sens_file, sensitive)
    info(f"sensitive files: {len(sensitive)}")


def _is_interesting(url: str) -> bool:
    """Cocokkan pattern sebagai path segment exact, bukan substring.
    /admin → match.  /administrator → TIDAK match 'admin'.
    /developer → TIDAK match 'dev'.
    """
    try:
        path = urlparse(url.lower()).path
    except Exception:
        return False
    segments = set(path.strip("/").split("/"))
    return bool(segments & set(INTERESTING_PATTERNS))


# Ekstensi file yang jelas sensitif
_SENS_EXTS = {".sql", ".bak", ".zip", ".tar", ".gz", ".env",
              ".log", ".conf", ".config", ".pem", ".key"}

# Nama file spesifik yang berbahaya jika terekspos
_SENS_NAMES = {
    "package.json", "composer.json", ".git/config", ".git/HEAD",
    "web.config", ".htaccess", ".htpasswd", ".dockerenv",
    "wp-config.php", "database.yml", ".env.local", ".env.production",
    "id_rsa", "id_ed25519", "shadow", "passwd",
}


def _is_sensitive(url: str) -> bool:
    """Filter file sensitif berdasarkan ekstensi spesifik atau nama file berbahaya.
    Tidak lagi match .json/.xml secara blanket — terlalu banyak false positive.
    """
    try:
        path = urlparse(url.lower()).path
    except Exception:
        return False
    # Cek ekstensi
    if any(path.endswith(ext) for ext in _SENS_EXTS):
        return True
    # Cek nama file spesifik
    basename = path.rsplit("/", 1)[-1] if "/" in path else path
    if basename in _SENS_NAMES:
        return True
    # Cek path fragments yang berbahaya
    if "/.git/" in path or path.endswith("/.git"):
        return True
    return False


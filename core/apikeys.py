"""
Registry API key OSINT + query ternormalisasi (stdlib, tanpa dependency tambahan).
Provider tanpa key otomatis dilewati. Semua query aman: gagal → hasil kosong,
tidak pernah raise ke pemanggil.
"""

import os
import ssl
import json
import time
import base64
import urllib.parse
import urllib.request
import urllib.error

from core.utils import info, warn

_TIMEOUT = 15
_UA      = "recon.io/2.0"

# ── registry provider ───────────────────────────────────────────
# (nama, env var yang dibutuhkan, keterangan free tier)
_PROVIDERS = [
    ("chaos",          ("CHAOS_API_KEY",),                     "gratis utk personal use, chaos.projectdiscovery.io"),
    ("securitytrails", ("SECURITYTRAILS_API_KEY",),            "free tier terbatas, securitytrails.com"),
    ("virustotal",     ("VIRUSTOTAL_API_KEY",),                "public API 500 req/hari, virustotal.com"),
    ("shodan",         ("SHODAN_API_KEY",),                    "free key terbatas, shodan.io"),
    ("censys",         ("CENSYS_API_ID", "CENSYS_API_SECRET"), "free tier kredit bulanan, censys.io"),
    ("netlas",         ("NETLAS_API_KEY",),                    "community 50 req/hari, netlas.io"),
    ("leakix",         ("LEAKIX_API_KEY",),                    "gratis, leakix.net"),
]

_KEYLESS = [
    ("crt.sh",            "tanpa key, certificate transparency"),
    ("shodan-internetdb", "tanpa key, internetdb.shodan.io"),
]

_warned: set[str] = set()


def _keys(provider: str) -> tuple[str, ...] | None:
    """Nilai env var provider, atau None bila ada yang kosong."""
    for name, envs, _ in _PROVIDERS:
        if name == provider:
            vals = tuple(os.environ.get(e, "").strip() for e in envs)
            return vals if all(vals) else None
    return None


def configured() -> list[str]:
    return [name for name, _, _ in _PROVIDERS if _keys(name)]


def status() -> list[tuple[str, bool, str]]:
    rows = [(name, bool(_keys(name)), note) for name, _, note in _PROVIDERS]
    rows += [(name, True, note) for name, note in _KEYLESS]
    return rows


# ── http ────────────────────────────────────────────────────────

def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _warn_once(tag: str, msg: str):
    if tag not in _warned:
        _warned.add(tag)
        warn(msg)


def _get(url: str, headers: dict | None = None, timeout: int = _TIMEOUT, tag: str = "") -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            _warn_once(tag, f"{tag}: key ditolak (HTTP {e.code})")
        elif e.code == 429:
            _warn_once(tag, f"{tag}: kena rate limit (HTTP 429)")
        elif e.code != 404:
            _warn_once(tag, f"{tag}: HTTP {e.code}")
        return ""
    except Exception as e:
        _warn_once(tag, f"{tag}: gagal ({e})")
        return ""


def _get_json(url: str, headers: dict | None = None, timeout: int = _TIMEOUT, tag: str = ""):
    body = _get(url, headers, timeout, tag)
    if not body:
        return None
    try:
        return json.loads(body)
    except Exception:
        _warn_once(f"{tag}:parse", f"{tag}: respons bukan JSON valid")
        return None


# ── normalisasi ─────────────────────────────────────────────────

def _norm_subs(items, domain: str) -> list[str]:
    root = domain.lower().strip().rstrip(".")
    out: set[str] = set()
    for raw in items:
        if not raw:
            continue
        for part in str(raw).replace(",", "\n").split("\n"):
            h = part.strip().lower().rstrip(".")
            if h.startswith("*."):
                h = h[2:]
            if not h or " " in h or "@" in h:
                continue
            if h == root or h.endswith("." + root):
                out.add(h)
    return sorted(out)


def _with_root(items, domain: str) -> list[str]:
    """Provider yang mengembalikan prefix saja (mis. 'api') → jadikan FQDN."""
    root = domain.lower().strip().rstrip(".")
    full = []
    for raw in items:
        s = str(raw).strip().lower().rstrip(".")
        if not s:
            continue
        full.append(s if s == root or s.endswith("." + root) else f"{s}.{root}")
    return full


# ── subdomain sources ───────────────────────────────────────────

def crtsh_subdomains(domain: str, timeout: int = 30) -> list[str]:
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    data = _get_json(url, timeout=timeout, tag="crt.sh")
    if not isinstance(data, list):
        return []
    names = []
    for row in data:
        if isinstance(row, dict):
            names.append(row.get("name_value") or "")
            names.append(row.get("common_name") or "")
    return _norm_subs(names, domain)


def chaos_subdomains(domain: str, timeout: int = _TIMEOUT) -> list[str]:
    keys = _keys("chaos")
    if not keys:
        return []
    url  = f"https://dns.projectdiscovery.io/dns/{urllib.parse.quote(domain)}/subdomains"
    data = _get_json(url, {"Authorization": keys[0]}, timeout, "chaos")
    if not isinstance(data, dict):
        return []
    return _norm_subs(_with_root(data.get("subdomains") or [], domain), domain)


def securitytrails_subdomains(domain: str, timeout: int = _TIMEOUT) -> list[str]:
    keys = _keys("securitytrails")
    if not keys:
        return []
    url = (f"https://api.securitytrails.com/v1/domain/{urllib.parse.quote(domain)}"
           f"/subdomains?children_only=false&include_inactive=true")
    data = _get_json(url, {"APIKEY": keys[0], "Accept": "application/json"}, timeout, "securitytrails")
    if not isinstance(data, dict):
        return []
    return _norm_subs(_with_root(data.get("subdomains") or [], domain), domain)


def virustotal_subdomains(domain: str, timeout: int = _TIMEOUT, max_pages: int = 3) -> list[str]:
    keys = _keys("virustotal")
    if not keys:
        return []
    url   = (f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}"
             f"/subdomains?limit=40")
    names = []
    for i in range(max_pages):
        data = _get_json(url, {"x-apikey": keys[0], "Accept": "application/json"}, timeout, "virustotal")
        if not isinstance(data, dict):
            break
        for item in data.get("data") or []:
            if isinstance(item, dict):
                names.append(item.get("id") or "")
        url = ((data.get("links") or {}).get("next")) or ""
        if not url:
            break
        if i < max_pages - 1:
            time.sleep(1)
    return _norm_subs(names, domain)


def netlas_subdomains(domain: str, timeout: int = _TIMEOUT) -> list[str]:
    keys = _keys("netlas")
    if not keys:
        return []
    url = "https://app.netlas.io/api/domains/?" + urllib.parse.urlencode({
        "q": f"domain:(*.{domain} OR {domain})",
        "start": 0,
        "fields": "domain",
        "source_type": "include",
    })
    data = _get_json(url, {"X-API-Key": keys[0], "Accept": "application/json"}, timeout, "netlas")
    names = []
    items = []
    if isinstance(data, dict):
        items = data.get("items") or data.get("data") or []
    elif isinstance(data, list):
        items = data
    for item in items:
        if not isinstance(item, dict):
            continue
        inner = item.get("data") if isinstance(item.get("data"), dict) else item
        names.append(inner.get("domain") or inner.get("name") or "")
    return _norm_subs(names, domain)


# ── host enrichment ─────────────────────────────────────────────

def shodan_internetdb(ip: str, timeout: int = _TIMEOUT) -> dict:
    empty = {"ports": [], "hostnames": [], "vulns": [], "cpes": []}
    data  = _get_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}",
                      timeout=timeout, tag="internetdb")
    if not isinstance(data, dict):
        return empty
    return {
        "ports":     [p for p in (data.get("ports") or []) if p != ""],
        "hostnames": [str(h) for h in (data.get("hostnames") or []) if h],
        "vulns":     [str(v) for v in (data.get("vulns") or []) if v],
        "cpes":      [str(c) for c in (data.get("cpes") or []) if c],
    }


def shodan_host(ip: str, timeout: int = _TIMEOUT) -> dict:
    empty = {"ports": [], "hostnames": [], "vulns": [], "org": "", "tags": []}
    keys  = _keys("shodan")
    if not keys:
        return empty
    url  = (f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}?"
            + urllib.parse.urlencode({"key": keys[0], "minify": "true"}))
    data = _get_json(url, timeout=timeout, tag="shodan")
    if not isinstance(data, dict):
        return empty
    vulns = data.get("vulns") or []
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())
    return {
        "ports":     [p for p in (data.get("ports") or []) if p != ""],
        "hostnames": [str(h) for h in (data.get("hostnames") or []) if h],
        "vulns":     [str(v) for v in vulns if v],
        "org":       str(data.get("org") or ""),
        "tags":      [str(t) for t in (data.get("tags") or []) if t],
    }


def leakix_host(host: str, timeout: int = _TIMEOUT) -> list[dict]:
    keys = _keys("leakix")
    if not keys:
        return []
    url  = f"https://leakix.net/host/{urllib.parse.quote(host)}"
    data = _get_json(url, {"api-key": keys[0], "Accept": "application/json"}, timeout, "leakix")
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        out = []
        for key in ("Services", "services", "Leaks", "leaks"):
            for item in data.get(key) or []:
                if isinstance(item, dict):
                    out.append(item)
        return out
    return []


def censys_search(query: str, timeout: int = _TIMEOUT, limit: int = 50) -> list[str]:
    keys = _keys("censys")
    if not keys:
        return []
    token = base64.b64encode(f"{keys[0]}:{keys[1]}".encode()).decode()
    url   = "https://search.censys.io/api/v2/hosts/search?" + urllib.parse.urlencode({
        "q": query,
        "per_page": min(max(limit, 1), 100),
    })
    data = _get_json(url, {"Authorization": f"Basic {token}", "Accept": "application/json"},
                     timeout, "censys")
    if not isinstance(data, dict):
        return []
    hits = ((data.get("result") or {}).get("hits")) or []
    out  = []
    for h in hits:
        if isinstance(h, dict):
            val = h.get("ip") or h.get("name") or ""
            if val:
                out.append(str(val))
        elif h:
            out.append(str(h))
    return list(dict.fromkeys(out))


# ── agregator ───────────────────────────────────────────────────

def passive_subdomains(domain: str, timeout: int = _TIMEOUT) -> list[str]:
    """Gabungan semua sumber pasif yang tersedia. crt.sh selalu jalan (keyless)."""
    sources = [
        ("crt.sh",         lambda: crtsh_subdomains(domain, max(timeout, 30))),
        ("chaos",          lambda: chaos_subdomains(domain, timeout)),
        ("securitytrails", lambda: securitytrails_subdomains(domain, timeout)),
        ("virustotal",     lambda: virustotal_subdomains(domain, timeout)),
        ("netlas",         lambda: netlas_subdomains(domain, timeout)),
    ]

    found: set[str] = set()
    parts: list[str] = []
    for name, fn in sources:
        if name != "crt.sh" and not _keys(name):
            continue
        res = fn()
        if res:
            found.update(res)
            parts.append(f"{name}:{len(res)}")

    if parts:
        info(f"OSINT pasif, {', '.join(parts)}, total {len(found)} unik")
    return sorted(found)

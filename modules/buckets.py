"""
Fase: Cloud Storage Bucket Enumeration
Permutasi nama bucket dari target, lalu cek keberadaan dan keterbukaan
di S3, Google Cloud Storage, Azure Blob, dan DigitalOcean Spaces.
"""

import os
import re
import ssl
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.utils import info, warn, write_lines
from config import DEFAULT_USER_AGENT, TIMEOUTS


_AFFIXES = [
    "dev", "prod", "production", "staging", "stage", "test", "qa",
    "backup", "backups", "bak", "archive", "assets", "static", "media",
    "uploads", "upload", "files", "data", "logs", "cdn", "public",
    "private", "internal", "images", "img", "docs", "db", "dump",
    "s3", "storage", "web", "www",
]

# label yang bukan nama organisasi pada domain bertingkat (co.uk, go.id, ...)
_SLD = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "go", "mil", "sch", "ne"}

_OPEN_MARKERS = ("<ListBucketResult", "<EnumerationResults", "<Contents>")

_S3_RE    = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_GCS_RE   = re.compile(r"^[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9]$")
_AZURE_RE = re.compile(r"^[a-z0-9]{3,24}$")


def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


_CTX = _ssl_context()


def _base_and_affixes(target: str) -> tuple[str, list[str]]:
    host = target.lower().strip().split("/")[0].split(":")[0].rstrip(".")
    labels = [l for l in host.split(".") if l]
    if not labels:
        return "", list(_AFFIXES)

    core = labels[:-1] if len(labels) > 1 else labels
    if len(core) > 1 and core[-1] in _SLD:
        core = core[:-1]
    if not core:
        return "", list(_AFFIXES)

    affixes = list(_AFFIXES)
    for sub in core[:-1]:
        if sub and sub != "www" and sub not in affixes:
            affixes.append(sub)
    return core[-1], affixes


def _candidates(base: str, affixes: list[str], limit: int) -> list[str]:
    names = [base]
    for a in affixes:
        names += [f"{base}-{a}", f"{a}-{base}", f"{base}{a}", f"{base}.{a}"]

    seen, out = set(), []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        out.append(n)
        if len(out) >= limit:
            break
    return out


def _targets_for(bucket: str) -> list[tuple[str, str]]:
    urls = []
    if _S3_RE.match(bucket):
        # nama bermutasi titik tidak cocok dengan wildcard cert, pakai path-style
        if "." in bucket:
            urls.append(("s3", f"https://s3.amazonaws.com/{bucket}/"))
        else:
            urls.append(("s3", f"https://{bucket}.s3.amazonaws.com/"))
            urls.append(("spaces", f"https://{bucket}.nyc3.digitaloceanspaces.com/"))
    if _GCS_RE.match(bucket):
        urls.append(("gcs", f"https://storage.googleapis.com/{bucket}"))
    if _AZURE_RE.match(bucket):
        urls.append(("azure", f"https://{bucket}.blob.core.windows.net/?comp=list"))
    return urls


def _fetch(url: str, timeout: int) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(4096).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def _classify(provider: str, code: int, body: str) -> str | None:
    if code == 200:
        return "terbuka" if any(m in body for m in _OPEN_MARKERS) else "ada"
    if code == 400:
        return "ada" if provider == "azure" else None
    if code in (301, 307, 308, 401, 403, 409):
        return "ada"
    if code == 404:
        return "ada" if ("ContainerNotFound" in body or "NoSuchKey" in body) else None
    return None


def _check(bucket: str, deadline: float, timeout: int) -> list[str]:
    hits = []
    for provider, url in _targets_for(bucket):
        if time.monotonic() > deadline:
            break
        code, body = _fetch(url, timeout)
        status = _classify(provider, code, body)
        if status:
            hits.append(f"{provider} {url} [{status}]")
    return hits


def run(target: str, target_dir: str):
    out = os.path.join(target_dir, "buckets")
    os.makedirs(out, exist_ok=True)

    base, affixes = _base_and_affixes(target)
    if not base:
        warn("nama dasar bucket tidak bisa ditentukan, dilewati")
        return

    try:
        limit = max(1, int(os.environ.get("RECON_BUCKET_MAX", "400")))
    except ValueError:
        limit = 400

    cands = _candidates(base, affixes, limit)
    write_lines(os.path.join(out, "bucket_candidates.txt"), cands)
    info(f"kandidat bucket: {len(cands)}")

    deadline = time.monotonic() + TIMEOUTS["buckets"]
    found = []
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = [pool.submit(_check, c, deadline, 8) for c in cands]
        for fut in as_completed(futures):
            try:
                found += fut.result()
            except Exception:
                continue

    if time.monotonic() > deadline:
        warn("timeout fase buckets tercapai, sebagian kandidat tidak dicek")

    found.sort()
    open_buckets = [f for f in found if f.endswith("[terbuka]")]
    write_lines(os.path.join(out, "found_buckets.txt"), found)
    write_lines(os.path.join(out, "open_buckets.txt"), open_buckets)

    info(f"bucket ditemukan: {len(found)}")
    if open_buckets:
        warn(f"bucket terbuka (listable): {len(open_buckets)}")
        for b in open_buckets[:10]:
            warn(b)

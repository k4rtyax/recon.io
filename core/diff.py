"""
Bandingkan hasil recon dengan run sebelumnya untuk target yang sama.
Baseline disimpan per target, hanya selisihnya yang ditampilkan.
"""

import os

from core.utils import warn, read_lines, write_lines

# ── file hasil yang dilacak antar-run ───────────────────────────
TRACKED = [
    "subdomain/alive_subdomains.txt",
    "subdomain/all_subdomains.txt",
    "ports/open_ports.txt",
    "urls/all_urls.txt",
    "js/js_endpoints.txt",
    "js/js_secrets.txt",
    "params/discovered_params.txt",
    "security/takeover.txt",
    "dirbrute/found_paths.txt",
    "buckets/found_buckets.txt",
    "api/graphql_endpoints.txt",
]

_MAX_SHOWN = 20


def _folder_name(target: str) -> str:
    return target.replace("*.", "").replace("/", "_")


def _baseline_dir(target: str, output_dir: str) -> str:
    return os.path.join(output_dir, _folder_name(target), ".baseline")


def _load(path: str) -> set[str]:
    return {l for l in read_lines(path) if l}


# ── api publik ──────────────────────────────────────────────────

def is_first_run(target: str, output_dir: str) -> bool:
    base = _baseline_dir(target, output_dir)
    if not os.path.isdir(base):
        return True
    for rel in TRACKED:
        if os.path.exists(os.path.join(base, rel)):
            return False
    return True


def compare(target: str, target_dir: str, output_dir: str) -> dict:
    if is_first_run(target, output_dir):
        return {}

    base = _baseline_dir(target, output_dir)
    result: dict[str, dict[str, list[str]]] = {}

    for rel in TRACKED:
        cur_path = os.path.join(target_dir, rel)
        if not os.path.exists(cur_path):
            continue
        cur  = _load(cur_path)
        prev = _load(os.path.join(base, rel))
        added   = sorted(cur - prev)
        removed = sorted(prev - cur)
        if added or removed:
            result[rel] = {"added": added, "removed": removed}

    return result


def update_baseline(target: str, target_dir: str, output_dir: str) -> int:
    base = _baseline_dir(target, output_dir)
    saved = 0
    for rel in TRACKED:
        src = os.path.join(target_dir, rel)
        if not os.path.exists(src):
            continue
        dst = os.path.join(base, rel)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            write_lines(dst, read_lines(src))
            saved += 1
        except OSError as e:
            warn(f"gagal menyimpan baseline {rel}: {e}")
    return saved


def render(diff: dict, target: str) -> str:
    if not diff:
        return f"{target}: tidak ada perubahan dari run sebelumnya"

    lines = [f"{target} — perubahan dari run sebelumnya:"]
    for rel in TRACKED:
        entry = diff.get(rel)
        if not entry:
            continue
        added, removed = entry["added"], entry["removed"]
        lines.append(f"\n  {rel}  (+{len(added)} baru, -{len(removed)} hilang)")
        for item in added[:_MAX_SHOWN]:
            lines.append(f"    + {item}")
        if len(added) > _MAX_SHOWN:
            lines.append(f"    ... {len(added) - _MAX_SHOWN} lagi")
    return "\n".join(lines)

"""
Fase opsional: verifikasi PoC bertarget dengan human confirmation.

Tiga kelas cek, semua NON-DESTRUKTIF:
  - nuclei      : template deteksi nuclei (tag diusulkan AI / deterministik)
  - open_redirect: inject canary ke param redirect, cek header Location (tanpa follow)
  - exposed_tool : satu GET ke endpoint exposed_tool, catat status (near-passive)

Guardrail wajib untuk SETIAP request aktif:
  1. scope re-check pada host tepat sebelum request (URL gau/wayback bisa ke pihak ketiga)
  2. chokepoint konfirmasi manusia dengan dry-run (default TIDAK)
  3. audit log ke verify/exploit_log.txt

AI hanya MENGUSULKAN kandidat & MENAFSIRKAN hasil — tidak pernah menembak sendiri.
Alur: kandidat -> [pilih] -> dry-run + [konfirmasi] -> scope re-check -> jalankan -> bukti -> tafsir AI.
"""

import os
import re
import sys
from datetime import datetime
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from rich.markup import escape

from core.utils import (
    info, warn, err, section, console,
    run as exec_cmd, tool_available, read_lines, get_working_url,
)
from config import TOOLS, DEFAULT_USER_AGENT

_VERIFY_TIMEOUT = int(os.environ.get("RECON_TIMEOUT_VERIFY", "600"))
_URL_LIMIT      = int(os.environ.get("RECON_VERIFY_URL_LIMIT", "20"))
_CANARY         = "recon-canary.example"

_REDIRECT_PARAMS = {
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "next", "return",
    "return_url", "returnurl", "dest", "destination", "rurl", "callback",
    "continue", "goto", "target", "ref", "out",
}

_TECH_TAGS = {
    "wordpress": ["wordpress"],
    "joomla":    ["joomla"],
    "drupal":    ["drupal"],
    "jira":      ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "gitlab":    ["gitlab"],
    "jenkins":   ["jenkins"],
    "grafana":   ["grafana"],
    "spring":    ["springboot"],
    "tomcat":    ["tomcat"],
    "laravel":   ["laravel"],
    "django":    ["django"],
    "kubernetes": ["kubernetes"],
    "graphql":   ["graphql"],
}


def _host_of(url: str) -> str:
    net = urlparse(url).netloc.lower()
    return net.split("@")[-1].split(":")[0]


def _in_target(scope, host: str, target: str) -> tuple[bool, str]:
    """Gerbang scope per-host.

    Tanpa pola allow (tanpa --scope, atau file scope yang tidak menghasilkan
    satu pun pola in-scope) Scope.check() mengembalikan allow-all. Untuk request
    aktif itu tidak aman — URL hasil wayback/gau bisa menunjuk CDN atau domain
    pihak ketiga — jadi di sini kita jatuhkan ke pagar ketat target+subdomain.
    Pola deny tetap dihormati.
    """
    if not host:
        return False, "host kosong"
    h = host.strip().lower().rstrip(".")
    t = (target or "").strip().lower().rstrip(".")
    if t.startswith("*."):
        t = t[2:]

    if scope is not None and scope.allow:
        return scope.check(h)

    if scope is not None:
        allowed, why = scope.check(h)     # di sini hanya pola deny yang bisa menolak
        if not allowed:
            return False, why

    if h and t and (h == t or h.endswith("." + t)):
        return True, "cocok target (tanpa pola in-scope)"
    return False, "di luar target (tanpa pola in-scope)"


def _inject(url: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    newq = [(k, value if k.lower() in _REDIRECT_PARAMS else v) for k, v in q]
    return urlunparse(p._replace(query=urlencode(newq)))


def _has_redirect_param(url: str) -> bool:
    q = parse_qsl(urlparse(url).query, keep_blank_values=True)
    return any(k.lower() in _REDIRECT_PARAMS for k, _ in q)


def _load_context(target_dir: str) -> str:
    parts = []
    tech = read_lines(os.path.join(target_dir, "fingerprint", "tech_stack.txt"))
    if tech:
        parts.append("tech: " + ", ".join(tech[:20]))
    cat = read_lines(os.path.join(target_dir, "urls", "categorized.txt"))
    if cat:
        parts.append(f"kategori URL ({len(cat)}):\n" + "\n".join(cat[:40]))
    waf = read_lines(os.path.join(target_dir, "fingerprint", "waf.txt"))
    if waf:
        parts.append("waf: " + " ".join(waf[:5]))
    return "\n".join(parts) if parts else "(tidak ada konteks recon)"


def _deterministic_tags(target_dir: str) -> set[str]:
    ctx = _load_context(target_dir).lower()
    tags: set[str] = set()
    for needle, mapped in _TECH_TAGS.items():
        if needle in ctx:
            tags.update(mapped)
    if "actuator" in ctx:
        tags.update(["springboot", "exposure"])
    if "graphql" in ctx:
        tags.add("graphql")
    if "swagger" in ctx or "api-docs" in ctx:
        tags.update(["swagger", "exposure"])
    if "heapdump" in ctx or "jolokia" in ctx:
        tags.add("exposure")
    return tags


def _clean_urls(paths: list[str], keep) -> list[str]:
    out, seen = [], set()
    for p in paths:
        for u in read_lines(p):
            u = u.strip()
            if u.startswith("[") and "] " in u:
                u = u.split("] ", 1)[1].strip()
            if not u.lower().startswith(("http://", "https://")):
                continue
            if u in seen or not keep(u):
                continue
            seen.add(u)
            out.append(u)
    return out[:_URL_LIMIT]


def _build_candidates(target_dir: str) -> list[dict]:
    cands: list[dict] = [
        {"kind": "nuclei", "tags": "exposure,misconfig",
         "label": "exposure & misconfig (umum)", "why": "eksposur & salah-konfigurasi umum"},
        {"kind": "nuclei", "tags": "cve",
         "label": "CVE (deteksi)", "why": "template CVE mode deteksi, non-destruktif"},
        {"kind": "nuclei", "tags": "default-login",
         "label": "default login", "why": "cek halaman login kredensial default"},
    ]
    # subzy/nuclei tetap membuat file output walau nol temuan — cek isinya.
    if read_lines(os.path.join(target_dir, "security", "takeover.txt")):
        cands.append({"kind": "nuclei", "tags": "takeover",
                      "label": "subdomain takeover", "why": "ada kandidat dari fase security"})

    seen_tags = {c["tags"] for c in cands}
    for tag in sorted(_deterministic_tags(target_dir)):
        if tag not in seen_tags:
            cands.append({"kind": "nuclei", "tags": tag,
                          "label": f"tech: {tag}", "why": f"terdeteksi '{tag}' di fingerprint"})
            seen_tags.add(tag)

    try:
        from core import ai
        for tag in ai.suggest_nuclei_tags(_load_context(target_dir)):
            if tag and tag not in seen_tags:
                cands.append({"kind": "nuclei", "tags": tag,
                              "label": f"AI: {tag}", "why": "diusulkan AI dari konteks recon"})
                seen_tags.add(tag)
    except Exception as exc:
        warn(f"usulan tag AI dilewati: {exc}")

    redir = _clean_urls([os.path.join(target_dir, "urls", "ssrf_prone.txt")], _has_redirect_param)
    if redir:
        cands.append({"kind": "open_redirect", "urls": redir,
                      "label": f"open redirect ({len(redir)} URL)",
                      "why": "param redirect di kategori ssrf_prone"})

    exposed = _clean_urls([os.path.join(target_dir, "urls", "exposed_tool.txt")], lambda u: True)
    if exposed:
        cands.append({"kind": "exposed_tool", "urls": exposed,
                      "label": f"exposed tool ({len(exposed)} URL)",
                      "why": "endpoint internal/debug di kategori exposed_tool"})

    return cands


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "verify"


def _log(log_path: str, line: str):
    with open(log_path, "a") as f:
        f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {line}\n")


def _confirm(title: str, lines: list[str]) -> bool:
    """Chokepoint tunggal: tampilkan request PERSIS, minta persetujuan (default TIDAK)."""
    from core import menu as kbmenu
    console.print(f"\n[bold]dry-run — {title}:[/bold]")
    for ln in lines:
        console.print(f"  [cyan]{escape(ln)}[/cyan]")
    console.print("  [dim]non-destruktif; hanya ke host in-scope[/dim]")
    return kbmenu.confirm("Kirim request verifikasi ini?", default=False)


def _run_nuclei(url: str, tags: str, out: str) -> tuple[list[str], str]:
    evidence = os.path.join(out, f"nuclei_{_slug(tags)}.txt")

    # nuclei membuka -o dalam mode append dan path bukti deterministik per hari,
    # jadi run kedua akan membaca ulang temuan run sebelumnya. Sisihkan dulu.
    if os.path.exists(evidence):
        backup = os.path.join(out, f"nuclei_{_slug(tags)}.{datetime.now():%H%M%S}.prev.txt")
        try:
            os.replace(evidence, backup)
            info(f"bukti run sebelumnya disimpan sebagai {os.path.basename(backup)}")
        except OSError as exc:
            warn(f"gagal memindah bukti lama ({exc}) — hasil bisa tercampur run sebelumnya")

    rc, _, stderr = exec_cmd(
        [TOOLS["nuclei"], "-u", url, "-tags", tags,
         "-severity", "critical,high,medium,low", "-o", evidence, "-silent"],
        timeout=_VERIFY_TIMEOUT,
    )
    if rc != 0:
        detail = (stderr or "").strip().splitlines()
        why = detail[-1] if detail else f"rc={rc}"
        if rc == -1 and "timeout" in why.lower():
            why = f"timeout {_VERIFY_TIMEOUT}s (atur lewat RECON_TIMEOUT_VERIFY)"
        warn(f"nuclei [{tags}] tidak selesai normal: {why} — hasil di bawah bisa parsial")

    return (read_lines(evidence) if os.path.exists(evidence) else []), evidence


def _run_open_redirect(urls, out, scope, target, log_path) -> tuple[list[str], str]:
    findings = []
    for u in urls:
        host = _host_of(u)
        okk, why = _in_target(scope, host, target)
        if not okk:
            _log(log_path, f"SKIP open_redirect url={u} alasan={why}")
            continue
        test = _inject(u, f"https://{_CANARY}/")
        _, head, _ = exec_cmd(
            [TOOLS["curl"], "-sI", "-A", DEFAULT_USER_AGENT, "--max-time", "10", test],
            timeout=15,
        )
        loc = ""
        for line in head.splitlines():
            if line.lower().startswith("location:"):
                loc = line.split(":", 1)[1].strip()
        if _CANARY in loc.lower():
            findings.append(f"[VULN] open-redirect: {u} -> Location: {loc}")
        elif loc:
            findings.append(f"[info] redirect (bukan canary): {u} -> {loc}")
    evidence = os.path.join(out, "open_redirect.txt")
    if findings:
        with open(evidence, "w") as f:
            f.write("\n".join(findings) + "\n")
    return findings, evidence


def _run_exposed_tool(urls, out, scope, target, log_path) -> tuple[list[str], str]:
    findings = []
    for u in urls:
        host = _host_of(u)
        okk, why = _in_target(scope, host, target)
        if not okk:
            _log(log_path, f"SKIP exposed_tool url={u} alasan={why}")
            continue
        code, body, _ = exec_cmd(
            [TOOLS["curl"], "-s", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
             "-A", DEFAULT_USER_AGENT, "--max-time", "10", u],
            timeout=15,
        )
        status = (body.strip().split() or ["?"])[0]
        if status in {"200", "401", "403", "500"}:
            tag = "ACCESSIBLE" if status == "200" else "exists"
            findings.append(f"[{status}] {tag}: {u}")
    evidence = os.path.join(out, "exposed_tool.txt")
    if findings:
        with open(evidence, "w") as f:
            f.write("\n".join(findings) + "\n")
    return findings, evidence


def run_verify(target: str, target_dir: str, scope=None):
    """Entry point verifikasi. Interaktif — tidak dipanggil dari runner paralel."""
    section(f"verifikasi PoC — {target}")

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        warn("verifikasi butuh terminal interaktif (konfirmasi manual) — dilewati")
        return

    in_scope, reason = _in_target(scope, target, target)
    if not in_scope:
        err(f"{target} DI LUAR scope ({reason}) — verifikasi dibatalkan")
        return

    out = os.path.join(target_dir, "verify")
    os.makedirs(out, exist_ok=True)
    log_path = os.path.join(out, "exploit_log.txt")
    _log(log_path, f"mulai verifikasi target={target}")

    candidates = _build_candidates(target_dir)
    nuclei_needed = any(c["kind"] == "nuclei" for c in candidates)
    if nuclei_needed and not tool_available(TOOLS["nuclei"]):
        warn("nuclei tidak ditemukan — kandidat nuclei tidak akan bisa dijalankan")
    if not tool_available(TOOLS["curl"]):
        warn("curl tidak ditemukan — kandidat open_redirect/exposed_tool tidak bisa dijalankan")

    if not candidates:
        warn("tidak ada kandidat verifikasi")
        return

    from core import menu as kbmenu
    labels = [f"{c['label']}  — {c['why']}" for c in candidates]
    by_label = dict(zip(labels, candidates))

    console.print("[dim]pilih cek (space = toggle, enter = ok). "
                  "tiap cek dikonfirmasi lagi sebelum dikirim.[/dim]")
    picked = kbmenu.multi_pick("kandidat verifikasi:", labels)
    if not picked:
        info("tidak ada cek dipilih — dibatalkan")
        _log(log_path, "user tidak memilih cek apa pun")
        return

    url = get_working_url(target)
    evidence_files: list[str] = []
    ran = 0

    for lbl in picked:
        c = by_label[lbl]
        kind = c["kind"]

        again, why = _in_target(scope, target, target)
        if not again:
            warn(f"skip '{c['label']}': {target} di luar scope ({why})")
            _log(log_path, f"SKIP kind={kind} alasan=out-of-scope")
            continue

        if kind == "nuclei":
            if not tool_available(TOOLS["nuclei"]):
                warn(f"skip '{c['label']}': nuclei tidak ada")
                continue
            cmd = (f"{TOOLS['nuclei']} -u {url} -tags {c['tags']} "
                   f"-severity critical,high,medium,low -silent")
            if not _confirm(f"nuclei [{c['tags']}]", [cmd]):
                _log(log_path, f"DITOLAK kind=nuclei tags={c['tags']}")
                continue
            info(f"menjalankan: {c['label']}...")
            _log(log_path, f"JALAN kind=nuclei tags={c['tags']} url={url}")
            hits, ev = _run_nuclei(url, c["tags"], out)

        elif kind == "open_redirect":
            if not tool_available(TOOLS["curl"]):
                continue
            sample = c["urls"][:3]
            lines = [f"curl -sI '{_inject(u, f'https://{_CANARY}/')}'" for u in sample]
            if len(c["urls"]) > len(sample):
                lines.append(f"... (+{len(c['urls']) - len(sample)} URL lagi, HEAD only, tanpa follow)")
            if not _confirm(f"open redirect ({len(c['urls'])} URL, canary={_CANARY})", lines):
                _log(log_path, "DITOLAK kind=open_redirect")
                continue
            info(f"menjalankan: {c['label']}...")
            _log(log_path, f"JALAN kind=open_redirect n={len(c['urls'])}")
            hits, ev = _run_open_redirect(c["urls"], out, scope, target, log_path)

        elif kind == "exposed_tool":
            if not tool_available(TOOLS["curl"]):
                continue
            sample = c["urls"][:3]
            lines = [f"curl -s -o /dev/null -w '%{{http_code}}' '{u}'" for u in sample]
            if len(c["urls"]) > len(sample):
                lines.append(f"... (+{len(c['urls']) - len(sample)} URL lagi, GET tunggal)")
            if not _confirm(f"exposed tool probe ({len(c['urls'])} URL)", lines):
                _log(log_path, "DITOLAK kind=exposed_tool")
                continue
            info(f"menjalankan: {c['label']}...")
            _log(log_path, f"JALAN kind=exposed_tool n={len(c['urls'])}")
            hits, ev = _run_exposed_tool(c["urls"], out, scope, target, log_path)

        else:
            continue

        info(f"selesai — {len(hits)} temuan")
        _log(log_path, f"HASIL kind={kind} temuan={len(hits)}")
        if hits:
            evidence_files.append(ev)
        ran += 1

    if ran == 0:
        info("tidak ada verifikasi yang dijalankan")
        return

    combined = ""
    for ev in evidence_files:
        combined += f"\n# {os.path.basename(ev)}\n" + "\n".join(read_lines(ev)) + "\n"

    section("verifikasi selesai")
    if not combined.strip():
        info("tidak ada temuan dari cek yang dijalankan")
        return
    console.print(escape(combined.strip()))

    try:
        from core import ai
        verdict = ai.interpret_nuclei(target, combined)
        if verdict:
            section("tafsir AI")
            console.print(escape(verdict))
            with open(os.path.join(out, "verify_analysis.md"), "w") as f:
                f.write(f"# Verifikasi — {target}\n\n")
                f.write(f"*{datetime.now():%Y-%m-%d %H:%M} — wajib verifikasi manual "
                        f"sebelum submit.*\n\n{verdict}\n")
    except Exception as exc:
        warn(f"tafsir AI dilewati: {exc}")

    info(f"bukti & log tersimpan di: {out}")

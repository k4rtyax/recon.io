"""
Runner — orkestrasi semua fase recon untuk satu target.
Fase independen dijalankan secara paralel menggunakan ThreadPoolExecutor.

Urutan eksekusi:
  Gelombang 1 : subdomain (output-nya dipakai fase lain)
  Gelombang 2 : dns, ports, fingerprint, urls, security, dirbrute (paralel)
  Gelombang 3 : js, params (paralel, setelah urls selesai)
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from config import FASE_LIST, DEFAULT_OUTPUT_DIR
from core.report import Report
from core.utils import info, ok, warn, err, section, console
from rich.progress import Progress, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
from rich.table import Table

import modules.subdomain   as mod_subdomain
import modules.dns         as mod_dns
import modules.ports       as mod_ports
import modules.fingerprint as mod_fingerprint
import modules.urls        as mod_urls
import modules.js          as mod_js
import modules.params      as mod_params
import modules.security    as mod_security
import modules.dirbrute    as mod_dirbrute


FASE_MAP = {
    "subdomain":   mod_subdomain,
    "dns":         mod_dns,
    "ports":       mod_ports,
    "fingerprint": mod_fingerprint,
    "urls":        mod_urls,
    "js":          mod_js,
    "params":      mod_params,
    "security":    mod_security,
    "dirbrute":    mod_dirbrute,
}

_HARD_DEPS: dict[str, str] = {
    "js":     "urls",
    "params": "urls",
}

# File output yang menandakan fase sudah pernah jalan
_FASE_OUTPUT_CHECK: dict[str, str] = {
    "subdomain":   "subdomain/alive_subdomains.txt",
    "dns":         "dns/dns_records.txt",
    "ports":       "ports/open_ports.txt",
    "fingerprint": "fingerprint/tech_stack.txt",
    "urls":        "urls/all_urls.txt",
    "js":          "js/js_files.txt",
    "params":      "params/discovered_params.txt",
    "security":    "security/security_analysis.txt",
    "dirbrute":    "dirbrute/ffuf_results.txt",
}


def _setup_dirs(target_dir: str, fases: list = None):
    subdirs = list(fases) if fases else [
        "subdomain", "dns", "ports", "fingerprint",
        "urls", "js", "security", "dirbrute",
    ]
    for d in subdirs + ["report"]:
        os.makedirs(os.path.join(target_dir, d), exist_ok=True)


def _get_waves(fases: list[str]) -> list[list[str]]:
    waves: list[list[str]] = []
    if "subdomain" in fases:
        waves.append(["subdomain"])
    wave2 = [f for f in fases if f != "subdomain" and f not in _HARD_DEPS]
    if wave2:
        waves.append(wave2)
    wave3 = [f for f in fases if f in _HARD_DEPS]
    if wave3:
        waves.append(wave3)
    return waves


def _fase_done(target_dir: str, fase: str) -> bool:
    """Cek apakah fase sudah punya output dari run sebelumnya."""
    check = _FASE_OUTPUT_CHECK.get(fase)
    if not check:
        return False
    path = os.path.join(target_dir, check)
    return os.path.exists(path) and os.path.getsize(path) > 0


def _run_fase(
    fase: str,
    target: str,
    target_dir: str,
) -> bool:
    mod = FASE_MAP[fase]
    try:
        mod.run(target, target_dir)
        ok(f"fase {fase} selesai")
        return True
    except Exception as exc:
        warn(f"fase {fase} gagal: {exc}")
        return False


def _print_summary(report: Report):
    s = report.get_stats()

    table = Table(title=f"ringkasan — {report.target}", show_header=True, header_style="bold cyan")
    table.add_column("temuan", style="white")
    table.add_column("jumlah", justify="right")

    def _row(label, val, critical=False):
        color = "bold red" if critical and val > 0 else ("bold green" if val > 0 else "dim")
        table.add_row(label, f"[{color}]{val}[/{color}]")

    _row("subdomain aktif",       s["alive_sub"])
    _row("subdomain total",       s["total_sub"])
    _row("open ports",            s["open_ports"])
    _row("total URLs",            s["total_urls"])
    _row("URL terkategorisasi",   s["categorized"])
    _row("JS endpoints",          s["js_ep"])
    _row("potential secrets",     s["secrets"],      critical=True)
    _row("hidden params",         s["disc_params"],  critical=True)
    _row("takeover candidates",   s["takeover"],     critical=True)
    _row("CORS issues",           s["cors"],         critical=True)
    _row("missing sec headers",   s["missing_hdrs"])
    _row("insecure cookies",      s["cookies_bad"])

    console.print()
    console.print(table)


def run_target(
    target: str,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    fases: list = None,
    resume: bool = False,
):
    if fases is None:
        fases = FASE_LIST

    invalid = [f for f in fases if f not in FASE_MAP]
    if invalid:
        err(f"Fase tidak dikenal: {', '.join(invalid)}")
        err(f"Fase yang tersedia: {', '.join(FASE_LIST)}")
        return

    date_tag    = datetime.now().strftime("recon_%d_%m_%Y")
    folder_name = target.replace("*.", "").replace("/", "_")
    target_dir  = os.path.join(output_dir, folder_name, date_tag)
    _setup_dirs(target_dir, fases)

    # filter fase yang sudah punya output jika --resume
    skipped: list[str] = []
    if resume:
        skipped = [f for f in fases if _fase_done(target_dir, f)]
        if skipped:
            info(f"resume: melewati {len(skipped)} fase: {', '.join(skipped)}")
        fases = [f for f in fases if f not in skipped]
        if not fases:
            info("semua fase sudah selesai, tidak ada yang perlu dijalankan")
            return

    report       = Report(target, target_dir)
    # load data fase yang di-skip agar report tetap lengkap
    for fase in skipped:
        _add_to_report(report, fase)

    waves        = _get_waves(fases)
    total        = len(fases)
    done_fases: list[str] = []

    section(f"target: {target}")
    info(f"output : {target_dir}")
    info(f"fase   : {', '.join(fases)}")

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("memulai...", total=total)

        for wave in waves:
            if len(wave) == 1:
                fase = wave[0]
                progress.update(task_id, description=f"fase: {fase}")
                if _run_fase(fase, target, target_dir):
                    done_fases.append(fase)
                progress.advance(task_id)
            else:
                info(f"menjalankan {len(wave)} fase paralel: {', '.join(wave)}")
                progress.update(task_id, description=f"paralel ({len(wave)} fase)")
                with ThreadPoolExecutor(max_workers=len(wave)) as executor:
                    future_to_fase = {
                        executor.submit(_run_fase, f, target, target_dir): f
                        for f in wave
                    }
                    for future in as_completed(future_to_fase):
                        fase = future_to_fase[future]
                        if future.result():
                            done_fases.append(fase)
                        progress.advance(task_id)

    # tambah ke report dalam urutan FASE_LIST, bukan urutan selesai
    for fase in FASE_LIST:
        if fase in done_fases:
            _add_to_report(report, fase)

    done_c  = len(done_fases)
    md_path, txt_path = report.save()
    _print_summary(report)

    section("selesai")
    info(f"fase berhasil : {done_c}/{total}")
    info(f"report md     : {md_path}")
    info(f"report txt    : {txt_path}")


def _add_to_report(report: Report, fase: str):
    getattr(report, f"fase_{fase}", lambda: None)()

"""
Runner — orkestrasi semua fase recon untuk satu target.
Mendukung pemilihan fase tertentu.
"""

import os
from datetime import datetime

from config import FASE_LIST, DEFAULT_OUTPUT_DIR
from core.report import Report
from core import utils
from core.utils import info, ok, warn, err, section, console
from rich.progress import Progress, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn

import modules.subdomain  as mod_subdomain
import modules.dns        as mod_dns
import modules.ports      as mod_ports
import modules.fingerprint as mod_fingerprint
import modules.urls       as mod_urls
import modules.js         as mod_js
import modules.security   as mod_security
import modules.dirbrute   as mod_dirbrute


FASE_MAP = {
    "subdomain":   mod_subdomain,
    "dns":         mod_dns,
    "ports":       mod_ports,
    "fingerprint": mod_fingerprint,
    "urls":        mod_urls,
    "js":          mod_js,
    "security":    mod_security,
    "dirbrute":    mod_dirbrute,
}


def _setup_dirs(target_dir: str, fases: list = None):
    subdirs = list(fases) if fases else [
        "subdomain", "dns", "ports", "fingerprint",
        "urls", "js", "security", "dirbrute",
    ]
    for d in subdirs + ["report"]:
        os.makedirs(os.path.join(target_dir, d), exist_ok=True)


def run_target(
    target: str,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    fases: list = None,
):
    """
    Jalankan recon untuk satu target.

    Args:
        target:     domain target (misal: example.com)
        output_dir: base folder output
        fases:      list fase yang mau dijalankan; None = semua
    """
    if fases is None:
        fases = FASE_LIST

    # validasi fase
    invalid = [f for f in fases if f not in FASE_MAP]
    if invalid:
        err(f"Fase tidak dikenal: {', '.join(invalid)}")
        err(f"Fase yang tersedia: {', '.join(FASE_LIST)}")
        return

    # setup folder target
    # Format: recon_DD_MM_YYYY
    date_tag    = datetime.now().strftime("recon_%d_%m_%Y")
    folder_name = target.replace("*.", "").replace("/", "_")
    target_dir  = os.path.join(output_dir, folder_name, date_tag)
    _setup_dirs(target_dir, fases)

    # report
    report = Report(target, target_dir)

    section(f"target: {target}")
    info(f"output : {target_dir}")
    info(f"fase   : {', '.join(fases)}")

    total  = len(fases)
    done_c = 0

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Memulai...", total=total)

        for fase in fases:
            progress.update(task_id, description=f"Fase {fase}")
            info(f"Menjalankan fase {fase}...")
            mod = FASE_MAP[fase]

            try:
                mod.run(target, target_dir)
                _add_to_report(report, fase)
                ok(f"Fase {fase} selesai")
                done_c += 1
            except Exception as exc:
                warn(f"Fase {fase} gagal: {exc}")

            progress.advance(task_id)

    # simpan laporan
    md_path, txt_path = report.save()

    section("selesai")
    info(f"fase berhasil : {done_c}/{total}")
    info(f"report md     : {md_path}")
    info(f"report txt    : {txt_path}")


def _add_to_report(report: Report, fase: str):
    getattr(report, f"fase_{fase}", lambda: None)()


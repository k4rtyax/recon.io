"""
Runner — orkestrasi semua fase recon untuk satu target.
Fase independen dijalankan secara paralel menggunakan ThreadPoolExecutor.

Urutan eksekusi:
  Gelombang 1 : subdomain (output-nya dipakai fase lain)
  Gelombang 2 : dns, ports, fingerprint, urls, security, dirbrute (paralel)
  Gelombang 3 : js, params (paralel, setelah urls selesai)
"""

import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from config import FASE_LIST, DEFAULT_OUTPUT_DIR
from core.report import Report
from core.utils import info, ok, warn, err, section, console
from rich.progress import Progress, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn

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

# Fase yang harus menunggu fase lain selesai dulu
_HARD_DEPS: dict[str, str] = {
    "js":     "urls",
    "params": "urls",
}


def _setup_dirs(target_dir: str, fases: list = None):
    subdirs = list(fases) if fases else [
        "subdomain", "dns", "ports", "fingerprint",
        "urls", "js", "security", "dirbrute",
    ]
    for d in subdirs + ["report"]:
        os.makedirs(os.path.join(target_dir, d), exist_ok=True)


def _get_waves(fases: list[str]) -> list[list[str]]:
    """Pisahkan fases ke dalam gelombang eksekusi berurutan."""
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


def _run_fase(
    fase: str,
    target: str,
    target_dir: str,
    report: Report,
    report_lock: threading.Lock,
) -> bool:
    mod = FASE_MAP[fase]
    try:
        mod.run(target, target_dir)
        with report_lock:
            _add_to_report(report, fase)
        ok(f"fase {fase} selesai")
        return True
    except Exception as exc:
        warn(f"fase {fase} gagal: {exc}")
        return False


def run_target(
    target: str,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    fases: list = None,
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

    report      = Report(target, target_dir)
    report_lock = threading.Lock()
    waves       = _get_waves(fases)
    total       = len(fases)
    done_c      = 0

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
                if _run_fase(fase, target, target_dir, report, report_lock):
                    done_c += 1
                progress.advance(task_id)
            else:
                info(f"menjalankan {len(wave)} fase paralel: {', '.join(wave)}")
                progress.update(task_id, description=f"paralel ({len(wave)} fase)")
                with ThreadPoolExecutor(max_workers=len(wave)) as executor:
                    future_to_fase = {
                        executor.submit(
                            _run_fase, f, target, target_dir, report, report_lock
                        ): f
                        for f in wave
                    }
                    for future in as_completed(future_to_fase):
                        if future.result():
                            done_c += 1
                        progress.advance(task_id)

    md_path, txt_path = report.save()

    section("selesai")
    info(f"fase berhasil : {done_c}/{total}")
    info(f"report md     : {md_path}")
    info(f"report txt    : {txt_path}")


def _add_to_report(report: Report, fase: str):
    getattr(report, f"fase_{fase}", lambda: None)()

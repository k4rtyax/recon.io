"""
Runner, orkestrasi semua fase recon untuk satu target.
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
from core.utils import info, ok, warn, err, section, console, sink_active, cancelled, reset_cancel
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
import modules.api         as mod_api
import modules.buckets     as mod_buckets


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
    "api":         mod_api,
    "buckets":     mod_buckets,
}

_HARD_DEPS: dict[str, str] = {
    "js":     "urls",
    "params": "urls",
    "api":    "urls",
}


def _setup_dirs(target_dir: str, fases: list = None):
    subdirs = list(fases) if fases else [
        "subdomain", "dns", "ports", "fingerprint",
        "urls", "js", "params", "security", "dirbrute", "api", "buckets",
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


_DONE_DIR = ".done"


def _marker(target_dir: str, fase: str) -> str:
    return os.path.join(target_dir, _DONE_DIR, fase)


def _mark_done(target_dir: str, fase: str):
    os.makedirs(os.path.join(target_dir, _DONE_DIR), exist_ok=True)
    with open(_marker(target_dir, fase), "w") as f:
        f.write(datetime.now().isoformat(timespec="seconds") + "\n")


def _resolve_target_dir(target: str, output_dir: str, resume: bool) -> str:
    """Folder run baru, atau run terakhir yang ada bila --resume."""
    folder_name = target.replace("*.", "").replace("/", "_")
    base = os.path.join(output_dir, folder_name)
    if resume and os.path.isdir(base):
        runs = [
            d for d in os.listdir(base)
            if d.startswith("recon_") and os.path.isdir(os.path.join(base, d))
        ]
        if runs:
            latest = max(runs, key=lambda d: os.path.getmtime(os.path.join(base, d)))
            return os.path.join(base, latest)
    return os.path.join(base, datetime.now().strftime("recon_%d_%m_%Y"))


def _notify(on_fase, fase: str, status: str):
    """Teruskan status fase ke UI. Error di callback tidak boleh menggagalkan fase."""
    if on_fase is None:
        return
    try:
        on_fase(fase, status)
    except Exception:
        pass


def _run_fase(
    fase: str,
    target: str,
    target_dir: str,
    on_fase=None,
) -> bool:
    mod = FASE_MAP[fase]
    if cancelled():
        _notify(on_fase, fase, "skip")
        return False
    _notify(on_fase, fase, "start")
    try:
        mod.run(target, target_dir)
        if cancelled():
            # tool-nya dimatikan di tengah jalan, hasilnya tidak lengkap:
            # jangan tandai selesai supaya --resume mengulang fase ini
            warn(f"fase {fase} dihentikan")
            _notify(on_fase, fase, "stop")
            return False
        _mark_done(target_dir, fase)
        ok(f"fase {fase} selesai")
        _notify(on_fase, fase, "done")
        return True
    except Exception as exc:
        warn(f"fase {fase} gagal: {exc}")
        _notify(on_fase, fase, "fail")
        return False


_SUMMARY_ROWS = [
    ("subdomain aktif",     "alive_sub",    False),
    ("subdomain total",     "total_sub",    False),
    ("open ports",          "open_ports",   False),
    ("total URLs",          "total_urls",   False),
    ("URL terkategorisasi", "categorized",  False),
    ("JS endpoints",        "js_ep",        False),
    ("potential secrets",   "secrets",      True),
    ("hidden params",       "disc_params",  True),
    ("takeover candidates", "takeover",     True),
    ("CORS issues",         "cors",         True),
    ("bucket terbuka",      "open_buckets", True),
    ("bucket terdeteksi",   "buckets",      False),
    ("endpoint GraphQL",    "graphql",      False),
    ("endpoint OpenAPI",    "api_eps",      False),
    ("missing sec headers", "missing_hdrs", False),
    ("insecure cookies",    "cookies_bad",  False),
]


def _print_summary(report: Report):
    s = report.get_stats()

    if sink_active():
        section(f"ringkasan, {report.target}")
        for label, key, critical in _SUMMARY_ROWS:
            val = s[key]
            if critical and val > 0:
                warn(f"{label:<20}: {val}")
            else:
                info(f"{label:<20}: {val}")
        return

    table = Table(title=f"ringkasan, {report.target}", show_header=True, header_style="bold cyan")
    table.add_column("temuan", style="white")
    table.add_column("jumlah", justify="right")

    for label, key, critical in _SUMMARY_ROWS:
        val = s[key]
        color = "bold red" if critical and val > 0 else ("bold green" if val > 0 else "dim")
        table.add_row(label, f"[{color}]{val}[/{color}]")

    console.print()
    console.print(table)


def run_target(
    target: str,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    fases: list = None,
    resume: bool = False,
    on_fase=None,
) -> str | None:
    """Jalankan semua fase untuk satu target.

    `on_fase(fase, status)` opsional, dipanggil dengan status "start", "done",
    "fail", "stop" (dihentikan di tengah jalan) atau "skip" (sudah selesai saat
    --resume, atau tidak dijalankan karena recon dihentikan). Bisa dipanggil
    dari thread worker.

    Recon bisa dihentikan dari thread lain lewat core.utils.cancel_all().

    Return folder output target (dipakai caller untuk fase lanjutan seperti
    verifikasi, jangan hitung ulang dari datetime.now(), karena recon panjang
    bisa melewati tengah malam dan menghasilkan folder tanggal yang berbeda),
    atau None bila fase tidak valid.
    """
    if fases is None:
        fases = FASE_LIST

    invalid = [f for f in fases if f not in FASE_MAP]
    if invalid:
        err(f"Fase tidak dikenal: {', '.join(invalid)}")
        err(f"Fase yang tersedia: {', '.join(FASE_LIST)}")
        return None

    reset_cancel()
    target_dir = _resolve_target_dir(target, output_dir, resume)
    _setup_dirs(target_dir, fases)

    done_fases: list[str] = []
    pending = list(fases)
    if resume:
        done_fases = [f for f in fases if os.path.exists(_marker(target_dir, f))]
        pending    = [f for f in fases if f not in done_fases]

    report       = Report(target, target_dir)
    waves        = _get_waves(pending)
    total        = len(fases)

    section(f"target: {target}")
    info(f"output : {target_dir}")
    info(f"fase   : {', '.join(fases)}")
    if done_fases:
        info(f"resume : {len(done_fases)} fase sudah selesai, dilewati ({', '.join(done_fases)})")
    for fase in done_fases:
        _notify(on_fase, fase, "skip")

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=sink_active(),
    ) as progress:
        task_id = progress.add_task("memulai...", total=total)
        if done_fases:
            progress.advance(task_id, len(done_fases))

        for wave in waves:
            if cancelled():
                for fase in wave:
                    _notify(on_fase, fase, "skip")
                continue
            if len(wave) == 1:
                fase = wave[0]
                progress.update(task_id, description=f"fase: {fase}")
                if _run_fase(fase, target, target_dir, on_fase):
                    done_fases.append(fase)
                progress.advance(task_id)
            else:
                info(f"menjalankan {len(wave)} fase paralel: {', '.join(wave)}")
                progress.update(task_id, description=f"paralel ({len(wave)} fase)")
                with ThreadPoolExecutor(max_workers=len(wave)) as executor:
                    future_to_fase = {
                        executor.submit(_run_fase, f, target, target_dir, on_fase): f
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

    if cancelled():
        warn("recon dihentikan, report dibuat dari fase yang sudah selesai")

    done_c  = len(done_fases)
    md_path, txt_path = report.save()
    _print_summary(report)

    section("selesai")
    info(f"fase berhasil : {done_c}/{total}")
    info(f"report md     : {md_path}")
    info(f"report txt    : {txt_path}")

    return target_dir


def _add_to_report(report: Report, fase: str):
    getattr(report, f"fase_{fase}", lambda: None)()

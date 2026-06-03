"""
Runner — orkestrasi semua fase recon untuk satu target.
Mendukung checkpoint/resume dan pemilihan fase tertentu.
"""

import os
from datetime import datetime

from config import FASE_LIST, DEFAULT_OUTPUT_DIR
from core.checkpoint import Checkpoint
from core.report import Report
from core import utils
from core.utils import info, ok, warn, err, section

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


def _setup_dirs(target_dir: str):
    subdirs = [
        "subdomain", "dns", "ports", "fingerprint",
        "urls", "js", "security", "dirbrute", "report",
    ]
    for d in subdirs:
        os.makedirs(os.path.join(target_dir, d), exist_ok=True)


def run_target(
    target: str,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    fases: list = None,
    resume: bool = True,
):
    """
    Jalankan recon untuk satu target.

    Args:
        target:     domain target (misal: example.com)
        output_dir: base folder output
        fases:      list fase yang mau dijalankan; None = semua
        resume:     lanjutkan dari checkpoint jika ada
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
    date_tag    = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = target.replace("*.", "").replace("/", "_")
    target_dir  = os.path.join(output_dir, folder_name, date_tag)
    _setup_dirs(target_dir)

    # checkpoint
    ckpt = Checkpoint(target_dir, target)

    # jika resume, cari checkpoint lama
    if resume:
        old_dir = _find_latest_dir(output_dir, folder_name)
        if old_dir and old_dir != target_dir:
            ckpt_old = Checkpoint(old_dir, target)
            done = ckpt_old.completed()
            if done:
                info(f"checkpoint ditemukan di: {old_dir}")
                info(f"fase selesai sebelumnya: {', '.join(done)}")
                target_dir = old_dir
                ckpt = ckpt_old
                _setup_dirs(target_dir)

    # report
    report = Report(target, target_dir)

    section(f"target: {target}")
    info(f"output : {target_dir}")
    info(f"fase   : {', '.join(fases)}")

    total  = len(fases)
    done_c = 0

    for i, fase in enumerate(fases, 1):
        if ckpt.is_done(fase):
            ok(f"[{i}/{total}] {fase} (skip — sudah selesai)")
            done_c += 1
            _add_to_report(report, fase)
            continue

        info(f"[{i}/{total}] {fase} ...")
        mod = FASE_MAP[fase]

        try:
            mod.run(target, target_dir)
            ckpt.mark_done(fase)
            _add_to_report(report, fase)
            ok(f"[{i}/{total}] {fase} selesai")
            done_c += 1
        except Exception as exc:
            ckpt.mark_failed(fase, str(exc))
            warn(f"[{i}/{total}] {fase} gagal: {exc}")

    # simpan laporan
    md_path, txt_path = report.save()

    section("selesai")
    info(f"fase berhasil : {done_c}/{total}")
    info(f"report md     : {md_path}")
    info(f"report txt    : {txt_path}")


def _add_to_report(report: Report, fase: str):
    getattr(report, f"fase_{fase}", lambda: None)()


def _find_latest_dir(base: str, folder_name: str) -> str | None:
    parent = os.path.join(base, folder_name)
    if not os.path.isdir(parent):
        return None
    dirs = sorted(
        [d for d in os.listdir(parent) if os.path.isdir(os.path.join(parent, d))],
        reverse=True,
    )
    for d in dirs:
        candidate = os.path.join(parent, d)
        ckpt_file = os.path.join(candidate, ".checkpoint.json")
        if os.path.exists(ckpt_file):
            return candidate
    return None

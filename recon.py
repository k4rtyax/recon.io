#!/usr/bin/env python3
"""
recon.io — universal web recon framework
-----------------------------------------
Penggunaan:
  python recon.py -t example.com
  python recon.py -f targets.txt
  python recon.py -t example.com --fase subdomain,dns,ports
  python recon.py -t example.com -o ~/hasil
  python recon.py -t example.com --no-resume
"""

import sys

if sys.version_info < (3, 10):
    sys.stderr.write("Error: Python 3.10+ is required to run recon.io due to union type hinting.\n")
    sys.exit(1)

import os
import argparse

# ── pastikan root project ada di path ────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import FASE_LIST, DEFAULT_OUTPUT_DIR
from core.utils import banner, section, info, warn, err
from core.runner import run_target


def parse_args():
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="recon.io — universal web recon framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=_help_epilog(),
    )

    # ── target ───────────────────────────────────────────────────
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-t", "--target",
        metavar="DOMAIN",
        help="satu target domain (contoh: example.com)",
    )
    group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="file teks berisi daftar target, satu per baris",
    )

    # ── opsional ─────────────────────────────────────────────────
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        default=DEFAULT_OUTPUT_DIR,
        help="folder output (default: ./results)",
    )
    parser.add_argument(
        "--fase",
        metavar="FASE",
        default="",
        help=(
            "pilih fase yang dijalankan, pisahkan dengan koma\n"
            f"tersedia: {', '.join(FASE_LIST)}\n"
            "contoh: --fase subdomain,dns,ports"
        ),
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        default=False,
        help="jangan lanjutkan dari checkpoint, mulai dari awal",
    )
    parser.add_argument(
        "--list-fase",
        action="store_true",
        help="tampilkan daftar fase yang tersedia lalu keluar",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="recon.io 1.0.0",
    )

    return parser.parse_args()


def _help_epilog() -> str:
    return f"""
contoh penggunaan:
  python recon.py -t opera.com
  python recon.py -f targets.txt -o ~/hasil
  python recon.py -t example.com --fase subdomain,dns,ports
  python recon.py -t example.com --no-resume

fase yang tersedia:
  {chr(10)+'  '.join(f'{i+1:2}. {f}' for i, f in enumerate(FASE_LIST))}
"""


def _load_targets_from_file(path: str) -> list[str]:
    if not os.path.exists(path):
        err(f"file tidak ditemukan: {path}")
        sys.exit(1)
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    if not targets:
        err(f"tidak ada target valid di: {path}")
        sys.exit(1)
    return targets


def main():
    args = parse_args()

    banner()

    # ── list fase ────────────────────────────────────────────────
    if args.list_fase:
        print("  fase yang tersedia:\n")
        for i, f in enumerate(FASE_LIST, 1):
            print(f"    {i:2}. {f}")
        print()
        sys.exit(0)

    # ── tentukan daftar fase ─────────────────────────────────────
    if args.fase:
        fases = [f.strip() for f in args.fase.split(",") if f.strip()]
        invalid = [f for f in fases if f not in FASE_LIST]
        if invalid:
            err(f"fase tidak dikenal: {', '.join(invalid)}")
            err(f"gunakan --list-fase untuk melihat daftar fase")
            sys.exit(1)
    else:
        fases = FASE_LIST

    # ── tentukan target(s) ───────────────────────────────────────
    if args.target:
        targets = [args.target.strip()]
    else:
        targets = _load_targets_from_file(args.file)

    # ── buat output dir ──────────────────────────────────────────
    os.makedirs(args.output, exist_ok=True)

    # ── jalankan recon ───────────────────────────────────────────
    total = len(targets)
    info(f"total target  : {total}")
    info(f"fase          : {', '.join(fases)}")
    info(f"output        : {args.output}")
    info(f"resume        : {'tidak' if args.no_resume else 'ya'}")

    for i, target in enumerate(targets, 1):
        section(f"[{i}/{total}] {target}")
        try:
            run_target(
                target=target,
                output_dir=args.output,
                fases=fases,
                resume=not args.no_resume,
            )
        except KeyboardInterrupt:
            print()
            warn("dihentikan oleh pengguna (Ctrl+C)")
            warn("progress sudah disimpan di checkpoint")
            warn("jalankan ulang untuk melanjutkan")
            sys.exit(0)
        except Exception as exc:
            err(f"error pada target {target}: {exc}")
            continue

    section("semua target selesai")
    info(f"hasil disimpan di: {args.output}")


if __name__ == "__main__":
    main()

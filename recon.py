#!/usr/bin/env python3
"""
recon.io — universal web recon framework
-----------------------------------------
Penggunaan:
  python recon.py -d example.com
  python recon.py -s api.example.com
  python recon.py -f targets.txt
  python recon.py -d example.com --fase subdomain,dns,ports
  python recon.py -d example.com -o ~/hasil
"""

import sys
import shutil

if sys.version_info < (3, 10):
    sys.stderr.write("Error: Python 3.10+ is required to run recon.io due to union type hinting.\n")
    sys.exit(1)

import os
import argparse

# ── pastikan root project ada di path ────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import FASE_LIST, DEFAULT_OUTPUT_DIR
from core.utils import banner, section, info, warn, err, console
from core.runner import run_target


def parse_args():
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="recon.io — universal web recon framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=_help_epilog(),
    )

    # ── target ───────────────────────────────────────────────────
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        help="target root domain (contoh: example.com), menjalankan semua fase",
    )
    group.add_argument(
        "-s", "--subdomain",
        metavar="SUBDOMAIN",
        help="target spesifik subdomain (contoh: api.example.com), otomatis melewati fase pencarian subdomain",
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
        "-A",
        action="store_true",
        help="jalankan fase pemetaan jaringan dasar saja (subdomain, dns, ports)",
    )
    parser.add_argument(
        "--list-fase",
        action="store_true",
        help="tampilkan daftar fase yang tersedia lalu keluar",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="cek status semua tools yang dibutuhkan lalu keluar",
    )
    parser.add_argument(
        "--recon-subs",
        action="store_true",
        dest="recon_subs",
        help=(
            "enumerasi subdomain dulu di root domain, lalu jalankan recon\n"
            "pada tiap subdomain aktif yang ditemukan\n"
            "gunakan --fase untuk pilih fase yang dijalankan per subdomain\n"
            "contoh: -d example.com --recon-subs --fase urls,js,security"
        ),
    )
    parser.add_argument(
        "--scope",
        metavar="FILE",
        help=(
            "file scope (.txt / .csv HackerOne) untuk membatasi target.\n"
            "target out-of-scope dilewati; pada --recon-subs, subdomain hasil\n"
            "enumerasi difilter ke yang in-scope saja"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="recon.io 2.0",
    )

    args = parser.parse_args()
    # target boleh kosong: bila tanpa target + terminal interaktif + ada GEMINI_API_KEY,
    # recon.py masuk mode chat (ditangani di main). Selain itu main yang beri error.
    if args.recon_subs and not args.domain:
        parser.error("--recon-subs hanya bisa digunakan dengan -d/--domain")
    return args


def _help_epilog() -> str:
    return f"""
contoh penggunaan:
  python recon.py -d opera.com
  python recon.py -s api.opera.com
  python recon.py -f targets.txt -o ~/hasil
  python recon.py -d example.com -A
  python recon.py -d example.com --fase subdomain,dns,ports
  python recon.py -d example.com --recon-subs
  python recon.py -d example.com --recon-subs --fase urls,js,security

fase yang tersedia:
  {chr(10)+'  '.join(f'{i+1:2}. {f}' for i, f in enumerate(FASE_LIST))}
"""


def _check_tools():
    from rich.table import Table
    from config import TOOLS

    _install_hint = {
        "subfinder":   "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "alterx":      "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
        "dnsx":        "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "httpx":       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "naabu":       "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "katana":      "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "nuclei":      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "ffuf":        "go install github.com/ffuf/ffuf/v2@latest",
        "amass":       "go install github.com/owasp-amass/amass/v4/...@master",
        "gau":         "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "subzy":       "go install github.com/PentestPad/subzy@latest",
        "wafw00f":     "pip install wafw00f",
        "arjun":       "pip install arjun",
        "nmap":        "brew install nmap  /  apt install nmap",
    }

    table = Table(title="recon.io — status tools", header_style="bold cyan")
    table.add_column("tool",    style="bold white", min_width=14)
    table.add_column("status",  min_width=10)
    table.add_column("install jika belum ada")

    all_tools = {**{k: v for k, v in TOOLS.items() if v}, "curl": "curl", "dig": "dig", "whois": "whois"}

    found = missing = 0
    for name, binary in sorted(all_tools.items()):
        if shutil.which(binary):
            table.add_row(name, "[bold green]✓ ada[/bold green]", "")
            found += 1
        else:
            hint = _install_hint.get(name, "")
            table.add_row(name, "[bold red]✗ tidak ada[/bold red]", f"[dim]{hint}[/dim]")
            missing += 1

    console.print(table)
    console.print(f"\n  [bold green]{found} tools siap[/bold green]  |  [bold red]{missing} belum terinstall[/bold red]\n")


def _find_alive_subs(output_dir: str, target: str) -> list[str]:
    """Baca alive_subdomains.txt dari hasil subdomain phase yang baru saja jalan."""
    from datetime import datetime
    date_tag    = datetime.now().strftime("recon_%d_%m_%Y")
    folder_name = target.replace("*.", "").replace("/", "_")
    alive_file  = os.path.join(output_dir, folder_name, date_tag, "subdomain", "alive_subdomains.txt")

    if not os.path.exists(alive_file):
        return []

    subs = []
    with open(alive_file) as f:
        for line in f:
            cleaned = _clean_target(line.strip())
            cleaned = cleaned.split("/")[0]  # buang path jika ada
            if cleaned:
                subs.append(cleaned)

    return list(dict.fromkeys(subs))  # dedupe, jaga urutan


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


def _clean_target(raw_target: str) -> str:
    # Hapus whitespace, http(s)://, dan wildcard prefix (*.)
    t = raw_target.strip()
    t = t.replace("http://", "").replace("https://", "")
    if t.startswith("*."):
        t = t[2:]
    return t.rstrip("/")


def main():
    args = parse_args()

    banner()

    # ── check tools ──────────────────────────────────────────────
    if args.check:
        _check_tools()
        sys.exit(0)

    # ── list fase ────────────────────────────────────────────────
    if args.list_fase:
        console.print("  [bold cyan]fase yang tersedia:[/bold cyan]\n")
        for i, f in enumerate(FASE_LIST, 1):
            console.print(f"    [bold green]{i:2}.[/bold green] [bold white]{f}[/bold white]")
        console.print()
        sys.exit(0)

    # ── tanpa target: mode chat AI (TTY + ada key) atau error ────
    if not (args.domain or args.subdomain or args.file):
        import core.ai as ai
        if sys.stdin.isatty() and sys.stdout.isatty() and ai.available():
            ai.chat_session(args.output)
            sys.exit(0)
        if ai.available():
            err("mode chat butuh terminal interaktif. jalankan: recon -d <domain>")
        else:
            err("tidak ada target. jalankan: recon -d <domain>")
            err("(set API key AI di .env — lihat .env.example — + jalankan di terminal untuk mode chat)")
        sys.exit(1)

    # ── tentukan daftar fase ─────────────────────────────────────
    if args.fase:
        fases = [f.strip() for f in args.fase.split(",") if f.strip()]
        invalid = [f for f in fases if f not in FASE_LIST]
        if invalid:
            err(f"fase tidak dikenal: {', '.join(invalid)}")
            err(f"gunakan --list-fase untuk melihat daftar fase")
            sys.exit(1)
    elif args.A:
        fases = ["subdomain", "dns", "ports"]
    else:
        fases = list(FASE_LIST)

    # ── tentukan target(s) ───────────────────────────────────────
    if args.domain:
        targets = [_clean_target(args.domain)]
    elif args.subdomain:
        targets = [_clean_target(args.subdomain)]
        if "subdomain" in fases:
            fases.remove("subdomain")
            info("Target adalah subdomain spesifik, fase 'subdomain' dilewati.")
    else:
        raw_targets = _load_targets_from_file(args.file)
        targets = [_clean_target(t) for t in raw_targets]

    # ── buat output dir ──────────────────────────────────────────
    os.makedirs(args.output, exist_ok=True)

    # ── load scope (opsional) ────────────────────────────────────
    scope = None
    if args.scope:
        from core.scope import Scope
        if not os.path.exists(args.scope):
            err(f"file scope tidak ditemukan: {args.scope}")
            sys.exit(1)
        try:
            scope = Scope.from_file(args.scope)
        except Exception as exc:
            err(f"gagal membaca scope: {exc}")
            sys.exit(1)
        info(f"scope         : {scope.summary()}")

    # ── jalankan recon ───────────────────────────────────────────
    if args.recon_subs:
        root = targets[0]

        # fase per subdomain = fase terpilih minus 'subdomain'.
        # 'fases' sudah menghormati --fase, -A, maupun default, jadi cukup pakai itu.
        sub_fases = [f for f in fases if f != "subdomain"]
        if not sub_fases:
            warn("tidak ada fase tersisa untuk dijalankan per subdomain")
            sys.exit(0)

        info(f"mode          : recon-subs")
        info(f"root domain   : {root}")
        info(f"fase subs     : {', '.join(sub_fases)}")
        info(f"output        : {args.output}")

        # step 1: enumerasi subdomain di root
        section(f"[1] enumerasi subdomain — {root}")
        try:
            run_target(target=root, output_dir=args.output, fases=["subdomain"])
        except KeyboardInterrupt:
            console.print()
            warn("dihentikan oleh pengguna (Ctrl+C)")
            sys.exit(0)

        # step 2: load subdomain aktif
        alive_subs = _find_alive_subs(args.output, root)
        if not alive_subs:
            warn("tidak ada subdomain aktif ditemukan, recon-subs berhenti")
            sys.exit(0)

        info(f"subdomain aktif ditemukan: {len(alive_subs)}")

        # filter ke scope (buang subdomain out-of-scope sebelum di-recon)
        if scope:
            before = len(alive_subs)
            alive_subs = scope.filter(alive_subs)
            dropped = before - len(alive_subs)
            if dropped:
                info(f"scope filter  : {dropped} out-of-scope dibuang, {len(alive_subs)} in-scope")
            if not alive_subs:
                warn("tidak ada subdomain in-scope, recon-subs berhenti")
                sys.exit(0)

        # step 3: recon tiap subdomain
        total_subs = len(alive_subs)
        for i, sub in enumerate(alive_subs, 1):
            section(f"[{i}/{total_subs}] {sub}")
            try:
                run_target(target=sub, output_dir=args.output, fases=sub_fases)
            except KeyboardInterrupt:
                console.print()
                warn("dihentikan oleh pengguna (Ctrl+C)")
                sys.exit(0)
            except Exception as exc:
                err(f"error pada {sub}: {exc}")
                continue

        section("semua subdomain selesai")
        info(f"hasil disimpan di: {args.output}")
        return

    total = len(targets)
    info(f"total target  : {total}")
    info(f"fase          : {', '.join(fases)}")
    info(f"output        : {args.output}")

    for i, target in enumerate(targets, 1):
        if scope:
            in_scope, reason = scope.check(target)
            if not in_scope:
                warn(f"[{i}/{total}] {target} di luar scope ({reason}), dilewati")
                continue
        section(f"[{i}/{total}] {target}")
        try:
            run_target(
                target=target,
                output_dir=args.output,
                fases=fases,
            )
        except KeyboardInterrupt:
            console.print()
            warn("dihentikan oleh pengguna (Ctrl+C)")
            sys.exit(0)
        except Exception as exc:
            err(f"error pada target {target}: {exc}")
            continue

    section("semua target selesai")
    info(f"hasil disimpan di: {args.output}")


if __name__ == "__main__":
    main()

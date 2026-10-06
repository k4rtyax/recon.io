import os
import sys
import shutil
import signal
import subprocess
import threading
from datetime import datetime
from rich.console import Console
from rich.markup import escape
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from config import TOOLS

# Windows: stdout yang dialihkan (pipe/file) memakai codepage lokal (cp1252),
# banner dan simbol unicode bisa memicu UnicodeEncodeError. Paksa UTF-8.
for _stream in (sys.stdout, sys.stderr):
    if _stream and hasattr(_stream, "reconfigure") and \
            (_stream.encoding or "").lower().replace("-", "") != "utf8":
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

# Inisialisasi rich console
console = Console(
    theme=Theme({
        "info": "cyan",
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "timestamp": "dim white",
    })
)


def _ts():
    return datetime.now().strftime("%H:%M:%S")


# ── sink: alihkan log ke UI lain (mode TUI) ──────────────────────
# Selama sink aktif, tidak ada yang boleh menulis langsung ke stdout
# karena akan merusak tampilan layar penuh.

_sink = None


def set_sink(fn):
    """fn(level, msg, data=None) menerima semua log. None mengembalikan output ke console.

    Level "finding" membawa data {"kind", "severity", "detail"}.
    """
    global _sink
    _sink = fn


def sink_active() -> bool:
    return _sink is not None


def info(msg: str):
    if _sink:
        _sink("info", msg)
        return
    console.print(f"[timestamp][{_ts()}][/timestamp] [info][*][/info] {escape(msg)}")


def ok(msg: str):
    if _sink:
        _sink("ok", msg)
        return
    console.print(f"[timestamp][{_ts()}][/timestamp] [ok][✓][/ok] {escape(msg)}")


def warn(msg: str):
    if _sink:
        _sink("warn", msg)
        return
    console.print(f"[timestamp][{_ts()}][/timestamp] [warn][!][/warn] {escape(msg)}")


def err(msg: str):
    if _sink:
        _sink("err", msg)
        return
    console.print(f"[timestamp][{_ts()}][/timestamp] [err][✗][/err] {escape(msg)}")


def finding(kind: str, severity: str, detail: str, cli: str | None = None, quiet_cli: bool = False):
    """Laporkan temuan (secret, takeover, bucket terbuka, dll).

    Di TUI masuk ke panel temuan. Di CLI dicetak sebagai warn(cli or detail),
    kecuali quiet_cli, supaya output CLI yang lama tidak berubah.
    """
    if _sink:
        _sink("finding", detail, {"kind": kind, "severity": severity.upper(), "detail": detail})
        return
    if not quiet_cli:
        warn(cli or detail)


def section(title: str):
    if _sink:
        _sink("section", title)
        return
    console.print()
    console.print(f"[bold cyan]── {escape(title)} ──[/bold cyan]")


def banner(version="2.0"):
    art = r"""
░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░       ░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓██████▓▒░  
"""
    console.print(f"[bold cyan]{art}[/bold cyan]")
    console.print(f"  [dim]v{version}, universal web recon framework[/dim]\n")


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run(cmd: list, timeout: int = 60, silent: bool = True, input_data: str | None = None) -> tuple[int, str, str]:
    """
    Jalankan perintah (tanpa shell). `input_data` dikirim ke stdin bila diberikan.
    Return: (returncode, stdout, stderr)
    """
    try:
        return _exec(cmd, timeout, input_data=input_data)
    except FileNotFoundError:
        return -1, "", f"tool not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def run_shell(cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    """Jalankan string perintah via shell."""
    try:
        return _exec(cmd, timeout, shell=True)
    except Exception as e:
        return -1, "", str(e)


# ── pembatalan: hentikan semua proses tool yang sedang jalan ─────
# Dipakai TUI (ctrl+x). Runner berhenti memulai fase baru, modul HTTP
# berhenti di request berikutnya, dan run() menolak menjalankan tool baru.

_procs: set = set()
_procs_lock = threading.Lock()
_cancel = threading.Event()


def cancelled() -> bool:
    return _cancel.is_set()


def reset_cancel():
    _cancel.clear()


def cancel_all():
    _cancel.set()
    with _procs_lock:
        procs = list(_procs)
    for proc in procs:
        _kill_tree(proc)


def _kill_tree(proc: subprocess.Popen):
    """Matikan proses beserta anaknya (penting untuk shell=True)."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=10,
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _exec(cmd, timeout: int, shell: bool = False, input_data: str | None = None) -> tuple[int, str, str]:
    if _cancel.is_set():
        return -1, "", "dibatalkan"

    proc = subprocess.Popen(
        cmd,
        shell=shell,
        stdin=subprocess.PIPE if input_data is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # grup proses sendiri supaya _kill_tree bisa mematikan anak-anaknya
        start_new_session=(os.name != "nt"),
    )
    with _procs_lock:
        _procs.add(proc)
    try:
        # cancel_all bisa jalan di antara cek awal dan pendaftaran proses
        if _cancel.is_set():
            _kill_tree(proc)
        try:
            out, errout = proc.communicate(input=input_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.communicate()
            return -1, "", "timeout"
    except BaseException:
        # mis. KeyboardInterrupt di mode CLI: jangan tinggalkan proses yatim
        _kill_tree(proc)
        raise
    finally:
        with _procs_lock:
            _procs.discard(proc)

    if _cancel.is_set():
        return -1, out or "", "dibatalkan"
    return proc.returncode, out, errout


def write_lines(path: str, lines: list[str]):
    with open(path, "w") as f:
        for line in lines:
            f.write(line.strip() + "\n")


def read_lines(path: str) -> list[str]:
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def count_lines(path: str) -> int:
    return len(read_lines(path))


def dedupe_file(path: str):
    lines = read_lines(path)
    write_lines(path, sorted(set(lines)))


_url_cache: dict[str, str] = {}


def get_working_url(target: str, timeout: int = 5) -> str:
    """Cek apakah target mendukung HTTPS, jika gagal gunakan HTTP. Hasil di-cache."""
    if target in _url_cache:
        return _url_cache[target]
    code, stdout, _ = run(
        [TOOLS["curl"], "-sI", "-L", "--max-time", str(timeout), f"https://{target}"],
        timeout=timeout + 2,
    )
    result = f"https://{target}" if code == 0 and stdout.strip() else f"http://{target}"
    _url_cache[target] = result
    return result

import sys
import shutil
import subprocess
from datetime import datetime
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text

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


def info(msg: str):
    console.print(f"[timestamp][{_ts()}][/timestamp] [info][*][/info] {msg}")


def ok(msg: str):
    console.print(f"[timestamp][{_ts()}][/timestamp] [ok][✓][/ok] {msg}")


def warn(msg: str):
    console.print(f"[timestamp][{_ts()}][/timestamp] [warn][!][/warn] {msg}")


def err(msg: str):
    console.print(f"[timestamp][{_ts()}][/timestamp] [err][✗][/err] {msg}")


def section(title: str):
    console.print()
    console.print(f"[bold cyan]── {title} ──[/bold cyan]")


def banner(version="1.5"):
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
    console.print(f"  [dim]v{version} — universal web recon framework[/dim]\n")


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run(cmd: list, timeout: int = 60, silent: bool = True) -> tuple[int, str, str]:
    """
    Jalankan perintah shell.
    Return: (returncode, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"tool not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def run_shell(cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    """Jalankan string perintah via shell."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


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


def get_working_url(target: str, timeout: int = 5) -> str:
    """Cek apakah target mendukung HTTPS, jika gagal gunakan HTTP."""
    code, stdout, _ = run(
        ["curl", "-sI", "-L", "--max-time", str(timeout), f"https://{target}"],
        timeout=timeout + 2,
    )
    if code == 0 and stdout.strip():
        return f"https://{target}"
    return f"http://{target}"

import sys
import shutil
import subprocess
from datetime import datetime

# ─── WARNA TERMINAL (minimal, tidak mencolok) ────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
WHITE  = "\033[37m"
GRAY   = "\033[90m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str):
    print(f"  {GRAY}[{_ts()}]{RESET}  {msg}")


def ok(msg: str):
    print(f"  {GRAY}[{_ts()}]{RESET}  {GREEN}ok{RESET}  {msg}")


def warn(msg: str):
    print(f"  {GRAY}[{_ts()}]{RESET}  {YELLOW}!{RESET}   {msg}")


def err(msg: str):
    print(f"  {GRAY}[{_ts()}]{RESET}  {RED}err{RESET} {msg}")


def section(title: str):
    width = 52
    print()
    print(f"  {DIM}{'─' * width}{RESET}")
    print(f"  {BOLD}{title}{RESET}")
    print(f"  {DIM}{'─' * width}{RESET}")


def banner(version="1.0.0"):
    art = r"""
░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░       ░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓██████▓▒░  
"""
    print(f"{CYAN}{art}{RESET}")
    print(f"  {DIM}v{version} — universal web recon framework{RESET}")
    print()


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

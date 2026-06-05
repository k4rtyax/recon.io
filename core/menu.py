"""
Menu interaktif keyboard (panah / checkbox) via simple-term-menu.

Degrade aman: bila lib tidak terpasang ATAU output non-TTY (pipe/CI),
otomatis fallback ke input teks bernomor. Jadi tetap jalan di mana saja.
"""

import sys


def _enabled() -> bool:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    try:
        import simple_term_menu  # noqa: F401
        return True
    except Exception:
        return False


def pick(title: str, options: list[str]) -> str | None:
    """Pilih SATU dari options. Return string terpilih, atau None bila batal."""
    options = list(options)
    if not options:
        return None
    if _enabled():
        from simple_term_menu import TerminalMenu
        idx = TerminalMenu(options, title=title).show()
        return options[idx] if idx is not None else None
    # fallback teks
    print(title)
    for i, o in enumerate(options, 1):
        print(f"  {i}. {o}")
    raw = input("pilih nomor (kosong = batal): ").strip()
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1]
    return None


def multi_pick(title: str, options: list[str], preselected: list[str] | None = None) -> list[str]:
    """Pilih BEBERAPA (checkbox). Return list string terpilih (bisa kosong)."""
    options = list(options)
    if not options:
        return []
    preselected = [o for o in (preselected or []) if o in options]
    if _enabled():
        from simple_term_menu import TerminalMenu
        menu = TerminalMenu(
            options,
            multi_select=True,
            show_multi_select_hint=True,
            preselected_entries=preselected or None,
        )
        chosen = menu.show()
        if not chosen:
            return []
        return [options[i] for i in chosen]
    # fallback teks
    print(title)
    for i, o in enumerate(options, 1):
        mark = "x" if o in preselected else " "
        print(f"  [{mark}] {i}. {o}")
    raw = input("nomor pisah koma (kosong = pakai default): ").strip()
    if not raw:
        return list(preselected)
    out = []
    for tok in raw.split(","):
        tok = tok.strip()
        if tok.isdigit() and 1 <= int(tok) <= len(options):
            out.append(options[int(tok) - 1])
    return out


def confirm(question: str, default: bool = False) -> bool:
    """Konfirmasi ya/tidak."""
    if _enabled():
        from simple_term_menu import TerminalMenu
        idx = TerminalMenu(["ya", "tidak"], title=question).show()
        return idx == 0
    suffix = "[Y/n]" if default else "[y/N]"
    raw = input(f"{question} {suffix}: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "ya", "yes"}

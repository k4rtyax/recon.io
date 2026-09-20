"""
Mode TUI — antarmuka layar penuh untuk recon interaktif.
Log tiap fase dialirkan ke panel lewat sink di core.utils, jadi tidak ada
yang menulis langsung ke stdout selama TUI hidup.
"""

import os
import re
import threading
from datetime import datetime

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Input, RichLog, Static

from config import FASE_LIST, DEFAULT_OUTPUT_DIR
from core import utils


_HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
_FASE_RE = re.compile(r"(?:--fase|fase|fokus|fokusin)\s+([a-z0-9,\s]+)", re.I)

_QUIT  = {"exit", "quit", "keluar", "q"}
_YES   = {"y", "ya", "yes", "ok", "oke", "lanjut", "gas"}
_NO    = {"n", "no", "nggak", "gak", "batal", "tidak"}

_MARK = {
    "info":    ("*", "cyan"),
    "ok":      ("✓", "bold green"),
    "warn":    ("!", "bold yellow"),
    "err":     ("✗", "bold red"),
    "section": ("─", "bold cyan"),
}


def _clean_target(raw: str) -> str:
    t = raw.strip().replace("http://", "").replace("https://", "")
    if t.startswith("*."):
        t = t[2:]
    return t.rstrip("/")


def _parse_local(text: str) -> dict | None:
    """Intent tanpa AI: '<domain>' atau 'recon <domain> fase urls,js'."""
    host = _HOST_RE.search(text)
    if not host:
        return None

    fases = None
    m = _FASE_RE.search(text)
    if m:
        picked = [f.strip() for f in re.split(r"[,\s]+", m.group(1)) if f.strip()]
        fases  = [f for f in picked if f in FASE_LIST] or None

    return {"action": "run", "target": host.group(1), "fases": fases}


class ReconTUI(App):
    CSS = """
    Screen { background: $surface; }

    #topbar {
        dock: top;
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 1;
    }

    #log {
        background: $surface;
        padding: 0 1;
        scrollbar-size-vertical: 1;
    }

    #status {
        dock: bottom;
        height: 1;
        background: $surface;
        color: $text-muted;
        padding: 0 1;
    }

    #prompt {
        dock: bottom;
        border: none;
        border-left: thick $accent;
        background: $panel;
        padding: 0 1;
    }

    #prompt:focus { border-left: thick $success; }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit",  "keluar"),
        Binding("escape", "batal", "batal"),
        Binding("ctrl+l", "bersih", "bersihkan"),
    ]

    def __init__(self, output_dir: str = DEFAULT_OUTPUT_DIR, scope=None):
        super().__init__()
        self.output_dir = output_dir
        self.scope      = scope
        self.target: str | None     = None
        self.target_dir: str | None = None
        self.pending: dict | None   = None
        self.running    = False
        self.fase_done  = 0
        self.fase_total = 0
        self.started: datetime | None = None
        self.history: list[str] = []
        self.use_ai = False

    # ── layout ───────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Static("recon.io", id="topbar")
        yield RichLog(id="log", wrap=True, auto_scroll=True)
        yield Static("", id="status")
        yield Input(placeholder="sebut target, mis. example.com fokus urls,js", id="prompt")
        yield Footer()

    def on_mount(self):
        utils.set_sink(self._sink)
        self.set_interval(1.0, self._refresh_topbar)

        from core import ai
        self.use_ai = ai.available()

        self._say("recon.io — mode TUI", "bold cyan")
        if self.use_ai:
            self._say(f"AI aktif ({ai.provider_name()}) — bicara biasa saja.", "dim")
        else:
            self._say("AI belum dikonfigurasi — pakai perintah langsung.", "dim")
            self._say("contoh: example.com fokus urls,js   |   recon api.example.com", "dim")
        self._say("ketik 'fase' untuk daftar fase, 'keluar' untuk berhenti.", "dim")
        self._blank()
        self.query_one("#prompt", Input).focus()

    def on_unmount(self):
        utils.set_sink(None)

    # ── tulis ke panel ───────────────────────────────────────────

    def _sink(self, level: str, msg: str):
        """Dipanggil modul fase, sering dari thread worker."""
        if threading.current_thread() is threading.main_thread():
            self._write(level, msg)
        else:
            self.call_from_thread(self._write, level, msg)

    def _write(self, level: str, msg: str):
        log = self.query_one("#log", RichLog)

        if level == "section":
            log.write(Text(f"\n── {msg} ──", style="bold cyan"))
            return

        if level == "ok" and msg.startswith("fase ") and msg.endswith("selesai"):
            self.fase_done += 1

        mark, style = _MARK.get(level, ("*", "cyan"))
        line = Text()
        line.append(f"{datetime.now():%H:%M:%S} ", style="dim")
        line.append(f"{mark} ", style=style)
        line.append(msg, style="bold yellow" if level == "warn" else
                         ("bold red" if level == "err" else ""))
        log.write(line)

    def _say(self, msg: str, style: str = ""):
        self.query_one("#log", RichLog).write(Text(msg, style=style))

    def _blank(self):
        self.query_one("#log", RichLog).write("")

    def _echo_user(self, msg: str):
        line = Text()
        line.append("› ", style="bold cyan")
        line.append(msg, style="bold")
        self._blank()
        self.query_one("#log", RichLog).write(line)

    def _set_status(self, msg: str, style: str = "dim"):
        self.query_one("#status", Static).update(Text(msg, style=style))

    def _refresh_topbar(self):
        bits = ["recon.io"]
        if self.target:
            bits.append(self.target)
        if self.fase_total:
            bits.append(f"{self.fase_done}/{self.fase_total} fase")
        if self.started and self.running:
            secs = int((datetime.now() - self.started).total_seconds())
            bits.append(f"{secs // 60:02d}:{secs % 60:02d}")
        self.query_one("#topbar", Static).update(Text("  ·  ".join(bits), style="dim"))

    # ── input ────────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted):
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return

        self._echo_user(text)
        cmd = text.strip("'\"`. ").lower()

        if cmd in _QUIT:
            self.exit()
            return
        if cmd in {"fase", "fases", "list-fase"}:
            self._say("fase tersedia: " + ", ".join(FASE_LIST), "cyan")
            return
        if cmd in {"bantuan", "help", "?"}:
            self._help()
            return

        if self.pending:
            self._answer_confirm(cmd)
            return

        if self.running:
            self._say("masih ada recon berjalan — tunggu sampai selesai.", "bold yellow")
            return

        self._handle(text)

    def _help(self):
        self._say("example.com                 jalankan semua fase", "cyan")
        self._say("example.com fokus urls,js   pilih fase tertentu", "cyan")
        self._say("fase                        daftar fase", "cyan")
        self._say("keluar                      tutup TUI", "cyan")

    def _handle(self, text: str):
        got = _parse_local(text)

        if not got and self.use_ai:
            self._set_status("menghubungi AI...")
            got = self._ask_ai(text)
            self._set_status("")

        if not got:
            self._say("target tidak terbaca — sebut domainnya, mis. example.com", "bold yellow")
            return

        if got.get("action") != "run":
            msg = (got.get("message") or "").strip()
            if msg:
                self._say(msg, "green")
            return

        target = _clean_target(got.get("target") or "")
        if not target:
            self._say("target mana yang mau di-recon?", "bold yellow")
            return

        if self.scope is not None:
            in_scope, reason = self.scope.check(target)
            if not in_scope:
                self._say(f"{target} di luar scope ({reason}) — tidak dijalankan.", "bold red")
                return

        fases = [f for f in (got.get("fases") or []) if f in FASE_LIST] or list(FASE_LIST)
        self.pending = {"target": target, "fases": fases}
        self._blank()
        self._say(f"rencana: {target}  ·  {', '.join(fases)}", "bold")
        self._say(f"output : {self.output_dir}", "dim")
        self._set_status("jalankan? [y/n]", "bold yellow")

    def _ask_ai(self, text: str) -> dict | None:
        from core import ai
        try:
            got = ai.intent(text, self.history)
        except Exception as exc:
            self._say(f"AI gagal: {exc}", "bold red")
            return None
        if got:
            self.history += [f"USER: {text}", f"AI: {got.get('action')}"]
        return got

    def _answer_confirm(self, cmd: str):
        plan = self.pending
        self.pending = None
        self._set_status("")

        if cmd not in _YES:
            if cmd in _NO:
                self._say("oke, dibatalkan.", "dim")
            else:
                self._say("dibatalkan — jawab y atau n.", "dim")
            return

        self.target     = plan["target"]
        self.fase_total = len(plan["fases"])
        self.fase_done  = 0
        self.started    = datetime.now()
        self.running    = True
        self._set_status("recon berjalan...", "bold green")
        self._run_recon(plan["target"], plan["fases"])

    # ── eksekusi recon ───────────────────────────────────────────

    @work(thread=True, exclusive=True)
    def _run_recon(self, target: str, fases: list[str]):
        from core.runner import run_target
        try:
            target_dir = run_target(target=target, output_dir=self.output_dir, fases=fases)
        except Exception as exc:
            self.call_from_thread(self._finish, None, str(exc))
            return
        self.call_from_thread(self._finish, target_dir, "")

    def _finish(self, target_dir: str | None, error: str):
        self.running = False
        self._set_status("")
        if error:
            self._say(f"recon gagal: {error}", "bold red")
            return
        self.target_dir = target_dir
        self._blank()
        self._say(f"selesai — hasil di {target_dir}", "bold green")
        self.query_one("#prompt", Input).focus()

    # ── aksi keybinding ──────────────────────────────────────────

    def action_batal(self):
        if self.pending:
            self.pending = None
            self._set_status("")
            self._say("dibatalkan.", "dim")

    def action_bersih(self):
        self.query_one("#log", RichLog).clear()


def run_tui(output_dir: str = DEFAULT_OUTPUT_DIR, scope=None):
    ReconTUI(output_dir=output_dir, scope=scope).run()

"""
Mode TUI, antarmuka layar penuh untuk recon interaktif.
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
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Input, ProgressBar, RichLog, Static

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

# status fase dari runner.on_fase, plus "idle" (tidak dipilih) dan "queued" (antre)
_FASE_MARK = {
    "idle":   ("·", "dim"),
    "queued": ("·", ""),
    "start":  ("▶", "bold cyan"),
    "done":   ("✔", "bold green"),
    "fail":   ("✗", "bold red"),
    "skip":   ("↷", "dim"),
    "stop":   ("■", "bold yellow"),
}
_FASE_END = {"done", "fail", "skip", "stop"}

_SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "cyan",
}

_STOP_WINDOW = 3.0   # detik antara dua tekanan ctrl+x


def _clock(secs: float) -> str:
    secs = int(secs)
    return f"{secs // 60:02d}:{secs % 60:02d}"


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

    #main { height: 1fr; }

    #side {
        width: 26;
        background: $panel;
        padding: 0 1;
    }

    #side-title { color: $text-muted; text-style: bold; }
    #total { margin-bottom: 1; }
    #total Bar { width: 1fr; }
    .fase { height: 1; }

    #right { width: 1fr; }

    #findings-title {
        height: 1;
        background: $panel;
        color: $text-muted;
        text-style: bold;
        padding: 0 1;
    }

    #findings { height: 8; background: $surface; }

    #findings-title, #findings { display: none; }
    #right.has-findings #findings-title, #right.has-findings #findings { display: block; }

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
        Binding("ctrl+c", "keluar", "keluar", priority=True),
        Binding("ctrl+x", "stop",   "stop scan", priority=True),
        Binding("escape", "batal",  "batal"),
        Binding("ctrl+t", "temuan", "temuan", priority=True),
        Binding("ctrl+l", "bersih", "bersihkan"),
    ]

    def __init__(self, output_dir: str = DEFAULT_OUTPUT_DIR, scope=None, autorun: dict | None = None):
        super().__init__()
        # autorun {"target", "fases", "resume"}: langsung recon tanpa konfirmasi (-d target --tui)
        self.autorun    = autorun
        self.output_dir = output_dir
        self.scope      = scope
        self.target: str | None     = None
        self.target_dir: str | None = None
        self.pending: dict | None   = None
        self.running    = False
        self.stopping   = False
        self.quit_after = False
        self.stop_armed: datetime | None = None
        self.fase_done  = 0
        self.fase_total = 0
        # fase -> [status, waktu mulai, waktu selesai]
        self.fase_state: dict[str, list] = {f: ["idle", None, None] for f in FASE_LIST}
        self.started: datetime | None = None
        self.history: list[str] = []
        self.findings: list[dict] = []
        self.use_ai = False

    # ── layout ───────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Static("recon.io", id="topbar")
        with Horizontal(id="main"):
            with Vertical(id="side"):
                yield Static("FASE", id="side-title")
                yield ProgressBar(total=len(FASE_LIST), show_eta=False, id="total")
                for f in FASE_LIST:
                    yield Static(id=f"fase-{f}", classes="fase")
            with Vertical(id="right"):
                yield RichLog(id="log", wrap=True, auto_scroll=True)
                yield Static(id="findings-title")
                yield DataTable(id="findings", cursor_type="row", zebra_stripes=True)
        yield Static("", id="status")
        yield Input(placeholder="sebut target, mis. example.com fokus urls,js", id="prompt")
        yield Footer()

    def on_mount(self):
        utils.set_sink(self._sink)
        self.set_interval(1.0, self._refresh_topbar)
        self.set_interval(1.0, self._refresh_running)
        for f in FASE_LIST:
            self._render_fase(f)
        self.query_one("#findings", DataTable).add_columns("severity", "jenis", "detail")

        from core import ai
        self.use_ai = ai.available()

        self._say("recon.io, mode TUI", "bold cyan")
        if self.use_ai:
            self._say(f"AI aktif ({ai.provider_name()}), bicara biasa saja.", "dim")
        else:
            self._say("AI belum dikonfigurasi, pakai perintah langsung.", "dim")
            self._say("contoh: example.com fokus urls,js   |   recon api.example.com", "dim")
        self._say("ketik 'fase' untuk daftar fase, 'keluar' untuk berhenti.", "dim")
        self._blank()
        self.query_one("#prompt", Input).focus()

        if self.autorun:
            run = self.autorun
            self._say(f"recon: {run['target']}  ·  {', '.join(run['fases'])}", "bold")
            self._start(run["target"], run["fases"], run.get("resume", False))

    def on_unmount(self):
        utils.set_sink(None)

    # ── tulis ke panel ───────────────────────────────────────────

    def _ui(self, fn, *args):
        """Jalankan fn di thread UI, aman dipanggil dari thread worker."""
        if threading.current_thread() is threading.main_thread():
            fn(*args)
        else:
            self.call_from_thread(fn, *args)

    def _sink(self, level: str, msg: str, data: dict | None = None):
        """Dipanggil modul fase, sering dari thread worker."""
        if level == "finding" and data:
            self._ui(self._add_finding, data)
            return
        self._ui(self._write, level, msg)

    def _on_fase(self, fase: str, status: str):
        """Callback runner.on_fase, dipanggil dari thread worker."""
        self._ui(self._set_fase, fase, status)

    def _write(self, level: str, msg: str):
        log = self.query_one("#log", RichLog)

        if level == "section":
            log.write(Text(f"\n── {msg} ──", style="bold cyan"))
            return

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

    # ── panel temuan ─────────────────────────────────────────────

    def _add_finding(self, f: dict):
        sev, kind, detail = f["severity"], f["kind"], f["detail"]
        style = _SEV_STYLE.get(sev, "")
        table = self.query_one("#findings", DataTable)
        table.add_row(Text(sev, style=style), Text(kind, style="bold"), Text(detail))
        table.move_cursor(row=table.row_count - 1)
        self.findings.append(f)
        self.query_one("#right").add_class("has-findings")
        self._refresh_findings_title()

        # tetap satu baris di log supaya urutan kejadian terbaca
        line = Text()
        line.append(f"{datetime.now():%H:%M:%S} ", style="dim")
        line.append("◆ ", style=style or "bold yellow")
        line.append(f"[{sev}] {kind}: ", style=style or "bold yellow")
        line.append(detail)
        self.query_one("#log", RichLog).write(line)

    def _refresh_findings_title(self):
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f["kind"]] = counts.get(f["kind"], 0) + 1
        title = Text(f"TEMUAN ({len(self.findings)})")
        if counts:
            title.append("  " + " · ".join(f"{k} {n}" for k, n in counts.items()), style="dim")
        title.append("   ctrl+t fokus", style="dim")
        self.query_one("#findings-title", Static).update(title)

    def _reset_findings(self):
        self.findings = []
        self.query_one("#findings", DataTable).clear()
        self.query_one("#right").remove_class("has-findings")

    # ── panel fase ───────────────────────────────────────────────

    def _reset_fases(self, picked: list[str]):
        for f in FASE_LIST:
            self.fase_state[f] = ["queued" if f in picked else "idle", None, None]
            self._render_fase(f)
        self.fase_done  = 0
        self.fase_total = len(picked)
        self.query_one("#total", ProgressBar).update(total=len(picked), progress=0)

    def _set_fase(self, fase: str, status: str):
        state = self.fase_state.get(fase)
        if state is None:
            return
        now = datetime.now()
        if status == "start":
            state[:] = ["start", now, None]
        else:
            state[0] = status
            state[2] = now
            if status in _FASE_END:
                self.fase_done += 1
                self.query_one("#total", ProgressBar).update(progress=self.fase_done)
        self._render_fase(fase)
        self._refresh_topbar()

    def _render_fase(self, fase: str):
        status, t0, t1 = self.fase_state[fase]
        mark, style = _FASE_MARK[status]
        line = Text()
        line.append(f"{mark} ", style=style)
        line.append(f"{fase:<12}", style="dim" if status in {"idle", "skip"} else "")
        if t0:
            line.append(_clock(((t1 or datetime.now()) - t0).total_seconds()), style="dim")
        self.query_one(f"#fase-{fase}", Static).update(line)

    def _refresh_running(self):
        for f, (status, _, _) in self.fase_state.items():
            if status == "start":
                self._render_fase(f)

    def _refresh_topbar(self):
        bits = ["recon.io"]
        if self.target:
            bits.append(self.target)
        if self.fase_total:
            bits.append(f"{self.fase_done}/{self.fase_total} fase")
        if self.started and self.running:
            bits.append(_clock((datetime.now() - self.started).total_seconds()))
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
            self.action_keluar()
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
            self._say("masih ada recon berjalan, tunggu selesai atau ctrl+x dua kali untuk stop.", "bold yellow")
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
            self._say("target tidak terbaca, sebut domainnya, mis. example.com", "bold yellow")
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
                self._say(f"{target} di luar scope ({reason}), tidak dijalankan.", "bold red")
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
                self._say("dibatalkan, jawab y atau n.", "dim")
            return

        self._start(plan["target"], plan["fases"])

    # ── eksekusi recon ───────────────────────────────────────────

    def _start(self, target: str, fases: list[str], resume: bool = False):
        self.target     = target
        self._reset_fases(fases)
        self._reset_findings()
        self.started    = datetime.now()
        self.running    = True
        self.stopping   = False
        self.refresh_bindings()
        self._set_status("recon berjalan...", "bold green")
        self._run_recon(target, fases, resume)

    @work(thread=True, exclusive=True)
    def _run_recon(self, target: str, fases: list[str], resume: bool = False):
        from core.runner import run_target
        try:
            target_dir = run_target(
                target=target, output_dir=self.output_dir, fases=fases,
                resume=resume, on_fase=self._on_fase,
            )
        except Exception as exc:
            self.call_from_thread(self._finish, None, str(exc))
            return
        self.call_from_thread(self._finish, target_dir, "")

    def _finish(self, target_dir: str | None, error: str):
        stopped = self.stopping
        self.running    = False
        self.stopping   = False
        self.stop_armed = None
        self.refresh_bindings()
        if self.quit_after:
            self.exit()
            return
        self._set_status("")
        self._refresh_topbar()
        if error:
            self._say(f"recon gagal: {error}", "bold red")
            return
        self.target_dir = target_dir
        self._blank()
        if stopped:
            self._say(f"recon dihentikan, hasil sebagian di {target_dir}", "bold yellow")
        else:
            self._say(f"selesai, hasil di {target_dir}", "bold green")
        self.query_one("#prompt", Input).focus()

    # ── aksi keybinding ──────────────────────────────────────────

    def check_action(self, action: str, parameters) -> bool | None:
        # ctrl+x hanya tampil di footer selama recon berjalan
        if action == "stop":
            return self.running
        return True

    def action_stop(self):
        if not self.running or self.stopping:
            return
        now = datetime.now()
        if self.stop_armed and (now - self.stop_armed).total_seconds() <= _STOP_WINDOW:
            self._stop_scan()
            return
        self.stop_armed = now
        self._set_status("tekan ctrl+x lagi untuk menghentikan recon", "bold yellow")
        self.set_timer(_STOP_WINDOW, self._disarm_stop)

    def _disarm_stop(self):
        if self.stop_armed and not self.stopping and self.running:
            self.stop_armed = None
            self._set_status("recon berjalan...", "bold green")

    def _stop_scan(self):
        self.stopping   = True
        self.stop_armed = None
        self._set_status("menghentikan recon...", "bold yellow")
        self._say("menghentikan recon, menunggu proses tool berhenti...", "bold yellow")
        utils.cancel_all()

    def action_keluar(self):
        """Keluar; kalau recon masih jalan, hentikan dulu supaya tidak ada proses yatim."""
        if not self.running or self.quit_after:
            # ctrl+c kedua saat menunggu proses berhenti: paksa keluar
            self.exit()
            return
        self.quit_after = True
        if not self.stopping:
            self._stop_scan()

    def action_temuan(self):
        """Pindah fokus antara tabel temuan dan prompt."""
        table = self.query_one("#findings", DataTable)
        if table.has_focus or not self.findings:
            self.query_one("#prompt", Input).focus()
        else:
            table.focus()

    def action_batal(self):
        if not self.query_one("#prompt", Input).has_focus:
            self.query_one("#prompt", Input).focus()
        if self.pending:
            self.pending = None
            self._set_status("")
            self._say("dibatalkan.", "dim")

    def action_bersih(self):
        self.query_one("#log", RichLog).clear()


def run_tui(output_dir: str = DEFAULT_OUTPUT_DIR, scope=None, autorun: dict | None = None):
    ReconTUI(output_dir=output_dir, scope=scope, autorun=autorun).run()

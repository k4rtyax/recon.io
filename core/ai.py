"""
AI assistant — Google Gemini via REST API (stdlib, tanpa dependency tambahan).

Dua mode:
  - attack_suggestions() : saran serangan berprioritas dari hasil recon (flag --ai)
  - ask()                : tanya-jawab bebas atas hasil recon  (flag --ask "...")

API key dibaca dari env GEMINI_API_KEY (atau GOOGLE_API_KEY). Tidak pernah ditulis
ke disk maupun di-commit. Bila key tidak ada, fitur dilewati dengan aman.

Provider (env RECON_AI_PROVIDER):
  gemini  (default) — key dari GEMINI_API_KEY / GOOGLE_API_KEY
  openai            — OpenAI-compatible: Groq / OpenRouter / OpenAI / Ollama (lokal)
                      set RECON_AI_BASE_URL (mis. https://api.groq.com/openai/v1
                      atau http://localhost:11434/v1 utk Ollama) + RECON_AI_MODEL;
                      key dari RECON_AI_KEY / OPENAI_API_KEY / GROQ_API_KEY
                      (Ollama lokal tak butuh key)

Override via env:
  RECON_AI_MODEL      (default: gemini-2.5-flash untuk provider gemini)
  RECON_AI_TIMEOUT    (default: 120 detik)
  RECON_AI_MAX_CHARS  (default: 100000 — batas konteks report yang dikirim)
  RECON_AI_MAX_TOKENS (default: 4096)
"""

import os
import ssl
import json
import urllib.request
import urllib.error
from datetime import datetime

from rich.markup import escape
from core.utils import info, warn, err, section, console, run as exec_cmd, get_working_url
from config import FASE_LIST, TOOLS, DEFAULT_USER_AGENT
from core.scope import Scope

_PROVIDER   = os.environ.get("RECON_AI_PROVIDER", "gemini").strip().lower()
_API_BASE   = "https://generativelanguage.googleapis.com/v1beta/models"
_BASE_URL   = os.environ.get("RECON_AI_BASE_URL", "").rstrip("/")   # untuk provider openai-compatible
_MODEL      = os.environ.get("RECON_AI_MODEL",
                             "gemini-2.5-flash" if _PROVIDER == "gemini" else "")
_TIMEOUT    = int(os.environ.get("RECON_AI_TIMEOUT", "120"))
_MAX_CHARS  = int(os.environ.get("RECON_AI_MAX_CHARS", "100000"))
_MAX_TOKENS = int(os.environ.get("RECON_AI_MAX_TOKENS", "4096"))


def _api_key() -> str | None:
    if _PROVIDER == "gemini":
        return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    # openai-compatible: Groq / OpenRouter / OpenAI / Ollama (Ollama tak butuh key)
    return (os.environ.get("RECON_AI_KEY") or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("GROQ_API_KEY") or os.environ.get("OPENROUTER_API_KEY"))


def _ssl_context() -> ssl.SSLContext:
    """SSL context dengan CA bundle certifi (hindari CERTIFICATE_VERIFY_FAILED di macOS)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def available() -> bool:
    if _PROVIDER == "gemini":
        return bool(_api_key())
    # openai-compatible cukup punya base_url (key opsional utk Ollama lokal)
    return bool(_BASE_URL)


def ping() -> tuple[bool, str]:
    """Validasi key/koneksi dengan request minimal. Return (ok, pesan_error)."""
    key = _api_key() or ""
    try:
        if _PROVIDER == "gemini":
            url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context()):
                pass
            return True, ""

        else:  # openai-compatible
            if not _BASE_URL:
                return False, "RECON_AI_BASE_URL belum diset"
            is_ollama = "localhost" in _BASE_URL or "127.0.0.1" in _BASE_URL
            if is_ollama:
                url = _BASE_URL.rstrip("/").replace("/v1", "") + "/api/tags"
                req = urllib.request.Request(url)
            else:
                url = _BASE_URL.rstrip("/") + "/models"
                req = urllib.request.Request(
                    url,
                    headers={"Authorization": f"Bearer {key}", "User-Agent": "recon.io/2.0"},
                )
            with urllib.request.urlopen(req, timeout=10, context=_ssl_context()):
                pass
            return True, ""

    except urllib.error.HTTPError as e:
        if e.code in (400, 401, 403):
            return False, f"key tidak valid (HTTP {e.code})"
        if e.code >= 500:
            return False, f"server error ({e.code})"
        return True, ""
    except urllib.error.URLError as e:
        return False, f"tidak bisa terhubung: {e.reason}"
    except Exception as e:
        return False, f"error: {e}"


def resolve_target_dir(output_dir: str, target: str) -> str:
    """Tentukan folder output target untuk run hari ini (samakan dengan runner)."""
    date_tag    = datetime.now().strftime("recon_%d_%m_%Y")
    folder_name = target.replace("*.", "").replace("/", "_")
    return os.path.join(output_dir, folder_name, date_tag)


def _load_report(target_dir: str) -> str | None:
    """Baca report_*.txt sebagai konteks untuk AI."""
    report_dir = os.path.join(target_dir, "report")
    if not os.path.isdir(report_dir):
        return None
    txts = sorted(
        f for f in os.listdir(report_dir)
        if f.startswith("report_") and f.endswith(".txt")
    )
    if not txts:
        return None
    with open(os.path.join(report_dir, txts[0])) as f:
        return f.read()[:_MAX_CHARS]


def _call_gemini(system: str, user: str, silent: bool = False) -> str | None:
    key = _api_key()
    if not key:
        warn("API_KEY tidak di-set — fitur AI dilewati (set di .env)")
        return None

    url  = f"{_API_BASE}/{_MODEL}:generateContent?key={key}"
    body = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": _MAX_TOKENS},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_ssl_context()) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            msg = json.loads(body)["error"]["message"]
        except Exception:
            msg = body[:200]
        if e.code == 429:
            if not silent:
                err("Gemini API: kuota habis / rate limit (429). Coba lagi nanti atau cek billing.")
        else:
            err(f"Gemini API error {e.code}: {msg[:200]}")
        return None
    except Exception as e:
        err(f"Gemini API gagal: {e}")
        return None

    try:
        return payload["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError, AttributeError):
        # kemungkinan terfilter safety / respon kosong
        warn(f"Gemini tidak mengembalikan teks (mungkin terfilter): {json.dumps(payload)[:200]}")
        return None


def _call_openai(system: str, user: str, silent: bool = False) -> str | None:
    """Provider OpenAI-compatible: Groq, OpenRouter, OpenAI, atau Ollama (lokal)."""
    if not _BASE_URL:
        warn("RECON_AI_BASE_URL belum diset untuk provider 'openai' (mis. Groq/Ollama)")
        return None
    if not _MODEL:
        warn("RECON_AI_MODEL belum diset (mis. llama-3.3-70b-versatile)")
        return None

    # User-Agent normal: endpoint seperti Groq di belakang Cloudflare memblok
    # UA default urllib (Python-urllib/*) dengan error 1010.
    headers = {"Content-Type": "application/json", "User-Agent": DEFAULT_USER_AGENT}
    key = _api_key()
    if key:
        headers["Authorization"] = f"Bearer {key}"

    body = {
        "model": _MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.4,
        "max_tokens": _MAX_TOKENS,
    }
    req = urllib.request.Request(
        f"{_BASE_URL}/chat/completions",
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_ssl_context()) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        try:
            msg = json.loads(body)["error"]["message"]
        except Exception:
            msg = body[:200]
        if e.code == 429:
            if not silent:
                err("LLM API: kuota / rate limit (429). Coba lagi nanti.")
        else:
            err(f"LLM API error {e.code}: {msg[:200]}")
        return None
    except Exception as e:
        err(f"LLM API gagal: {e}  (cek RECON_AI_BASE_URL / koneksi)")
        return None

    try:
        return payload["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError):
        warn(f"LLM tidak mengembalikan teks: {json.dumps(payload)[:200]}")
        return None


def _call_llm(system: str, user: str, silent: bool = False) -> str | None:
    """Dispatcher LLM sesuai RECON_AI_PROVIDER (gemini | openai)."""
    if _PROVIDER == "openai":
        return _call_openai(system, user, silent=silent)
    return _call_gemini(system, user, silent=silent)


_SYS_ATTACK = (
    "Kamu pentester web / bug bounty hunter senior. Berdasarkan laporan recon di bawah, "
    "susun rencana serangan BERPRIORITAS dan actionable dalam Bahasa Indonesia.\n"
    "Untuk tiap temuan prioritas, jelaskan: (1) kenapa menarik, (2) langkah verifikasi/tes "
    "manual yang konkret, (3) tool / nuclei template / payload yang relevan. "
    "Rujuk host, URL, atau parameter spesifik dari data. Ringkas dan padat, tanpa basa-basi. "
    "Tandai jelas mana yang high-impact. Jangan mengarang temuan yang tidak ada di data."
)

_SYS_ASK = (
    "Kamu asisten recon untuk bug bounty. Jawab pertanyaan user HANYA berdasarkan laporan "
    "recon yang diberikan, dalam Bahasa Indonesia. Spesifik — rujuk host/URL/temuan nyata "
    "dari data. Bila data tidak cukup untuk menjawab, katakan terus terang."
)


def attack_suggestions(target: str, target_dir: str):
    report = _load_report(target_dir)
    if not report:
        warn("report tidak ditemukan, saran serangan AI dilewati")
        return

    info(f"meminta saran serangan dari Gemini ({_MODEL})...")
    answer = _call_llm(_SYS_ATTACK, f"Target: {target}\n\n=== LAPORAN RECON ===\n{report}")
    if not answer:
        return

    out = os.path.join(target_dir, "report", "ai_attack_suggestions.md")
    with open(out, "w") as f:
        f.write(f"# AI Attack Suggestions — {target}\n\n")
        f.write(f"*Dihasilkan {datetime.now():%Y-%m-%d %H:%M} via Gemini ({_MODEL}). "
                f"Wajib verifikasi manual sebelum eksploitasi.*\n\n")
        f.write(answer + "\n")

    section(f"AI — saran serangan ({target})")
    console.print(escape(answer))
    info(f"saran serangan disimpan: {out}")


def ask(target: str, target_dir: str, question: str):
    report = _load_report(target_dir)
    if not report:
        err(f"report untuk {target} tidak ditemukan di {target_dir} — jalankan recon dulu")
        return

    answer = _call_llm(
        _SYS_ASK,
        f"Target: {target}\n\n=== LAPORAN RECON ===\n{report}\n\n=== PERTANYAAN ===\n{question}",
    )
    if not answer:
        return

    section(f"AI — jawaban ({target})")
    console.print(escape(answer))


# ── mode percakapan ──────────────────────────────────────────────────

_SYS_CHAT = (
    "Kamu asisten recon CLI untuk bug bounty, berbahasa Indonesia. "
    "Untuk SETIAP pesan user, balas HANYA satu objek JSON valid (tanpa code fence, "
    "tanpa teks lain) dengan skema:\n"
    '{"action":"set_scope"|"run"|"answer"|"chat",'
    '"target":<domain atau null>,"fases":<array fase atau null>,'
    '"scope":<teks scope / path file atau null>,"program":<link program atau null>,'
    '"message":<teks untuk user>}\n'
    "- action=set_scope: user memberi SCOPE (pola domain, atau path file .csv/.txt) "
    "dan/atau LINK PROGRAM. Di 'scope': jika user memberi PATH file, salin path apa adanya; "
    "jika user memberi pola, NORMALKAN ke format kanonik — satu pola dipisah koma, awali '!' "
    "untuk yang DIKECUALIKAN (contoh: user bilang '*.example.com kecuali blog' -> "
    "'*.example.com, !blog.example.com'). Taruh link di 'program'. Di 'message' rangkum "
    "scope-nya dan tanya target mana yang mau di-recon.\n"
    "- action=run  : user ingin MENJALANKAN recon pada sebuah target. Ekstrak domain & fase. "
    "Kamu TIDAK menjalankan apa pun — hanya mengusulkan. ATURAN: recon hanya boleh untuk "
    "target yang ada di dalam scope. Jika scope BELUM diset, JANGAN action=run — pakai "
    "action=chat untuk meminta scope dulu.\n"
    "- action=answer: user bertanya tentang hasil recon. Jawab di 'message' dari KONTEKS LAPORAN.\n"
    "- action=chat  : sapaan / klarifikasi / minta scope / rekomendasi target. Isi 'message'.\n"
    "SCOPE SUDAH DISET — ATURAN KRITIS: jika konteks menunjukkan [scope aktif: ...] dan user "
    "menyebut domain atau menjawab 'ya'/'oke'/'lanjut' setelah rekomendasi, LANGSUNG "
    "action=run dengan target yang dimaksud. JANGAN panggil action=set_scope lagi kecuali "
    "user eksplisit minta 'ganti scope' atau 'ubah scope'.\n"
    "PENTING: link program OPSIONAL (cuma untuk catatan). JANGAN PERNAH menuntut/blokir "
    "user karena link program belum ada — scope saja sudah cukup untuk lanjut.\n"
    "Jika user minta REKOMENDASI, sebutkan beberapa host in-scope yang paling menarik "
    "(mis. dev tools seperti bugzilla/phabricator, API, admin, auth) dengan alasan singkat, "
    "lalu tanya mau mulai yang mana. Jangan minta link program.\n"
    f"Fase valid: {', '.join(FASE_LIST)}. fases=null berarti semua fase.\n"
    "STRATEGI SCOPE: jika scope berisi wildcard (*.domain), boleh enumerate root lalu "
    "filter ke scope. Jika scope hanya daftar host SPESIFIK (tanpa wildcard), JANGAN "
    "sarankan fase 'subdomain' — recon tiap host langsung (fase web: urls, js, ports, "
    "fingerprint, security). Mengetes subdomain di luar daftar = di luar scope.\n"
    "Jangan memakai emoji."
)

_SYS_TARGET = (
    "Kamu asisten recon. Diberi info teknis singkat sebuah target, beri ringkasan 2-3 "
    "kalimat (jenis situs & teknologi) lalu sarankan fase recon paling relevan dari: "
    f"{', '.join(FASE_LIST)}. Bahasa Indonesia, ringkas, tanpa emoji."
)


def _clean_target(t: str) -> str:
    t = (t or "").strip().replace("http://", "").replace("https://", "")
    if t.startswith("*."):
        t = t[2:]
    return t.rstrip("/")


def _parse_intent(raw: str) -> dict | None:
    s = raw.strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s[:4].lower() == "json":
            s = s[4:]
    i, j = s.find("{"), s.rfind("}")
    if i == -1 or j == -1:
        return None
    try:
        return json.loads(s[i:j + 1])
    except Exception:
        return None


def _fetch_context(target: str) -> str:
    """Kenalan singkat target via curl: status, server, title, deteksi SPA. Sentuhan ringan."""
    import re
    url = get_working_url(target)
    _, head, _ = exec_cmd(
        [TOOLS["curl"], "-sIL", "-A", DEFAULT_USER_AGENT, "--max-time", "10", url], timeout=12)
    _, body, _ = exec_cmd(
        [TOOLS["curl"], "-sL", "-A", DEFAULT_USER_AGENT, "--max-time", "10", url], timeout=12)

    status = server = ""
    for line in head.splitlines():
        low = line.lower()
        if low.startswith("http/"):
            status = line.strip()
        elif low.startswith("server:"):
            server = line.split(":", 1)[1].strip()

    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    scripts = len(re.findall(r"<script", body, re.I))
    spa = bool(re.search(r'id=["\'](root|app|__next)["\']', body, re.I)) and scripts >= 3
    hints = sorted({kw for kw in
                    ("react", "vue", "angular", "next", "nuxt", "svelte", "webpack")
                    if kw in body.lower()})

    line = (f"url={url} | status={status or '?'} | server={server or '?'} | "
            f"title={title or '-'} | spa={'ya' if spa else 'tidak'}")
    if hints:
        line += f" | hint={','.join(hints)}"
    return line


def _summarize_target(target: str, ctx: str) -> str | None:
    return _call_llm(_SYS_TARGET, f"Target: {target}\nInfo teknis: {ctx}", silent=True)


def _write_authorization(target_dir: str, target: str, program: str, scope: "Scope | None"):
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, "authorization.txt")
    with open(path, "w") as f:
        f.write(f"target  : {target}\n")
        f.write(f"program : {program or '(tidak dinyatakan)'}\n")
        f.write(f"scope   : {scope.summary() if scope else '(tidak diset)'}\n")
        f.write(f"waktu   : {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write("catatan : otorisasi DINYATAKAN oleh user via mode chat. "
                "recon.io tidak memverifikasi klaim ini.\n")
    return path


def _execute_run(target, fases, scope, program, output_dir, ai_summary=True):
    """Validasi scope -> fetch konteks -> gerbang 'berwenang' -> jalankan recon.
    Return (target, target_dir) bila jalan; None bila out-of-scope / dibatalkan.
    Dipakai bersama oleh mode chat (AI) dan mode menu (keyboard).
    ai_summary=False (mode menu): TIDAK ada panggilan AI sama sekali."""
    target = _clean_target(target or "")
    if not target:
        console.print("[bold green][AI][/bold green] Target mana yang mau di-recon?")
        return None

    in_scope, reason = scope.check(target)
    if not in_scope:
        console.print(f"[bold red][AI][/bold red] {escape(target)} DI LUAR scope ({escape(reason)}). Tidak dijalankan.")
        return None

    fases = [f for f in (fases or []) if f in FASE_LIST] or list(FASE_LIST)
    if "subdomain" in fases and not scope.is_wildcard_match(target):
        fases = [f for f in fases if f != "subdomain"]
        info(f"{target}: host spesifik (scope non-wildcard) — fase subdomain dilewati")

    # ── konfirmasi SEBELUM probe apapun ke target ────────────────
    console.print(
        f"\n[bold]rencana:[/bold] target=[cyan]{target}[/cyan]  "
        f"fase=[cyan]{', '.join(fases)}[/cyan]  output=[cyan]{output_dir}[/cyan]"
    )
    console.print(f"[green][scope] in-scope ({escape(reason)})[/green]")
    from core import menu as kbmenu
    if not kbmenu.confirm("Jalankan recon sekarang?", default=False):
        console.print("[bold green][AI][/bold green] Oke, dibatalkan.")
        return None

    # ── baru probe setelah user konfirmasi ───────────────────────
    info(f"kenalan singkat dengan {target}...")
    tctx = _fetch_context(target)
    console.print(f"[dim]target: {escape(tctx)}[/dim]")
    if ai_summary and available():
        summary = _summarize_target(target, tctx)
        if summary:
            console.print(f"[bold green][AI][/bold green] {escape(summary)}")

    from core.runner import run_target
    try:
        run_target(target=target, output_dir=output_dir, fases=fases)
    except KeyboardInterrupt:
        console.print()
        warn("recon dihentikan (Ctrl+C)")
        return None
    except Exception as exc:
        err(f"recon gagal: {exc}")
        return None

    cur_dir = resolve_target_dir(output_dir, target)
    auth = _write_authorization(cur_dir, target, program, scope)
    info(f"otorisasi dicatat: {auth}")
    console.print("\n[bold green][AI][/bold green] Recon beres. Tanya hasilnya, atau minta 'analisis serangan'.")
    return target, cur_dir


def _menu_select(scope, output_dir, program=""):
    """Picker keyboard: pilih host in-scope + fase, lalu jalankan. Return (target, dir) | None."""
    from core import menu as kbmenu
    hosts = [a for a in scope.allow if not a.startswith("*.")]
    if not hosts:
        warn("scope hanya wildcard — tak ada host spesifik untuk dipilih via menu")
        warn("untuk wildcard: recon -d <root> --recon-subs --scope <file>")
        return None
    target = kbmenu.pick("pilih target (Esc = batal):", hosts)
    if not target:
        return None
    opts    = [f for f in FASE_LIST if f != "subdomain"]
    default = ["dns", "ports", "fingerprint", "urls", "js", "security"]
    fases = kbmenu.multi_pick("pilih fase (space = toggle, enter = ok):", opts, preselected=default)
    if not fases:
        warn("tidak ada fase dipilih")
        return None
    return _execute_run(target, fases, scope, program, output_dir, ai_summary=False)


def menu_session(output_dir: str, scope, program: str = ""):
    """Mode menu keyboard tanpa AI: pilih target dari scope + fase, jalankan berulang."""
    from core import menu as kbmenu
    section("recon.io — mode menu (scope)")
    console.print(scope.describe(), markup=False)
    while True:
        _menu_select(scope, output_dir, program)
        if not kbmenu.confirm("recon target lain?", default=False):
            break
    section("selesai")


def chat_session(output_dir: str):
    """Mode percakapan scope-first: AI mengusulkan, user menyetujui sebelum recon."""
    if not available():
        warn("GEMINI_API_KEY tidak di-set — mode chat tidak tersedia (set di .env)")
        return

    section("recon.io — asisten AI")
    console.print("[bold]Mau recon apa hari ini?[/bold] Sebutkan dulu scope-nya.")
    console.print("[dim]   scope: pola domain (mis. *.example.com kecuali blog) atau path file .csv/.txt[/dim]")
    console.print("[dim]   ketik 'menu' untuk pilih target via keyboard  |  'keluar' untuk berhenti[/dim]\n")

    history: list[str] = []
    scope: Scope | None = None
    program: str = ""
    cur_target: str | None = None
    cur_dir: str | None = None

    while True:
        try:
            user = console.input("[bold cyan]> [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        if not user:
            continue
        # normalisasi perintah pendek: buang petik/spasi/tanda baca yang sering ikut keketik
        cmd = user.strip("'\"`. ").lower()
        if cmd in {"exit", "quit", "keluar", "q"}:
            console.print("[dim]selesai. semua hasil tersimpan di folder output.[/dim]")
            break

        # ── picker keyboard (tanpa AI) ───────────────────────────
        if cmd in {"menu", "pilih", "pilih target", "m"}:
            if scope is None:
                console.print("[bold green][AI][/bold green] Set scope dulu sebelum pakai menu.")
                continue
            res = _menu_select(scope, output_dir, program)
            if res:
                cur_target, cur_dir = res
            continue

        ctx = f"\n\n[scope aktif: {scope.summary() if scope else 'BELUM diset'}]"
        if cur_dir:
            rep = _load_report(cur_dir)
            if rep:
                ctx += f"\n\n=== LAPORAN RECON ({cur_target}) ===\n{rep}"
        hist = "\n".join(history[-6:])
        raw = _call_llm(_SYS_CHAT, f"{hist}\nUSER: {user}{ctx}")
        if not raw:
            continue

        intent = _parse_intent(raw)
        if not intent:
            console.print(f"[bold green][AI][/bold green] {escape(raw)}")
            history += [f"USER: {user}", f"AI: {raw[:300]}"]
            continue

        action = intent.get("action", "chat")
        msg    = intent.get("message", "").strip()

        # ── set scope ────────────────────────────────────────────
        if action == "set_scope":
            raw_scope = (intent.get("scope") or "").strip()
            if intent.get("program"):
                program = intent["program"].strip()
            if raw_scope:
                try:
                    scope = (Scope.from_file(raw_scope)
                             if os.path.isfile(raw_scope) else Scope.from_text(raw_scope))
                except Exception as exc:
                    err(f"gagal membaca scope: {exc}")
                    continue
                section("scope ditetapkan")
                console.print(scope.describe(), markup=False)
                if program:
                    console.print(f"[dim]program: {escape(program)}[/dim]")
            if msg:
                console.print(f"[bold green][AI][/bold green] {escape(msg)}")

        # ── run (wajib in-scope) ─────────────────────────────────
        elif action == "run":
            if scope is None:
                console.print("[bold green][AI][/bold green] Set scope dulu ya sebelum recon.")
                history += [f"USER: {user}", "AI: minta scope"]
                continue
            new_target = _clean_target(intent.get("target") or "")
            if new_target and new_target != cur_target:
                cur_dir = None  # clear report lama saat ganti target
            res = _execute_run(intent.get("target"), intent.get("fases"), scope, program, output_dir)
            if res:
                cur_target, cur_dir = res

        # ── answer / chat ────────────────────────────────────────
        else:
            console.print(f"[bold green][AI][/bold green] {escape(msg or raw)}")

        history += [f"USER: {user}", f"AI: {json.dumps(intent, ensure_ascii=False)[:400]}"]

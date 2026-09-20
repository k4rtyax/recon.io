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

Privasi (hanya berlaku untuk provider cloud, endpoint lokal dilewati):
  RECON_AI_REDACT        (default: 1 — sensor secret/header/email/JWT sebelum kirim)
  RECON_AI_ZDR           (default: 1 — minta provider tidak menyimpan data, bila didukung)
  RECON_AI_QUIET_PRIVACY (default: 0 — 1 untuk membungkam peringatan privasi)
"""

import os
import re
import ssl
import json
import urllib.request
import urllib.error
from datetime import datetime

from rich.markup import escape
from core.utils import info, warn, err, section, console
from config import FASE_LIST, DEFAULT_USER_AGENT, SECRET_PATTERNS
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


def _is_local_endpoint() -> bool:
    return any(h in _BASE_URL for h in ("localhost", "127.0.0.1", "0.0.0.0", "::1"))


# ── privasi: redaksi, ZDR, peringatan ────────────────────────────────
# Hanya berlaku untuk provider cloud; inference lokal dilewati sepenuhnya.

_REDACT     = os.environ.get("RECON_AI_REDACT", "1").strip() != "0"
_ZDR        = os.environ.get("RECON_AI_ZDR", "1").strip() != "0"
_QUIET_PRIV = os.environ.get("RECON_AI_QUIET_PRIVACY", "0").strip() == "1"

_privacy_warned = False

_REDACT_RULES = [
    (re.compile(r"(?im)^([ \t]*authorization[ \t]*:[ \t]*).*$"), r"\1[REDACTED:authorization]"),
    (re.compile(r"(?im)^([ \t]*(?:set-)?cookie[ \t]*:[ \t]*).*$"), r"\1[REDACTED:cookie]"),
    (re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), "[REDACTED:authorization]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "[REDACTED:jwt]"),
] + [
    (re.compile(p, re.IGNORECASE), "[REDACTED:secret]") for p in SECRET_PATTERNS
] + [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED:email]"),
]


def redact(text: str) -> str:
    """Sensor data sensitif sebelum meninggalkan mesin. No-op untuk endpoint lokal."""
    if not text or not _REDACT or _is_local_endpoint():
        return text
    for pat, repl in _REDACT_RULES:
        text = pat.sub(repl, text)
    return text


def _privacy_notice():
    global _privacy_warned
    if _privacy_warned or _QUIET_PRIV or _is_local_endpoint():
        return
    _privacy_warned = True
    warn(f"isi recon dikirim ke AI cloud: {_BASE_URL or 'Google AI Studio'}")
    if _PROVIDER == "gemini":
        warn("Gemini tier gratis: data bisa dipakai Google untuk pengembangan produk & direview manusia")
    if "openrouter.ai" in _BASE_URL:
        warn("OpenRouter: mengaktifkan logging memberi hak pakai komersial atas data — biarkan logging mati")
    info("jangan pakai bila program melarang data keluar — alternatif lokal: Ollama / LM Studio (--setup-ai)")
    if not _REDACT:
        warn("RECON_AI_REDACT=0 — data dikirim tanpa sensor")


def _ungrounded_hosts(answer: str, source: str, target: str) -> list[str]:
    """Host milik target yang disebut AI tapi tidak ada di data sumber."""
    root = _clean_target(target).lower()
    if not root or not answer:
        return []
    src = source.lower()
    found = set()
    for m in re.finditer(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", answer.lower()):
        host = m.group(0)
        if (host == root or host.endswith("." + root)) and host not in src:
            found.add(host)
    return sorted(found)


def provider_name() -> str:
    return _PROVIDER


def available() -> bool:
    if _PROVIDER == "gemini":
        return bool(_api_key())
    if not _BASE_URL:
        return False
    # endpoint lokal (Ollama) tidak butuh key
    return _is_local_endpoint() or bool(_api_key())


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
            if _is_local_endpoint():
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

    _privacy_notice()
    user = redact(user)

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

    _privacy_notice()
    user = redact(user)

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
    # OpenRouter: satu-satunya flag retensi yang resmi terdokumentasi di sini.
    if _ZDR and "openrouter.ai" in _BASE_URL:
        body["provider"] = {"data_collection": "deny"}

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


_SYS_NUCLEI = (
    "Kamu pentester web. Diberi ringkasan teknologi & temuan recon sebuah target, "
    "usulkan tag nuclei yang RELEVAN untuk verifikasi. HANYA template DETEKSI "
    "non-destruktif — jangan usulkan sesuatu yang menulis, menghapus, brute-force, "
    "atau membanjiri target. Balas HANYA satu array JSON berisi string tag "
    'nuclei, contoh: ["springboot","exposure","cve"]. Tanpa teks lain, tanpa code fence. '
    "Maksimal 8 tag, urut dari paling relevan. Jika data tak cukup, balas []."
)

_SYS_VERIFY = (
    "Kamu pentester web / bug bounty hunter senior. Diberi output verifikasi bertarget "
    "(bisa dari nuclei, cek open-redirect via canary, atau probe exposed-tool), tafsirkan "
    "dalam Bahasa Indonesia: mana temuan yang nyata & high-impact, mana yang kemungkinan "
    "noise/false positive, dan langkah verifikasi manual berikutnya untuk tiap temuan "
    "penting. Ringkas dan rujuk baris spesifik. Jangan mengarang temuan yang tidak ada di "
    "output. Jangan pakai emoji."
)


def suggest_nuclei_tags(context: str) -> list[str]:
    """Minta AI mengusulkan tag nuclei dari konteks recon. [] bila gagal / tak tersedia."""
    if not available():
        return []
    raw = _call_llm(_SYS_NUCLEI, context, silent=True)
    if not raw:
        return []
    s = raw.strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s[:4].lower() == "json":
            s = s[4:]
    i, j = s.find("["), s.rfind("]")
    if i == -1 or j == -1:
        return []
    try:
        arr = json.loads(s[i:j + 1])
    except Exception:
        return []
    return [str(t).strip().lower() for t in arr if isinstance(t, (str,)) and str(t).strip()][:8]


def interpret_nuclei(target: str, results_text: str) -> str | None:
    """Minta AI menafsirkan output nuclei hasil verifikasi. None bila tak tersedia."""
    if not available() or not results_text.strip():
        return None
    answer = _call_llm(_SYS_VERIFY, f"Target: {target}\n\n=== OUTPUT NUCLEI ===\n{results_text}", silent=True)
    if not answer:
        return None
    ghosts = _ungrounded_hosts(answer, results_text, target)
    if ghosts:
        warn(f"tafsir AI menyebut host di luar output nuclei: {', '.join(ghosts)}")
        answer += ("\n\n[!] host berikut disebut AI tapi tidak ada di output nuclei — "
                   f"abaikan sebagai klaim: {', '.join(ghosts)}\n")
    return answer


def attack_suggestions(target: str, target_dir: str):
    report = _load_report(target_dir)
    if not report:
        warn("report tidak ditemukan, saran serangan AI dilewati")
        return

    info(f"meminta saran serangan dari Gemini ({_MODEL})...")
    answer = _call_llm(_SYS_ATTACK, f"Target: {target}\n\n=== LAPORAN RECON ===\n{report}")
    if not answer:
        return

    ghosts = _ungrounded_hosts(answer, report, target)
    if ghosts:
        warn(f"saran AI menyebut host yang tidak ada di laporan: {', '.join(ghosts)}")
        answer += ("\n\n[!] host berikut disebut AI tapi tidak ada di laporan recon — "
                   f"jangan ditindak tanpa verifikasi: {', '.join(ghosts)}\n")

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
    "Kamu TIDAK menjalankan apa pun — hanya mengusulkan; user yang mengonfirmasi.\n"
    "- action=answer: user bertanya tentang hasil recon. Jawab di 'message' dari KONTEKS LAPORAN.\n"
    "- action=chat  : sapaan / klarifikasi / rekomendasi target. Isi 'message'.\n"
    "ATURAN KRITIS: scope OPSIONAL. JANGAN PERNAH meminta scope, link program, atau izin "
    "tambahan sebelum menjalankan. Begitu user menyebut sebuah domain, atau menjawab "
    "'ya'/'oke'/'lanjut' setelah rekomendasi, LANGSUNG action=run. Pakai set_scope HANYA "
    "bila user sendiri yang memberi file atau pola scope.\n"
    "Jika konteks memuat [scope aktif: ...], pakai itu untuk menyusun rekomendasi, dan "
    "sebutkan beberapa host paling menarik (mis. dev tools seperti bugzilla/phabricator, "
    "API, admin, auth) dengan alasan singkat lalu tanya mau mulai yang mana.\n"
    f"Fase valid: {', '.join(FASE_LIST)}. fases=null berarti semua fase.\n"
    "STRATEGI SCOPE (hanya bila scope aktif): jika scope berisi wildcard (*.domain), boleh enumerate root lalu "
    "filter ke scope. Jika scope hanya daftar host SPESIFIK (tanpa wildcard), JANGAN "
    "sarankan fase 'subdomain' — recon tiap host langsung (fase web: urls, js, ports, "
    "fingerprint, security). Mengetes subdomain di luar daftar = di luar scope.\n"
    "Jangan memakai emoji."
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


def intent(user: str, history: list[str] | None = None, ctx: str = "") -> dict | None:
    """Satu putaran percakapan tanpa I/O console — dipakai mode TUI.
    Return dict intent (action/target/fases/message) atau None bila gagal."""
    hist = "\n".join((history or [])[-6:])
    raw = _call_llm(_SYS_CHAT, f"{hist}\nUSER: {user}{ctx}", silent=True)
    if not raw:
        return None
    return _parse_intent(raw) or {"action": "chat", "message": raw}


def _execute_run(target, fases, scope, output_dir):
    """Konfirmasi -> jalankan recon. Scope opsional: kalau ada, dipakai sebagai filter.
    Return (target, target_dir) bila jalan; None bila out-of-scope / dibatalkan."""
    target = _clean_target(target or "")
    if not target:
        console.print("[bold green][AI][/bold green] Target mana yang mau di-recon?")
        return None

    reason = ""
    if scope is not None:
        in_scope, reason = scope.check(target)
        if not in_scope:
            console.print(f"[bold red][AI][/bold red] {escape(target)} DI LUAR scope ({escape(reason)}). Tidak dijalankan.")
            return None

    fases = [f for f in (fases or []) if f in FASE_LIST] or list(FASE_LIST)
    if scope is not None and "subdomain" in fases and not scope.is_wildcard_match(target):
        fases = [f for f in fases if f != "subdomain"]
        info(f"{target}: host spesifik (scope non-wildcard) — fase subdomain dilewati")

    # ── konfirmasi sebelum menjalankan ───────────────────────────
    console.print(
        f"\n[bold]rencana:[/bold] target=[cyan]{target}[/cyan]  "
        f"fase=[cyan]{', '.join(fases)}[/cyan]  output=[cyan]{output_dir}[/cyan]"
    )
    if scope is not None:
        console.print(f"[green][scope] in-scope ({escape(reason)})[/green]")
    from core import menu as kbmenu
    if not kbmenu.confirm("Jalankan recon sekarang?", default=False):
        console.print("[bold green][AI][/bold green] Oke, dibatalkan.")
        return None

    from core.runner import run_target
    try:
        ran_dir = run_target(target=target, output_dir=output_dir, fases=fases)
    except KeyboardInterrupt:
        console.print()
        warn("recon dihentikan (Ctrl+C)")
        return None
    except Exception as exc:
        err(f"recon gagal: {exc}")
        return None

    # pakai folder yang benar-benar dipakai runner — recon yang melewati
    # tengah malam membuat resolve_target_dir() menunjuk folder tanggal lain.
    cur_dir = ran_dir or resolve_target_dir(output_dir, target)
    console.print()
    info("recon selesai — tanya hasilnya, atau minta 'analisis serangan'")
    return target, cur_dir


def specific_hosts(scope) -> list[str]:
    """Host non-wildcard di dalam scope — satu-satunya yang bisa dipilih lewat menu."""
    return [a for a in scope.allow if not a.startswith("*.")]


def _menu_select(scope, output_dir):
    """Picker keyboard: pilih host in-scope + fase, lalu jalankan. Return (target, dir) | None."""
    from core import menu as kbmenu
    hosts = specific_hosts(scope)
    if not hosts:
        warn("scope hanya wildcard — tak ada host spesifik untuk dipilih via menu")
        warn("untuk wildcard: recon.py -d <root> --recon-subs --scope <file>")
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
    return _execute_run(target, fases, scope, output_dir)


def menu_session(output_dir: str, scope):
    """Mode menu keyboard tanpa AI: pilih target dari scope + fase, jalankan berulang."""
    from core import menu as kbmenu
    section("recon.io — mode menu (scope)")
    console.print(scope.describe(), markup=False)
    while True:
        _menu_select(scope, output_dir)
        if not kbmenu.confirm("recon target lain?", default=False):
            break
    section("selesai")


def chat_session(output_dir: str):
    """Mode percakapan: AI mengusulkan, user menyetujui sebelum recon."""
    if not available():
        warn(f"provider AI '{_PROVIDER}' belum dikonfigurasi — jalankan: python recon.py --setup-ai")
        return

    section("recon.io — asisten AI")
    console.print("[bold]Mau recon apa?[/bold] Sebut targetnya, mis. 'recon example.com fokus urls sama js'.")
    console.print("[dim]   opsional: beri file/pola scope kalau mau target difilter otomatis[/dim]")
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
                console.print("[bold green][AI][/bold green] Menu memilih dari daftar scope. "
                              "Beri file scope dulu, atau sebut targetnya langsung.")
                continue
            res = _menu_select(scope, output_dir)
            if res:
                cur_target, cur_dir = res
            continue

        ctx = f"\n\n[scope aktif: {scope.summary()}]" if scope else ""
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
                # auto-picker jika ada host spesifik (non-wildcard)
                specific = specific_hosts(scope)
                if specific:
                    res = _menu_select(scope, output_dir)
                    if res:
                        cur_target, cur_dir = res
                    history += [f"USER: {user}", f"AI: scope set + picker ({len(specific)} host)"]
                    continue
            if msg:
                console.print(f"[bold green][AI][/bold green] {escape(msg)}")

        # ── run (scope dipakai sebagai filter bila ada) ──────────
        elif action == "run":
            new_target = _clean_target(intent.get("target") or "")
            if new_target and new_target != cur_target:
                cur_dir = None  # clear report lama saat ganti target
            res = _execute_run(intent.get("target"), intent.get("fases"), scope, output_dir)
            if res:
                cur_target, cur_dir = res

        # ── answer / chat ────────────────────────────────────────
        else:
            console.print(f"[bold green][AI][/bold green] {escape(msg or raw)}")

        history += [f"USER: {user}", f"AI: {json.dumps(intent, ensure_ascii=False)[:400]}"]

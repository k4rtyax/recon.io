"""
Notifikasi hasil recon ke Discord / Slack / Telegram.
Kanal dideteksi otomatis dari env, tanpa konfigurasi tambahan.
"""

import os
import ssl
import json
import urllib.request
import urllib.error

from core.utils import warn

# ── batas panjang pesan per platform ────────────────────────────
_LIMITS = {
    "discord":  2000,
    "slack":    3000,
    "telegram": 4096,
}

_TIMEOUT = 10


def _ssl_ctx():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _env(key: str) -> str:
    return (os.environ.get(key) or "").strip()


def _valid_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    mark = "\n... (dipotong)"
    return text[: limit - len(mark)] + mark


def _post(url: str, payload: dict) -> tuple[bool, str]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "recon.io/2.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=_ssl_ctx()):
            return True, ""
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, str(e.reason)
    except Exception as e:
        return False, str(e)


# ── kanal ───────────────────────────────────────────────────────

def _discord(title: str, body: str) -> tuple[bool, str]:
    url = _env("RECON_NOTIFY_DISCORD")
    if not _valid_url(url):
        return False, "webhook URL tidak valid"
    msg = _truncate(f"**{title}**\n{body}", _LIMITS["discord"])
    return _post(url, {"content": msg})


def _slack(title: str, body: str) -> tuple[bool, str]:
    url = _env("RECON_NOTIFY_SLACK")
    if not _valid_url(url):
        return False, "webhook URL tidak valid"
    msg = _truncate(f"*{title}*\n{body}", _LIMITS["slack"])
    return _post(url, {"text": msg})


def _telegram(title: str, body: str) -> tuple[bool, str]:
    token = _env("RECON_NOTIFY_TELEGRAM_TOKEN")
    chat  = _env("RECON_NOTIFY_TELEGRAM_CHAT")
    if not token or not chat:
        return False, "token/chat id kosong"
    msg = _truncate(f"{title}\n{body}", _LIMITS["telegram"])
    return _post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        {"chat_id": chat, "text": msg, "disable_web_page_preview": True},
    )


def _active() -> list[tuple[str, object]]:
    out = []
    if _env("RECON_NOTIFY_DISCORD"):
        out.append(("discord", _discord))
    if _env("RECON_NOTIFY_SLACK"):
        out.append(("slack", _slack))
    if _env("RECON_NOTIFY_TELEGRAM_TOKEN") and _env("RECON_NOTIFY_TELEGRAM_CHAT"):
        out.append(("telegram", _telegram))
    return out


# ── api publik ──────────────────────────────────────────────────

def enabled() -> bool:
    return bool(_active())


def channels() -> list[str]:
    return [name for name, _ in _active()]


def send(title: str, body: str) -> bool:
    sent = False
    for name, fn in _active():
        try:
            ok_, msg = fn(title, body)
        except Exception as e:
            ok_, msg = False, str(e)
        if ok_:
            sent = True
        else:
            warn(f"notifikasi {name} gagal: {msg}")
    return sent

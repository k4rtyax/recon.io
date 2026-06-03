import os

# ─── DEFAULT SETTINGS ───────────────────────────────────────────
# Semua bisa di-override via environment variable.

def _load_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip("'\""))

_load_env()

def _setup_path():
    # Tambahkan path Go bin dan local python bin ke PATH environment process
    # agar tools terdeteksi meskipun tidak ada di PATH shell non-interactive.
    go_bin = os.path.expanduser("~/go/bin")
    local_bin = os.path.expanduser("~/.local/bin")
    paths_to_add = [go_bin, local_bin]
    
    current_path = os.environ.get("PATH", "")
    paths = current_path.split(os.pathsep)
    
    for path in paths_to_add:
        if os.path.exists(path) and path not in paths:
            paths.insert(0, path)
            
    os.environ["PATH"] = os.pathsep.join(paths)

_setup_path()

DEFAULT_OUTPUT_DIR = os.environ.get(
    "RECON_OUTPUT_DIR",
    os.path.join(os.getcwd(), "results"),
)

DEFAULT_TIMEOUT = int(os.environ.get("RECON_TIMEOUT", "300"))
DEFAULT_THREADS = int(os.environ.get("RECON_THREADS", "10"))

DEFAULT_USER_AGENT = os.environ.get(
    "RECON_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)

# ─── TIMEOUT PER FASE ──────────────────────────────────────────
# Bisa di-override via env: RECON_TIMEOUT_SUBDOMAIN=600 dll.
TIMEOUTS = {
    "subdomain":   int(os.environ.get("RECON_TIMEOUT_SUBDOMAIN", "300")),
    "dns":         int(os.environ.get("RECON_TIMEOUT_DNS", "60")),
    "ports":       int(os.environ.get("RECON_TIMEOUT_PORTS", "300")),
    "fingerprint": int(os.environ.get("RECON_TIMEOUT_FINGERPRINT", "120")),
    "urls":        int(os.environ.get("RECON_TIMEOUT_URLS", "120")),
    "js":          int(os.environ.get("RECON_TIMEOUT_JS", "300")),
    "security":    int(os.environ.get("RECON_TIMEOUT_SECURITY", "360")),
    "dirbrute":    int(os.environ.get("RECON_TIMEOUT_DIRBRUTE", "600")),
}

# ─── TOOL PATHS ─────────────────────────────────────────────────
# Override via env: RECON_TOOL_NMAP=/usr/local/bin/nmap dll.
TOOLS = {
    "subfinder":    os.environ.get("RECON_TOOL_SUBFINDER",   "subfinder"),
    "alterx":       os.environ.get("RECON_TOOL_ALTERX",      "alterx"),
    "dnsx":         os.environ.get("RECON_TOOL_DNSX",        "dnsx"),
    "httpx":        os.environ.get("RECON_TOOL_HTTPX",       "httpx"),
    "nmap":         os.environ.get("RECON_TOOL_NMAP",        "nmap"),
    "wafw00f":      os.environ.get("RECON_TOOL_WAFW00F",    "wafw00f"),
    "katana":       os.environ.get("RECON_TOOL_KATANA",      "katana"),
    "nuclei":       os.environ.get("RECON_TOOL_NUCLEI",      "nuclei"),
    "ffuf":         os.environ.get("RECON_TOOL_FFUF",        "ffuf"),
    "naabu":        os.environ.get("RECON_TOOL_NAABU",       "naabu"),
    "linkfinder":   os.environ.get("RECON_TOOL_LINKFINDER",  ""),
}

# ─── FASE MAPPING ───────────────────────────────────────────────
FASE_LIST = [
    "subdomain",
    "dns",
    "ports",
    "fingerprint",
    "urls",
    "js",
    "security",
    "dirbrute",
]

# ─── INTERESTING URL PATTERNS ───────────────────────────────────
# Dicocokkan sebagai path segment (/admin, /api, dll) — bukan substring.
INTERESTING_PATTERNS = [
    "admin", "login", "upload", "api", "config", "backup",
    "debug", "test", "dev", "staging", "internal", "secret",
    "dashboard", "panel", "manager", "console",
    "auth", "oauth", "graphql", "swagger", "actuator",
]

# ─── SECRET PATTERNS (regex) ────────────────────────────────────
# Setiap pattern dirancang untuk mencocokkan format credential spesifik,
# bukan string generik. Meminimalkan false positive.
SECRET_PATTERNS = [
    # ── API keys dengan value nyata (min 16 char, wajib dalam quotes) ──
    r"api[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
    r"secret[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
    # ── Password/credential dengan value dalam quotes ──
    r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    # ── Cloud provider keys (format spesifik) ──
    r"AKIA[0-9A-Z]{16}",                                  # AWS Access Key ID
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",        # GitHub tokens
    r"sk-[a-zA-Z0-9]{20,}",                                # Stripe / OpenAI keys
    r"xox[baprs]-[a-zA-Z0-9\-]{10,}",                     # Slack tokens
    r"glpat-[A-Za-z0-9_\-]{20,}",                          # GitLab PAT
    # ── Private keys ──
    r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
    # ── JWT tokens ──
    r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
]

# ─── SECURITY HEADERS YANG HARUS ADA ────────────────────────────
REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ─── WORDLIST PATHS ─────────────────────────────────────────────
WORDLIST_PATHS = [
    os.environ.get("RECON_WORDLIST", ""),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "common.txt"),
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

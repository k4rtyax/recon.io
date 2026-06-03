import os

# ─── DEFAULT SETTINGS ───────────────────────────────────────────
# Semua bisa di-override via environment variable.

DEFAULT_OUTPUT_DIR = os.environ.get(
    "RECON_OUTPUT_DIR",
    os.path.join(os.path.expanduser("~"), "recon-output"),
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
    "dork":        int(os.environ.get("RECON_TIMEOUT_DORK", "30")),
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
    "dork",
    "dirbrute",
]

# ─── INTERESTING URL PATTERNS ───────────────────────────────────
INTERESTING_PATTERNS = [
    "admin", "login", "upload", "api", "config", "backup",
    "debug", "test", "dev", "staging", "internal", "secret",
    "token", "key", "password", "passwd", "auth", "oauth",
    "graphql", "swagger", "env", "git", ".sql", ".bak", ".zip",
]

# ─── SECRET PATTERNS (regex) ────────────────────────────────────
SECRET_PATTERNS = [
    r"api[_-]?key\s*[=:]\s*['\"]?\w+",
    r"secret[_-]?key\s*[=:]\s*['\"]?\w+",
    r"password\s*[=:]\s*['\"]?\w+",
    r"token\s*[=:]\s*['\"]?\w+",
    r"aws[_-]?access[_-]?key",
    r"private[_-]?key",
    r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    r"[a-zA-Z0-9+/]{40,}={0,2}",  # base64 blobs
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
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

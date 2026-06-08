#!/bin/bash
# install.sh — Setup recon.io (Linux & macOS)

set +e

RECON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Windows native: tidak didukung ────────────────────────────────────
case "$(uname -s)" in
    MINGW*|CYGWIN*|MSYS*)
        echo "[!] Windows native tidak didukung."
        echo "    Gunakan WSL2: https://docs.microsoft.com/windows/wsl/install"
        echo "    Lalu jalankan: bash install.sh"
        exit 1
        ;;
esac

# ── Deteksi OS ────────────────────────────────────────────────────────
_detect_os() {
    # WSL
    if [[ -n "$WSL_DISTRO_NAME" ]] || grep -qi microsoft /proc/version 2>/dev/null; then
        echo "wsl"; return
    fi
    case "$(uname -s)" in
        Darwin) echo "macos"; return ;;
    esac
    # Linux: baca /etc/os-release
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        case "${ID:-}" in
            ubuntu|debian|kali|parrot|linuxmint) echo "apt";    return ;;
            arch|manjaro|garuda|endeavouros)      echo "pacman"; return ;;
            fedora|rhel|rocky|centos|almalinux)   echo "dnf";   return ;;
        esac
    fi
    # Fallback: cek binary package manager
    command -v apt    &>/dev/null && echo "apt"    && return
    command -v pacman &>/dev/null && echo "pacman" && return
    command -v dnf    &>/dev/null && echo "dnf"    && return
    echo "unknown"
}

OS=$(_detect_os)

if [[ "$OS" == "wsl" ]]; then
    echo "[*] WSL terdeteksi — lanjut sebagai Debian/Ubuntu."
    OS="apt"
fi

if [[ "$OS" == "unknown" ]]; then
    echo "[!] OS tidak dikenali. Pastikan apt / pacman / dnf tersedia."
    exit 1
fi

echo "[*] OS terdeteksi: $OS"

# ── Helper: sed portable ──────────────────────────────────────────────
_sed_i() {
    if [[ "$OS" == "macos" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# ── Install paket sistem ──────────────────────────────────────────────
echo "[*] Install tools sistem..."
case "$OS" in
    apt)
        sudo apt update -y &>/dev/null
        sudo apt install -y nmap curl whois dnsutils python3-pip git &>/dev/null
        ;;
    pacman)
        sudo pacman -Sy --noconfirm &>/dev/null
        # bind menyediakan dig/nslookup di Arch
        sudo pacman -S --noconfirm --needed nmap curl whois bind python-pip git 2>/dev/null
        ;;
    dnf)
        sudo dnf install -y nmap curl whois bind-utils python3-pip git &>/dev/null
        ;;
    macos)
        if ! command -v brew &>/dev/null; then
            echo "[*] Homebrew tidak ada, menginstall..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            [[ -f /opt/homebrew/bin/brew ]] && eval "$(/opt/homebrew/bin/brew shellenv)"
            [[ -f /usr/local/bin/brew   ]] && eval "$(/usr/local/bin/brew shellenv)"
        fi
        brew update &>/dev/null
        brew install nmap curl whois git &>/dev/null
        ;;
esac

# ── Go ────────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    echo "[*] Go tidak ditemukan, menginstall..."
    case "$OS" in
        apt)    sudo apt install -y golang-go 2>/dev/null || sudo apt install -y golang &>/dev/null ;;
        pacman) sudo pacman -S --noconfirm --needed go 2>/dev/null ;;
        dnf)    sudo dnf install -y golang &>/dev/null ;;
        macos)  brew install go &>/dev/null ;;
    esac
fi

export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    grep -q "go/bin" "$rc"    || { echo 'export PATH="$PATH:$HOME/go/bin"'    >> "$rc"; echo "[+] go/bin → $rc"; }
    grep -q ".local/bin" "$rc" || { echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$rc"; echo "[+] .local/bin → $rc"; }
done

# ── Python packages ───────────────────────────────────────────────────
echo "[*] Install library Python (wafw00f, rich, arjun, simple-term-menu)..."
_pip_pkgs="wafw00f rich arjun simple-term-menu"

if [[ "$OS" == "macos" ]]; then
    pip3 install $_pip_pkgs 2>/dev/null \
        || pip install $_pip_pkgs 2>/dev/null
else
    pip install $_pip_pkgs --break-system-packages 2>/dev/null \
        || pip3 install $_pip_pkgs --break-system-packages 2>/dev/null

    # Arch: jika pip gagal total, coba pipx untuk CLI tools
    if [[ "$OS" == "pacman" ]] && ! python3 -c "import wafw00f" 2>/dev/null; then
        echo "[~] pip gagal, coba pipx untuk CLI tools..."
        command -v pipx &>/dev/null || sudo pacman -S --noconfirm --needed python-pipx 2>/dev/null
        pipx install wafw00f 2>/dev/null
        pipx install arjun 2>/dev/null
        pip install rich simple-term-menu --break-system-packages 2>/dev/null || true
    fi
fi

# ── Go tools ─────────────────────────────────────────────────────────
echo "[*] Install tools Go..."
if ! command -v go &>/dev/null; then
    echo "[!] Go tidak terdeteksi. Pasang manual: https://go.dev/doc/install"
else
    _go_install() {
        echo "    -> $(basename "${1%%@*}")"
        go install "$1" &>/dev/null && echo "    [+] OK" || echo "    [!] GAGAL: $1"
    }
    _go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    _go_install github.com/projectdiscovery/alterx/cmd/alterx@latest
    _go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    _go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
    _go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    _go_install github.com/projectdiscovery/katana/cmd/katana@latest
    _go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    _go_install github.com/ffuf/ffuf/v2@latest
    _go_install github.com/owasp-amass/amass/v4/cmd/amass@latest
    _go_install github.com/lc/gau/v2/cmd/gau@latest
    _go_install github.com/tomnomnom/waybackurls@latest
    _go_install github.com/PentestPad/subzy@latest
fi

# ── Wordlist ──────────────────────────────────────────────────────────
echo "[*] Cek wordlist sistem..."
WORDLIST_FOUND=false
for wl_path in \
    "/usr/share/wordlists/dirb/common.txt" \
    "/usr/share/dirb/wordlists/common.txt" \
    "/usr/share/seclists/Discovery/Web-Content/common.txt" \
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" \
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt" \
    "/usr/local/share/seclists/Discovery/Web-Content/common.txt"; do
    if [ -f "$wl_path" ]; then
        WORDLIST_FOUND=true
        echo "[+] Wordlist ditemukan: $wl_path"
        break
    fi
done

if [ "$WORDLIST_FOUND" = false ]; then
    echo "[!] Wordlist tidak ada. Mengunduh fallback..."
    mkdir -p "$RECON_DIR/wordlists"
    curl -s -L \
        "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" \
        -o "$RECON_DIR/wordlists/common.txt"
    echo "[+] Wordlist disimpan: $RECON_DIR/wordlists/common.txt"
fi

# ── Alias + symlink recon ─────────────────────────────────────────────
echo "[*] Menambahkan perintah 'recon'..."
chmod +x "$RECON_DIR/recon.py"

ALIAS_LINE="alias recon='python3 $RECON_DIR/recon.py'"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    if grep -q "alias recon=" "$rc"; then
        _sed_i "s|alias recon=.*|$ALIAS_LINE|" "$rc"
        echo "[~] Update alias di $rc"
    else
        echo "$ALIAS_LINE" >> "$rc"
        echo "[+] Alias ditambahkan ke $rc"
    fi
done

mkdir -p "$HOME/.local/bin"
ln -sf "$RECON_DIR/recon.py" "$HOME/.local/bin/recon"
echo "[+] Symlink: ~/.local/bin/recon -> $RECON_DIR/recon.py"

# ── Siapkan .env ──────────────────────────────────────────────────────
if [ ! -f "$RECON_DIR/.env" ]; then
    cp "$RECON_DIR/.env.example" "$RECON_DIR/.env"
    echo "[+] .env dibuat dari template"
fi

# ── Source shell ──────────────────────────────────────────────────────
if [ -n "$ZSH_VERSION" ] || [[ "$SHELL" == *"zsh"* ]]; then
    source "$HOME/.zshrc" 2>/dev/null \
        && echo "[+] .zshrc di-source" \
        || echo "[!] Gagal source .zshrc — jalankan manual: source ~/.zshrc"
else
    source "$HOME/.bashrc" 2>/dev/null \
        && echo "[+] .bashrc di-source" \
        || echo "[!] Gagal source .bashrc — jalankan manual: source ~/.bashrc"
fi

# ── Helper .env writer ────────────────────────────────────────────────
_set_env() {
    local key="$1" val="$2"
    if grep -qE "^#?\s*${key}=" "$RECON_DIR/.env" 2>/dev/null; then
        _sed_i "s|^#*\s*${key}=.*|${key}=${val}|" "$RECON_DIR/.env"
    else
        echo "${key}=${val}" >> "$RECON_DIR/.env"
    fi
}

# ── Ringkasan & AI wizard ─────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo " recon.io — instalasi selesai"
echo "══════════════════════════════════════════════"
echo " Penggunaan:"
echo "   recon -d example.com"
echo "   recon -d example.com --fase subdomain,urls,params"
echo "   recon -d example.com -A"
echo "   recon --check"
echo "   recon --setup-ai    (ubah provider AI kapan saja)"
echo ""
echo " (Opsional) Setup Asisten AI:"
echo ""
echo "   1) Gemini      (gratis — ai.google.dev)"
echo "   2) Groq        (gratis, cepat — console.groq.com)"
echo "   3) OpenRouter  (openrouter.ai)"
echo "   4) Ollama      (lokal, tanpa key)"
echo "   5) Provider lain  (OpenAI / Mistral / Together.ai / dll)"
echo "   6) Skip"
echo ""

read -rp "   Pilih [1-6] (default: 6): " ai_choice
ai_choice="${ai_choice:-6}"

case "$ai_choice" in
    1)
        read -rp "   GEMINI_API_KEY: " _key
        if [ -n "$_key" ]; then
            _set_env "GEMINI_API_KEY" "$_key"
            _set_env "RECON_AI_MODEL" "gemini-2.5-flash"
            echo "   [+] Gemini dikonfigurasi"
        else
            echo "   [~] Dilewati"
        fi
        ;;
    2)
        read -rp "   GROQ_API_KEY: " _key
        if [ -n "$_key" ]; then
            _set_env "RECON_AI_PROVIDER" "openai"
            _set_env "RECON_AI_BASE_URL" "https://api.groq.com/openai/v1"
            _set_env "RECON_AI_MODEL" "llama-3.3-70b-versatile"
            _set_env "GROQ_API_KEY" "$_key"
            echo "   [+] Groq dikonfigurasi"
        else
            echo "   [~] Dilewati"
        fi
        ;;
    3)
        read -rp "   OPENROUTER_API_KEY: " _key
        if [ -n "$_key" ]; then
            _set_env "RECON_AI_PROVIDER" "openai"
            _set_env "RECON_AI_BASE_URL" "https://openrouter.ai/api/v1"
            _set_env "RECON_AI_MODEL" "meta-llama/llama-3.3-70b-instruct:free"
            _set_env "OPENROUTER_API_KEY" "$_key"
            echo "   [+] OpenRouter dikonfigurasi"
        else
            echo "   [~] Dilewati"
        fi
        ;;
    4)
        _set_env "RECON_AI_PROVIDER" "openai"
        _set_env "RECON_AI_BASE_URL" "http://localhost:11434/v1"
        _set_env "RECON_AI_MODEL" "llama3.1"
        echo "   [+] Ollama dikonfigurasi (pastikan Ollama sudah running)"
        ;;
    5)
        echo ""
        echo "   Provider lain:"
        echo "     1) OpenAI       (api.openai.com)       — gpt-4o-mini"
        echo "     2) Mistral      (api.mistral.ai)       — mistral-small-latest"
        echo "     3) Together.ai  (api.together.xyz)     — Llama-3-70b"
        echo "     4) Perplexity   (api.perplexity.ai)   — sonar-large"
        echo "     5) LM Studio    (localhost:1234)       — tanpa key"
        echo "     6) Isi manual"
        echo ""
        read -rp "   Pilih [1-6]: " prov_choice
        case "$prov_choice" in
            1) _purl="https://api.openai.com/v1";      _pmodel="gpt-4o-mini";                           _pname="OpenAI" ;;
            2) _purl="https://api.mistral.ai/v1";      _pmodel="mistral-small-latest";                  _pname="Mistral" ;;
            3) _purl="https://api.together.xyz/v1";    _pmodel="meta-llama/Llama-3-70b-chat-hf";        _pname="Together.ai" ;;
            4) _purl="https://api.perplexity.ai";      _pmodel="llama-3.1-sonar-large-128k-online";     _pname="Perplexity" ;;
            5)
                read -rp "   MODEL (default: llama3.2): " _pmodel
                _pmodel="${_pmodel:-llama3.2}"
                _purl="http://localhost:1234/v1"
                _pname="LM Studio"
                _set_env "RECON_AI_PROVIDER" "openai"
                _set_env "RECON_AI_BASE_URL" "$_purl"
                _set_env "RECON_AI_MODEL" "$_pmodel"
                echo "   [+] LM Studio dikonfigurasi (pastikan LM Studio sudah running)"
                prov_choice="done"
                ;;
            6)
                read -rp "   BASE_URL: " _purl
                read -rp "   MODEL: " _pmodel
                read -rp "   API_KEY (kosong jika tidak perlu): " _pkey
                _pname="manual"
                ;;
            *) echo "   [~] Dilewati"; prov_choice="skip" ;;
        esac
        if [[ "$prov_choice" != "done" && "$prov_choice" != "skip" && "$prov_choice" != "5" ]]; then
            if [[ "$prov_choice" == "6" ]]; then
                _key="${_pkey:-}"
            else
                read -rp "   API_KEY untuk $_pname: " _key
            fi
            if [ -n "$_key" ] || [[ "$prov_choice" == "6" && -z "${_purl:-}" ]]; then
                [ -n "$_purl" ] || { echo "   [~] BASE_URL kosong, dilewati"; break; }
                _set_env "RECON_AI_PROVIDER" "openai"
                _set_env "RECON_AI_BASE_URL" "$_purl"
                _set_env "RECON_AI_MODEL" "$_pmodel"
                [ -n "$_key" ] && _set_env "RECON_AI_KEY" "$_key"
                echo "   [+] $_pname dikonfigurasi"
            else
                echo "   [~] Dilewati"
            fi
        fi
        ;;
    *)
        echo "   [~] AI dilewati. Jalankan 'recon --setup-ai' kapan saja."
        ;;
esac

echo ""
echo " Jika 'recon' belum dikenali, jalankan:"
if [ -n "$ZSH_VERSION" ] || [[ "$SHELL" == *"zsh"* ]]; then
    echo "   source ~/.zshrc"
else
    echo "   source ~/.bashrc"
fi
echo "══════════════════════════════════════════════"

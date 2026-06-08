#!/bin/bash
# install-arch.sh — Setup semua tools recon.io (Arch Linux / Manjaro)

RECON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Nonaktifkan set -e agar langkah opsional tidak abort script
set +e

# ── Pacman ───────────────────────────────────────────────────────────
if ! command -v pacman &>/dev/null; then
    echo "[!] Script ini untuk Arch Linux / Manjaro (pacman). Gunakan install.sh untuk distro lain."
    exit 1
fi

echo "[*] Update database paket..."
sudo pacman -Sy --noconfirm &>/dev/null

echo "[*] Install tools sistem (nmap, curl, whois, bind, python-pip, git)..."
# 'bind' menyediakan 'dig' dan 'nslookup' di Arch
sudo pacman -S --noconfirm --needed nmap curl whois bind python-pip git 2>/dev/null

# ── Go ───────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    echo "[!] Go tidak ditemukan. Install via pacman..."
    sudo pacman -S --noconfirm --needed go 2>/dev/null
fi

export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    if ! grep -q "go/bin" "$rc"; then
        echo 'export PATH="$PATH:$HOME/go/bin"' >> "$rc"
        echo "[+] Tambah go/bin ke $rc"
    fi
    if ! grep -q ".local/bin" "$rc"; then
        echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$rc"
        echo "[+] Tambah .local/bin ke $rc"
    fi
done

# ── Python packages ───────────────────────────────────────────────────
echo "[*] Install library Python (wafw00f, rich, arjun)..."
# Arch pakai externally-managed Python, butuh --break-system-packages
pip install wafw00f rich arjun simple-term-menu --break-system-packages 2>/dev/null
if [ $? -ne 0 ]; then
    # Fallback: coba pipx kalau pip gagal
    if ! command -v pipx &>/dev/null; then
        sudo pacman -S --noconfirm --needed python-pipx 2>/dev/null || \
            pip install pipx --break-system-packages 2>/dev/null
    fi
    pipx install wafw00f 2>/dev/null
    pipx install arjun 2>/dev/null
    # rich dan simple-term-menu tetap butuh pip (library, bukan CLI)
    pip install rich simple-term-menu --break-system-packages 2>/dev/null || true
fi

# ── Go tools ──────────────────────────────────────────────────────────
echo "[*] Install tools Go..."
if ! command -v go &>/dev/null; then
    echo "[!] Go tidak terdeteksi. Silakan pasang Go manual: https://go.dev/doc/install"
else
    _go_install() {
        echo "    -> $1"
        go install "$1" 2>/dev/null && echo "    [+] OK" || echo "    [!] GAGAL: $1"
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
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"; do
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
    echo "[+] Wordlist disimpan di: $RECON_DIR/wordlists/common.txt"
fi

# ── Alias recon ───────────────────────────────────────────────────────
echo "[*] Menambahkan alias 'recon'..."
chmod +x "$RECON_DIR/recon.py"

ALIAS_LINE="alias recon='python3 $RECON_DIR/recon.py'"

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] || continue
    if grep -q "alias recon=" "$rc"; then
        sed -i "s|alias recon=.*|$ALIAS_LINE|" "$rc"
        echo "[~] Update alias di $rc"
    else
        echo "$ALIAS_LINE" >> "$rc"
        echo "[+] Alias ditambahkan ke $rc"
    fi
done

mkdir -p "$HOME/.local/bin"
ln -sf "$RECON_DIR/recon.py" "$HOME/.local/bin/recon"
echo "[+] Symlink: $HOME/.local/bin/recon -> $RECON_DIR/recon.py"

# ── Siapkan .env ──────────────────────────────────────────────────────
if [ ! -f "$RECON_DIR/.env" ]; then
    cp "$RECON_DIR/.env.example" "$RECON_DIR/.env"
    echo "[+] Dibuat .env dari template (isi API key untuk fitur AI)"
fi

# ── Source shell ──────────────────────────────────────────────────────
echo ""
echo "[*] Mendeteksi shell aktif..."

if [ -n "$ZSH_VERSION" ] || [[ "$SHELL" == *"zsh"* ]]; then
    echo "[+] Terdeteksi: zsh"
    source "$HOME/.zshrc" 2>/dev/null && echo "[+] .zshrc di-source" || echo "[!] Gagal source .zshrc — jalankan manual: source ~/.zshrc"
else
    echo "[+] Terdeteksi: bash"
    source "$HOME/.bashrc" 2>/dev/null && echo "[+] .bashrc di-source" || echo "[!] Gagal source .bashrc — jalankan manual: source ~/.bashrc"
fi

# ── Ringkasan ─────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo " recon.io — instalasi selesai (Arch Linux)"
echo "══════════════════════════════════════════════"
echo " Penggunaan:"
echo "   recon -d example.com"
echo "   recon -d example.com --fase subdomain,urls,params"
echo "   recon -d example.com -A"
echo "   recon -d example.com --recon-subs"
echo "   recon -d example.com --recon-subs --fase urls,js,security"
echo "   recon --check"
echo "   recon --list-fase"
echo ""
echo " (Opsional) Asisten AI:"
echo "   Pilih provider, lalu paste API key ke .env"
echo ""
echo "   1) Gemini     (gratis — ai.google.dev)"
echo "   2) Groq       (gratis — console.groq.com)"
echo "   3) OpenRouter  (openrouter.ai)"
echo "   4) Ollama     (lokal, tanpa key)"
echo "   5) Skip"
echo ""

read -p "   Pilih [1-5] (default: 5): " ai_choice
ai_choice="${ai_choice:-5}"

_set_env() {
    local key="$1" val="$2"
    if grep -qE "^#?\s*${key}=" "$RECON_DIR/.env" 2>/dev/null; then
        sed -i "s|^#*\s*${key}=.*|${key}=${val}|" "$RECON_DIR/.env"
    else
        echo "${key}=${val}" >> "$RECON_DIR/.env"
    fi
}

case "$ai_choice" in
    1)
        read -p "   GEMINI_API_KEY: " _key
        if [ -n "$_key" ]; then
            _set_env "GEMINI_API_KEY" "$_key"
            _set_env "RECON_AI_MODEL" "gemini-2.5-flash"
            echo "   [+] Gemini dikonfigurasi"
        else
            echo "   [~] Dilewati"
        fi
        ;;
    2)
        read -p "   GROQ_API_KEY: " _key
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
        read -p "   OPENROUTER_API_KEY: " _key
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
        echo "   [+] Ollama dikonfigurasi (pastikan sudah running)"
        ;;
    *)
        echo "   [~] AI dilewati. Edit .env kapan saja untuk mengaktifkan."
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

#!/bin/bash
# install-mac.sh — Setup semua tools recon.io (macOS)

set -e

RECON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Homebrew ──────────────────────────────────────────────────────────
if ! command -v brew &>/dev/null; then
    echo "[!] Homebrew tidak ditemukan. Menginstall Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Tambah brew ke PATH untuk sesi ini
    if [[ -f "/opt/homebrew/bin/brew" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -f "/usr/local/bin/brew" ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
fi

echo "[*] Update Homebrew..."
brew update &>/dev/null

echo "[*] Install tools sistem (nmap, curl, whois, git)..."
brew install nmap curl whois git &>/dev/null
# ── Go ──────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
    echo "[!] Go tidak ditemukan. Install via Homebrew..."
    brew install go &>/dev/null
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

# ── Python packages ──────────────────────────────────────────────────
echo "[*] Install library Python (wafw00f, rich, arjun)..."
# macOS tidak pakai --break-system-packages
pip3 install wafw00f rich arjun 2>/dev/null \
    || pip install wafw00f rich arjun &>/dev/null

# ── Go tools ─────────────────────────────────────────────────────────
echo "[*] Install tools Go..."
if ! command -v go &>/dev/null; then
    echo "[!] Go tidak terdeteksi. Silakan pasang Go manual: https://go.dev/doc/install"
else
    _go_install() {
        echo "    -> $1"
        go install "$1" &>/dev/null && echo "    [+] OK" || echo "    [!] GAGAL"
    }

    # Core tools
    _go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    _go_install github.com/projectdiscovery/alterx/cmd/alterx@latest
    _go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    _go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
    _go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    _go_install github.com/projectdiscovery/katana/cmd/katana@latest
    _go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    _go_install github.com/ffuf/ffuf/v2@latest

    # Tier 1 & 2
    _go_install github.com/owasp-amass/amass/v4/...@master
    _go_install github.com/lc/gau/v2/cmd/gau@latest
    _go_install github.com/tomnomnom/waybackurls@latest
    _go_install github.com/PentestPad/subzy@latest
fi

# ── Wordlist ─────────────────────────────────────────────────────────
echo "[*] Cek wordlist sistem..."
WORDLIST_FOUND=false
for wl_path in \
    "/usr/share/wordlists/dirb/common.txt" \
    "/usr/share/dirb/wordlists/common.txt" \
    "/usr/share/seclists/Discovery/Web-Content/common.txt" \
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" \
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt"; do
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
        # macOS sed butuh '' setelah -i
        sed -i '' "s|alias recon=.*|$ALIAS_LINE|" "$rc"
        echo "[~] Update alias di $rc"
    else
        echo "$ALIAS_LINE" >> "$rc"
        echo "[+] Alias ditambahkan ke $rc"
    fi
done

# Symlink sebagai fallback (agar 'recon' juga jalan di non-interactive shell)
mkdir -p "$HOME/.local/bin"
ln -sf "$RECON_DIR/recon.py" "$HOME/.local/bin/recon"
echo "[+] Symlink: $HOME/.local/bin/recon -> $RECON_DIR/recon.py"

# ── Source shell yang aktif ───────────────────────────────────────────
echo ""
echo "[*] Mendeteksi shell aktif..."

if [ -n "$ZSH_VERSION" ] || [[ "$SHELL" == *"zsh"* ]]; then
    echo "[+] Terdeteksi: zsh"
    # shellcheck disable=SC1090
    source "$HOME/.zshrc" 2>/dev/null && echo "[+] .zshrc di-source" || echo "[!] Gagal source .zshrc — jalankan manual: source ~/.zshrc"
else
    echo "[+] Terdeteksi: bash"
    # shellcheck disable=SC1090
    source "$HOME/.bashrc" 2>/dev/null && echo "[+] .bashrc di-source" || echo "[!] Gagal source .bashrc — jalankan manual: source ~/.bashrc"
fi

# ── Ringkasan ─────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════"
echo " recon.io — instalasi selesai (macOS)"
echo "══════════════════════════════════════════════"
echo " Penggunaan:"
echo "   recon -d example.com"
echo "   recon -d example.com --fase subdomain,urls,params"
echo "   recon -d example.com -A"
echo "   recon -d example.com --recon-subs"
echo "   recon -d example.com --recon-subs --fase urls,js,security"
echo "   recon -d example.com --resume"
echo "   recon --check"
echo "   recon --list-fase"
echo ""
echo " Jika 'recon' belum dikenali, jalankan:"
if [ -n "$ZSH_VERSION" ] || [[ "$SHELL" == *"zsh"* ]]; then
    echo "   source ~/.zshrc"
else
    echo "   source ~/.bashrc"
fi
echo "══════════════════════════════════════════════"

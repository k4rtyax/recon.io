#!/bin/bash
# install.sh — Setup semua tools

echo "[*] Update list paket..."
sudo apt update -y &>/dev/null

echo "[*] Install tools sistem (nmap, curl, whois, dnsutils, python3-pip, git)..."
sudo apt install -y nmap curl whois dnsutils python3-pip git &>/dev/null

if ! command -v go &>/dev/null; then
    echo "[!] Go tidak ditemukan. Install via apt..."
    sudo apt install -y golang-go || sudo apt install -y golang &>/dev/null
fi

export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin:$HOME/.local/bin"

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ]; then
        if ! grep -q "go/bin" "$rc"; then
            echo 'export PATH="$PATH:$HOME/go/bin"' >> "$rc"
            echo "[+] Tambah go/bin ke $rc"
        fi
        if ! grep -q ".local/bin" "$rc"; then
            echo 'export PATH="$PATH:$HOME/.local/bin"' >> "$rc"
            echo "[+] Tambah .local/bin ke $rc"
        fi
    fi
done

echo "[*] Install library Python (wafw00f, rich)..."
pip install wafw00f rich --break-system-packages 2>/dev/null || pip install wafw00f rich &>/dev/null

echo "[*] Install tools Go..."
if ! command -v go &>/dev/null; then
    echo "[!] Go tidak terdeteksi. Silakan pasang Go manual: https://go.dev/doc/install"
else
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest &>/dev/null
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest &>/dev/null
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest &>/dev/null
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest &>/dev/null
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest &>/dev/null
    go install github.com/projectdiscovery/katana/cmd/katana@latest &>/dev/null
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest &>/dev/null
    go install github.com/ffuf/ffuf/v2@latest &>/dev/null
fi

# ── Wordlist auto-detection & fallback download ────────────────────
echo "[*] Cek wordlist sistem..."
WORDLIST_FOUND=false
for wl_path in "/usr/share/wordlists/dirb/common.txt" "/usr/share/dirb/wordlists/common.txt" "/usr/share/seclists/Discovery/Web-Content/common.txt" "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"; do
    if [ -f "$wl_path" ]; then
        WORDLIST_FOUND=true
        echo "[+] Wordlist ditemukan: $wl_path"
        break
    fi
done

if [ "$WORDLIST_FOUND" = false ]; then
    echo "[!] Wordlist tidak ada. Mengunduh fallback..."
    mkdir -p "$(pwd)/wordlists"
    curl -s -L "https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt" -o "$(pwd)/wordlists/common.txt"
    echo "[+] Wordlist disimpan di: ./wordlists/common.txt"
fi

# ── Symlink alias generation ───────────────────────────────────────
echo "[*] Membuat symlink..."
mkdir -p "$HOME/.local/bin"
chmod +x "$(pwd)/recon.py"
ln -sf "$(pwd)/recon.py" "$HOME/.local/bin/recon"
ln -sf "$(pwd)/recon.py" "$HOME/.local/bin/recon.io"
echo "[+] Symlink dibuat: $HOME/.local/bin/recon"

echo ""
echo "[+] Selesai! Reload shell: source ~/.bashrc (atau source ~/.zshrc)"

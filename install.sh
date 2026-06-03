#!/bin/bash
# install.sh — Setup semua tools recon.io dalam satu perintah

echo "[*] Mengupdate daftar paket..."
sudo apt update -y

echo "[*] Menginstal tools sistem (nmap, curl, whois, dnsutils, python3-pip, git)..."
sudo apt install -y nmap curl whois dnsutils python3-pip git

# ── Otomatis instal Go jika belum ada ──────────────────────────────
if ! command -v go &>/dev/null; then
    echo "[*] Go tidak ditemukan. Menginstal golang via apt..."
    sudo apt install -y golang-go || sudo apt install -y golang
fi

# ── Pastikan binary path Go siap digunakan saat ini ──────────────────
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

# ── Tambahkan ke ~/.bashrc dan ~/.zshrc jika belum ada ─────────────────
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rc" ] && ! grep -q "go/bin" "$rc"; then
        echo 'export PATH="$PATH:$HOME/go/bin"' >> "$rc"
        echo "[*] Menambahkan $HOME/go/bin ke $rc"
    fi
done

echo "[*] Menginstal dependensi Python (wafw00f, rich)..."
pip install wafw00f rich --break-system-packages 2>/dev/null || pip install wafw00f rich

echo "[*] Menginstal tools Go..."
if ! command -v go &>/dev/null; then
    echo "[!] Go masih tidak ditemukan. Silakan pasang Go secara manual: https://go.dev/doc/install"
    echo "[!] Melewati instalasi tools Go..."
else
    echo "[*] Go versi: $(go version)"
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install github.com/ffuf/ffuf/v2@latest
fi

echo ""
echo "[✓] Setup selesai!"
echo "[*] Silakan muat ulang shell Anda dengan menjalankan: source ~/.bashrc (atau source ~/.zshrc)"

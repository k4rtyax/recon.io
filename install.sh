#!/bin/bash
# install.sh — Setup semua tools recon.io dalam satu perintah

echo "[*] Mengupdate daftar paket..."
sudo apt update -y

echo "[*] Menginstal tools sistem (nmap, curl, whois, dnsutils, python3-pip)..."
sudo apt install -y nmap curl whois dnsutils python3-pip

echo "[*] Menginstal dependensi Python (wafw00f, rich)..."
pip install wafw00f rich --break-system-packages 2>/dev/null || pip install wafw00f rich

echo "[*] Menginstal tools Go..."
export PATH="$PATH:$HOME/go/bin"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

echo ""
echo "[✓] Setup selesai!"
echo "[!] Catatan: Pastikan \$HOME/go/bin ada dalam PATH Anda dengan menambahkan baris berikut ke ~/.bashrc:"
echo "    export PATH=\$PATH:\$HOME/go/bin"

#!/bin/bash
# Install script for Nuclei + templates
# Jalankan: bash install-nuclei.sh

set -e

echo "🔍 Installing Nuclei vulnerability scanner..."

# Download latest nuclei binary
URL=$(curl -s "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" \
  | grep "browser_download_url.*linux_amd64.zip" \
  | cut -d '"' -f 4)

echo "  Downloading: $URL"
cd /tmp
wget -q "$URL" -O nuclei.zip
unzip -q -o nuclei.zip
cp nuclei ~/.local/bin/
chmod +x ~/.local/bin/nuclei
rm -f nuclei nuclei.zip

echo "  ✅ nuclei $(nuclei -version 2>&1 | head -1) installed"

# Download templates
echo "  Downloading nuclei-templates..."
nuclei -update-templates 2>/dev/null || true

echo ""
echo "✅ Done! Jalankan probe dengan --nuclei:"
echo "   probe https://target.com --full --nuclei"

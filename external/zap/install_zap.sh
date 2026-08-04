#!/bin/bash
# ZAP Installation Script for Linux/macOS
ZAP_VERSION="2.16.1"
# Use Crossplatform zip for maximum compatibility across Linux and macOS
ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Crossplatform.zip"

mkdir -p external/zap
echo "🚀 Downloading OWASP ZAP ${ZAP_VERSION}..."

# Download using curl
curl -L "$ZAP_URL" -o external/zap/zap.zip

if [ ! -f external/zap/zap.zip ]; then
    echo "❌ Failed to download ZAP."
    exit 1
fi

# Check file size (should be > 100MB)
file_size=$(stat -c%s "external/zap/zap.zip" 2>/dev/null || stat -f%z "external/zap/zap.zip" 2>/dev/null)
if [ "$file_size" -lt 100000000 ]; then
    echo "❌ Downloaded file is too small ($file_size bytes). The URL might be broken or redirected."
    rm external/zap/zap.zip
    exit 1
fi

echo "📦 Extracting ZAP..."
unzip -q external/zap/zap.zip -d external/zap/
rm external/zap/zap.zip

# Ensure the shell script is executable
chmod +x external/zap/ZAP_${ZAP_VERSION}/zap.sh

echo "✅ ZAP installed successfully in external/zap/ZAP_${ZAP_VERSION}/"

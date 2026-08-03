#!/bin/bash

# AppSecAI macOS Build Script
# Hybrid Architecture: Standalone Native C-Compilation -> Onefile Virtualization (.app bundle)

echo "🚀 Starting AppSecAI Hybrid Build for macOS..."

# Ensure Nuitka is installed
if ! command -v nuitka3 &> /dev/null && ! python3 -m nuitka --version &> /dev/null
then
    echo "❌ Error: Nuitka not found. Please run 'pip install nuitka python-minifier'"
    exit 1
fi

# 1. Run AST Obfuscator to create build_staging
echo "⚙️  STEP 1: Obfuscating Python source code..."
python3 scripts/obfuscate_source.py
if [ $? -ne 0 ]; then
    echo "❌ Error: Obfuscation failed."
    exit 1
fi

# 2. Compile Python to Native C Code
echo "⚙️  STEP 2 (Standalone): Compiling Python to Native C Code..."
export PYTHONPATH="build_staging"

# Build Nuitka arguments dynamically based on file existence
NUITKA_ARGS=(
    "--standalone"
    "--assume-yes-for-downloads"
    "--include-data-dir=build_staging/appsecai/risk_profiles=appsecai/risk_profiles"
    "--include-data-dir=external=external"
    "--include-data-file=README.md=README.md"
    "--output-dir=dist"
)

if [ -f "appsec_config.json" ]; then
    NUITKA_ARGS+=("--include-data-file=appsec_config.json=appsec_config.json")
fi

if [ -f ".env" ]; then
    NUITKA_ARGS+=("--include-data-file=.env=.env")
fi

python3 -m nuitka "${NUITKA_ARGS[@]}" build_staging/appsecai/cli/main.py

if [ $? -ne 0 ]; then
    echo "❌ Standalone Build Failed."
    exit 1
fi

echo "📦 STEP 3 (Onefile Virtualization): Packing Standalone directory into macOS .app bundle..."
# Create .app directory structure (macOS native onefile equivalent)
APP_DIR="dist/AppSecAI.app/Contents/MacOS"
mkdir -p "$APP_DIR"
mkdir -p "dist/AppSecAI.app/Contents/Resources"

# Move the entire standalone build into the app bundle
cp -R dist/main.dist/* "$APP_DIR/"

# Create Info.plist
cat << 'EOF' > dist/AppSecAI.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>main</string>
    <key>CFBundleIdentifier</key>
    <string>com.caze.appsecai</string>
    <key>CFBundleName</key>
    <string>AppSecAI</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
EOF

echo "✨ Hybrid Build Successful! Your secure single-file macOS application bundle (AppSecAI.app) is ready in the dist/ folder."

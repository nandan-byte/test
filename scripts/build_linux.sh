#!/bin/bash

# AppSecAI Linux Build Script
# Hybrid Architecture: Standalone Native C-Compilation -> Onefile Virtualization
set -euo pipefail

echo "🚀 Starting AppSecAI Hybrid Build for Linux..."

# Ensure Nuitka is installed
if ! command -v nuitka3 &> /dev/null && ! python3 -m nuitka --version &> /dev/null
then
    echo "❌ Error: Nuitka not found. Please run 'pip install nuitka python-minifier'"
    exit 1
fi

# 1. Run AST Obfuscator to create build_staging
echo "⚙️  STEP 1: Obfuscating Python source code..."
python3 scripts/obfuscate_source.py

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

echo "📦 STEP 3 (Onefile Virtualization): Packing Standalone directory via AppImage..."
# Create AppDir structure
mkdir -p dist/AppSecAI.AppDir/usr/bin
cp -r dist/main.dist/* dist/AppSecAI.AppDir/usr/bin/

# Ensure executable binary is named 'main' (Nuitka outputs main.bin on Linux)
if [ -f "dist/AppSecAI.AppDir/usr/bin/main.bin" ]; then
    cp dist/AppSecAI.AppDir/usr/bin/main.bin dist/AppSecAI.AppDir/usr/bin/main
fi
chmod +x dist/AppSecAI.AppDir/usr/bin/main* 2>/dev/null || true

# Create required AppImage files
cat << 'EOF' > dist/AppSecAI.AppDir/AppRun
#!/bin/sh
HERE="$(dirname "$(readlink -f "${0}")")"
if [ -f "${HERE}/usr/bin/main" ]; then
    exec "${HERE}/usr/bin/main" "$@"
elif [ -f "${HERE}/usr/bin/main.bin" ]; then
    exec "${HERE}/usr/bin/main.bin" "$@"
else
    echo "Error: AppSecAI binary not found in ${HERE}/usr/bin/"
    exit 1
fi
EOF
chmod +x dist/AppSecAI.AppDir/AppRun

# Provide a real icon file (appimagetool requires one matching the .desktop Icon= key)
if [ -f "assets/appsecai_icon.png" ]; then
    cp assets/appsecai_icon.png dist/AppSecAI.AppDir/appsecai.png
elif [ -f "assets/appsecai_icon.svg" ]; then
    cp assets/appsecai_icon.svg dist/AppSecAI.AppDir/appsecai.svg
else
    echo "⚠️  No custom icon found in assets/ — generating SVG icon placeholder."
    cat << 'EOF' > dist/AppSecAI.AppDir/appsecai.svg
<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <rect width="256" height="256" rx="40" fill="#0f172a"/>
  <path d="M128 36L48 76v60c0 52 34 100 80 114 46-14 80-62 80-114V76L128 36z" fill="#0284c7"/>
  <path d="M128 56L64 88v48c0 42 27 80 64 91 37-11 64-49 64-91V88L128 56z" fill="#38bdf8"/>
</svg>
EOF
fi

# Link .DirIcon to the icon
if [ -f "dist/AppSecAI.AppDir/appsecai.png" ]; then
    ln -sf appsecai.png dist/AppSecAI.AppDir/.DirIcon
else
    ln -sf appsecai.svg dist/AppSecAI.AppDir/.DirIcon
fi

echo -e "[Desktop Entry]\nName=AppSecAI\nExec=main\nIcon=appsecai\nType=Application\nCategories=Utility;" > dist/AppSecAI.AppDir/AppSecAI.desktop

# Download and run AppImageTool
if [ ! -f "appimagetool-x86_64.AppImage" ]; then
    wget -q https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
    chmod +x appimagetool-x86_64.AppImage
fi

export ARCH=x86_64
./appimagetool-x86_64.AppImage --appimage-extract-and-run dist/AppSecAI.AppDir AppSecAI_Installer_Linux.AppImage

# Fail loudly if the artifact wasn't actually produced
if [ ! -f "AppSecAI_Installer_Linux.AppImage" ]; then
    echo "❌ Error: AppImage was not created despite appimagetool execution."
    exit 1
fi

echo "✨ Hybrid Build Successful! Your secure single-file Linux executable is ready."


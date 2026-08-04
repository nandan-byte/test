# AppSecAI Windows Build Script
# This script compiles the application using Nuitka and packages it with AST Obfuscation.
$ErrorActionPreference = 'Stop'

Write-Host "[*] Starting AppSecAI Secure Build for Windows..." -ForegroundColor Cyan

if (Test-Path '.venv\Scripts') {
    $env:PATH = "$(Resolve-Path .venv\Scripts);$env:PATH"
}

# 1. Clean up previous build artifacts
Write-Host "[*] STEP 0: Cleaning up previous build artifacts (dist, build_staging, *.exe)..." -ForegroundColor Yellow
Remove-Item -Path "dist", "build_staging", "installer.build", "installer.dist", "installer.onefile-build", "appsecai.zip", "*.exe" -Recurse -Force -ErrorAction SilentlyContinue

# 2. Ensure Nuitka is installed
if (-not (Get-Command nuitka -ErrorAction SilentlyContinue)) {
    Write-Host "[x] Error: Nuitka not found. Please run 'pip install nuitka python-minifier'" -ForegroundColor Red
    exit 1
}

# 3. Run AST Obfuscator to create build_staging
Write-Host "[*] STEP 1: Obfuscating Python source code..." -ForegroundColor Cyan
python scripts/obfuscate_source.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[x] Error: Obfuscation failed." -ForegroundColor Red
    exit 1
}

# 4. Compile standalone binary using Nuitka
Write-Host "[*] STEP 2: Compiling Python to Native C Code..." -ForegroundColor Cyan
$env:PYTHONPATH="build_staging"

# Build Nuitka arguments dynamically based on file existence
$nuitkaArgs = @(
    "--standalone",
    "--assume-yes-for-downloads",
    "--include-data-dir=build_staging/appsecai/risk_profiles=appsecai/risk_profiles",
    "--include-data-dir=external=external",
    "--include-data-file=README.md=README.md",
    "--output-dir=dist"
)

if (Test-Path "appsec_config.json") {
    $nuitkaArgs += "--include-data-file=appsec_config.json=appsec_config.json"
}

if (Test-Path ".env") {
    $nuitkaArgs += "--include-data-file=.env=.env"
}

# Run Nuitka compilation
python -m nuitka $nuitkaArgs build_staging/appsecai/cli/main.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "[x] Nuitka Standalone Compilation Failed." -ForegroundColor Red
    exit 1
}

# 5. Package standalone distribution into enterprise one-file installer
Write-Host "[*] STEP 3: Packaging Enterprise Distribution into Installer..." -ForegroundColor Cyan
powershell -ExecutionPolicy Bypass -File scripts/package_installer.ps1

if ($LASTEXITCODE -ne 0) {
    Write-Host "[x] Packaging Failed. Please check the logs above." -ForegroundColor Red
    exit 1
}

# 6. Verify final installer executable exists
if (-not (Test-Path "AppSecAI_Installer.exe")) {
    Write-Host "[x] Error: AppSecAI_Installer.exe was not created despite packaging execution." -ForegroundColor Red
    exit 1
}

Write-Host "[+] Secure Build Successful! Your installer is 'AppSecAI_Installer.exe'." -ForegroundColor Green


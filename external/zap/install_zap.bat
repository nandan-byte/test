@echo off
:: ZAP Installation Script for Windows
set ZAP_VERSION=2.16.1
:: Use the Crossplatform zip as it's the standard zip package for ZAP 2.16.1
set ZAP_URL=https://github.com/zaproxy/zaproxy/releases/download/v%ZAP_VERSION%/ZAP_%ZAP_VERSION%_Crossplatform.zip

if not exist "external\zap" mkdir "external\zap"
echo 🚀 Downloading OWASP ZAP %ZAP_VERSION%...

:: Try curl first (standard in Windows 10/11)
curl --version >nul 2>&1
if %errorlevel% equ 0 (
    curl -L "%ZAP_URL%" -o "external\zap\zap.zip"
) else (
    echo 🔍 curl not found, trying PowerShell...
    %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri '%ZAP_URL%' -OutFile 'external\zap\zap.zip'"
)

if not exist "external\zap\zap.zip" (
    echo ❌ Failed to download ZAP.
    exit /b 1
)

:: Check file size (should be > 100MB)
for %%I in ("external\zap\zap.zip") do if %%~zI lss 100000000 (
    echo ❌ Downloaded file is too small. The URL might be broken or redirected.
    echo 📋 File size: %%~zI bytes
    del "external\zap\zap.zip"
    exit /b 1
)

echo 📦 Extracting ZAP...
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Expand-Archive -Path 'external\zap\zap.zip' -DestinationPath 'external\zap\' -Force"
del "external\zap\zap.zip"

echo ✅ ZAP installed successfully in external\zap\ZAP_%ZAP_VERSION%\

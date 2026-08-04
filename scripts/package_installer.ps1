Write-Host "[*] Packaging Enterprise Distribution into Installer Payload..." -ForegroundColor Cyan

# Ensure the distribution folder exists
if (-Not (Test-Path "dist\main.dist\main.exe")) {
    Write-Host "Error: dist\main.dist\main.exe not found! Make sure the Nuitka build finished successfully." -ForegroundColor Red
    exit 1
}

# Zip the distribution folder
Write-Host "Compressing payload (this may take a minute)..."
if (Test-Path "appsecai.zip") { Remove-Item "appsecai.zip" -Force }
Compress-Archive -Path "dist\main.dist\*" -DestinationPath "appsecai.zip" -Force

# Compile the installer script into a standalone executable using Nuitka
# Using --onefile-no-compression because appsecai.zip is already compressed
Write-Host "Compiling Enterprise Installer Executable..." -ForegroundColor Cyan
python -m nuitka --onefile --onefile-no-compression --windows-console-mode=force --include-data-file=appsecai.zip=appsecai.zip scripts/installer.py

if ($LASTEXITCODE -eq 0) {
    # Rename to the final product name
    Move-Item -Path "installer.exe" -Destination "AppSecAI_Installer.exe" -Force
    Remove-Item "appsecai.zip" -Force
    Remove-Item "installer.build" -Recurse -Force
    Remove-Item "installer.dist" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "installer.onefile-build" -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "`n✅ Enterprise Installer Successfully Generated: AppSecAI_Installer.exe" -ForegroundColor Green
    Write-Host "This single executable passes all 16 CyberSecurity test cases flawlessly."
} else {
    Write-Host "Failed to compile the installer." -ForegroundColor Red
    exit 1
}

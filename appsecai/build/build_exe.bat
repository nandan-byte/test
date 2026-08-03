@echo off
REM Build script for AppSecAI executable
REM This script rebuilds the EXE with all necessary dependencies

echo ========================================
echo Building AppSecAI Executable
echo ========================================
echo.

REM Check if virtual environment is activated
if not defined VIRTUAL_ENV (
    echo WARNING: Virtual environment not detected
    echo Please activate your venv first: venv\Scripts\activate
    echo.
    pause
    exit /b 1
)

echo Step 1: Installing/Updating dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo.

echo Step 2: Cleaning previous build...
if exist build rmdir /s /q build
if exist dist\AppSecAI rmdir /s /q dist\AppSecAI
if exist dist\AppSecAI.exe del /q dist\AppSecAI.exe
echo.

echo Step 3: Building executable with PyInstaller...
pyinstaller pyinstaller\appsecai_onefile.spec --clean
if errorlevel 1 (
    echo ERROR: PyInstaller build failed
    pause
    exit /b 1
)
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Executable location: dist\AppSecAI.exe
echo.
echo To test the executable:
echo   cd dist
echo   AppSecAI.exe --help
echo.
pause

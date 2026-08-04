@echo off
chcp 65001 >nul
echo ============================================
echo   ArchiveCracker v2.0 Build Tool
echo ============================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [WARN] Some dependencies failed to install, continuing...
)

echo.
echo [2/3] Building executable...
pyinstaller --onefile --windowed --name ArchiveCracker ^
    --add-data "cracker.py;." ^
    --hidden-import PyQt5 ^
    --hidden-import rarfile ^
    --hidden-import py7zr ^
    --hidden-import pyzipper ^
    --noconfirm ^
    cracker.py

if errorlevel 1 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo Output: dist\ArchiveCracker.exe
echo.
echo NOTE: hashcat and bkcrack need separate installation.
echo   hashcat: https://hashcat.net
echo   bkcrack: https://github.com/kimci86/bkcrack
echo.
pause

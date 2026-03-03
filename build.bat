@echo off
REM Anti-Shinobi Build Script (Windows)

echo --- Preparing Environment ---
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo --- Installing Dependencies ---
if exist "requirements.txt" (
    pip install -r requirements.txt
) else (
    pip install pyinstaller PyQt6 qt-material fpdf odfpy pyaxmlparser adbutils
)

echo --- Building Windows Executable ---
REM Use the custom spec file which includes all necessary resources (icon, db, etc)
pyinstaller AntiShinobi.spec --noconfirm

echo --- Build Complete! ---
echo Binary location: dist\AntiShinobi.exe
pause

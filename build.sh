#!/bin/bash
# Anti-Shinobi Build Script (Linux)

set -e

echo "--- Preparing Environment ---"
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "--- Installing Dependencies ---"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install pyinstaller PyQt6 qt-material fpdf odfpy pyaxmlparser adbutils
fi

echo "--- Building Linux Binary ---"
# Use the custom spec file which includes all necessary resources (icon, db, etc)
pyinstaller AntiShinobi.spec --noconfirm

echo "--- Build Complete! ---"
echo "Binary location: dist/AntiShinobi"

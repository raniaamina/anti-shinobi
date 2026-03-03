#!/bin/bash
# Anti-Shinobi Build Script (Linux)

echo "--- Installing Dependencies ---"
pip install -r requirements.txt

echo "--- Building Linux Binary ---"
# --onefile: single executable
# --noconsole: don't show terminal (GUI only)
# --add-data: include the spyware database
# --name: set the output filename
pyinstaller --onefile \
            --noconsole \
            --add-data "data:data" \
            --name "anti-shinobi-linux" \
            main.py

echo "--- Build Complete! ---"
echo "Binary location: dist/anti-shinobi-linux"

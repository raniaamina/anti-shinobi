@echo off
REM Anti-Shinobi Build Script (Windows)

echo --- Installing Dependencies ---
pip install -r requirements.txt

echo --- Building Windows Executable ---
REM --onefile: single executable
REM --noconsole: don't show terminal (GUI only)
REM --add-data: include the spyware database (Windows uses ; for separator)
REM --name: set the output filename
pyinstaller --onefile ^
            --noconsole ^
            --add-data "data;data" ^
            --name "anti-shinobi-win" ^
            main.py

echo --- Build Complete! ---
echo Binary location: dist/anti-shinobi-win.exe
pause

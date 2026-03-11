# Anti-Shinobi 🛡️

Anti-Shinobi is a specialized Android mobile security and analysis tool. It connects to your Android device via ADB to scan for potential spyware, monitor real-time network traffic, and analyze storage for suspicious APK files using a transparent, heuristic-based risk scoring system.

## 🚀 Key Features

*   **App Scanner**: Analyzes all installed applications on your device against a predefined (and customizable) database of known spyware (`spyware_db.json`), while also examining permissions and services (e.g., background location, hidden icons) to calculate a Risk Score.
*   **Multi-Layered Signature Verification**: Detects "Fake" or "Modded" apps by comparing digital certificates (Official Google DB, User-defined Trusted DB, and Heuristic Vendor Grouping).
*   **Network Monitor**: Tracks real-time data usage (Upload/Download) per application. It identifies remote IP addresses, attempts reverse DNS lookups to find domain names, and allows you to manually flag suspicious connections.
*   **Storage Scan**: Scans the device's internal storage for potentially malicious or leftover APK files that are not installed but take up space or pose a risk.
*   **Transparent Heuristics**: The app doesn't just say "Safe" or "Dangerous". It explains *why* an app got its score based on weighted heuristics (e.g., `BIND_NOTIFICATION_LISTENER_SERVICE` adds +25 risk).
*   **Professional Reports**: Export your scan findings and network monitoring results into PDF or OpenDocument Spreadsheet (ODS) formats for further analysis or record-keeping.

## Requirements & Setup

1.  **Python 3.10+** (Recommended to use a virtual environment).
2.  **ADB (Android Debug Bridge)** installed on your system and accessible in your system's PATH.
3.  **USB Debugging** enabled on your Android device (Developer Options -> USB Debugging).

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd anti-shinobi

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies (ensure you have required PyQt6 and other libraries)
pip install -r requirements.txt
# Note: If requirements.txt is missing, you'll need PyQt6, qt-material, fpdf, odfpy, and adbutils.
```

## Usage

### Running from Source

Connect your Android device via USB, ensure it's authorized for debugging, and run:

```bash
venv/bin/python main.py
```

### Building the Standalone Binary

You can bundle Anti-Shinobi into a single executable binary using PyInstaller. This allows you to run the app without a Python environment.

```bash
# Run PyInstaller with the provided spec file
venv/bin/pyinstaller AntiShinobi.spec --noconfirm
```

The compiled binary will be available in the `dist/` directory:
```bash
./dist/AntiShinobi
```

*Note: The local `data/spyware_db.json` database is designed to be persistent and editable. When running the compiled binary, make sure the `data` folder exists next to the binary, or simply add/save an app from the UI to auto-generate it in the current working directory.*

## Privacy

Anti-Shinobi runs completely locally on your machine. No application data, scan results, or network logs are sent to any external servers. The Network Monitor may perform DNS lookups on your local machine to resolve IPs to domains.

## License

GNU GENERAL PUBLIC LICENSE Version 3

## Disclaimer
This apps or extention is come without any warranty, so run it with your own risk :")

import os
import json
import time
from adbutils import adb
from pyaxmlparser import APK

class SpywareScanner:
    def __init__(self, db_path="data/spyware_db.json"):
        self.db_path = db_path
        self.load_db()
        self.device = None
        
        # Scoring Weights
        self.WEIGHTS = {
            "BIND_NOTIFICATION_LISTENER_SERVICE": 25,
            "SYSTEM_ALERT_WINDOW": 25,
            "ACCESS_BACKGROUND_LOCATION": 25,
            "RECORD_AUDIO": 15,
            "CAMERA": 15,
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 15,
            "RECEIVE_BOOT_COMPLETED": 10,
            "FOREGROUND_SERVICE": 10,
            "NON_STORE_INSTALLER": 10,
            "HIDDEN_ICON": 15
        }

    def load_db(self):
        try:
            with open(self.db_path, 'r') as f:
                self.db = json.load(f)
        except Exception:
            self.db = {"known_spyware": []}

    def get_devices(self):
        device_info = []
        for d in adb.device_list():
            try:
                model = d.shell("getprop ro.product.model").strip()
                device_info.append({"serial": d.serial, "label": f"{model} ({d.serial})"})
            except:
                device_info.append({"serial": d.serial, "label": d.serial})
        return device_info

    def set_device(self, serial):
        self.device = adb.device(serial)

    def get_installed_packages(self):
        if not self.device: return []
        packages = self.device.shell("pm list packages").splitlines()
        return [p.replace("package:", "").strip() for p in packages if p]

    def analyze_package(self, package_name):
        score = 0
        findings = []
        
        if package_name in self.db["known_spyware"]:
            score += 100
            findings.append("Known spyware package name match!")

        dump = self.device.shell(f"dumpsys package {package_name}")
        
        # Check Permissions
        for perm, weight in self.WEIGHTS.items():
            if perm in dump:
                score += weight
                findings.append(f"Permission/Service found: {perm}")

        # Check Installer
        installer = self.device.shell(f"pm list packages -i {package_name}")
        if "installer=null" in installer or "installer=adb" in installer:
            score += self.WEIGHTS["NON_STORE_INSTALLER"]
            findings.append("Sideloaded (Non-Store) installation")

        # Check if third-party
        is_third = False
        tp_list = self.device.shell(f"pm list packages -3 {package_name}")
        if package_name in tp_list:
            is_third = True

        # Clamp score
        score = min(score, 100)
        return {
            "package": package_name, 
            "score": score, 
            "findings": findings,
            "is_third_party": is_third
        }

    def analyze_apk_manifest(self, local_apk_path):
        """Analyzes a local APK's manifest using pyaxmlparser."""
        try:
            apk = APK(local_apk_path)
            score = 0
            findings = []
            
            perms = apk.get_permissions()
            for perm in perms:
                p_name = perm.split('.')[-1]
                if p_name in self.WEIGHTS:
                    score += self.WEIGHTS[p_name]
                    findings.append(f"Suspicious Permission: {p_name}")
            
            score = min(score, 100)
            return {"package": apk.package, "score": score, "findings": findings}
        except Exception as e:
            return {"package": "Unknown", "score": 0, "findings": [f"Error parsing: {str(e)}"]}

    def scan_storage_apks(self, path="/sdcard/"):
        files = self.device.shell(f"find {path} -name '*.apk'").splitlines()
        findings = []
        for apk_path in files:
            if not apk_path.strip(): continue
            findings.append({"path": apk_path, "type": "APK on storage"})
        return findings

    def monitor_network(self, interval=30):
        # Placeholder for netstat monitoring
        # In a real app, we'd diff netstat output before and after
        return "Network monitoring started..."

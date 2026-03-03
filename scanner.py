import os
import json
import time
import socket
import re
from adbutils import adb
from pyaxmlparser import APK

class SpywareScanner:
    def __init__(self, db_path="data/spyware_db.json"):
        self.db_path = db_path
        self.load_db()
        self.device = None
        self._uid_cache = {}
        
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

    def _get_label_for_uid(self, uid):
        """Maps UID to package name or human readable label."""
        try:
            # First get package name for UID using pm
            pkg = self.device.shell(f"pm list packages --uid {uid}").strip()
            if "package:" in pkg:
                pkg_name = pkg.split("package:")[1].split()[0]
                # Try to get label for package
                try:
                    res = self.device.shell(f"dumpsys package {pkg_name} | grep -i label")
                    match = re.search(r"label=(.+)", res)
                    if match: return f"{match.group(1).strip()} ({pkg_name})"
                except: pass
                return pkg_name
        except: pass
        return f"UID:{uid}"

    def _get_network_stats(self):
        """Returns map of UID -> {rx: bytes, tx: bytes}"""
        stats = {}
        try:
            # dumpsys netstats --uid provides historical/total stats per app
            output = self.device.shell("dumpsys netstats --uid")
            # Look for lines like: ident=[...] uid=10112 set=DEFAULT tag=0x0 rxBytes=1234 txBytes=5678 ...
            matches = re.findall(r"uid=(\d+) set=DEFAULT tag=0x0 .*? rxBytes=(\d+) txBytes=(\d+)", output)
            for uid, rx, tx in matches:
                uid = int(uid)
                if uid not in stats:
                    stats[uid] = {"rx": 0, "tx": 0}
                stats[uid]["rx"] += int(rx)
                stats[uid]["tx"] += int(tx)
        except Exception as e:
            print(f"Error fetching netstats: {e}")
        return stats

    def _get_active_connections(self):
        """Returns map of UID -> list of (RemoteIP, Port)"""
        connections = {}
        try:
            # Parse /proc/net/tcp and /proc/net/udp
            for proto in ["tcp", "udp"]:
                output = self.device.shell(f"cat /proc/net/{proto}")
                lines = output.splitlines()[1:] # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) < 8: continue
                    
                    remote_addr_hex = parts[2]
                    uid = int(parts[7])
                    
                    # Convert hex IP:Port to string
                    try:
                        ip_hex, port_hex = remote_addr_hex.split(':')
                        # IP is in little-endian hex
                        ip = socket.inet_ntoa(bytes.fromhex(ip_hex)[::-1])
                        port = int(port_hex, 16)
                        
                        if ip == "0.0.0.0" or ip == "127.0.0.1": continue
                        
                        if uid not in connections: connections[uid] = []
                        connections[uid].append((ip, port))
                    except: continue
        except Exception as e:
            print(f"Error fetching connections: {e}")
        return connections

    def monitor_network(self, duration=10, progress_callback=None, on_connection_found=None):
        """Monitors network traffic for a specific duration."""
        if not self.device: return []
        
        # 1. Get initial snapshots
        start_stats = self._get_network_stats()
        active_conn = {} # UID -> list of (IP, Port, Domain)
        uid_labels = {} # Cache for labels
        
        # 2. Wait/Monitor
        for i in range(duration):
            remaining = duration - i
            if progress_callback: 
                progress_callback(int((i+1)/duration * 100), remaining)
            
            # Update active connections periodically during monitoring
            new_conns = self._get_active_connections()
            for uid, conns in new_conns.items():
                if uid not in active_conn: active_conn[uid] = []
                
                if uid not in uid_labels:
                    uid_labels[uid] = self._get_label_for_uid(uid)
                
                label = uid_labels[uid]
                
                for ip, port in conns:
                    # Check if already seen
                    if any(c["ip"] == ip and c["port"] == port for c in active_conn[uid]):
                        continue
                        
                    # New connection!
                    domain = "Unknown"
                    try:
                        domain = socket.gethostbyaddr(ip)[0]
                    except: pass
                    
                    conn_info = {"ip": ip, "port": port, "domain": domain}
                    active_conn[uid].append(conn_info)
                    
                    # Live callback for immediate UI update
                    if on_connection_found:
                        on_connection_found({
                            "package": label,
                            "connection": conn_info
                        })
            
            time.sleep(1)

        # 3. Get final snapshot for volumes
        end_stats = self._get_network_stats()
        
        # 4. Compile final results
        # Union of all UIDs seen in stats OR connections
        all_uids = set(end_stats.keys()) | set(active_conn.keys())
        
        results = []
        for uid in all_uids:
            stats_end = end_stats.get(uid, {"rx": 0, "tx": 0})
            stats_start = start_stats.get(uid, {"rx": 0, "tx": 0})
            
            rx_delta = stats_end["rx"] - stats_start["rx"]
            tx_delta = stats_end["tx"] - stats_start["tx"]
            
            # Show if there was traffic OR active connections
            if rx_delta > 0 or tx_delta > 0 or uid in active_conn:
                label = uid_labels.get(uid) or self._get_label_for_uid(uid)
                results.append({
                    "package": label,
                    "upload": tx_delta,
                    "download": rx_delta,
                    "connections": active_conn.get(uid, [])
                })
        
        return results

import os
import shutil
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
        self._sig_cache = {} # Mapping of short signature ID or package name -> (SHA256, CN, ORG)
        self.tmp_dir = None
        
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
            self.db = {"known_spyware": [], "trusted_signatures": []}

    def get_temp_dir(self):
        """Centrally manage the .tmp folder for the current device."""
        if not self.device:
            return os.path.join(os.getcwd(), ".tmp", "no_device")
        
        serial = self.device.serial
        tmp = os.path.join(os.getcwd(), ".tmp", serial)
        if not os.path.exists(tmp):
            os.makedirs(tmp, exist_ok=True)
        return tmp

    def _get_signature(self, package_name):
        """Extracts signature fingerprint and DN info (CN/O) via dumpsys and optimized APK fallback."""
        if not self.device: return None, None, None
        
        # Method 1: Dumpsys Package (Fastest)
        dump = self.device.shell(f"dumpsys package {package_name}")
        
        # Extract Short Signature ID (Commonly found in signatures=[...])
        short_sig_match = re.search(r"signatures=\[([0-9A-Fa-f]+)\]", dump)
        short_id = short_sig_match.group(1) if short_sig_match else None
        
        # Check cache first!
        if short_id and short_id in self._sig_cache:
            return self._sig_cache[short_id]

        # Try to extract full Fingerprint (SHA-256) from dump if available
        fingerprints = re.findall(r"([0-9A-Fa-f]{64})", dump)
        sig = fingerprints[0].upper() if fingerprints else None
        
        # Extract DN (CN and Organization)
        cn_match = re.search(r"CN=([^,\]\n\r]+)", dump)
        org_match = re.search(r"O=([^,\]\n\r]+)", dump)
        cn = cn_match.group(1).strip() if cn_match else None
        org = org_match.group(1).strip() if org_match else None
        
        # METHOD 2: Robust Fallback (Signing Info or APK Pull)
        if not sig or not cn:
            try:
                # Type 2: Signing Info Dump (Fast)
                cert_dump = self.device.shell(f"dumpsys package {package_name} --signing-info")
                if "SHA-256" in cert_dump:
                    sig_match = re.search(r"SHA-256: ([0-9A-Fa-f:]{40,})", cert_dump)
                    if sig_match:
                        sig = sig_match.group(1).replace(":", "").upper()
                    
                    dn_match = re.search(r"Subject: (.+)", cert_dump)
                    if dn_match:
                        dn_str = dn_match.group(1)
                        cn_find = re.search(r"CN=([^, ]+)", dn_str)
                        org_find = re.search(r"O=([^, ]+)", dn_str)
                        cn = cn_find.group(1) if cn_find else cn
                        org = org_find.group(1) if org_find else org

                # Type 3: Final Fallback - One-time APK pull per Short ID
                if not sig or not cn:
                    path_dump = self.device.shell(f"pm path {package_name}")
                    lines = [l.strip().split("package:")[1].strip() for l in path_dump.splitlines() if "package:" in l]
                    if lines:
                        # Choose base.apk if split
                        apk_path = next((l for l in lines if "base.apk" in l), lines[0])
                        
                        # Robust directory detection using shell test
                        check_cmd = f"""
                        if [ -f '{apk_path}' ] || [ -f '{apk_path}/base.apk' ]; then
                            if [ -f '{apk_path}/base.apk' ]; then
                                echo "split|{apk_path}/base.apk"
                            else
                                echo "file|{apk_path}"
                            fi
                        else
                            echo "skip|{apk_path}"
                        fi
                        """
                        check_result = self.device.shell(check_cmd).strip().split('|')
                        if check_result[0] == "skip":
                            return None, None, "System Meta-Package (Directory)"
                        
                        actual_apk_path = check_result[1]

                        # Use centralized temp dir
                        tmp_dir = self.get_temp_dir()
                        tmp_apk = os.path.join(tmp_dir, f"{package_name}_{int(time.time())}.apk")
                        
                        try:
                            # Ensure clean state
                            if os.path.exists(tmp_apk):
                                if os.path.isdir(tmp_apk): shutil.rmtree(tmp_apk)
                                else: os.remove(tmp_apk)

                            self.device.sync.pull(actual_apk_path, tmp_apk)
                            if os.path.isfile(tmp_apk):
                                import subprocess
                                import shlex
                                
                                # Use configured apksigner path
                                apksigner_path = self.db.get("settings", {}).get("apksigner_path", "apksigner")
                                cmd = shlex.split(apksigner_path)
                                cmd.extend(["verify", "--print-certs", tmp_apk])
                                
                                try:
                                    proc = subprocess.run(cmd, capture_output=True, text=True)
                                    output = proc.stdout
                                except FileNotFoundError:
                                    print(f"Fallback extraction failed for {package_name}: Apksigner not found. Check path in settings.")
                                    return None, None, None
                                except Exception as e:
                                    print(f"Fallback extraction failed for {package_name}: {str(e)}")
                                    return None, None, None
                                
                                if "SHA-256 digest:" in output:
                                    sig_match = re.search(r"SHA-256 digest: ([0-9A-Fa-f]{64})", output)
                                    if sig_match:
                                        sig = sig_match.group(1).upper()
                                    
                                    dn_match = re.search(r"DN: (.+)", output)
                                    if dn_match:
                                        dn_str = dn_match.group(1)
                                        cn_f = re.search(r"CN=([^, ]+)", dn_str)
                                        org_f = re.search(r"O=([^, ]+)", dn_str)
                                        cn = cn_f.group(1).strip() if cn_f else cn
                                        org = org_f.group(1).strip() if org_f else org
                        finally:
                            if os.path.exists(tmp_apk):
                                if os.path.isdir(tmp_apk): shutil.rmtree(tmp_apk)
                                else: os.remove(tmp_apk)
            except Exception as e:
                print(f"Fallback extraction failed for {package_name}: {e}")

        # Update Cache (Check if we matched by package name or short ID)
        if short_id and sig:
            self._sig_cache[short_id] = (sig, cn, org)
        self._sig_cache[package_name] = (sig, cn, org)

        return sig, cn, org

    def verify_signature(self, package_name, actual_sig, cn=None, org=None, all_packages_sigs=None):
        """
        Multi-layered verification:
        1. Official Google DB
        2. User Trusted DB (CN/O/Fingerprint)
        3. Signature Grouping Heuristics
        """
        if not actual_sig:
            return 0, "No signature extracted"

        # LAYER 1: User-Defined Database (Signer Info)
        trusted_apps = self.db.get("trusted_signatures", [])
        
        name_matched = False
        matched_dev_name = None

        for app in trusted_apps:
            app_cn = app.get("common_name")
            app_sigs = app.get("fingerprint")
            
            if not app_sigs:
                continue

            # Support both single string and list of fingerprints
            if isinstance(app_sigs, str):
                app_sigs = [app_sigs]
            
            # 1. Check for PERFECT match (Fingerprint match)
            match_found = False
            for sig in app_sigs:
                if isinstance(sig, str) and actual_sig.strip().upper() == sig.strip().upper():
                    match_found = True
                    break
            
            if match_found:
                dev_name = cn if cn else (app_cn if app_cn else "Trusted Entity")
                return 0, f"Verified Signature ({dev_name})"

            # 2. Check for Name match (to detect fraud later)
            if cn and app_cn and isinstance(cn, str) and isinstance(app_cn, str):
                if cn.strip().lower() == app_cn.strip().lower():
                    name_matched = True
                    matched_dev_name = app_cn

        # If we reached here, no perfect fingerprint match was found in User DB.
        # Now check if it's an official Google package
        
        # LAYER 2: Official Google Database
        official_google = {
            "com.android.vending": "38918241690941A416D71336DCF69894BC10D12E6B39C6D3D3BA794C7650C2C3",
            "com.google.android.youtube": "AF12E208F322797C23B9B9A608035DB5D9D10DC9D8746D4916C82F2D1F50A949",
            "com.google.android.gms": "F0FD6C5B410F25CB25C3B53346C89729E293E3D34158F6343C8848C1421717E6",
        }
        
        if package_name in official_google:
            if actual_sig != official_google[package_name]:
                return 100, f"OFFICIAL GOOGLE MISMATCH! Fake/Modded app detected."
            return 0, "Verified Official Google App"

        # Now check if we had a name match (which means it's a fraud attempt against a user-trusted dev)
        if name_matched:
            return 90, f"SIGNATURE FRAUD! Developer {matched_dev_name} detected, but signature is WRONG."

        # LAYER 3: Signature Grouping Heuristics
        if all_packages_sigs:
            prefix = ".".join(package_name.split(".")[:2])
            group = [sig for pkg, sig in all_packages_sigs.items() if pkg.startswith(prefix) and sig]
            
            if len(group) > 3:
                from collections import Counter
                counts = Counter(group)
                dominant_sig, freq = counts.most_common(1)[0]
                
                if actual_sig != dominant_sig and freq > (len(group) / 2):
                    return 70, f"ANOMALOUS SIGNATURE! Outlier in {prefix} vendor group."

        return 0, None

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

    def prepare_batch_scan(self, package_names, progress_callback=None, max_workers=8):
        """Pre-pulls APKs and builds signature cache in batch with multithreading."""
        if not self.device: return
        self.is_running = True # Reset internal run state
        
        self.tmp_dir = self.get_temp_dir()

        # 1. Identify targets
        to_pull = [pkg for pkg in package_names if pkg not in self._sig_cache]
        total = len(to_pull)
        if total == 0: return

        from concurrent.futures import ThreadPoolExecutor, as_completed
        import shutil

        # Helper for pulling a single APK
        def pull_apk(pkg):
            try:
                local_path = os.path.join(self.tmp_dir, f"{pkg}.apk")
                
                # OPTIMIZATION: If APK already exists locally, skip shell and pulling!
                if os.path.exists(local_path) and not os.path.isdir(local_path):
                    if os.path.getsize(local_path) > 1024: # > 1KB as sanity check
                        return pkg

                path_dump = self.device.shell(f"pm path {pkg}")
                lines = [l.strip().split("package:")[1].strip() for l in path_dump.splitlines() if "package:" in l]
                if not lines: return None
                
                apk_path = next((l for l in lines if "base.apk" in l), lines[0])
                
                # Robust directory detection using shell test
                # Also ensure we only pull regular files, not directories or block devices
                check_cmd = f"""
                if [ -f '{apk_path}' ] || [ -f '{apk_path}/base.apk' ]; then
                    if [ -f '{apk_path}/base.apk' ]; then
                        echo "split|{apk_path}/base.apk"
                    else
                        echo "file|{apk_path}"
                    fi
                else
                    echo "skip|{apk_path}"
                fi
                """
                
                check_result = self.device.shell(check_cmd).strip().split('|')
                if check_result[0] == "skip":
                    return None
                    
                actual_apk_path = check_result[1]

                # Ensure local_path is NOT a directory from previous failed/interrupted runs
                if os.path.exists(local_path) and os.path.isdir(local_path):
                    shutil.rmtree(local_path)

                # Pull if still doesn't exist
                self.device.sync.pull(actual_apk_path, local_path)
                
                # FINAL VALIDATION: Must be a file and have APK magic bytes (PK..)
                if not os.path.isfile(local_path):
                    return None
                
                if os.path.getsize(local_path) < 100: # Too small to be APK
                    os.remove(local_path)
                    return None
                    
                with open(local_path, 'rb') as f:
                    header = f.read(4)
                    if header != b'PK\x03\x04': # Standard ZIP/APK header
                        os.remove(local_path)
                        return None
                    
                return pkg
            except Exception as e:
                print(f"DEBUG: Failed to pull {pkg}: {e}")
                if 'local_path' in locals() and os.path.exists(local_path):
                    try:
                        if os.path.isdir(local_path): shutil.rmtree(local_path)
                        else: os.remove(local_path)
                    except: pass
                return None

        # 2. Multithreaded Pulling Phase (Turbo)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(pull_apk, pkg): pkg for pkg in to_pull}
            completed = 0
            for future in as_completed(futures):
                if not self.is_running:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                completed += 1
                if progress_callback:
                    if progress_callback(completed, total, f"Pulling APK (Turbo): {futures[future]}") is False:
                        self.is_running = False
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

        # 3. Batch Process Signatures
        for i, pkg in enumerate(to_pull):
            if not self.is_running: break
            if progress_callback:
                if progress_callback(i + 1, total, f"Extracting Cert (apksigner): {pkg}") is False:
                    self.is_running = False
                    break
                
            local_path = os.path.join(self.tmp_dir, f"{pkg}.apk")
            if os.path.exists(local_path) and not os.path.isdir(local_path):
                try:
                    import subprocess
                    cmd = ["apksigner", "verify", "--print-certs", local_path]
                    proc = subprocess.run(cmd, capture_output=True, text=True)
                    output = proc.stdout
                    
                    if "SHA-256 digest:" in output:
                        sig_match = re.search(r"SHA-256 digest: ([0-9A-Fa-f]{64})", output)
                        dn_match = re.search(r"DN: (.+)", output)
                        
                        f_sig = sig_match.group(1).upper() if sig_match else None
                        f_cn, f_org = None, None
                        
                        if dn_match:
                            dn_str = dn_match.group(1)
                            cn_f = re.search(r"CN=([^, ]+)", dn_str)
                            org_f = re.search(r"O=([^, ]+)", dn_str)
                            f_cn = cn_f.group(1).strip() if cn_f else None
                            f_org = org_f.group(1).strip() if org_f else None
                        
                        if f_sig:
                            self._sig_cache[pkg] = (f_sig, f_cn, f_org)
                except Exception as e:
                    print(f"DEBUG: Failed to process cert for {pkg}: {e}")

    def cleanup_batch_scan(self):
        """No longer deletes persistent cache automatically (By User Request)."""
        pass

    def clear_local_cache(self):
        """Manually clears the entire staging cache."""
        tmp_root = os.path.join(os.getcwd(), ".tmp")
        if os.path.exists(tmp_root):
            import shutil
            try:
                shutil.rmtree(tmp_root)
                os.makedirs(tmp_root) # Recreate the root .tmp directory
                return True, "Cache cleared successfully."
            except Exception as e:
                return False, f"Failed to clear cache: {e}"
        return True, "Cache is already empty."

    def analyze_package(self, package_name):
        """Analyzes a package with a Trust-First approach and pre-built cache."""
        findings = []
        
        # 0. Basic Name Check
        if package_name in self.db.get("known_spyware", []):
            return {
                "package": package_name, "score": 100, "findings": ["Known spyware match!"],
                "is_third_party": True, "signature": "BLACK-LISTED", "signer": "Malicious"
            }

        # 1. SIGNATURE TRUST LAYER
        # Check cache (populated by prepare_batch_scan)
        sig, cn, org = self._sig_cache.get(package_name, (None, None, None))
        
        # If not in cache (e.g. was a directory or pull failed), try dumpsys
        if not sig:
            sig, cn, org = self._get_signature(package_name)

        sig_risk, sig_reason = self.verify_signature(package_name, sig, cn, org)
        
        # Check if trusted
        is_trusted = (sig_risk == 0 and sig_reason and ("Verified" in sig_reason or "Official" in sig_reason))

        # Fast third-party check
        is_third = package_name in self.device.shell(f"pm list packages -3 {package_name}")

        if is_trusted:
            return {
                "package": package_name, "score": 0, "findings": [f"TRUSTED: {sig_reason}"],
                "is_third_party": is_third, "signature": sig, "signer": cn if cn else (org if org else "Trusted Publisher")
            }

        # 2. AUDIT LAYER
        score = 0
        dump = self.device.shell(f"dumpsys package {package_name}")
        for perm, weight in self.WEIGHTS.items():
            if perm in dump:
                score += weight
                findings.append(f"Permission/Service found: {perm}")

        installer = self.device.shell(f"pm list packages -i {package_name}")
        if "installer=null" in installer or "installer=adb" in installer:
            score += self.WEIGHTS["NON_STORE_INSTALLER"]
            findings.append("Sideloaded (Non-Store) installation")

        if sig_risk > 0:
            score = max(score, sig_risk)
            findings.append(f"SIGNATURE ALERT: {sig_reason}")
        elif sig_reason:
             findings.append(f"Signature: {sig_reason}")

        return {
            "package": package_name, "score": min(score, 100), "findings": findings,
            "is_third_party": is_third, "signature": sig, "signer": cn if cn else (org if org else "Unknown")
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

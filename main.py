import sys
import os
import json
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox, QTableWidgetItem
from PyQt6.QtCore import QThread, pyqtSignal
from ui_components import MainWindow, RiskCard
from scanner import SpywareScanner
from report_gen import ReportGenerator

class ScanThread(QThread):
    progress = pyqtSignal(int)
    progress_with_time = pyqtSignal(int, int) # percent, remaining
    result_found = pyqtSignal(str, int, list, bool)
    connection_found = pyqtSignal(dict) # new connection found
    finished_scan = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, scanner, mode="apps", max_workers=8):
        super().__init__()
        self.scanner = scanner
        self.mode = mode
        self.max_workers = max_workers
        self.all_results = []
        self.is_running = True

    def stop(self):
        self.is_running = False

    def run(self):
        try:
            if self.mode == "apps":
                packages = self.scanner.get_installed_packages()
                total = len(packages)
                
                # Use a ThreadPoolExecutor for concurrent analysis
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {executor.submit(self.scanner.analyze_package, pkg): pkg for pkg in packages}
                    
                    for i, future in enumerate(as_completed(futures)):
                        if not self.is_running:
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                        
                        try:
                            res = future.result()
                            if res["score"] > 10:
                                self.result_found.emit(res["package"], res["score"], res["findings"], res["is_third_party"])
                                self.all_results.append(res)
                        except Exception as e:
                            print(f"Error analyzing package: {e}")
                            
                        self.progress.emit(int((i + 1) / total * 100))
                        self.progress_info.emit(i + 1, total)
            
            elif self.mode == "storage":
                findings = self.scanner.scan_storage_apks()
                total = len(findings)
                for i, f in enumerate(findings):
                    if not self.is_running: break
                    self.result_found.emit(f["path"], 50, [f["type"]], True)
                    self.all_results.append({"package": f["path"], "score": 50, "findings": [f["type"]], "is_third_party": True})
                    self.progress.emit(int((i + 1) / total * 100))
            
            elif self.mode == "network":
                # scanner.monitor_network returns a list of result dicts
                results = self.scanner.monitor_network(
                    duration=self.max_workers, 
                    progress_callback=lambda p, r: self.progress_with_time.emit(p, r),
                    on_connection_found=lambda c: self.connection_found.emit(c)
                )
                self.all_results = results
            
            self.finished_scan.emit(self.all_results)
        except Exception as e:
            self.error.emit(str(e))

class AntiShinobiApp:
    def __init__(self):
        self.app = QApplication(sys.argv)
        try:
            self.app.setStyle("Fusion")
        except:
            pass
            
        self.window = MainWindow()
        self.scanner = SpywareScanner()
        self.last_results = []
        self.device_map = {} # label -> serial
        self.current_device_serial = None
        self.current_device_label = "NONE"
        self.current_stats = {"safe": 0, "warn": 0, "crit": 0}
        self.is_scanning = False
        
        # Connect Signals
        self.window.btn_refresh_devices.clicked.connect(self.refresh_devices)
        self.window.device_combo.currentIndexChanged.connect(self.on_device_selected)
        self.window.scan_action_btn.clicked.connect(self.start_scan)
        self.window.btn_sort_risk.clicked.connect(self.window.show_sort_menu)
        self.window.filter_tp.stateChanged.connect(self.on_filter_changed)
        self.window.btn_float_pdf.clicked.connect(lambda: self.export_report("pdf"))
        self.window.btn_float_ods.clicked.connect(lambda: self.export_report("ods"))
        
        # Scan Settings
        self.window.thread_spin.valueChanged.connect(self.on_thread_changed)
        
        # Network Connections
        self.window.btn_start_network.clicked.connect(self.start_network_monitor)
        
        # Package DB Connections
        self.window.btn_db_add.clicked.connect(self.add_db_package)
        self.window.btn_db_delete.clicked.connect(self.delete_db_package)
        self.window.btn_db_save.clicked.connect(self.save_db_json)
        self.load_db_json()
        
        self.refresh_devices()
        self.window.show()

    def start_network_monitor(self):
        if not self.scanner.get_devices():
            QMessageBox.warning(self.window, "No Device", "Please connect a device first.")
            return
            
        self.window.net_table.setRowCount(0)
        self.window.btn_start_network.setEnabled(False)
        self.window.btn_start_network.setText("MONITORING...")
        self.window.net_status_label.setText("Preparing monitor...")
        self.window.net_status_label.setVisible(True)
        
        duration = self.window.net_duration_spin.value()
        self.thread = ScanThread(self.scanner, mode="network", max_workers=duration)
        self.thread.progress.connect(self.window.progress.setValue)
        self.thread.progress_with_time.connect(self.update_net_progress)
        self.thread.connection_found.connect(self.on_net_connection_found)
        self.thread.finished_scan.connect(self.update_network_results)
        self.thread.start()

    def update_net_progress(self, percent, remaining):
        self.window.progress.setValue(percent)
        self.window.net_status_label.setText(f"Monitoring: {remaining}s remaining")

    def on_net_connection_found(self, data):
        # Data contains {package, connection: {ip, port, domain}}
        row = self.window.net_table.rowCount()
        # Check if package already exists to group or just append
        # For real-time, we append new connections
        self.window.net_table.insertRow(row)
        self.window.net_table.setItem(row, 0, QTableWidgetItem(data["package"]))
        self.window.net_table.setItem(row, 1, QTableWidgetItem("...")) # Volumes come later
        self.window.net_table.setItem(row, 2, QTableWidgetItem("..."))
        self.window.net_table.setItem(row, 3, QTableWidgetItem(f"{data['connection']['ip']}:{data['connection']['port']}"))
        self.window.net_table.setItem(row, 4, QTableWidgetItem(data["connection"]["domain"]))

    def update_network_results(self, results):
        self.window.btn_start_network.setEnabled(True)
        self.window.btn_start_network.setText("START MONITORING")
        self.window.net_status_label.setVisible(False)
        self.window.progress.setValue(0)
        
        # Redraw table to include volumes (clearing partial entries)
        self.window.net_table.setRowCount(0)
        self.window.net_table.setRowCount(len(results))
        for row, res in enumerate(results):
            self.window.net_table.setItem(row, 0, QTableWidgetItem(res["package"]))
            self.window.net_table.setItem(row, 1, QTableWidgetItem(f"{res['upload'] / 1024:.2f} KB"))
            self.window.net_table.setItem(row, 2, QTableWidgetItem(f"{res['download'] / 1024:.2f} KB"))
            
            # Connection List
            conns = res.get("connections", [])
            ips = ", ".join([f"{c['ip']}:{c['port']}" for c in conns]) if conns else "None"
            domains = ", ".join([c['domain'] for c in conns if c['domain'] != "Unknown"]) if conns else "None"
            
            self.window.net_table.setItem(row, 3, QTableWidgetItem(ips))
            self.window.net_table.setItem(row, 4, QTableWidgetItem(domains or "None"))

    def refresh_devices(self):
        self.window.device_combo.clear()
        self.window.device_combo.addItem("-- Please Select Device --")
        self.device_map = {}
        devices = self.scanner.get_devices()
        for d in devices:
            self.window.device_combo.addItem(d["label"])
            self.device_map[d["label"]] = d["serial"]
        
        self.window.device_combo.setCurrentIndex(0)
            
        if not devices:
            self.window.device_status.setText("Status: No devices connected")
            self.window.device_app_count.setText("Installed Apps: --")
            self.current_device_serial = None
            self.window.selected_device_label.setText("NO DEVICE SELECTED")

    def on_device_selected(self):
        label = self.window.device_combo.currentText()
        serial = self.device_map.get(label)
        if serial:
            self.current_device_serial = serial
            self.current_device_label = label
            self.scanner.set_device(serial)
            self.window.selected_device_label.setText(label.upper())
            self.window.device_status.setText("Status: Connected & Ready")
            
            # Fetch app count
            try:
                packages = self.scanner.get_installed_packages()
                count = len(packages)
                self.window.device_app_count.setText(f"Installed Apps: {count}")
                self.window.stat_total.setText(str(count))
            except:
                self.window.device_app_count.setText("Installed Apps: Error fetching")
        else:
            self.current_device_serial = None
            self.window.selected_device_label.setText("NO DEVICE SELECTED")
            self.window.device_status.setText("Status: Please Select a Device")
            self.window.device_app_count.setText("Installed Apps: --")
            self.window.stat_total.setText("0")

    def start_scan(self):
        if not self.current_device_serial:
            QMessageBox.warning(self.window, "Error", "Please select a device on the Dashboard first!")
            self.window.btn_dashboard.click()
            return

        if self.is_scanning:
            self.thread.stop()
            self.window.scan_action_btn.setText("ANALYZE APPS")
            self.is_scanning = False
            return

        self.window.clear_results()
        self.window.progress.setVisible(True)
        self.window.scan_action_btn.setText("STOP ANALYZE")
        self.is_scanning = True
        
        self.current_stats = {"safe": 0, "warn": 0, "crit": 0}
        self.window.stat_safe.setText("0")
        self.window.stat_warn.setText("0")
        self.window.stat_crit.setText("0")
        self.window.filter_tp.setVisible(False)
        self.window.export_float_container.setVisible(False)
        
        mode = "apps"
        if "STORAGE" in self.window.scan_action_btn.text(): mode = "storage"
        
        threads = self.window.thread_spin.value()
        self.thread = ScanThread(self.scanner, mode=mode, max_workers=threads)
        self.thread.progress.connect(self.window.progress.setValue)
        self.thread.progress_info.connect(self.update_progress_info)
        self.thread.result_found.connect(self.add_and_update_stats)
        self.thread.finished_scan.connect(self.on_finished)
        self.thread.error.connect(self.on_error)
        self.thread.start()

    def add_and_update_stats(self, package, score, findings, is_tp):
        self.window.add_result(package, score, findings, is_tp)
        if score >= 70:
            self.current_stats["crit"] += 1
            self.window.stat_crit.setText(str(self.current_stats["crit"]))
        elif score > 20:
            self.current_stats["warn"] += 1
            self.window.stat_warn.setText(str(self.current_stats["warn"]))
        else:
            self.current_stats["safe"] += 1
            self.window.stat_safe.setText(str(self.current_stats["safe"]))

    def update_progress_info(self, current, total):
        self.window.scan_progress_label.setText(f"Scanning {current} of {total} applications...")

    def on_finished(self, results):
        self.last_results = results
        self.window.scan_action_btn.setText("ANALYZE APPS")
        self.is_scanning = False
        self.window.progress.setVisible(False)
        self.window.sort_results()
        
        # Show options
        self.window.filter_tp.setVisible(True)
        self.window.export_float_container.setVisible(True)
        
        # Trigger layout refresh for float buttons
        self.window.export_float_container.adjustSize()
        x = self.window.results_area_container.width() - self.window.export_float_container.width() - 20
        y = self.window.results_area_container.height() - self.window.export_float_container.height() - 20
        self.window.export_float_container.move(x, y)
        
        self.window.scan_progress_label.setText(f"Scan Finished. {len(results)} potential threats identified.")

    def on_filter_changed(self, state):
        only_tp = state == 2 # Qt.CheckState.Checked
        for i in range(self.window.results_layout.count()):
            item = self.window.results_layout.itemAt(i)
            if item and item.widget() and isinstance(item.widget(), RiskCard):
                card = item.widget()
                if only_tp:
                    card.setVisible(card.is_third_party)
                else:
                    card.setVisible(True)

    def on_error(self, message):
        self.window.scan_action_btn.setEnabled(True)
        self.window.progress.setVisible(False)
        QMessageBox.critical(self.window, "Scan Error", f"An error occurred: {message}")

    def export_report(self, format="pdf"):
        # Collect results from visible cards in layout to respect filter and sort order
        export_results = []
        for i in range(self.window.results_layout.count()):
            item = self.window.results_layout.itemAt(i)
            if item and item.widget() and isinstance(item.widget(), RiskCard):
                card = item.widget()
                if card.isVisible():
                    export_results.append({
                        "package": card.title,
                        "score": card.score,
                        "findings": card.findings,
                        "is_third_party": card.is_third_party
                    })

        if not export_results:
            QMessageBox.warning(self.window, "Export Error", "No visible scan results to export!")
            return
            
        file_filter = "PDF document (*.pdf)" if format == "pdf" else "OpenDocument Spreadsheet (*.ods)"
        path, _ = QFileDialog.getSaveFileName(self.window, "Export Report", "", file_filter)
        
        if path:
            # Auto-append extension if missing
            ext = f".{format}"
            if not path.lower().endswith(ext):
                path += ext
                
            try:
                gen = ReportGenerator()
                if format == "pdf":
                    gen.export_pdf(export_results, path, self.current_device_label)
                else:
                    gen.export_ods(export_results, path, self.current_device_label)
                QMessageBox.information(self.window, "Success", f"Report exported successfully to {path}")
            except Exception as e:
                QMessageBox.critical(self.window, "Export Error", f"Failed to export report: {str(e)}")

    def on_thread_changed(self, value):
        self.window.thread_warning.setVisible(value > 10)

    def load_db_json(self):
        db_path = "data/spyware_db.json"
        if not os.path.exists(db_path): return
        
        try:
            with open(db_path, "r") as f:
                data = json.load(f)
                packages = data.get("known_spyware", [])
                
            self.window.db_table.setRowCount(0)
            for pkg in packages:
                row = self.window.db_table.rowCount()
                self.window.db_table.insertRow(row)
                self.window.db_table.setItem(row, 0, QTableWidgetItem(pkg))
            self.scanner.blacklist = set(packages) # Update scanner's blacklist
        except Exception as e:
            QMessageBox.critical(self.window, "DB Error", f"Failed to load database: {str(e)}")

    def add_db_package(self):
        row = self.window.db_table.rowCount()
        self.window.db_table.insertRow(row)
        item = QTableWidgetItem("com.example.package")
        self.window.db_table.setItem(row, 0, item)
        self.window.db_table.editItem(item)

    def delete_db_package(self):
        current_row = self.window.db_table.currentRow()
        if current_row >= 0:
            self.window.db_table.removeRow(current_row)

    def save_db_json(self):
        db_path = "data/spyware_db.json"
        packages = []
        for i in range(self.window.db_table.rowCount()):
            item = self.window.db_table.item(i, 0)
            if item and item.text().strip():
                packages.append(item.text().strip())
        
        try:
            # Ensure the data directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            with open(db_path, "w") as f:
                json.dump({"known_spyware": packages}, f, indent=4)
            QMessageBox.information(self.window, "Success", "Package database saved successfully.")
            # Refresh scanner blacklist
            self.scanner.blacklist = set(packages)
        except Exception as e:
            QMessageBox.critical(self.window, "DB Error", f"Failed to save database: {str(e)}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = AntiShinobiApp()
    sys.exit(app.app.exec())

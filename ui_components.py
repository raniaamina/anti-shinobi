from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLabel, QListWidget, QProgressBar, 
                             QFrame, QScrollArea, QStackedWidget, QComboBox,
                             QFileDialog, QMessageBox, QMenu, QCheckBox,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QSpinBox)
from PyQt6.QtCore import Qt, pyqtSignal, QSize
from PyQt6.QtGui import QIcon
from qt_material import apply_stylesheet

class NavButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setFixedHeight(50)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            NavButton {
                text-align: left;
                padding-left: 20px;
                border: none;
                font-size: 14px;
                background-color: transparent;
                color: #FFFFFF;
            }
            NavButton:hover {
                background-color: #3D3D3D;
                color: #50C878;
            }
            NavButton:checked {
                background-color: #1E1E1E;
                color: #50C878;
                font-weight: bold;
                border-left: 4px solid #50C878;
            }
        """)

class RiskCard(QFrame):
    def __init__(self, title, score, findings, is_third_party=False, parent=None):
        super().__init__(parent)
        self.title = title
        self.score = score
        self.findings = findings
        self.is_third_party = is_third_party
        self.is_expanded = False
        
        self.setFrameShape(QFrame.Shape.StyledPanel)
        border_color = self.get_color(score)
        self.setStyleSheet(f"""
            RiskCard {{
                background-color: #1A1A1A;
                border: 1px solid #333333;
                border-left: 5px solid {border_color};
                border-radius: 6px;
                margin-bottom: 5px;
            }}
            RiskCard:hover {{
                border: 1px solid #444444;
                border-left: 5px solid {border_color};
                background-color: #222222;
            }}
        """)
        
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(15, 10, 15, 10)
        self.main_layout.setSpacing(0)
        
        # Header Row
        header = QHBoxLayout()
        header.setSpacing(15)
        
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #FFFFFF; border: none;")
        
        self.score_badge = QLabel(f"{score}% RISK")
        self.score_badge.setFixedWidth(80)
        self.score_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.score_badge.setStyleSheet(f"""
            QLabel {{
                background-color: {border_color}; 
                color: {"#FFFFFF" if score >= 50 else "#000000"}; 
                font-weight: bold; 
                font-size: 11px; 
                padding: 4px; 
                border-radius: 4px;
            }}
        """)
        
        self.toggle_btn = QPushButton("▼")
        self.toggle_btn.setFixedSize(24, 24)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #FFFFFF;
                border-radius: 4px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                background-color: #444444;
            }
        """)
        self.toggle_btn.clicked.connect(self.toggle_expand)
        
        header.addWidget(self.title_label)
        header.addStretch()
        header.addWidget(self.score_badge)
        header.addWidget(self.toggle_btn)
        
        self.main_layout.addLayout(header)
        
        # Expandable Content
        self.findings_container = QWidget()
        self.findings_layout = QVBoxLayout(self.findings_container)
        self.findings_layout.setContentsMargins(25, 10, 0, 5)
        self.findings_layout.setSpacing(5)
        
        for f in findings:
            f_label = QLabel(f"• {f}")
            f_label.setStyleSheet("color: #AAAAAA; font-size: 12px; border: none;")
            f_label.setWordWrap(True)
            self.findings_layout.addWidget(f_label)
            
        self.findings_container.setVisible(False)
        self.main_layout.addWidget(self.findings_container)
    
    def toggle_expand(self):
        self.is_expanded = not self.is_expanded
        self.findings_container.setVisible(self.is_expanded)
        self.toggle_btn.setText("▲" if self.is_expanded else "▼")

    def get_color(self, score):
        if score >= 90: return "#FF0000" # Pure Red
        if score >= 70: return "#FF4B4B" # Red
        if score >= 40: return "#FFA500" # Orange
        if score > 20: return "#FFFF00"  # Yellow
        return "#50C878" # Green

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Anti-Shinobi - Mobile Security & Analysis")
        self.setWindowIcon(QIcon("resources/icon.png"))
        self.setMinimumSize(1000, 700)
        
        apply_stylesheet(self, theme='dark_teal.xml')
        
        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.main_layout = QHBoxLayout(central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Sidebar
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(220)
        self.sidebar.setStyleSheet("background-color: #1E1E1E; border-right: 1px solid #333333;")
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(0, 20, 0, 20)

        self.logo = QLabel("ANTI-SHINOBI")
        self.logo.setStyleSheet("color: #50C878; font-size: 20px; font-weight: bold; margin-bottom: 20px; padding-left: 20px;")
        self.sidebar_layout.addWidget(self.logo)

        self.btn_dashboard = NavButton("Dashboard")
        self.btn_apps = NavButton("App Scanner")
        self.btn_network = NavButton("Network Monitor")
        self.btn_storage = NavButton("Storage Scan")
        self.btn_db = NavButton("Package DB")
        self.btn_heuristics = NavButton("Risk Heuristics")
        
        self.nav_group = [self.btn_dashboard, self.btn_apps, self.btn_network, 
                          self.btn_storage, self.btn_db, self.btn_heuristics]
        for btn in self.nav_group:
            self.sidebar_layout.addWidget(btn)
            btn.clicked.connect(self.switch_tab)

        self.sidebar_layout.addStretch()
        
        self.main_layout.addWidget(self.sidebar)

        # Content Area
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)
        self.main_layout.addWidget(self.content)

        # Stacked Widget for Pages
        self.pages = QStackedWidget()
        self.content_layout.addWidget(self.pages)

        # Global Progress Bar (Bottom)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: #1A1A1A;
                border: none;
            }
            QProgressBar::chunk {
                background-color: #50C878;
            }
        """)
        self.content_layout.addWidget(self.progress)

        # Initialize Pages
        self.init_dashboard() # Index 0
        self.init_scanner_page() # Index 1
        self.init_placeholder_page("NETWORK MONITOR", "Monitor real-time network traffic from your device.") # Index 2
        self.init_placeholder_page("STORAGE SCAN", "Identify risky APK files stored on your phone.") # Index 3
        self.init_db_page() # Index 4
        self.init_heuristics_page() # Index 5
        
        self.btn_dashboard.setChecked(True)

    def init_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        
        title = QLabel("DEVICE SELECTION")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white; margin-bottom: 30px;")
        layout.addWidget(title)
        
        # Device Selector in Dashboard
        selector_frame = QFrame()
        selector_frame.setObjectName("SelectorFrame")
        selector_frame.setStyleSheet("""
            #SelectorFrame {
                background-color: #1A1A1A; 
                border-radius: 12px; 
                border: 1px solid #333333; 
                padding: 20px;
            }
            QLabel { border: none; background: transparent; }
        """)
        selector_layout = QVBoxLayout(selector_frame)
        
        combo_label = QLabel("SELECT ACTIVE DEVICE")
        combo_label.setStyleSheet("color: #666666; font-size: 11px; font-weight: bold; letter-spacing: 1px;")
        selector_layout.addWidget(combo_label)
        
        self.device_combo = QComboBox()
        self.device_combo.setFixedHeight(50)
        self.device_combo.setStyleSheet("""
            QComboBox {
                background-color: #2D2D2D;
                border: 1px solid #444444;
                border-radius: 6px;
                padding: 10px;
                color: #FFFFFF;
                font-size: 14px;
            }
            QComboBox QAbstractItemView {
                background-color: #2D2D2D;
                color: #FFFFFF;
                selection-background-color: #50C878;
                selection-color: #000000;
            }
        """)
        selector_layout.addWidget(self.device_combo)
        
        self.btn_refresh_devices = QPushButton("REFRESH CONNECTIONS")
        self.btn_refresh_devices.setFixedHeight(45)
        self.btn_refresh_devices.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh_devices.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #50C878;
                color: #50C878;
                border-radius: 6px;
                margin-top: 10px;
                font-weight: bold;
                padding: 5px 15px;
            }
            QPushButton:hover { background-color: #50C878; color: black; }
        """)
        selector_layout.addWidget(self.btn_refresh_devices)
        layout.addWidget(selector_frame)
        
        # Device Stats
        self.stats_frame = QFrame()
        self.stats_frame.setObjectName("StatsFrame")
        self.stats_frame.setStyleSheet("""
            #StatsFrame {
                background-color: #1A1A1A; 
                border-radius: 12px; 
                border: 1px solid #333333; 
                margin-top: 20px; 
                padding: 20px;
            }
            QLabel { border: none; background: transparent; }
        """)
        stats_layout = QVBoxLayout(self.stats_frame)
        
        self.device_app_count = QLabel("Installed Apps: --")
        self.device_app_count.setStyleSheet("font-size: 16px; color: #FFFFFF;")
        stats_layout.addWidget(self.device_app_count)
        
        self.device_status = QLabel("Status: Unknown")
        self.device_status.setStyleSheet("font-size: 16px; color: #888888;")
        stats_layout.addWidget(self.device_status)
        
        layout.addWidget(self.stats_frame)
        
        # Scan Settings Card (NEW)
        self.settings_frame = QFrame()
        self.settings_frame.setObjectName("SettingsFrame")
        self.settings_frame.setStyleSheet("""
            #SettingsFrame {
                background-color: #1A1A1A; 
                border-radius: 12px; 
                border: 1px solid #333333; 
                margin-top: 20px; 
                padding: 20px;
            }
            QLabel { border: none; background: transparent; }
        """)
        settings_layout = QVBoxLayout(self.settings_frame)
        
        settings_title = QLabel("SCAN SETTINGS")
        settings_title.setStyleSheet("color: #666666; font-size: 11px; font-weight: bold; letter-spacing: 1px;")
        settings_layout.addWidget(settings_title)
        
        thread_layout = QHBoxLayout()
        thread_label = QLabel("Parallel Processing Threads")
        thread_label.setStyleSheet("color: #FFFFFF; font-size: 14px;")
        thread_layout.addWidget(thread_label)
        
        self.thread_spin = QSpinBox()
        self.thread_spin.setRange(1, 20)
        self.thread_spin.setValue(8)
        self.thread_spin.setFixedWidth(80)
        self.thread_spin.setFixedHeight(35)
        self.thread_spin.setStyleSheet("""
            QSpinBox {
                background-color: #2D2D2D;
                border: 1px solid #444444;
                border-radius: 4px;
                color: white;
                padding: 5px;
            }
        """)
        thread_layout.addWidget(self.thread_spin)
        settings_layout.addLayout(thread_layout)
        
        self.thread_warning = QLabel("⚠️ High thread count! Ensure high-quality USB cable and device stability.")
        self.thread_warning.setWordWrap(True)
        self.thread_warning.setStyleSheet("color: #FF4B4B; font-size: 11px; font-weight: bold; margin-top: 5px;")
        self.thread_warning.setVisible(False)
        settings_layout.addWidget(self.thread_warning)
        
        layout.addWidget(self.settings_frame)
        layout.addStretch()
        self.pages.addWidget(page)

    def init_scanner_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 20, 30, 0)
        
        # Header Area
        header = QHBoxLayout()
        self.selected_device_label = QLabel("NO DEVICE SELECTED")
        self.selected_device_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #FFFFFF;")
        
        self.scan_action_btn = QPushButton("ANALYZE APPS")
        self.scan_action_btn.setFixedSize(140, 35)
        self.scan_action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_action_btn.setStyleSheet("""
            QPushButton {
                background-color: #50C878; color: black; font-weight: bold; border-radius: 4px; font-size: 11px;
            }
            QPushButton:hover { background-color: #45B068; }
        """)
        
        self.btn_sort_risk = QPushButton("SORT")
        self.btn_sort_risk.setFixedSize(70, 35)
        self.btn_sort_risk.setStyleSheet("background-color: #333; color: white; border-radius: 4px; font-size: 10px;")
        
        header.addWidget(self.selected_device_label)
        header.addStretch()
        header.addWidget(self.btn_sort_risk)
        header.addWidget(self.scan_action_btn)
        layout.addLayout(header)
        self.btn_sort_risk.clicked.connect(self.show_sort_menu)

        # Stats Row (Individual Cards)
        self.stats_row = QHBoxLayout()
        self.stats_row.setSpacing(10)
        
        def create_stat_card(label, color):
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #1A1A1A;
                    border: 1px solid #333333;
                    border-radius: 8px;
                }}
                QLabel {{ border: none; background: transparent; }}
            """)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(10, 15, 10, 15)
            card_layout.setSpacing(5)
            
            val = QLabel("0")
            val.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
            val.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            lbl = QLabel(label)
            lbl.setStyleSheet("font-size: 10px; color: #666666; font-weight: bold;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(val)
            card_layout.addWidget(lbl)
            return card, val

        c_total, self.stat_total = create_stat_card("TOTAL APPS", "#FFFFFF")
        c_safe, self.stat_safe = create_stat_card("SAFE", "#50C878")
        c_warn, self.stat_warn = create_stat_card("POTENTIAL", "#FFFF00")
        c_crit, self.stat_crit = create_stat_card("CRITICAL", "#FF0000")
        
        self.stats_row.addWidget(c_total)
        self.stats_row.addWidget(c_safe)
        self.stats_row.addWidget(c_warn)
        self.stats_row.addWidget(c_crit)
        layout.addLayout(self.stats_row)

        self.scan_progress_label = QLabel("")
        self.scan_progress_label.setStyleSheet("color: #AAAAAA; font-size: 12px; margin-top: 15px; margin-bottom: 5px;")
        
        self.filter_tp = QCheckBox("Show 3rd Party Only")
        self.filter_tp.setStyleSheet("color: #888888; font-size: 11px;")
        self.filter_tp.setVisible(False)
        
        progress_row = QHBoxLayout()
        progress_row.addWidget(self.scan_progress_label)
        progress_row.addStretch()
        progress_row.addWidget(self.filter_tp)
        layout.addLayout(progress_row)

        # Results Area
        self.results_area_container = QWidget()
        res_container_layout = QVBoxLayout(self.results_area_container)
        res_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("background-color: transparent; border: none;")
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setContentsMargins(0, 0, 5, 0)
        self.results_layout.setSpacing(2)
        self.results_layout.addStretch()
        self.scroll.setWidget(self.results_container)
        res_container_layout.addWidget(self.scroll)
        
        # Floating Export Layout (Container)
        self.export_float_container = QWidget(self.results_area_container)
        export_layout = QHBoxLayout(self.export_float_container)
        export_layout.setSpacing(10)
        
        self.btn_float_pdf = QPushButton("PDF")
        self.btn_float_ods = QPushButton("ODS")
        for b in [self.btn_float_pdf, self.btn_float_ods]:
            b.setFixedSize(50, 50)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setStyleSheet("""
                QPushButton {
                    background-color: #50C878; color: black; font-weight: bold; border-radius: 25px; 
                    border: none; font-size: 10px;
                }
                QPushButton:hover { background-color: #45B068; }
            """)
        
        export_layout.addWidget(self.btn_float_pdf)
        export_layout.addWidget(self.btn_float_ods)
        self.export_float_container.setVisible(False)
        
        layout.addWidget(self.results_area_container)
        self.pages.addWidget(page)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Position floating exports at bottom right of results area
        if hasattr(self, 'export_float_container') and self.export_float_container.isVisible():
            x = self.results_area_container.width() - self.export_float_container.width() - 20
            y = self.results_area_container.height() - self.export_float_container.height() - 20
            self.export_float_container.move(x, y)

    def switch_tab(self):
        sender = self.sender()
        if not sender: return
        
        for btn in self.nav_group:
            btn.setChecked(btn == sender)
        
        index = self.nav_group.index(sender)
        self.pages.setCurrentIndex(index)
        
        # Update scan button text and visibility based on tab
        labels = ["", "ANALYZE APPS", "START MONITOR", "START STORAGE SCAN", "", ""]
        txt = labels[index]
        self.scan_action_btn.setText(txt)
        self.scan_action_btn.setVisible(txt != "")
    def add_result(self, package_name, score, findings, is_third_party=False):
        card = RiskCard(package_name, score, findings, is_third_party)
        self.results_layout.insertWidget(self.results_layout.count() - 1, card)

    def clear_results(self):
        while self.results_layout.count() > 1:
            item = self.results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def sort_results(self):
        self.perform_sort("risk", True)

    def show_sort_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet("background-color: #2D2D2D; color: white;")
        
        a_risk_desc = menu.addAction("Risk: Highest First")
        a_risk_asc = menu.addAction("Risk: Lowest First")
        menu.addSeparator()
        a_name_asc = menu.addAction("Name: A to Z")
        a_name_desc = menu.addAction("Name: Z to A")
        
        action = menu.exec(self.btn_sort_risk.mapToGlobal(self.btn_sort_risk.rect().bottomLeft()))
        
        if action == a_risk_desc: self.perform_sort("risk", True)
        elif action == a_risk_asc: self.perform_sort("risk", False)
        elif action == a_name_asc: self.perform_sort("name", False)
        elif action == a_name_desc: self.perform_sort("name", True)

    def perform_sort(self, criteria, descending):
        cards = []
        for i in range(self.results_layout.count()):
            item = self.results_layout.itemAt(i)
            if item and item.widget() and isinstance(item.widget(), RiskCard):
                cards.append(item.widget())
        
        if criteria == "risk":
            cards.sort(key=lambda x: x.score, reverse=descending)
        elif criteria == "name":
            cards.sort(key=lambda x: x.title.lower(), reverse=descending)
        
        # Re-insert into layout
        for i, card in enumerate(cards):
            self.results_layout.insertWidget(i, card)
    def init_heuristics_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        title = QLabel("RISK SCORING HEURISTICS")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #50C878;")
        layout.addWidget(title)
        
        desc = QLabel("Transparency on how we calculate risk scores based on permissions, architecture, and installation source.")
        desc.setStyleSheet("color: #AAAAAA; font-size: 14px;")
        layout.addWidget(desc)
        
        # Table
        self.heuristic_table = QTableWidget()
        self.heuristic_table.setColumnCount(2)
        self.heuristic_table.setHorizontalHeaderLabels(["Permission / Service / Activity", "Risk Weight"])
        self.heuristic_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.heuristic_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.heuristic_table.setColumnWidth(1, 150)
        self.heuristic_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.heuristic_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.heuristic_table.verticalHeader().setVisible(False)
        self.heuristic_table.setShowGrid(False)
        
        self.heuristic_table.setStyleSheet("""
            QTableWidget {
                background-color: #1A1A1A;
                color: #FFFFFF;
                border: 1px solid #333333;
                gridline-color: transparent;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #2D2D2D;
                color: #50C878;
                padding: 10px;
                border: none;
                font-weight: bold;
                border-bottom: 2px solid #50C878;
            }
            QTableWidget::item {
                padding: 15px;
                border-bottom: 1px solid #2D2D2D;
            }
        """)
        
        # Data
        weights = {
            "BIND_NOTIFICATION_LISTENER_SERVICE": 25,
            "SYSTEM_ALERT_WINDOW": 25,
            "ACCESS_BACKGROUND_LOCATION": 25,
            "RECORD_AUDIO": 15,
            "CAMERA": 15,
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 15,
            "RECEIVE_BOOT_COMPLETED": 10,
            "FOREGROUND_SERVICE": 10,
            "NON_STORE_INSTALLER": 10,
            "HIDDEN_ICON": 15,
            "KNOWN_SPYWARE_MATCH": 100
        }
        
        self.heuristic_table.setRowCount(len(weights))
        for row, (perm, weight) in enumerate(weights.items()):
            name_item = QTableWidgetItem(perm)
            weight_item = QTableWidgetItem(f"+ {weight}")
            weight_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            if weight >= 25: weight_item.setForeground(Qt.GlobalColor.red)
            elif weight >= 15: weight_item.setForeground(Qt.GlobalColor.yellow)
            
            self.heuristic_table.setItem(row, 0, name_item)
            self.heuristic_table.setItem(row, 1, weight_item)
            
        layout.addWidget(self.heuristic_table)
        
        # Legend
        legend = QLabel("Score Thresholds: 0-20 (Safe), 21-69 (Potential), 70-100 (Critical)")
        legend.setStyleSheet("color: #888888; font-style: italic;")
        layout.addWidget(legend)
        
        self.pages.addWidget(page)
    def init_placeholder_page(self, title_text, desc_text):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        icon_label = QLabel("🚧")
        icon_label.setStyleSheet("font-size: 64px;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)
        
        title = QLabel(title_text)
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #50C878;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        status = QLabel("COMING SOON")
        status.setStyleSheet("font-size: 14px; color: #FFFFFF; font-weight: bold; background: #333; padding: 5px 15px; border-radius: 4px;")
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(status)
        
        desc = QLabel(desc_text)
        desc.setStyleSheet("color: #888888; font-size: 14px; margin-top: 10px;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        self.pages.addWidget(page)

    def init_db_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        header = QHBoxLayout()
        title = QLabel("PACKAGE DATABASE")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #50C878;")
        header.addWidget(title)
        header.addStretch()
        
        self.btn_db_add = QPushButton("ADD NEW")
        self.btn_db_delete = QPushButton("DELETE SELECTED")
        self.btn_db_save = QPushButton("SAVE CHANGES")
        
        for b, color in [(self.btn_db_add, "#50C878"), (self.btn_db_delete, "#FF4B4B"), (self.btn_db_save, "#2D2D2D")]:
            b.setFixedSize(140, 35)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            txt_color = "black" if color != "#2D2D2D" else "white"
            b.setStyleSheet(f"background-color: {color}; color: {txt_color}; font-weight: bold; border-radius: 4px; font-size: 11px;")
            header.addWidget(b)
            
        layout.addLayout(header)
        
        self.db_table = QTableWidget()
        self.db_table.setColumnCount(1)
        self.db_table.setHorizontalHeaderLabels(["Package Name (Identifier)"])
        self.db_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.db_table.setStyleSheet("""
            QTableWidget {
                background-color: #1A1A1A;
                color: #FFFFFF;
                border: 1px solid #333333;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #2D2D2D;
                color: #50C878;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.db_table)
        self.pages.addWidget(page)

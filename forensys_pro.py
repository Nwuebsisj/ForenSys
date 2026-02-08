import sys
import psutil
import winreg
import os
import subprocess
import pandas as pd
import json
import datetime
import sqlite3
import shutil
import google.generativeai as genai
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, 
                             QLabel, QHeaderView, QTabWidget, QLineEdit, QMessageBox)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor

class ForenSysApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ForenSys - AI-Powered Forensic Toolkit")
        self.resize(1200, 750)
        
        self.KNOWLEDGE_BASE = {
            "ms-teams.exe": "Microsoft Teams (Store App). Common AppData installation.",
            "onedrive.exe": "Microsoft OneDrive. Standard user-profile persistence.",
            "discord.exe": "Discord Chat. Normal AppData auto-start."
        }
        
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Initialize All Tabs
        self.init_persistence_tab()
        self.init_history_tab()  # The New Patient Zero Tab
        self.init_network_tab()
        self.init_settings_tab()

    # --- TAB: PERSISTENCE (Registry) ---
    def init_persistence_tab(self):
        self.scan_tab = QWidget()
        layout = QVBoxLayout(self.scan_tab)
        self.btn_scan = QPushButton("Run Forensic Scan (Registry + AI)")
        self.btn_scan.setFixedHeight(40)
        self.btn_scan.clicked.connect(self.run_forensic_scan)
        
        self.reg_table = QTableWidget(0, 5)
        self.reg_table.setHorizontalHeaderLabels(["Name", "Path", "Signature", "Risk", "AI Insight"])
        self.reg_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.btn_scan)
        layout.addWidget(self.reg_table)
        self.tabs.addTab(self.scan_tab, "Persistence Scanner")

    # --- TAB: WEB HISTORY (Patient Zero) ---
    def init_history_tab(self):
        self.history_tab = QWidget()
        layout = QVBoxLayout(self.history_tab)
        
        self.btn_history = QPushButton("Scan Browser History (Patient Zero)")
        self.btn_history.setFixedHeight(40)
        self.btn_history.clicked.connect(self.run_history_scan)
        
        self.history_table = QTableWidget(0, 3)
        self.history_table.setHorizontalHeaderLabels(["Title", "URL", "Last Visit Time"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(QLabel("Search for the 'Source' of infections in Chrome History:"))
        layout.addWidget(self.btn_history)
        layout.addWidget(self.history_table)
        self.tabs.addTab(self.history_tab, "Web History (Patient Zero)")

    # --- TAB: NETWORK ---
    def init_network_tab(self):
        self.net_tab = QWidget()
        layout = QVBoxLayout(self.net_tab)
        self.net_table = QTableWidget(0, 4)
        self.net_table.setHorizontalHeaderLabels(["PID", "Process", "Remote Address", "Status"])
        self.net_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.net_table)
        self.tabs.addTab(self.net_tab, "Network Monitor")
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_network)
        self.timer.start(3000)

    # --- TAB: SETTINGS ---
    def init_settings_tab(self):
        self.settings_tab = QWidget()
        layout = QVBoxLayout(self.settings_tab)
        
        layout.addWidget(QLabel("Google Gemini API Key:"))
        self.api_input = QLineEdit()
        self.api_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.api_input)
        
        # --- NEW SAVE API BUTTON ---
        self.btn_save_api = QPushButton("Save API Key (Remember Me)")
        self.btn_save_api.clicked.connect(self.save_settings)
        layout.addWidget(self.btn_save_api)
        
        layout.addSpacing(20)
        
        self.btn_export = QPushButton("Export All Findings to Timestamped CSV")
        self.btn_export.clicked.connect(self.export_report)
        layout.addWidget(self.btn_export)
        
        # --- HELP SECTION ---
        help_group = QLabel(
            "<b>How to use ForenSys:</b><br><br>"
            "1. <b>Persistence:</b> Finds files that start automatically with Windows.<br>"
            "2. <b>Web History:</b> Traces 'Patient Zero' (where files were downloaded).<br>"
            "3. <b>Network:</b> Shows live connections to remote servers.<br>"
            "4. <b>AI Insight:</b> Uses Gemini 3 Flash to explain 'High Risk' files."
        )
        help_group.setStyleSheet("background-color: #2c3e50; padding: 15px; border-radius: 5px;")
        layout.addWidget(help_group)
        
        layout.addStretch()
        self.tabs.addTab(self.settings_tab, "Settings & Export")
        
        # --- LOAD SETTINGS ON STARTUP ---
        self.load_settings()
        
    def save_settings(self):
        """Saves the API key to a local file so it's remembered next time."""
        settings = {"api_key": self.api_input.text().strip()}
        with open("settings.json", "w") as f:
            json.dump(settings, f)
        QMessageBox.information(self, "Saved", "API Key saved locally!")

    def load_settings(self):
        """Loads the API key from the local file if it exists."""
        if os.path.exists("settings.json"):
            try:
                with open("settings.json", "r") as f:
                    settings = json.load(f)
                    self.api_input.setText(settings.get("api_key", ""))
            except:
                pass # If file is corrupted, just start fresh

    # --- LOGIC: PATIENT ZERO (Web History) ---
    def run_history_scan(self):
        self.history_table.setRowCount(0)
        # Path to Chrome History (Standard Windows path)
        history_path = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default\History"
        
        if not os.path.exists(history_path):
            QMessageBox.warning(self, "Error", "Chrome History file not found.")
            return

        # We must copy the file because Chrome locks it while open
        temp_history = "temp_history.db"
        try:
            shutil.copy2(history_path, temp_history)
            conn = sqlite3.connect(temp_history)
            cursor = conn.cursor()
            # Select recent URLs (Last 100 for speed)
            cursor.execute("SELECT title, url, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
            
            for title, url, visit_time in cursor.fetchall():
                row = self.history_table.rowCount()
                self.history_table.insertRow(row)
                self.history_table.setItem(row, 0, QTableWidgetItem(str(title)))
                self.history_table.setItem(row, 1, QTableWidgetItem(str(url)))
                self.history_table.setItem(row, 2, QTableWidgetItem(str(visit_time)))
            
            conn.close()
            os.remove(temp_history)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not read Chrome History: {e}\n(Make sure Chrome is closed!)")

    # --- LOGIC: PERSISTENCE & AI ---
    def check_sig(self, path):
        if not os.path.exists(path): return "Missing"
        cmd = f'Get-AuthenticodeSignature "{path}" | Select-Object -ExpandProperty Status'
        try:
            res = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            return res.stdout.strip() or "Unsigned"
        except: return "Error"

    def get_ai_insight(self, filename, path):
        api_key = self.api_input.text().strip()
        if not api_key: return "Provide API Key in Settings."
        try:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-3-flash-preview')
            prompt = f"Forensic check: File {filename} at {path}. Explain if safe or suspicious in 10 words."
            return model.generate_content(prompt).text
        except Exception as e: return f"AI Error: {e}"

    def run_forensic_scan(self):
        self.reg_table.setRowCount(0)
        self.findings = []
        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
        
        for i in range(winreg.QueryInfoKey(key)[1]):
            name, val, _ = winreg.EnumValue(key, i)
            clean_p = val.split(' -')[0].replace('"', '').strip()
            fname = os.path.basename(clean_p).lower()
            sig = self.check_sig(clean_p)
            risk = "LOW"
            insight = "Common file."

            if "appdata" in clean_p.lower() or sig != "Valid":
                risk = "HIGH"
                if fname in self.KNOWLEDGE_BASE:
                    risk = "FLAGGED (SAFE)"
                    insight = self.KNOWLEDGE_BASE[fname]
                else:
                    insight = self.get_ai_insight(fname, clean_p)
            
            row = self.reg_table.rowCount()
            self.reg_table.insertRow(row)
            self.reg_table.setItem(row, 0, QTableWidgetItem(name))
            self.reg_table.setItem(row, 1, QTableWidgetItem(clean_p))
            self.reg_table.setItem(row, 2, QTableWidgetItem(sig))
            risk_item = QTableWidgetItem(risk)
            if risk == "HIGH": risk_item.setBackground(QColor(255, 100, 100))
            elif risk == "FLAGGED (SAFE)": risk_item.setBackground(QColor(255, 255, 150))
            self.reg_table.setItem(row, 3, risk_item)
            self.reg_table.setItem(row, 4, QTableWidgetItem(insight))
            self.findings.append({"Name": name, "Path": clean_p, "Risk": risk, "Insight": insight})

    def update_network(self):
        self.net_table.setRowCount(0)
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    proc = psutil.Process(conn.pid)
                    row = self.net_table.rowCount()
                    self.net_table.insertRow(row)
                    self.net_table.setItem(row, 0, QTableWidgetItem(str(conn.pid)))
                    self.net_table.setItem(row, 1, QTableWidgetItem(proc.name()))
                    self.net_table.setItem(row, 2, QTableWidgetItem(f"{conn.raddr.ip}:{conn.raddr.port}"))
                    self.net_table.setItem(row, 3, QTableWidgetItem(conn.status))
                except: continue

    def export_report(self):
        if not hasattr(self, 'findings'): return
        if not os.path.exists("reports"): os.makedirs("reports")
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        fpath = f"reports/ForenSys_Report_{ts}.csv"
        pd.DataFrame(self.findings).to_csv(fpath, index=False)
        QMessageBox.information(self, "Export Successful", f"Report saved to:\n{fpath}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForenSysApp()
    window.show()
    sys.exit(app.exec())
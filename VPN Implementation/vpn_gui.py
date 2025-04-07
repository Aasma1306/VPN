import os
import sys
import time
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel,
    QFileDialog, QComboBox, QCheckBox, QSystemTrayIcon, QMenu, QAction, QMessageBox,
    QHBoxLayout, QFrame
)
from PyQt5.QtCore import QProcess, Qt, QTimer
from PyQt5.QtGui import QIcon, QFont
from cryptography.fernet import Fernet

# Generate or load encryption key
KEY_FILE = "vpn_key.key"
CONFIG_FILE = "vpn_config.json"

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

fernet = Fernet(load_key())

class VPNClientUI(QWidget):
    def __init__(self):
        super().__init__()
        self.vpn_process = None
        self.auto_reconnect = False
        self.start_time = None
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_timer)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("VPN Client")
        self.setGeometry(300, 200, 550, 600)
        self.setStyleSheet(self.get_dark_mode_stylesheet())  # Default to dark mode

        layout = QVBoxLayout()

        # Status Label
        self.status_label = QLabel("🔴 Disconnected", self)
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(self.status_label)

        # Separator Line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        layout.addWidget(line)

        # Profile Selection
        self.profile_combo = QComboBox()
        self.profile_combo.setStyleSheet("padding: 5px; font-size: 14px;")
        layout.addWidget(self.profile_combo)

        # Server Details (IP & Port)
        form_layout = QVBoxLayout()

        self.ip_label = QLabel("Server IP:")
        self.ip_input = QLineEdit()
        form_layout.addWidget(self.ip_label)
        form_layout.addWidget(self.ip_input)

        self.port_label = QLabel("Server Port:")
        self.port_input = QLineEdit()
        form_layout.addWidget(self.port_label)
        form_layout.addWidget(self.port_input)

        layout.addLayout(form_layout)

        # Protocol Selection
        self.protocol_label = QLabel("Protocol:")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["UDP", "TCP", "WireGuard"])
        self.protocol_combo.setStyleSheet("padding: 5px; font-size: 14px;")
        layout.addWidget(self.protocol_label)
        layout.addWidget(self.protocol_combo)

        # Auto Reconnect
        self.auto_reconnect_checkbox = QCheckBox("Enable Auto-Reconnect")
        layout.addWidget(self.auto_reconnect_checkbox)

        # Dark Mode Toggle
        self.dark_mode_checkbox = QCheckBox("Enable Dark Mode")
        self.dark_mode_checkbox.setChecked(True)
        self.dark_mode_checkbox.stateChanged.connect(self.toggle_dark_mode)
        layout.addWidget(self.dark_mode_checkbox)

        # Start & Stop Buttons (Better UI)
        button_layout = QHBoxLayout()

        self.start_button = QPushButton("Start VPN")
        self.start_button.setStyleSheet(self.get_button_style("green"))
        self.start_button.clicked.connect(self.start_vpn)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop VPN")
        self.stop_button.setStyleSheet(self.get_button_style("red"))
        self.stop_button.clicked.connect(self.stop_vpn)
        button_layout.addWidget(self.stop_button)

        layout.addLayout(button_layout)

        # Connection Timer
        self.timer_label = QLabel("Connection Duration: 00:00:00")
        self.timer_label.setAlignment(Qt.AlignCenter)
        self.timer_label.setFont(QFont("Arial", 12))
        layout.addWidget(self.timer_label)

        # Logs Output (Improved UI)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setStyleSheet("padding: 5px; font-size: 12px; background-color: #333; color: #fff;")
        layout.addWidget(self.log_output)

        # Load Profiles
        self.load_profiles()

        # Log Actions (Save & Clear)
        log_button_layout = QHBoxLayout()

        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.setStyleSheet(self.get_button_style("blue"))
        self.save_logs_button.clicked.connect(self.save_logs)
        log_button_layout.addWidget(self.save_logs_button)

        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.setStyleSheet(self.get_button_style("orange"))
        self.clear_logs_button.clicked.connect(self.clear_logs)
        log_button_layout.addWidget(self.clear_logs_button)

        layout.addLayout(log_button_layout)

        self.setLayout(layout)

    def load_profiles(self):
        """Loads saved VPN profiles into the dropdown."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as file:
                    profiles = json.load(file)
                    self.profile_combo.clear()
                    for profile in profiles:
                        self.profile_combo.addItem(profile["name"])
            except Exception as e:
                self.log_message(f"[Error] Failed to load profiles: {e}", "error")
        else:
            self.log_message("No saved profiles found.")

    def start_vpn(self):
        if self.vpn_process is None:
            self.log_message("Starting VPN...")
            self.status_label.setText("🟡 Connecting...")
            self.start_time = time.time()
            self.timer.start(1000)

            self.vpn_process = QProcess(self)
            self.vpn_process.readyReadStandardOutput.connect(self.read_stdout)
            self.vpn_process.readyReadStandardError.connect(self.read_stderr)
            self.vpn_process.start("./vpn_client")
            self.status_label.setText("🟢 Connected")

    def stop_vpn(self):
        if self.vpn_process:
            self.vpn_process.terminate()
            self.vpn_process.waitForFinished()
            self.vpn_process = None
            self.status_label.setText("🔴 Disconnected")
            self.timer.stop()
            self.timer_label.setText("Connection Duration: 00:00:00")

    def update_timer(self):
        elapsed_time = int(time.time() - self.start_time)
        self.timer_label.setText(f"Connection Duration: {time.strftime('%H:%M:%S', time.gmtime(elapsed_time))}")

    def toggle_dark_mode(self):
        self.setStyleSheet(self.get_dark_mode_stylesheet() if self.dark_mode_checkbox.isChecked() else "")

    def log_message(self, message, msg_type="info"):
        self.log_output.append(message)

    def save_logs(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Logs", "vpn_logs.txt", "Text Files (*.txt)")
        if file_name:
            with open(file_name, "w") as file:
                file.write(self.log_output.toPlainText())

    def clear_logs(self):
        self.log_output.clear()

    def get_dark_mode_stylesheet(self):
        return """
            background-color: #2E3440;
            color: white;
            font-size: 14px;
        """

    def get_button_style(self, color):
        colors = {
            "green": "#28a745",
            "red": "#dc3545",
            "blue": "#007bff",
            "orange": "#fd7e14"
        }
        return f"""
            background-color: {colors[color]};
            color: white;
            border-radius: 8px;
            padding: 8px;
        """

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = VPNClientUI()
    window.show()
    sys.exit(app.exec_())

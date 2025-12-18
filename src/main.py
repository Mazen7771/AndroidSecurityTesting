import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget,
    QWidget, QVBoxLayout, QPushButton,
    QLabel, QTextEdit
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from modules.adb_manager import ADBManager


class AndroidSecurityTesting(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Android Security Testing Suite")
        self.setGeometry(100, 100, 1000, 700)

        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.icons_dir = os.path.join(self.base_dir, "icons")

        self.init_ui()

    def init_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tabs.addTab(
            DeviceConnectionTab(self.icons_dir),
            QIcon(os.path.join(self.icons_dir, "device.png")),
            "Device"
        )

        self.tabs.addTab(
            ApplicationAnalysisTab(),
            QIcon(os.path.join(self.icons_dir, "analysis.png")),
            "App Analysis"
        )

        self.tabs.addTab(
            NetworkAnalysisTab(),
            QIcon(os.path.join(self.icons_dir, "network.png")),
            "Network"
        )

        self.tabs.addTab(
            ExploitationTab(),
            QIcon(os.path.join(self.icons_dir, "exploit.png")),
            "Exploitation"
        )


class DeviceConnectionTab(QWidget):
    def __init__(self, icons_dir):
        super().__init__()
        self.icons_dir = icons_dir
        self.adb = ADBManager()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("Device Connection")
        title.setStyleSheet("font-size:16px; font-weight:bold;")

        self.status = QLabel("Not Connected")
        self.status.setStyleSheet("color:red;")

        self.btn_connect = QPushButton(" Connect Device")
        self.btn_connect.clicked.connect(self.connect_device)  # ⚡ connect_device يجب أن يكون موجودًا

        self.btn_refresh = QPushButton(" Refresh")
        self.btn_refresh.clicked.connect(self.refresh)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        layout.addWidget(title)
        layout.addWidget(self.status)
        layout.addWidget(self.btn_connect)
        layout.addWidget(self.btn_refresh)
        layout.addWidget(self.output)

        self.setLayout(layout)

    # <<< تأكد أن هذه الدالة موجودة داخل الكلاس وبالمسافة الصحيحة >>>
    def connect_device(self):
        self.output.clear()

        if not self.adb.is_adb_available():
            self.status.setText("ADB Not Found")
            self.status.setStyleSheet("color:red;")
            self.output.append("[!] adb is not installed")
            return

        devices = self.adb.get_devices()

        if not devices:
            self.status.setText("No Device Connected")
            self.status.setStyleSheet("color:red;")
            self.output.append("[!] No Android device detected")
            return

        self.status.setText("Connected")
        self.status.setStyleSheet("color:green;")

        self.output.append("[+] Connected devices:")
        for d in devices:
            self.output.append(f" - {d}")

    def refresh(self):
        self.output.append("[*] Refreshing device list...")
        self.connect_device()


class ApplicationAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Application Analysis Tools"))
        self.setLayout(layout)


class NetworkAnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Network Analysis Tools"))
        self.setLayout(layout)


class ExploitationTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Exploitation Tools"))
        self.setLayout(layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AndroidSecurityTesting()
    window.show()
    sys.exit(app.exec_())

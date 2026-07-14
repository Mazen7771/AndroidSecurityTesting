#!/usr/bin/env python3
"""
Security Toolkit - Application Entry Point

Launches the main window with one tab per module:
  - Network Scanner   (host/port/service discovery + CVE matching)   [functional]
  - Android Analyzer  (APK static analysis)                          [placeholder]
  - Report Generator  (export findings to PDF/HTML)                  [placeholder]

Run from the project root:
    python main.py
"""

import logging
import sys

from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QTabWidget, QVBoxLayout, QWidget

from src.modules.android_analyzer import AndroidAnalyzerGUI
from src.modules.network_scanner import NetworkScannerGUI

logger = logging.getLogger(__name__)


class ReportGeneratorPlaceholder(QWidget):
    """Temporary tab widget until the Report Generator GUI is built out."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Report Generator - Coming soon"))
        layout.addWidget(
            QLabel("Will export Network Scanner and Android Analyzer findings to PDF/HTML.")
        )
        layout.addStretch()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Toolkit")
        self.resize(1100, 750)

        tabs = QTabWidget()
        tabs.addTab(NetworkScannerGUI(), "Network Scanner")
        tabs.addTab(AndroidAnalyzerGUI(), "Android Analyzer")
        tabs.addTab(ReportGeneratorPlaceholder(), "Report Generator")
        self.setCentralWidget(tabs)

        self.statusBar().showMessage("Ready")


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def main() -> int:
    configure_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("Security Toolkit")
    app.setStyle("Fusion")

    window = MainWindow()
    window.show()

    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())

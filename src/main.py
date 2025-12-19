# src/main.py
"""
Android Security Testing Framework - Main Entry Point
Integration of all security modules with advanced GUI
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the path so we can import modules
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Try importing modules with error handling
modules = {}
try:
    from modules.exploitation_tools import ExploitationToolsGUI
    modules['exploitation'] = ExploitationToolsGUI
    print("Loaded exploitation_tools module")
except ImportError as e:
    print(f"Warning: Could not import exploitation_tools: {e}")
    modules['exploitation'] = None

try:
    from modules.network_analyzer import NetworkScannerGUI
    modules['network'] = NetworkScannerGUI
    print("Loaded network_analyzer module")
except ImportError as e:
    print(f"Warning: Could not import network_analyzer: {e}")
    modules['network'] = None

try:
    from modules.apk_analyzer import AndroidAnalyzerGUI
    modules['android'] = AndroidAnalyzerGUI
    print("Loaded apk_analyzer module")
except ImportError as e:
    print(f"Warning: Could not import apk_analyzer: {e}")
    modules['android'] = None

try:
    from modules.report_generator import ReportGenerator
    modules['report'] = ReportGenerator
    print("Loaded report_generator module")
except ImportError as e:
    print(f"Warning: Could not import report_generator: {e}")
    modules['report'] = None

# Try importing PyQt5
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QVBoxLayout, QWidget, 
        QTabWidget, QMessageBox, QMenuBar, QMenu, QAction, QLabel,
        QHBoxLayout, QPushButton
    )
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QIcon
    PYQT5_AVAILABLE = True
    print("Loaded PyQt5")
except ImportError as e:
    PYQT5_AVAILABLE = False
    print(f"Error: PyQt5 not available: {e}")
    print("Please install it with: pip install PyQt5")
    sys.exit(1)

class AndroidSecurityFramework(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Android Security Testing Framework")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create tabbed interface
        self.create_tabs()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
    
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_tabs(self):
        """Create tabbed interface for different tools"""
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Add exploitation tools tab if available
        if modules['exploitation']:
            try:
                exploitation_tab = modules['exploitation']()
                exploitation_tab.setWindowFlags(Qt.Widget)  # Make it a widget, not a window
                self.tabs.addTab(exploitation_tab, "Exploitation Tools")
            except Exception as e:
                error_widget = self.create_error_widget(f"Failed to load exploitation tools: {e}")
                self.tabs.addTab(error_widget, "Exploitation Tools (Error)")
        else:
            error_widget = self.create_error_widget(
                "Exploitation tools module not available.\n" +
                "Create modules/exploitation_tools.py with an ExploitationToolsGUI class."
            )
            self.tabs.addTab(error_widget, "Exploitation Tools")
        
        # Add network scanner tab if available
        if modules['network']:
            try:
                network_tab = modules['network']()
                network_tab.setWindowFlags(Qt.Widget)
                self.tabs.addTab(network_tab, "Network Scanner")
            except Exception as e:
                error_widget = self.create_error_widget(f"Failed to load network scanner: {e}")
                self.tabs.addTab(error_widget, "Network Scanner (Error)")
        else:
            error_widget = self.create_error_widget(
                "Network scanner module not available.\n" +
                "Create modules/network_scanner.py with a NetworkScannerGUI class."
            )
            self.tabs.addTab(error_widget, "Network Scanner")
        
        # Add android analyzer tab if available
        if modules['android']:
            try:
                android_tab = modules['android']()
                android_tab.setWindowFlags(Qt.Widget)
                self.tabs.addTab(android_tab, "Android Analyzer")
            except Exception as e:
                error_widget = self.create_error_widget(f"Failed to load android analyzer: {e}")
                self.tabs.addTab(error_widget, "Android Analyzer (Error)")
        else:
            error_widget = self.create_error_widget(
                "Android analyzer module not available.\n" +
                "Create modules/android_analyzer.py with an AndroidAnalyzerGUI class."
            )
            self.tabs.addTab(error_widget, "Android Analyzer")
        
        # Add report generator tab if available
        if modules['report']:
            try:
                report_tab = modules['report']()
                report_tab.setWindowFlags(Qt.Widget)
                self.tabs.addTab(report_tab, "Report Generator")
            except Exception as e:
                error_widget = self.create_error_widget(f"Failed to load report generator: {e}")
                self.tabs.addTab(error_widget, "Report Generator (Error)")
        else:
            error_widget = self.create_error_widget(
                "Report generator module not available.\n" +
                "Create modules/report_generator.py with a ReportGenerator class."
            )
            self.tabs.addTab(error_widget, "Report Generator")
    
    def create_error_widget(self, message):
        """Create a widget to display error messages"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        error_label = QLabel(message)
        error_label.setWordWrap(True)
        error_label.setStyleSheet("color: red; padding: 20px;")
        
        layout.addWidget(error_label)
        return widget
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About", 
                         "Android Security Testing Framework\n\n"
                         "A comprehensive toolkit for Android application security testing.\n"
                         "Features include:\n"
                         "- Exploitation tools with virus detection\n"
                         "- Network scanning capabilities\n"
                         "- Android APK analysis\n"
                         "- Detailed reporting\n\n"
                         "Version 1.0")

def main():
    # Set application attributes
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    app.setApplicationName("Android Security Framework")
    
    # Create and show main window
    window = AndroidSecurityFramework()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

"""
Network Scanner Module

PyQt5 GUI for discovering hosts, scanning ports, detecting services, and
matching known CVEs against detected service versions. All blocking work
runs on a background QThread so the UI never freezes.
"""

import logging
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QBrush, QColor
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.core.models import NetworkScanResult, PortState
from src.core.network_scanner_engine import NetworkScannerEngine, NmapNotFoundError
from src.utils.threading_utils import run_in_thread
from src.utils.validators import InvalidTargetError, validate_port_range, validate_target

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#8B0000",
    "HIGH": "#D9534F",
    "MEDIUM": "#F0AD4E",
    "LOW": "#5BC0DE",
    "UNKNOWN": "#777777",
}


class NetworkScannerGUI(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._thread = None
        self._worker = None
        self._engine: Optional[NetworkScannerEngine] = None
        self._last_result: Optional[NetworkScanResult] = None

        self._build_ui()
        self._init_engine()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        title = QLabel("Network Scanner")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        form_row = QHBoxLayout()
        form_row.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.1, 192.168.1.0/24, or example.com")
        self.target_input.setAccessibleName("Scan target")
        self.target_input.returnPressed.connect(self._on_scan_clicked)
        form_row.addWidget(self.target_input, 2)

        form_row.addWidget(QLabel("Ports:"))
        self.port_input = QLineEdit("1-1024")
        self.port_input.setAccessibleName("Port range")
        form_row.addWidget(self.port_input, 1)

        form_row.addWidget(QLabel("CVE Lookup:"))
        self.cve_toggle = QComboBox()
        self.cve_toggle.addItems(["Enabled", "Disabled"])
        self.cve_toggle.setAccessibleName("Toggle CVE lookup")
        self.cve_toggle.setToolTip(
            "Queries the public NVD database for each detected service. "
            "Disable for faster scans on large networks."
        )
        form_row.addWidget(self.cve_toggle)
        layout.addLayout(form_row)

        button_row = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setAccessibleName("Start network scan")
        self.scan_button.clicked.connect(self._on_scan_clicked)
        button_row.addWidget(self.scan_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._on_cancel_clicked)
        button_row.addWidget(self.cancel_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # indeterminate: nmap doesn't report % reliably
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Host / Port", "State", "Service / CVSS", "CVEs / Severity"])
        self.results_tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.results_tree.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.results_tree, 3)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(120)
        self.log_output.setAccessibleName("Scan log")
        layout.addWidget(self.log_output, 1)

    def _init_engine(self) -> None:
        try:
            self._engine = NetworkScannerEngine()
        except NmapNotFoundError as exc:
            self._engine = None
            self._log(str(exc))
            self.scan_button.setEnabled(False)
            QMessageBox.warning(self, "nmap not found", str(exc))

    # ------------------------------------------------------------- actions

    def _on_scan_clicked(self) -> None:
        if self._engine is None:
            QMessageBox.warning(self, "Unavailable", "nmap is not installed. Scanning is disabled.")
            return

        target = self.target_input.text()
        port_range = self.port_input.text()

        try:
            validate_target(target)
            validate_port_range(port_range)
        except InvalidTargetError as exc:
            QMessageBox.warning(self, "Invalid input", str(exc))
            return

        self.results_tree.clear()
        self.log_output.clear()
        self._set_busy(True)

        enable_cve = self.cve_toggle.currentText() == "Enabled"

        self._thread, self._worker = run_in_thread(
            self._engine.scan,
            target=target,
            port_range=port_range,
            enable_cve_lookup=enable_cve,
        )
        self._worker.progress.connect(self._log)
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.failed.connect(self._on_scan_failed)
        self._thread.start()

    def _on_cancel_clicked(self) -> None:
        if self._engine:
            self._engine.cancel()
        self.cancel_button.setEnabled(False)
        self._log("Cancelling... (finishes the current host, then stops)")

    def _on_scan_finished(self, result: NetworkScanResult) -> None:
        self._last_result = result
        self._set_busy(False)
        self._populate_results(result)
        if result.errors:
            self._log("Errors: " + "; ".join(result.errors))
        self._log(
            f"Done. {len(result.hosts)} host(s), {result.total_open_ports} open port(s), "
            f"{result.total_cves} CVE match(es)."
        )

    def _on_scan_failed(self, error_message: str) -> None:
        self._set_busy(False)
        self._log(f"Scan failed: {error_message}")
        QMessageBox.critical(self, "Scan failed", error_message)

    # -------------------------------------------------------------- helpers

    def _set_busy(self, busy: bool) -> None:
        self.scan_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress_bar.setVisible(busy)

    def _log(self, message: str) -> None:
        self.log_output.append(message)

    def _populate_results(self, result: NetworkScanResult) -> None:
        for host in result.hosts:
            host_label = host.ip + (f" ({host.hostname})" if host.hostname else "")
            host_item = QTreeWidgetItem([host_label, "up" if host.is_up else "down", "", ""])
            self.results_tree.addTopLevelItem(host_item)

            open_ports = [p for p in host.ports if p.state == PortState.OPEN]
            if not open_ports:
                host_item.addChild(QTreeWidgetItem(["(no open ports found)", "", "", ""]))
                continue

            for port in open_ports:
                service_label = port.service.search_term if port.service else "unknown"
                cve_label = f"{len(port.cves)} found" if port.cves else "none"
                port_item = QTreeWidgetItem(
                    [f"{port.port}/{port.protocol}", port.state.value, service_label, cve_label]
                )
                host_item.addChild(port_item)

                for cve in sorted(port.cves, key=lambda c: c.cvss_score or 0, reverse=True):
                    cve_item = QTreeWidgetItem(
                        [cve.cve_id, "", f"CVSS {cve.cvss_score if cve.cvss_score is not None else '?'}", cve.severity.value]
                    )
                    color = QColor(SEVERITY_COLORS.get(cve.severity.value, "#777777"))
                    cve_item.setForeground(3, QBrush(color))
                    cve_item.setToolTip(0, cve.description)
                    port_item.addChild(cve_item)

            host_item.setExpanded(True)

        self.results_tree.expandAll()

    # -------------------------------------------------------------- Qt hooks

    def closeEvent(self, event) -> None:
        """Ensure the background thread is stopped cleanly if the widget closes mid-scan."""
        if self._thread is not None and self._thread.isRunning():
            if self._engine:
                self._engine.cancel()
            self._thread.quit()
            self._thread.wait(3000)
        super().closeEvent(event)

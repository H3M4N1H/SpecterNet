from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QColor
from core.scanner import PortScanner


class ScanWorker(QThread):
    result_ready = pyqtSignal(int, str, str)
    scan_done = pyqtSignal(dict)

    def __init__(self, target, ports=None):
        super().__init__()
        self.target = target
        self.ports = ports
        self.scanner = PortScanner(
            on_result=self._on_result,
            on_done=self._on_done
        )

    def _on_result(self, port, status, service):
        self.result_ready.emit(port, status, service)

    def _on_done(self, results):
        self.scan_done.emit(results)

    def run(self):
        self.scanner.scan(self.target, self.ports)
        # Wait for scanner thread to finish
        import time
        while self.scanner.running:
            time.sleep(0.1)

    def stop(self):
        self.scanner.stop()


class ScanPanel(QWidget):
    def __init__(self):
        super().__init__()
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Top bar
        top = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Target IP (e.g. 192.168.1.1)")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 4px; padding: 5px;
                font-family: monospace;
            }
        """)

        self.scan_btn = QPushButton("▶ Scan")
        self.scan_btn.clicked.connect(self._start_scan)
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)

        for btn in [self.scan_btn, self.stop_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background: #313244; color: #89b4fa;
                    border: 1px solid #45475a; border-radius: 4px;
                    padding: 5px 12px; font-weight: bold;
                }
                QPushButton:hover { background: #45475a; }
                QPushButton:disabled { color: #6c7086; }
            """)

        top.addWidget(QLabel("Target:"))
        top.addWidget(self.target_input, 1)
        top.addWidget(self.scan_btn)
        top.addWidget(self.stop_btn)
        layout.addLayout(top)

        # Status
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #6c7086; font-size: 11px;")
        layout.addWidget(self.status_label)

        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Port", "Status", "Service"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 80)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e2e; color: #cdd6f4;
                border: none; font-family: monospace; font-size: 12px;
            }
            QTableWidget::item:selected { background-color: #313244; }
            QHeaderView::section {
                background-color: #313244; color: #89b4fa;
                padding: 4px; border: none; font-weight: bold;
            }
        """)
        layout.addWidget(self.table)

    def _start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            return

        self.table.setRowCount(0)
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"Scanning {target}...")

        self._worker = ScanWorker(target)
        self._worker.result_ready.connect(self._add_result)
        self._worker.scan_done.connect(self._scan_done)
        self._worker.start()

    def _stop_scan(self):
        if self._worker:
            self._worker.stop()
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Scan stopped")

    def _add_result(self, port, status, service):
        row = self.table.rowCount()
        self.table.insertRow(row)
        color = QColor("#1a2b1a") if status == "open" else QColor("#2d1515")

        for col, val in enumerate([str(port), status, service]):
            item = QTableWidgetItem(val)
            item.setBackground(color)
            if col == 1:
                item.setForeground(QColor("#3fb950") if status == "open" else QColor("#f85149"))
            self.table.setItem(row, col, item)

        open_count = sum(1 for r in range(self.table.rowCount())
                        if self.table.item(r, 1) and self.table.item(r, 1).text() == "open")
        self.status_label.setText(f"Scanning... {open_count} open ports found")

    def _scan_done(self, results):
        open_count = sum(1 for v in results.values() if v["status"] == "open")
        self.status_label.setText(f"Done — {open_count} open ports out of {len(results)} scanned")
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

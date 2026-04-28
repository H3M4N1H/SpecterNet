from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget,
    QTableWidgetItem, QHeaderView, QLabel
)
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import Qt


class CredPanel(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.label = QLabel("⚠️  Captured Credentials")
        self.label.setStyleSheet("color: #f38ba8; font-weight: bold; padding: 5px;")
        layout.addWidget(self.label)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Protocol", "Source IP", "Credential"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 130)

        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e2e;
                color: #f38ba8;
                border: 1px solid #f38ba8;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #313244;
                color: #f38ba8;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.table)

    def add_credential(self, cred_tuple):
        """Add a credential row. cred_tuple = (proto, src_ip, cred_str)"""
        proto, src, cred = cred_tuple
        row = self.table.rowCount()
        self.table.insertRow(row)

        for col, val in enumerate([proto, src, cred]):
            item = QTableWidgetItem(val)
            item.setBackground(QColor("#2d1515"))
            self.table.setItem(row, col, item)

        self.table.scrollToBottom()
        self.label.setText(f"⚠️  Captured Credentials ({row + 1})")

    def clear(self):
        self.table.setRowCount(0)
        self.label.setText("⚠️  Captured Credentials")

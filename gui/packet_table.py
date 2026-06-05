from PyQt6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from utils.helpers import PROTO_COLORS


class PacketTable(QTableWidget):
    packet_selected = pyqtSignal(dict)

    COLUMNS = ["#", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    def __init__(self):
        super().__init__()
        self._packets = []
        self._max_rows = 10000
        self._setup_ui()

    def _setup_ui(self):
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.setSortingEnabled(False)

        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self.setColumnWidth(0, 50)
        self.setColumnWidth(1, 90)
        self.setColumnWidth(4, 90)
        self.setColumnWidth(5, 70)

        self.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                border: none;
                gridline-color: #313244;
                font-family: 'JetBrains Mono', 'Courier New', monospace;
                font-size: 12px;
            }
            QTableWidget::item:selected {
                background-color: #313244;
                color: #cdd6f4;
            }
            QTableWidget::item:alternate {
                background-color: #181825;
            }
            QHeaderView::section {
                background-color: #313244;
                color: #89b4fa;
                padding: 5px;
                border: none;
                font-weight: bold;
            }
        """)

        self.itemSelectionChanged.connect(self._on_selection)

    def add_packet(self, packet_data):
        """Add a packet row to the table."""
        if self.rowCount() >= self._max_rows:
            self.removeRow(0)

        self._packets.append(packet_data)
        row = self.rowCount()
        self.insertRow(row)

        proto = packet_data.get("proto", "OTHER")
        color = QColor(PROTO_COLORS.get(proto, "#888888"))
        color.setAlpha(40)

        values = [
            str(packet_data.get("id", row + 1)),
            packet_data.get("time", ""),
            packet_data.get("src", ""),
            packet_data.get("dst", ""),
            proto,
            str(packet_data.get("length", 0)),
            packet_data.get("summary", ""),
        ]

        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setData(Qt.ItemDataRole.UserRole, packet_data)

            # Color protocol column
            if col == 4:
                item.setForeground(QColor(PROTO_COLORS.get(proto, "#888888")))

            item.setBackground(color)
            self.setItem(row, col, item)

        # Auto-scroll to bottom
        self.scrollToBottom()

    def _on_selection(self):
        selected = self.selectedItems()
        if selected:
            packet_data = selected[0].data(Qt.ItemDataRole.UserRole)
            if packet_data:
                self.packet_selected.emit(packet_data)

    def clear_packets(self):
        self.setRowCount(0)
        self._packets = []

    def get_packets(self):
        """Return a shallow copy of the packet records currently held by the table."""
        return list(self._packets)

    def apply_filter(self, text):
        """Filter visible rows by search text."""
        text = text.lower()
        for row in range(self.rowCount()):
            show = False
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item and text in item.text().lower():
                    show = True
                    break
            self.setRowHidden(row, not show)

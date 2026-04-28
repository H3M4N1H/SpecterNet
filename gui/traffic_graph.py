from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QPainter, QColor, QPen, QFont
from PyQt6.QtCore import Qt
import time


class TrafficGraph(QWidget):
    def __init__(self, stats, parent=None):
        super().__init__(parent)
        self.stats = stats
        self.history = [0] * 60   # 60 seconds of data
        self.max_val = 1
        self.setMinimumHeight(150)

        self.timer = QTimer()
        self.timer.timeout.connect(self._update)
        self.timer.start(1000)  # Update every second

    def _update(self):
        bps = self.stats.get_bytes_per_second()
        self.history.append(bps)
        self.history = self.history[-60:]
        self.max_val = max(max(self.history), 1)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        padding = 40

        # Background
        painter.fillRect(0, 0, w, h, QColor("#1e1e2e"))

        # Grid lines
        grid_pen = QPen(QColor("#313244"))
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)
        for i in range(4):
            y = padding + (h - 2 * padding) * i // 3
            painter.drawLine(padding, y, w - 10, y)

        if not self.history:
            return

        # Draw graph line
        graph_pen = QPen(QColor("#89b4fa"))
        graph_pen.setWidth(2)
        painter.setPen(graph_pen)

        points = self.history[-((w - 2 * padding) // 4):]
        n = len(points)
        if n < 2:
            return

        step = (w - 2 * padding) / max(n - 1, 1)
        graph_h = h - 2 * padding

        prev_x, prev_y = None, None
        for i, val in enumerate(points):
            x = int(padding + i * step)
            y = int(h - padding - (val / self.max_val) * graph_h)
            if prev_x is not None:
                painter.drawLine(prev_x, prev_y, x, y)
            prev_x, prev_y = x, y

        # Fill area under graph
        from PyQt6.QtGui import QPainterPath, QLinearGradient
        path = QPainterPath()
        path.moveTo(padding, h - padding)
        for i, val in enumerate(points):
            x = int(padding + i * step)
            y = int(h - padding - (val / self.max_val) * graph_h)
            path.lineTo(x, y)
        path.lineTo(padding + (n - 1) * step, h - padding)
        path.closeSubpath()

        gradient = QLinearGradient(0, 0, 0, h)
        gradient.setColorAt(0, QColor(137, 180, 250, 80))
        gradient.setColorAt(1, QColor(137, 180, 250, 0))
        painter.fillPath(path, gradient)

        # Labels
        painter.setPen(QColor("#6c7086"))
        font = QFont("Courier New", 9)
        painter.setFont(font)

        # Y-axis max label
        from utils.helpers import format_bytes
        painter.drawText(2, padding + 10, format_bytes(self.max_val) + "/s")
        painter.drawText(2, h - padding, "0")

        # Title
        painter.setPen(QColor("#89b4fa"))
        font.setBold(True)
        painter.setFont(font)
        current = format_bytes(self.history[-1]) + "/s" if self.history else "0 B/s"
        painter.drawText(w // 2 - 40, 15, f"Traffic: {current}")

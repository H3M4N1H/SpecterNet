from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QToolBar, QComboBox,
    QLineEdit, QPushButton, QLabel, QStatusBar,
    QFileDialog, QTextEdit, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from core.sniffer import PacketSniffer
from core.stats import TrafficStats
from core.analyzer import dissect_packet
from gui.packet_table import PacketTable
from gui.traffic_graph import TrafficGraph
from gui.cred_panel import CredPanel
from gui.scan_panel import ScanPanel
from utils.helpers import get_interfaces, format_bytes


class SnifferWorker(QThread):
    packet_received = pyqtSignal(dict)
    credential_found = pyqtSignal(tuple)
    error_occurred = pyqtSignal(str)

    def __init__(self, iface, bpf_filter):
        super().__init__()
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.sniffer = PacketSniffer(
            on_packet=self._on_packet,
            on_credential=self._on_cred,
            on_error=self._on_error,
        )

    def _on_packet(self, pkt):
        self.packet_received.emit(pkt)

    def _on_cred(self, cred):
        self.credential_found.emit(cred)

    def _on_error(self, msg):
        self.error_occurred.emit(msg)

    def run(self):
        try:
            self.sniffer.start(self.iface, self.bpf_filter)
            self.exec()
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self.sniffer.stop()
        self.quit()

    def save_pcap(self, path):
        return self.sniffer.save_pcap(path)

    def load_pcap(self, path):
        return self.sniffer.load_pcap(path)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("👻 SpecterNet — Network Sniffer")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        self.stats = TrafficStats()
        self.worker = None
        self.packet_count = 0
        self.paused = False

        self._apply_theme()
        self._build_ui()
        self._build_toolbar()
        self._build_statusbar()

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_status)
        self.status_timer.start(1000)

    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e2e; }
            QWidget { background-color: #1e1e2e; color: #cdd6f4; }
            QSplitter::handle { background: #313244; }
            QSplitter::handle:vertical { height: 4px; }
            QSplitter::handle:horizontal { width: 4px; }
            
            QTabWidget::pane { border: 1px solid #313244; background: #1e1e2e; border-radius: 4px; }
            QTabBar::tab {
                background: #181825; color: #6c7086;
                padding: 8px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px;
                margin-right: 2px; font-family: 'Segoe UI', sans-serif; font-size: 13px;
            }
            QTabBar::tab:selected { background: #313244; color: #cdd6f4; border-bottom: 2px solid #89b4fa; }
            QTabBar::tab:hover { background: #2a2a3a; }
            
            QToolBar {
                background: #11111b; border-bottom: 1px solid #313244;
                spacing: 8px; padding: 6px;
            }
            QStatusBar { background: #11111b; color: #a6adc8; font-size: 11px; border-top: 1px solid #313244; }
            
            QComboBox {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 6px;
                padding: 4px 10px; min-width: 160px;
            }
            QComboBox::drop-down { border: none; }
            
            QLineEdit {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 6px; padding: 5px 10px;
                font-family: 'JetBrains Mono', monospace;
            }
            QLineEdit:focus { border: 1px solid #89b4fa; }
            
            QPushButton {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 6px;
                padding: 6px 16px; font-weight: 600; font-size: 12px;
            }
            QPushButton:hover { background: #45475a; border-color: #585b70; }
            QPushButton:pressed { background: #585b70; }
            QPushButton:disabled { color: #585b70; background: #181825; border-color: #313244; }
            
            QPushButton#startBtn { background: #2d3d3d; color: #a6e3a1; border-color: #a6e3a1; }
            QPushButton#startBtn:hover { background: #3d4d4d; }
            QPushButton#stopBtn { background: #3d2d2d; color: #f38ba8; border-color: #f38ba8; }
            QPushButton#stopBtn:hover { background: #4d3d3d; }
            
            QTextEdit {
                background: #181825; color: #cdd6f4;
                border: 1px solid #313244; border-radius: 6px;
                font-family: 'JetBrains Mono', monospace; font-size: 12px;
                padding: 10px;
            }
            
            QScrollBar:vertical {
                background: #11111b; width: 10px; border-radius: 5px; margin: 2px;
            }
            QScrollBar::handle:vertical {
                background: #45475a; border-radius: 5px; min-height: 20px;
            }
            QScrollBar::handle:vertical:hover { background: #585b70; }
            
            QHeaderView::section {
                background-color: #11111b; color: #89b4fa;
                padding: 8px; border: none; border-bottom: 1px solid #313244;
                font-weight: bold;
            }
        """)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)

        graph_label = QLabel("📊 Live Traffic")
        graph_label.setStyleSheet("color: #89b4fa; font-weight: bold; padding: 4px;")
        left_layout.addWidget(graph_label)

        self.traffic_graph = TrafficGraph(self.stats)
        left_layout.addWidget(self.traffic_graph)

        proto_label = QLabel("📡 Protocol Distribution")
        proto_label.setStyleSheet("color: #89b4fa; font-weight: bold; padding: 4px;")
        left_layout.addWidget(proto_label)

        self.proto_stats = QTextEdit()
        self.proto_stats.setReadOnly(True)
        self.proto_stats.setMaximumHeight(200)
        left_layout.addWidget(self.proto_stats)
        left_layout.addStretch()

        left_panel.setMaximumWidth(280)
        main_splitter.addWidget(left_panel)

        # Right panel
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)

        search_bar = QHBoxLayout()
        search_bar.setContentsMargins(5, 3, 5, 3)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Filter packets (IP, protocol, port...)")
        self.search_input.textChanged.connect(self._apply_filter)
        search_bar.addWidget(self.search_input)
        right_layout.addLayout(search_bar)

        self.tabs = QTabWidget()

        # Packets tab
        packets_widget = QWidget()
        packets_layout = QVBoxLayout(packets_widget)
        packets_layout.setContentsMargins(0, 0, 0, 0)
        packets_layout.setSpacing(0)

        # Create vertical splitter for table and detail panel
        packet_splitter = QSplitter(Qt.Orientation.Vertical)

        self.packet_table = PacketTable()
        self.packet_table.packet_selected.connect(self._show_packet_detail)
        packet_splitter.addWidget(self.packet_table)

        self.detail_panel = QTextEdit()
        self.detail_panel.setReadOnly(True)
        self.detail_panel.setPlaceholderText("Click a packet to see full layer dissection...")
        packet_splitter.addWidget(self.detail_panel)
        
        # Set initial sizes for the vertical splitter (70% table, 30% detail)
        packet_splitter.setSizes([600, 300])

        packets_layout.addWidget(packet_splitter)

        self.tabs.addTab(packets_widget, "📦 Packets")

        self.cred_panel = CredPanel()
        self.tabs.addTab(self.cred_panel, "🔑 Credentials (0)")

        self.scan_panel = ScanPanel()
        self.tabs.addTab(self.scan_panel, "🔍 Port Scanner")

        right_layout.addWidget(self.tabs)
        main_splitter.addWidget(right_panel)
        main_splitter.setSizes([260, 940])
        main_layout.addWidget(main_splitter)

        self.proto_timer = QTimer()
        self.proto_timer.timeout.connect(self._update_proto_stats)
        self.proto_timer.start(2000)

    def _build_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        toolbar.addWidget(QLabel("  Interface: "))
        self.iface_combo = QComboBox()
        ifaces = get_interfaces()
        self.iface_combo.addItems(ifaces if ifaces else ["eth0", "lo"])
        toolbar.addWidget(self.iface_combo)

        toolbar.addSeparator()

        toolbar.addWidget(QLabel("  BPF Filter: "))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g. tcp port 80")
        self.filter_input.setMinimumWidth(200)
        toolbar.addWidget(self.filter_input)

        toolbar.addSeparator()

        self.start_btn = QPushButton("▶ Start")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self.start_capture)
        toolbar.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        toolbar.addWidget(self.stop_btn)

        self.pause_btn = QPushButton("⏸ Pause")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        toolbar.addWidget(self.pause_btn)

        toolbar.addSeparator()

        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self.clear_packets)
        toolbar.addWidget(clear_btn)

        save_btn = QPushButton("💾 PCAP")
        save_btn.clicked.connect(self.save_pcap)
        toolbar.addWidget(save_btn)

        export_btn = QPushButton("📄 Export")
        export_btn.clicked.connect(self.export_packets)
        toolbar.addWidget(export_btn)

        load_btn = QPushButton("📂 Load")
        load_btn.clicked.connect(self.load_pcap)
        toolbar.addWidget(load_btn)

    def _build_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)

        self.status_packets = QLabel("Packets: 0")
        self.status_bytes = QLabel("Bytes: 0")
        self.status_bps = QLabel("Speed: 0 B/s")
        self.status_state = QLabel("● Idle")
        self.status_state.setStyleSheet("color: #6c7086;")

        for w in [self.status_packets, self.status_bytes,
                  self.status_bps, self.status_state]:
            w.setStyleSheet(w.styleSheet() + " padding: 0 10px;")
            self.statusbar.addWidget(w)

    def start_capture(self):
        iface = self.iface_combo.currentText()
        bpf = self.filter_input.text().strip()

        self.worker = SnifferWorker(iface, bpf)
        self.worker.packet_received.connect(self._on_packet)
        self.worker.credential_found.connect(self._on_credential)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.pause_btn.setEnabled(True)
        self.status_state.setText("● Capturing")
        self.status_state.setStyleSheet("color: #a6e3a1; padding: 0 10px;")

    def stop_capture(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait(2000)
            self.worker = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)
        self.paused = False
        self.pause_btn.setText("⏸ Pause")
        self.status_state.setText("● Stopped")
        self.status_state.setStyleSheet("color: #f38ba8; padding: 0 10px;")

    def toggle_pause(self):
        self.paused = not self.paused
        if self.paused:
            self.pause_btn.setText("▶ Resume")
            self.status_state.setText("● Paused")
            self.status_state.setStyleSheet("color: #f9e2af; padding: 0 10px;")
        else:
            self.pause_btn.setText("⏸ Pause")
            self.status_state.setText("● Capturing")
            self.status_state.setStyleSheet("color: #a6e3a1; padding: 0 10px;")

    def clear_packets(self):
        self.packet_table.clear_packets()
        self.cred_panel.clear()
        self.detail_panel.clear()
        self.packet_count = 0
        self.stats.__init__()

    def save_pcap(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "capture.pcap", "PCAP Files (*.pcap)"
        )
        if path:
            packets = self.packet_table.get_packets()
            if not packets:
                self.statusbar.showMessage("No packets to save", 3000)
                return
            try:
                from scapy.all import wrpcap
                raw_packets = [p["raw"] for p in packets if p.get("raw")]
                wrpcap(path, raw_packets)
                self.statusbar.showMessage(f"Saved {len(raw_packets)} packets → {path}", 4000)
            except Exception as e:
                self.statusbar.showMessage(f"Save failed: {e}", 4000)

    def export_packets(self):
        """Export packets to CSV or JSON."""
        packets = self.packet_table.get_packets()
        if not packets:
            self.statusbar.showMessage("No packets to export", 3000)
            return

        path, filter = QFileDialog.getSaveFileName(
            self, "Export Packets", "export", "JSON Files (*.json);;CSV Files (*.csv)"
        )
        if not path:
            return

        try:
            if path.endswith(".json"):
                import json
                # Strip raw scapy object for JSON
                export_data = []
                for p in packets:
                    d = p.copy()
                    if "raw" in d: del d["raw"]
                    export_data.append(d)
                with open(path, "w") as f:
                    json.dump(export_data, f, indent=4)
            else:
                import csv
                keys = ["id", "time", "src", "dst", "proto", "length", "summary"]
                with open(path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(packets)
            self.statusbar.showMessage(f"Exported to {path}", 4000)
        except Exception as e:
            self.statusbar.showMessage(f"Export failed: {e}", 4000)

    def load_pcap(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load PCAP", "", "PCAP Files (*.pcap *.cap)"
        )
        if not path:
            return
        # Use a fresh sniffer to load
        loader = PacketSniffer(on_packet=self._on_packet)
        ok, msg = loader.load_pcap(path)
        self.statusbar.showMessage(msg, 4000)

    def _on_packet(self, packet_data):
        self.stats.record(packet_data)
        if not self.paused:
            self.packet_table.add_packet(packet_data)
        self.packet_count += 1

    def _on_credential(self, cred):
        self.cred_panel.add_credential(cred)
        count = self.cred_panel.table.rowCount()
        self.tabs.setTabText(1, f"🔑 Credentials ({count})")

    def _on_error(self, msg):
        self.stop_capture()
        QMessageBox.critical(self, "Capture Error", f"Error: {msg}\n\nMake sure you run as root/sudo.")

    def _show_packet_detail(self, packet_data):
        raw = packet_data.get("raw")
        if not raw:
            return
        layers = dissect_packet(raw)
        text = ""
        for layer_name, fields in layers:
            text += f"{'─'*40}\n  [{layer_name}]\n"
            for k, v in fields.items():
                text += f"    {k:<20} = {v}\n"
        self.detail_panel.setPlainText(text)

    def _apply_filter(self, text):
        self.packet_table.apply_filter(text)

    def _update_status(self):
        summary = self.stats.get_summary()
        bps = self.stats.get_bytes_per_second()
        self.status_packets.setText(f"Packets: {summary['total_packets']}")
        self.status_bytes.setText(f"Bytes: {format_bytes(summary['total_bytes'])}")
        self.status_bps.setText(f"Speed: {format_bytes(bps)}/s")

    def _update_proto_stats(self):
        dist = self.stats.get_proto_distribution()
        if not dist:
            self.proto_stats.clear()
            return
        total = sum(dist.values()) or 1
        lines = []
        for proto, b in sorted(dist.items(), key=lambda x: -x[1]):
            pct = b / total * 100
            bar = "█" * int(pct / 5)
            lines.append(f"{proto:<8} {bar:<20} {pct:.1f}%")
        self.proto_stats.setPlainText("\n".join(lines))

    def closeEvent(self, event):
        self.stop_capture()
        event.accept()

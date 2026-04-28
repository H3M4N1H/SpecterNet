import sys
import os

# Must be set before PyQt6 imports on some systems
os.environ.setdefault("QT_QPA_PLATFORM", "xcb")

# Disable scapy IPv6 to avoid routing bugs on some Linux setups
os.environ['SCAPY_IPV6_ENABLED'] = '0'
try:
    from scapy.config import conf
    conf.ipv6_enabled = False
    conf.verb = 0  # Suppress scapy output
except Exception:
    pass


def check_root():
    """Warn if not running as root (needed for raw packet capture)."""
    if os.name != 'nt' and os.geteuid() != 0:
        print("\n⚠️  Warning: Packet capture requires root/sudo privileges.")
        print("   Run: sudo python main.py\n")


def main():
    check_root()

    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QFont
    from gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("SpecterNet")
    app.setOrganizationName("Dreadonyx")

    font = QFont("JetBrains Mono", 11)
    font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(font)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

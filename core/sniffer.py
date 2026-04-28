import threading

try:
    from scapy.all import sniff, wrpcap, rdpcap
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

from core.analyzer import (
    get_protocol, get_summary, get_src_dst,
    get_packet_length, sniff_credentials
)
from utils.helpers import format_timestamp
from utils.logger import get_logger

logger = get_logger("Sniffer")


class PacketSniffer:
    def __init__(self, on_packet=None, on_credential=None, on_error=None):
        self.on_packet = on_packet
        self.on_credential = on_credential
        self.on_error = on_error
        self.packets = []
        self.running = False
        self._thread = None
        self.interface = None
        self.bpf_filter = ""
        self.packet_count = 0
        self.bytes_captured = 0
        self._lock = threading.Lock()

    def start(self, interface=None, bpf_filter=""):
        if self.running:
            return
        if not SCAPY_OK:
            raise RuntimeError("Scapy not available")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def clear(self):
        with self._lock:
            self.packets = []
            self.packet_count = 0
            self.bytes_captured = 0

    def _capture_loop(self):
        try:
            while self.running:
                sniff(
                    iface=self.interface or None,
                    filter=self.bpf_filter or None,
                    prn=self._process_packet,
                    store=False,
                    timeout=1,
                )
        except PermissionError:
            msg = "[Sniffer] Permission denied — run as root/sudo"
            logger.error(msg)
            if self.on_error:
                self.on_error(msg)
            self.running = False
        except Exception as e:
            msg = f"[Sniffer Error] {e}"
            logger.exception(msg)
            if self.on_error:
                self.on_error(msg)
            self.running = False

    def _process_packet(self, packet):
        try:
            proto = get_protocol(packet)
            src, dst = get_src_dst(packet)
            summary = get_summary(packet)
            length = get_packet_length(packet)
            ts = format_timestamp(packet.time)

            with self._lock:
                self.packet_count += 1
                self.bytes_captured += length
                packet_id = self.packet_count

            packet_data = {
                "id": packet_id,
                "time": ts,
                "src": src,
                "dst": dst,
                "proto": proto,
                "length": length,
                "summary": summary,
                "raw": packet,
            }

            with self._lock:
                self.packets.append(packet_data)

            if self.on_packet:
                self.on_packet(packet_data)

            creds = sniff_credentials(packet)
            for cred in creds:
                if self.on_credential:
                    self.on_credential(cred)

        except Exception:
            pass

    def save_pcap(self, filepath):
        try:
            raw_packets = [p["raw"] for p in self.packets if "raw" in p]
            if raw_packets:
                wrpcap(filepath, raw_packets)
                return True, f"Saved {len(raw_packets)} packets → {filepath}"
            return False, "No packets to save"
        except Exception as e:
            return False, str(e)

    def load_pcap(self, filepath):
        try:
            loaded = rdpcap(filepath)
            for packet in loaded:
                self._process_packet(packet)
            return True, f"Loaded {len(loaded)} packets from {filepath}"
        except Exception as e:
            return False, str(e)

    def get_stats(self):
        with self._lock:
            proto_counts = {}
            for p in self.packets:
                proto = p["proto"]
                proto_counts[proto] = proto_counts.get(proto, 0) + 1
            return {
                "total": self.packet_count,
                "bytes": self.bytes_captured,
                "proto_counts": proto_counts,
            }

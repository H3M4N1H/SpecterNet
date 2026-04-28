import time
import threading
from collections import deque


class TrafficStats:
    def __init__(self, window=60):
        self.window = window  # seconds to keep history
        self._lock = threading.Lock()
        # Each entry: (timestamp, bytes, proto)
        self._history = deque()
        self.proto_totals = {}
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()

    def record(self, packet_data):
        """Record a packet."""
        now = time.time()
        length = packet_data.get("length", 0)
        proto = packet_data.get("proto", "OTHER")

        with self._lock:
            self._history.append((now, length, proto))
            self.proto_totals[proto] = self.proto_totals.get(proto, 0) + length
            self.total_packets += 1
            self.total_bytes += length
            self._cleanup(now)

    def _cleanup(self, now):
        """Remove entries outside the window."""
        cutoff = now - self.window
        while self._history and self._history[0][0] < cutoff:
            self._history.popleft()

    def get_bytes_per_second(self):
        """Return bytes/sec over last second."""
        now = time.time()
        with self._lock:
            cutoff = now - 1.0
            recent = sum(length for ts, length, _ in self._history if ts >= cutoff)
        return recent

    def get_proto_bytes_per_second(self):
        """Return dict of proto → bytes/sec over last second."""
        now = time.time()
        cutoff = now - 1.0
        proto_bytes = {}
        with self._lock:
            for ts, length, proto in self._history:
                if ts >= cutoff:
                    proto_bytes[proto] = proto_bytes.get(proto, 0) + length
        return proto_bytes

    def get_timeline(self, seconds=30):
        """Return list of (time_offset, bytes) for graph."""
        now = time.time()
        buckets = {}
        with self._lock:
            for ts, length, proto in self._history:
                offset = int(now - ts)
                if offset <= seconds:
                    buckets[offset] = buckets.get(offset, 0) + length

        # Fill gaps with 0
        timeline = [(i, buckets.get(i, 0)) for i in range(seconds, -1, -1)]
        return timeline

    def get_proto_distribution(self):
        with self._lock:
            return dict(self.proto_totals)

    def get_summary(self):
        elapsed = time.time() - self.start_time
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "elapsed": elapsed,
                "avg_bps": self.total_bytes / max(elapsed, 1),
                "proto_totals": dict(self.proto_totals),
            }

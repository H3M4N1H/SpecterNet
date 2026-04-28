import socket
import threading
from utils.helpers import SERVICE_PORTS
from utils.logger import get_logger

logger = get_logger("Scanner")


class PortScanner:
    def __init__(self, on_result=None, on_done=None):
        self.on_result = on_result  # callback(port, status, service)
        self.on_done = on_done      # callback(results)
        self.results = {}
        self.running = False
        self._lock = threading.Lock()

    def scan(self, target, ports=None, threads=100, timeout=1.0):
        """Start threaded port scan."""
        if ports is None:
            ports = list(range(1, 1025)) + list(SERVICE_PORTS.keys())
            ports = sorted(set(ports))

        self.results = {}
        self.running = True

        scan_thread = threading.Thread(
            target=self._scan_loop,
            args=(target, ports, threads, timeout),
            daemon=True
        )
        scan_thread.start()

    def _scan_loop(self, target, ports, max_threads, timeout):
        semaphore = threading.Semaphore(max_threads)
        threads = []

        for port in ports:
            if not self.running:
                break
            t = threading.Thread(
                target=self._check_port,
                args=(target, port, timeout, semaphore),
                daemon=True
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.running = False
        if self.on_done:
            self.on_done(self.results)

    def _check_port(self, target, port, timeout, semaphore):
        with semaphore:
            if not self.running:
                return
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()

                status = "open" if result == 0 else "closed"
                service = SERVICE_PORTS.get(port, self._grab_banner(target, port) if result == 0 else "")

                with self._lock:
                    self.results[port] = {"status": status, "service": service}

                if status == "open" and self.on_result:
                    self.on_result(port, status, service)

            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")

    def _grab_banner(self, target, port):
        """Try to grab service banner."""
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            banner = s.recv(256).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner[:30] if banner else "unknown"
        except Exception:
            return "unknown"

    def stop(self):
        self.running = False

    def get_open_ports(self):
        return {p: v for p, v in self.results.items() if v["status"] == "open"}

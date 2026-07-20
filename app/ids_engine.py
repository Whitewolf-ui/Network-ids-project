"""
ids_engine.py — Packet monitoring engine.
"""
import threading
import datetime
import subprocess
import re
from collections import defaultdict

from app import database

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

PORT_SCAN_THRESHOLD = 5  # unique ports from one IP = suspicious
DANGEROUS_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL"}


def get_available_interfaces():
    """Return list of available network interfaces on the system."""
    interfaces = ["lo"]  # always include loopback
    try:
        # Try ip command first
        result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            match = re.search(r'\d+:\s+([^:@]+)', line)
            if match:
                iface = match.group(1).strip()
                if iface not in interfaces and iface != "lo":
                    interfaces.append(iface)
    except Exception:
        pass
    
    try:
        # Fallback to ifconfig
        result = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            match = re.match(r'^([a-zA-Z0-9_-]+):', line)
            if match:
                iface = match.group(1)
                if iface not in interfaces:
                    interfaces.append(iface)
    except Exception:
        pass
    
    return interfaces


class NetworkIDS:
    def __init__(self, iface="lo"):
        self.iface = iface
        self.user_id = None
        self._thread = None
        self._stop_event = threading.Event()
        self.running = False
        self.started_at = None
        self.session_id = None
        self.connection_count = defaultdict(set)
        self._error = None
        self._lock = threading.Lock()

    def status(self):
        with self._lock:
            return {
                "running": self.running,
                "started_at": self.started_at,
                "iface": self.iface,
                "user_id": self.user_id,
                "monitored_ips": len(self.connection_count),
                "scapy_available": SCAPY_AVAILABLE,
                "error": self._error,
            }

    def _packet_monitor(self, packet):
        if self._stop_event.is_set():
            return False  # Tell sniff to stop

        if packet.haslayer(IP) and packet.haslayer(TCP):
            source_ip = packet[IP].src
            dest_port = packet[TCP].dport

            self.connection_count[source_ip].add(dest_port)
            unique_ports = len(self.connection_count[source_ip])

            if unique_ports == PORT_SCAN_THRESHOLD:
                try:
                    database.insert_alert(
                        user_id=self.user_id,
                        alert_type="port_scan",
                        source_ip=source_ip,
                        unique_ports=unique_ports,
                        details=f"Ports: {sorted(self.connection_count[source_ip])}",
                    )
                except Exception as e:
                    print(f"[IDS] Alert insert error: {e}", flush=True)

            if dest_port in DANGEROUS_PORTS:
                try:
                    database.insert_alert(
                        user_id=self.user_id,
                        alert_type="sensitive_port",
                        source_ip=source_ip,
                        dest_port=dest_port,
                        details=f"Attempted connection to {DANGEROUS_PORTS[dest_port]} (port {dest_port})",
                    )
                except Exception as e:
                    print(f"[IDS] Alert insert error: {e}", flush=True)

    def _run(self):
        try:
            print(f"[IDS] Starting sniff on interface: {self.iface}", flush=True)
            sniff(
                prn=self._packet_monitor,
                filter="tcp",
                store=0,
                iface=self.iface,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
            print("[IDS] Sniff stopped normally", flush=True)
        except PermissionError:
            with self._lock:
                self._error = "Permission denied — run the app with sudo/root to capture packets."
                self.running = False
            print(f"[IDS] PermissionError: {self._error}", flush=True)
        except OSError as e:
            with self._lock:
                self._error = f"Interface error on '{self.iface}': {e}"
                self.running = False
            print(f"[IDS] OSError: {self._error}", flush=True)
        except Exception as e:
            with self._lock:
                self._error = f"Unexpected error: {e}"
                self.running = False
            print(f"[IDS] Exception: {self._error}", flush=True)
        finally:
            with self._lock:
                self.running = False
                if self.session_id:
                    try:
                        database.stop_session(self.session_id)
                    except Exception:
                        pass
            print("[IDS] Engine thread ended", flush=True)

    def start(self, user_id, iface=None):
        if self.running:
            return False, "Already running."
        if not SCAPY_AVAILABLE:
            return False, "Scapy is not installed in this environment."

        if iface:
            self.iface = iface
        self.user_id = user_id
        self._error = None
        self._stop_event.clear()
        self.connection_count = defaultdict(set)
        self.started_at = datetime.datetime.now().isoformat()
        
        try:
            self.session_id = database.start_session()
        except Exception as e:
            print(f"[IDS] Failed to start session: {e}", flush=True)
            self.session_id = None
        
        with self._lock:
            self.running = True
        
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return True, "Monitoring started."

    def stop(self):
        if not self.running:
            return False, "Not currently running."
        print("[IDS] Stopping engine...", flush=True)
        self._stop_event.set()
        with self._lock:
            self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        if self.session_id:
            try:
                database.stop_session(self.session_id)
            except Exception:
                pass
        return True, "Monitoring stopped."


engine = NetworkIDS()
"""
ids_engine.py — Packet monitoring engine.

This wraps the original simple_ids.py detection logic (port-scan detection +
sensitive-port monitoring via Scapy) into a start/stop-able background thread
that the web dashboard can control, with alerts persisted to SQLite instead
of just a flat text file.
"""
import threading
import datetime
from collections import defaultdict

from app import database

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

PORT_SCAN_THRESHOLD = 5  # unique ports from one IP = suspicious
DANGEROUS_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL"}


class NetworkIDS:
    def __init__(self, iface="lo"):
        self.iface = iface
        self._thread = None
        self._stop_event = threading.Event()
        self.running = False
        self.started_at = None
        self.session_id = None
        self.connection_count = defaultdict(set)
        self._error = None

    def status(self):
        return {
            "running": self.running,
            "started_at": self.started_at,
            "iface": self.iface,
            "monitored_ips": len(self.connection_count),
            "scapy_available": SCAPY_AVAILABLE,
            "error": self._error,
        }

    def _packet_monitor(self, packet):
        if self._stop_event.is_set():
            return

        if packet.haslayer(IP) and packet.haslayer(TCP):
            source_ip = packet[IP].src
            dest_port = packet[TCP].dport

            self.connection_count[source_ip].add(dest_port)
            unique_ports = len(self.connection_count[source_ip])

            if unique_ports == PORT_SCAN_THRESHOLD:
                database.insert_alert(
                    alert_type="port_scan",
                    source_ip=source_ip,
                    unique_ports=unique_ports,
                    details=f"Ports: {sorted(self.connection_count[source_ip])}",
                )

            if dest_port in DANGEROUS_PORTS:
                database.insert_alert(
                    alert_type="sensitive_port",
                    source_ip=source_ip,
                    dest_port=dest_port,
                    details=f"Attempted connection to {DANGEROUS_PORTS[dest_port]} (port {dest_port})",
                )

    def _run(self):
        try:
            sniff(
                prn=self._packet_monitor,
                filter="tcp",
                store=0,
                iface=self.iface,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except PermissionError:
            self._error = "Permission denied — run the app with sudo/root to capture packets."
        except OSError as e:
            self._error = f"Interface error on '{self.iface}': {e}"
        except Exception as e:  # noqa: BLE001
            self._error = str(e)
        finally:
            self.running = False

    def start(self, iface=None):
        if self.running:
            return False, "Already running."
        if not SCAPY_AVAILABLE:
            return False, "Scapy is not installed in this environment."

        if iface:
            self.iface = iface
        self._error = None
        self._stop_event.clear()
        self.connection_count = defaultdict(set)
        self.started_at = datetime.datetime.now().isoformat()
        self.session_id = database.start_session()
        self.running = True

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return True, "Monitoring started."

    def stop(self):
        if not self.running:
            return False, "Not currently running."
        self._stop_event.set()
        self.running = False
        if self.session_id:
            database.stop_session(self.session_id)
        return True, "Monitoring stopped."


engine = NetworkIDS()

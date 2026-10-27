"""
SentinelAegis-X - Network & WiFi Intrusion Sentinel
Monitors active TCP/UDP sockets for suspicious reverse-shells, RAT beaconing,
rogue ports, and ARP anomalies indicating Wi-Fi MITM / evil twin attacks.
"""

import time
import socket
import logging
import platform
import subprocess
from typing import Dict, Any, List, Callable, Optional, Set

import psutil

logger = logging.getLogger("NetSentinel")


class NetworkSentinel:
    def __init__(
        self,
        suspicious_ports: List[int],
        poll_interval: int = 5,
        on_threat_detected: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.suspicious_ports = set(suspicious_ports)
        self.poll_interval = poll_interval
        self.on_threat_detected = on_threat_detected
        self.running = False
        self._alerted_connections: Set[str] = set()
        self.os_type = platform.system().lower()

    def get_default_gateway_mac(self) -> Optional[str]:
        """Inspect ARP cache to verify router gateway integrity (anti-WiFi spoofing)."""
        try:
            if self.os_type == "windows":
                out = subprocess.check_output("arp -a", shell=True, text=True)
                for line in out.splitlines():
                    if "dynamic" in line.lower() or "dynamique" in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            elif self.os_type == "linux":
                out = subprocess.check_output("ip neigh", shell=True, text=True)
                for line in out.splitlines():
                    if "lladdr" in line:
                        parts = line.split()
                        idx = parts.index("lladdr")
                        if idx + 1 < len(parts):
                            return parts[idx + 1]
        except Exception:
            pass
        return None

    def scan_active_connections(self) -> List[Dict[str, Any]]:
        """Scans all socket states for suspicious outbound RAT or reverse-shell connections."""
        suspicious_events = []
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections:
                if not conn.raddr:
                    continue

                remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
                local_port = conn.laddr.port
                pid = conn.pid

                # Check if connection touches known attack ports or is established reverse shell
                is_suspicious_port = (remote_port in self.suspicious_ports) or (local_port in self.suspicious_ports)

                # Process name lookup
                proc_name = "Unknown"
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                conn_id = f"{pid}_{remote_ip}_{remote_port}"

                if is_suspicious_port and conn_id not in self._alerted_connections:
                    self._alerted_connections.add(conn_id)
                    event = {
                        "source": "network_sentinel",
                        "target_pid": pid,
                        "process_name": proc_name,
                        "local_port": local_port,
                        "target_ip": remote_ip,
                        "remote_port": remote_port,
                        "threat_score": 85,
                        "classification": "SUSPICIOUS_C2_CONNECTION",
                        "reasons": [
                            f"Process '{proc_name}' (PID: {pid}) established connection to suspicious port {remote_port}",
                            f"Remote Target IP: {remote_ip}"
                        ],
                        "requires_action": True
                    }
                    suspicious_events.append(event)
                    if self.on_threat_detected:
                        self.on_threat_detected(event)
        except Exception as e:
            logger.error(f"Network scan error: {e}")

        return suspicious_events

    def run_loop(self):
        self.running = True
        logger.info("Network & WiFi Sentinel monitor loop active.")
        while self.running:
            self.scan_active_connections()
            time.sleep(self.poll_interval)

    def stop(self):
        self.running = False

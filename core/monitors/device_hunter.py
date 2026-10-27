"""
SentinelAegis-X - Rogue Device & Mobile Phone Hunter
Discovers, enumerates, and fingerprints all active devices, phones, and MAC addresses
on the local Wi-Fi / LAN subnet. Distinguishes between SELF workstation and unknown foreign devices.
"""

import os
import re
import sys
import json
import time
import socket
import logging
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger("DeviceHunter")

# Common Mobile Phone & Hardware OUI Vendor Database
OUI_DATABASE = {
    "64:F8:8A": "TP-Link Technologies",
    "F4:F5:DB": "Apple Inc. (iPhone/iPad)",
    "3C:06:30": "Apple Inc. (iPhone/iPad)",
    "AC:DE:48": "Apple Inc. (Mac/iPhone)",
    "F0:18:98": "Apple Inc. (iPhone)",
    "9C:8C:6E": "Apple Inc. (iPhone)",
    "A4:C3:61": "Apple Inc. (iPhone)",
    "28:6A:BA": "Apple Inc. (iPhone)",
    "50:ED:3C": "Samsung Electronics (Galaxy Mobile)",
    "DC:BF:E9": "Samsung Electronics (Galaxy Mobile)",
    "38:01:46": "Samsung Electronics (Galaxy Mobile)",
    "78:4B:87": "Samsung Electronics (Galaxy Mobile)",
    "B0:72:BF": "Xiaomi Communications (Redmi / Poco)",
    "7C:03:D8": "Xiaomi Communications (Redmi / Mi)",
    "D4:97:0B": "Xiaomi Communications (Redmi / Mi)",
    "28:6C:07": "Xiaomi Communications (Poco / Redmi)",
    "8C:85:90": "OnePlus Technology",
    "70:70:8B": "OnePlus Technology",
    "40:4E:36": "Huawei Device Co.",
    "00:E0:4C": "Realtek Semiconductor",
    "B4:2E:99": "Intel Corporate (Wi-Fi)",
    "C8:5A:CF": "Vivo Mobile Communication",
    "30:75:12": "Oppo Mobile",
    "34:60:F9": "Google Pixel Mobile",
    "44:07:0B": "Google LLC (Pixel / Nest)",
}


class NetworkDeviceHunter:
    def __init__(self, settings_path: str = "config/settings.json", on_device_detected=None):
        self.settings_path = settings_path
        self.on_device_detected = on_device_detected
        self.settings = self._load_settings()
        self.known_macs: Set[str] = set()
        self._init_known_devices()

    def _load_settings(self) -> Dict[str, Any]:
        if os.path.exists(self.settings_path):
            with open(self.settings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _init_known_devices(self):
        dev_cfg = self.settings.get("device_monitoring", {})
        for kd in dev_cfg.get("known_devices", []):
            if kd.get("mac"):
                self.known_macs.add(kd["mac"].lower().replace("-", ":"))

    @staticmethod
    def get_mac_vendor(mac: str) -> str:
        """Looks up the manufacturer of the MAC address to identify phone brands."""
        clean_mac = mac.upper().replace("-", ":")
        oui_prefix = clean_mac[:8]
        if oui_prefix in OUI_DATABASE:
            return OUI_DATABASE[oui_prefix]
        
        # Heuristic check for common randomized MACs (locally administered bit)
        first_byte = clean_mac.split(":")[0]
        try:
            if int(first_byte, 16) & 0x02:
                return "Private / Randomized MAC (Android / iOS Privacy Mode)"
        except Exception:
            pass
        return "Unknown Manufacturer / Generic Network Device"

    @staticmethod
    def resolve_hostname(ip: str) -> str:
        """Attempts reverse DNS and NetBIOS lookup for phone or workstation name."""
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            # Fallback to NetBIOS nbtstat on Windows
            if platform.system().lower() == "windows":
                try:
                    out = subprocess.check_output(f"nbtstat -A {ip}", shell=True, text=True, timeout=2)
                    for line in out.splitlines():
                        if "<00>" in line and "UNIQUE" in line:
                            parts = line.split()
                            if parts:
                                return parts[0].strip()
                except Exception:
                    pass
            return "Unresolved Hostname"

    def get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def sweep_ping(self, base_ip: str, host_id: int):
        target = f"{base_ip}.{host_id}"
        param = "-n 1 -w 150" if platform.system().lower() == "windows" else "-c 1 -W 1"
        try:
            subprocess.run(f"ping {param} {target}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def scan_subnet(self, subnet_base: str = "192.168.1") -> List[Dict[str, Any]]:
        """Active fast sweep to populate system ARP table with all active phones/devices."""
        logger.info(f"Initiating fast active ARP sweep on {subnet_base}.0/24...")
        with ThreadPoolExecutor(max_workers=50) as executor:
            for host in range(1, 255):
                executor.submit(self.sweep_ping, subnet_base, host)

        # Parse refreshed ARP table
        devices = self.get_active_arp_devices()
        return devices

    def get_active_arp_devices(self) -> List[Dict[str, Any]]:
        """Parses OS ARP table to pull all active devices and attributes them."""
        devices = []
        my_local_ip = self.get_local_ip()

        try:
            if platform.system().lower() == "windows":
                out = subprocess.check_output("arp -a", shell=True, text=True)
                for line in out.splitlines():
                    line = line.strip()
                    if not line or "Interface" in line or "Internet Address" in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        ip_addr, mac_addr, entry_type = parts[0], parts[1], parts[2]
                        if entry_type.lower() != "dynamic":
                            continue
                        
                        clean_mac = mac_addr.lower().replace("-", ":")
                        vendor = self.get_mac_vendor(clean_mac)
                        hostname = self.resolve_hostname(ip_addr)

                        is_self = (ip_addr == my_local_ip)
                        is_gateway = ip_addr.endswith(".1")
                        is_known = (clean_mac in self.known_macs) or is_self or is_gateway

                        dev_info = {
                            "ip": ip_addr,
                            "mac": clean_mac,
                            "vendor": vendor,
                            "hostname": hostname,
                            "is_self": is_self,
                            "is_gateway": is_gateway,
                            "is_known": is_known,
                            "device_type": "SELF_WORKSTATION" if is_self else ("GATEWAY_ROUTER" if is_gateway else "UNKNOWN_PHONE_OR_DEVICE"),
                            "attribution": "YOUR_MACHINE" if is_self else ("YOUR_ROUTER" if is_gateway else "FOREIGN_OR_MOBILE_DEVICE"),
                            "risk_level": "INFO" if is_known else "WARNING_UNKNOWN_LINK"
                        }
                        devices.append(dev_info)
        except Exception as e:
            logger.error(f"Error parsing ARP devices: {e}")

        return devices

    def check_for_unknown_devices(self) -> List[Dict[str, Any]]:
        """Flags any device that is NOT the user's computer or router."""
        all_devices = self.get_active_arp_devices()
        unknown_devices = [d for d in all_devices if not d["is_known"]]

        for u in unknown_devices:
            if self.on_device_detected:
                self.on_device_detected(u)

        return unknown_devices

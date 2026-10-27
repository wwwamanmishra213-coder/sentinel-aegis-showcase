"""
SentinelAegis-X - Cross-Platform Fightback & Quarantine Remediation Engine
Executes process termination, encrypted file quarantine, and network firewall isolation
ONLY upon receiving approved authorization from the Human Gate.
Supports Linux (iptables, SIGKILL, socket severance) and Windows (netsh, taskkill, process trees).
"""

import os
import sys
import json
import time
import shutil
import platform
import subprocess
from typing import Dict, Any, Optional

import psutil


class RemediationEngine:
    def __init__(self, vault_path: str = "./vault", xor_key: int = 165):
        self.vault_path = os.path.abspath(vault_path)
        self.xor_key = xor_key
        self.os_type = platform.system().lower()
        os.makedirs(self.vault_path, exist_ok=True)

    def _xor_encrypt_file(self, source_path: str, dest_path: str):
        """Scrambles malicious executable bytes so it cannot be executed in the vault."""
        with open(source_path, "rb") as fin, open(dest_path, "wb") as fout:
            while chunk := fin.read(65536):
                fout.write(bytes([b ^ self.xor_key for b in chunk]))

    def quarantine_file(self, file_path: str, incident_id: str, hashes: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Moves and XOR-encrypts malicious file into secure isolated vault."""
        if not os.path.exists(file_path):
            return {"success": False, "error": f"Target file does not exist: {file_path}"}

        try:
            sha256 = hashes.get("sha256") if hashes else hashlib.sha256(open(file_path, "rb").read()).hexdigest()
            vault_filename = f"{sha256}.vault"
            vault_full_path = os.path.join(self.vault_path, vault_filename)
            meta_path = os.path.join(self.vault_path, f"{sha256}.meta.json")

            # Encrypt into vault
            self._xor_encrypt_file(file_path, vault_full_path)

            # Restrict permissions (read-only for owner)
            os.chmod(vault_full_path, 0o400)

            # Write metadata sidecar
            meta_data = {
                "incident_id": incident_id,
                "original_path": os.path.abspath(file_path),
                "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "sha256": sha256,
                "file_size": os.path.getsize(file_path),
                "vault_file": vault_full_path
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta_data, f, indent=2)

            # Securely erase original file from disk
            try:
                # Zero out file before unlinking
                file_size = os.path.getsize(file_path)
                with open(file_path, "wb") as f:
                    f.write(b"\x00" * min(file_size, 1024 * 1024))
            except Exception:
                pass
            os.remove(file_path)

            return {
                "success": True,
                "vault_path": vault_full_path,
                "message": f"File quarantined and XOR-scrambled to {vault_filename}"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def terminate_process_tree(self, pid: int) -> Dict[str, Any]:
        """Force terminates a malicious process and all its child processes."""
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)

            terminated_pids = []
            for child in children:
                try:
                    child.kill()
                    terminated_pids.append(child.pid)
                except psutil.NoSuchProcess:
                    pass

            parent.kill()
            terminated_pids.append(pid)

            return {
                "success": True,
                "terminated_pids": terminated_pids,
                "message": f"Killed process tree for PID {pid} (Targets: {terminated_pids})"
            }
        except psutil.NoSuchProcess:
            return {"success": True, "message": f"Process {pid} already dead"}
        except psutil.AccessDenied:
            # Fallback to system elevated kill commands
            if self.os_type == "windows":
                cmd = f"taskkill /F /T /PID {pid}"
            else:
                cmd = f"kill -9 {pid}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return {
                "success": res.returncode == 0,
                "message": res.stdout or res.stderr
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def isolate_network_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Linux Fight Back & Windows Firewall system: Drops all inbound and outbound
        packets to the attacker or rogue C2 IP.
        """
        if not ip_address or ip_address in ["127.0.0.1", "0.0.0.0", "::1"]:
            return {"success": False, "error": "Cannot block loopback/unspecified IP"}

        if self.os_type == "linux":
            # Linux fightback system using iptables
            in_cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            out_cmd = f"iptables -A OUTPUT -d {ip_address} -j DROP"
            res_in = subprocess.run(in_cmd, shell=True, capture_output=True, text=True)
            res_out = subprocess.run(out_cmd, shell=True, capture_output=True, text=True)
            return {
                "success": res_in.returncode == 0 and res_out.returncode == 0,
                "platform": "linux",
                "rules_applied": [in_cmd, out_cmd],
                "output": (res_in.stdout + res_out.stdout).strip()
            }
        elif self.os_type == "windows":
            # Windows netsh defense
            rule_name = f"SentinelBlock_{ip_address.replace('.', '_')}"
            in_cmd = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip_address}'
            out_cmd = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip_address}'
            res_in = subprocess.run(in_cmd, shell=True, capture_output=True, text=True)
            res_out = subprocess.run(out_cmd, shell=True, capture_output=True, text=True)
            return {
                "success": res_in.returncode == 0,
                "platform": "windows",
                "rules_applied": [in_cmd, out_cmd],
                "output": res_in.stdout.strip()
            }
        else:
            return {"success": False, "error": f"Unsupported OS: {self.os_type}"}

    def execute_approved_remediation(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master gatekeeper: ONLY called when HumanGate marks incident APPROVED.
        Executes the authorized remediation and logs outcome.
        """
        action = incident.get("operator_action")
        results = []

        # 1. Process termination
        target_pid = incident.get("target_pid")
        if target_pid and action in ["KILL", "KILL_AND_QUARANTINE"]:
            kill_res = self.terminate_process_tree(target_pid)
            results.append({"type": "process_termination", "result": kill_res})

        # 2. File Quarantine
        target_path = incident.get("target_path")
        if target_path and action in ["QUARANTINE", "KILL_AND_QUARANTINE"]:
            hashes = incident.get("metadata", {}).get("hashes", {})
            quar_res = self.quarantine_file(target_path, incident.get("incident_id"), hashes)
            results.append({"type": "file_quarantine", "result": quar_res})

        # 3. Network Isolation
        target_ip = incident.get("target_ip")
        if target_ip and action in ["ISOLATE_IP", "KILL_AND_QUARANTINE", "KILL"]:
            iso_res = self.isolate_network_ip(target_ip)
            results.append({"type": "network_isolation", "result": iso_res})

        return {
            "incident_id": incident.get("incident_id"),
            "action": action,
            "results": results
        }

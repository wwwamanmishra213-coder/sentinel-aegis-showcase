"""
SentinelAegis-X - Discord Telemetry & C2 Integration
Sends cyber-defense alerts to Discord via Webhooks and runs an optional
operator bot for approving remediation actions directly from Discord.
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any, Optional

import requests

logger = logging.getLogger("SentinelDiscord")


class DiscordC2:
    def __init__(self, settings_path: str = "config/settings.json", human_gate=None, remediation_engine=None):
        self.settings_path = settings_path
        self.human_gate = human_gate
        self.remediation_engine = remediation_engine
        self.settings = self._load_settings()

    def _load_settings(self) -> Dict[str, Any]:
        if os.path.exists(self.settings_path):
            with open(self.settings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def get_webhook_url(self) -> str:
        return self.settings.get("discord", {}).get("webhook_url", "")

    def send_incident_alert(self, incident: Dict[str, Any]) -> bool:
        """Dispatches structured embed alert to Discord Webhook."""
        webhook_url = self.get_webhook_url()
        if not webhook_url or "YOUR_WEBHOOK_HERE" in webhook_url:
            logger.warning("Discord webhook URL not configured.")
            return False

        threat_score = incident.get("threat_score", 0)
        classification = incident.get("classification", "UNKNOWN")
        incident_id = incident.get("incident_id", "INC-XXXX")

        # Color based on threat level
        if threat_score >= 80:
            color = 0xFF0033  # Red
        elif threat_score >= 50:
            color = 0xFF9900  # Orange
        else:
            color = 0x33CC33  # Green

        reasons = incident.get("summary", [])
        reasons_formatted = "\n• " + "\n• ".join(reasons[:6]) if reasons else "Heuristic anomaly detected"

        fields = [
            {"name": "Incident ID", "value": f"`{incident_id}`", "inline": True},
            {"name": "Threat Score", "value": f"**{threat_score}/100**", "inline": True},
            {"name": "Classification", "value": f"`{classification}`", "inline": True},
        ]

        if incident.get("target_path"):
            fields.append({"name": "Target File", "value": f"`{incident['target_path']}`", "inline": False})
        if incident.get("target_pid"):
            fields.append({"name": "Target PID", "value": f"`{incident['target_pid']}`", "inline": True})
        if incident.get("target_ip"):
            fields.append({"name": "Target IP", "value": f"`{incident['target_ip']}`", "inline": True})

        sha256 = incident.get("metadata", {}).get("hashes", {}).get("sha256")
        if sha256:
            fields.append({"name": "SHA-256", "value": f"`{sha256}`", "inline": False})

        fields.append({"name": "Detection Reasons", "value": reasons_formatted[:1024], "inline": False})
        fields.append({
            "name": "Operator Action Required",
            "value": f"System is on STANDBY waiting for your approval.\n"
                     f"**1-Click Dashboard:** http://127.0.0.1:8800\n"
                     f"**Discord Bot Command:** `!approve {incident_id} kill`",
            "inline": False
        })

        payload = {
            "username": "SentinelAegis-X Defense Engine",
            "avatar_url": "https://img.icons8.com/fluency/96/shield.png",
            "embeds": [{
                "title": f"🛡️ THREAT DETECTED: {classification}",
                "description": "Malware/Anomaly Hunter has flagged an aggressive indicator. No action taken yet.",
                "color": color,
                "fields": fields,
                "footer": {"text": "SentinelAegis-X • Human-In-The-Loop Defense Gate"}
            }]
        }

        try:
            resp = requests.post(webhook_url, json=payload, timeout=8)
            return resp.status_code in [200, 204]
        except Exception as e:
            logger.error(f"Failed to post to Discord webhook: {e}")
            return False

    def send_resolution_alert(self, incident_id: str, action: str, details: str) -> bool:
        """Sends confirmation to Discord after human authorizes kill/quarantine."""
        webhook_url = self.get_webhook_url()
        if not webhook_url or "YOUR_WEBHOOK_HERE" in webhook_url:
            return False

        payload = {
            "username": "SentinelAegis-X Defense Engine",
            "avatar_url": "https://img.icons8.com/fluency/96/shield.png",
            "embeds": [{
                "title": f"⚡ REMEDIATION EXECUTED: {action}",
                "description": f"Incident `{incident_id}` resolved under operator authorization.",
                "color": 0x00FF99,
                "fields": [
                    {"name": "Authorized Action", "value": f"`{action}`", "inline": True},
                    {"name": "Status", "value": "SUCCESSFULLY EXECUTED", "inline": True},
                    {"name": "Details", "value": f"```{details}```", "inline": False}
                ],
                "footer": {"text": "SentinelAegis-X • Remediated"}
            }]
        }
        try:
            resp = requests.post(webhook_url, json=payload, timeout=8)
            return resp.status_code in [200, 204]
        except Exception:
            return False

    def send_device_alert(self, device: Dict[str, Any]) -> bool:
        """Dispatches an alert when an unknown mobile phone or foreign MAC links to the network."""
        webhook_url = self.get_webhook_url()
        if not webhook_url or "YOUR_WEBHOOK_HERE" in webhook_url:
            return False

        fields = [
            {"name": "Device Type", "value": f"`{device.get('device_type', 'UNKNOWN')}`", "inline": True},
            {"name": "IP Address", "value": f"`{device.get('ip', 'N/A')}`", "inline": True},
            {"name": "MAC Address", "value": f"`{device.get('mac', 'N/A')}`", "inline": True},
            {"name": "Hardware / Phone Brand", "value": f"**{device.get('vendor', 'Unknown')}**", "inline": False},
            {"name": "Hostname", "value": f"`{device.get('hostname', 'Unresolved')}`", "inline": True},
            {"name": "Attribution", "value": f"⚠️ **{device.get('attribution', 'FOREIGN_DEVICE')}**", "inline": True},
            {
                "name": "Operator Action Required",
                "value": "An unrecognized phone or computer linked to your Wi-Fi.\n"
                         "• To isolate this device: Authorize network block via dashboard.\n"
                         "• If this is your personal device: Add MAC to `known_devices` in settings.",
                "inline": False
            }
        ]

        payload = {
            "username": "SentinelAegis-X Network Sentinel",
            "avatar_url": "https://img.icons8.com/fluency/96/shield.png",
            "embeds": [{
                "title": f"📱 UNKNOWN DEVICE DETECTED: {device.get('vendor', 'Foreign MAC')}",
                "description": "A new device/phone was identified on your local Wi-Fi subnet.",
                "color": 0xFFAA00,
                "fields": fields,
                "footer": {"text": "SentinelAegis-X // Rogue Device Attribution"}
            }]
        }

        try:
            resp = requests.post(webhook_url, json=payload, timeout=8)
            return resp.status_code in [200, 204]
        except Exception as e:
            logger.error(f"Failed to post device alert to Discord: {e}")
            return False

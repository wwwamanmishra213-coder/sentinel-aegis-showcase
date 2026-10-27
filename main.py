"""
SentinelAegis-X - Master Orchestrator Daemon
Integrates Static/Heuristic Analyzer, Developer Whitelist, Rogue Device Hunter,
Gmail Security Auditor, Threat Learning, Human Approval Gate, and Web UI/Discord C2.
"""

import os
import sys
import json
import logging
import threading
from typing import Dict, Any, Optional, List

import uvicorn
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from core.analyzer import MalwareAnalyzer
from core.learning_engine import ThreatLearningEngine
from core.human_gate import HumanGate, IncidentStatus
from core.remediation import RemediationEngine
from core.discord_c2 import DiscordC2
from core.monitors.fs_watcher import FileSystemSentinel
from core.monitors.net_watcher import NetworkSentinel
from core.monitors.mail_parser import PhishingEmailParser
from core.monitors.device_hunter import NetworkDeviceHunter
from core.monitors.gmail_fetcher import GmailSecurityAuditor

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"
)
logger = logging.getLogger("SentinelMaster")

# Initialize Core Services
SETTINGS_PATH = "config/settings.json"
RULES_PATH = "config/rules.json"

analyzer = MalwareAnalyzer(rules_path=RULES_PATH, settings_path=SETTINGS_PATH)
learning_engine = ThreatLearningEngine(settings_path=SETTINGS_PATH)
human_gate = HumanGate()
remediation_engine = RemediationEngine(vault_path="./vault")
discord_c2 = DiscordC2(
    settings_path=SETTINGS_PATH,
    human_gate=human_gate,
    remediation_engine=remediation_engine
)
mail_parser = PhishingEmailParser(rules_path=RULES_PATH, analyzer=analyzer)
gmail_auditor = GmailSecurityAuditor(settings_path=SETTINGS_PATH, mail_parser=mail_parser)


def on_unknown_device_found(device: Dict[str, Any]):
    """Callback when an unknown mobile phone or foreign MAC links to the network."""
    logger.warning(f"ROGUE/UNKNOWN DEVICE IDENTIFIED: {device.get('ip')} [{device.get('mac')}] ({device.get('vendor')})")
    
    # 1. Alert Discord immediately
    discord_c2.send_device_alert(device)

    # 2. Register with Human Gate as an investigative incident
    threat_event = {
        "source": "device_hunter",
        "target_ip": device.get("ip"),
        "target_mac": device.get("mac"),
        "threat_score": 75,
        "classification": "UNKNOWN_NETWORK_DEVICE",
        "reasons": [
            f"Unrecognized device linked to Wi-Fi: {device.get('ip')}",
            f"Hardware / Phone Brand: {device.get('vendor')}",
            f"MAC Address: {device.get('mac')}",
            f"Hostname: {device.get('hostname')}"
        ],
        "requires_action": True,
        "device_metadata": device
    }
    human_gate.register_threat(threat_event)


device_hunter = NetworkDeviceHunter(settings_path=SETTINGS_PATH, on_device_detected=on_unknown_device_found)

app = FastAPI(title="SentinelAegis-X Cyber Defense")

# Mount static files
app.mount("/static", StaticFiles(directory="ui/static"), name="static")


def on_file_threat_detected(file_path: str):
    """Callback when Filesystem Sentinel encounters a file modification/creation."""
    logger.info(f"Scanning target file: {file_path}")
    analysis = analyzer.analyze_file(file_path)

    # If whitelisted self-developer file, skip alerting
    if analysis.get("is_self_program"):
        logger.info(f"Self-developer file verified: {file_path} - Whitelisted (Zero alert)")
        return

    if analysis.get("threat_score", 0) >= 50:
        rep = learning_engine.check_hash_reputation(analysis.get("hashes", {}).get("sha256", ""))
        if rep.get("is_known_malware"):
            analysis["threat_score"] = 100
            analysis["reasons"].append("Matches confirmed malware signature in Threat Intel feed")

        incident = human_gate.register_threat(analysis)
        logger.warning(f"THREAT FLAGGED: {incident['incident_id']} (Score: {analysis['threat_score']}) - WAITING OPERATOR APPROVAL")
        discord_c2.send_incident_alert(incident)
        learning_engine.learn_from_sample(analysis)


def on_network_threat_detected(event: Dict[str, Any]):
    """Callback when Network Sentinel identifies rogue connection or reverse shell."""
    incident = human_gate.register_threat(event)
    logger.warning(f"NETWORK THREAT FLAGGED: {incident['incident_id']} - WAITING OPERATOR APPROVAL")
    discord_c2.send_incident_alert(incident)


class ApprovalRequest(BaseModel):
    action: str
    operator: Optional[str] = "Operator"


class GmailAuditRequest(BaseModel):
    account: str
    app_password: Optional[str] = None
    days_back: Optional[int] = 60


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    with open("ui/templates/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/stats")
async def get_stats():
    pending = human_gate.list_incidents(filter_status=IncidentStatus.PENDING)
    resolved = [i for i in human_gate.list_incidents() if i["status"] in [IncidentStatus.EXECUTED, IncidentStatus.DISMISSED]]
    vault_files = len([f for f in os.listdir("./vault") if f.endswith(".vault")]) if os.path.exists("./vault") else 0
    learned_iocs = len(learning_engine.knowledge_base.get("known_bad_hashes", {})) + len(learning_engine.knowledge_base.get("learned_patterns", []))
    active_devices = len(device_hunter.get_active_arp_devices())

    return {
        "pending_incidents": len(pending),
        "resolved_incidents": len(resolved),
        "quarantined_files": vault_files,
        "learned_iocs": learned_iocs,
        "connected_devices": active_devices
    }


@app.get("/api/incidents")
async def list_incidents(status: Optional[str] = None):
    return human_gate.list_incidents(filter_status=status)


@app.post("/api/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str, req: ApprovalRequest):
    approval_result = human_gate.approve_action(incident_id, req.action, req.operator)
    if not approval_result["success"]:
        raise HTTPException(status_code=400, detail=approval_result["error"])

    incident = approval_result["incident"]

    if req.action.upper() != "DISMISS":
        rem_result = remediation_engine.execute_approved_remediation(incident)
        human_gate.mark_executed(incident_id, True, json.dumps(rem_result))
        discord_c2.send_resolution_alert(incident_id, req.action, json.dumps(rem_result, indent=2))
        return {"success": True, "remediation": rem_result}
    else:
        discord_c2.send_resolution_alert(incident_id, "DISMISSED", "Threat dismissed by operator.")
        return {"success": True, "message": "Incident dismissed."}


@app.post("/api/scan/file")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """Saves file temporarily, performs static & heuristic inspection, registers if high risk."""
    os.makedirs("./intel_cache/incoming_scans", exist_ok=True)
    temp_path = os.path.join("./intel_cache/incoming_scans", file.filename)
    
    with open(temp_path, "wb") as f:
        f.write(await file.read())

    analysis = analyzer.analyze_file(temp_path)
    
    if analysis.get("threat_score", 0) >= 50 and not analysis.get("is_self_program"):
        incident = human_gate.register_threat(analysis)
        discord_c2.send_incident_alert(incident)
        learning_engine.learn_from_sample(analysis)

    return analysis


@app.post("/api/intel/sync")
async def sync_threat_intelligence():
    """Fetches real-time malicious indicators from online threat intelligence feeds."""
    result = learning_engine.fetch_internet_threat_intel()
    return result


@app.get("/api/network/devices")
async def get_network_devices():
    """Returns active network devices, phones, and MAC addresses on local Wi-Fi."""
    devices = device_hunter.get_active_arp_devices()
    return {"count": len(devices), "devices": devices}


@app.post("/api/network/scan")
async def scan_network_subnet():
    """Performs an active sweep across 192.168.1.0/24 to discover all linked phones/devices."""
    devices = device_hunter.scan_subnet(subnet_base="192.168.1")
    unknown = [d for d in devices if not d["is_known"]]
    for u in unknown:
        on_unknown_device_found(u)
    return {"total_found": len(devices), "unknown_count": len(unknown), "devices": devices}


@app.get("/api/email/accounts")
async def get_monitored_email_accounts():
    """Lists the 3 target Gmail accounts and their scanning status."""
    return {
        "accounts": [
            {"email": "aman20770101@gmail.com", "status": "Ready for 30-60 day audit"},
            {"email": "cornela778@gmail.com", "status": "Ready for 30-60 day audit"},
            {"email": "rammishra9991@gmail.com", "status": "Ready for 30-60 day audit"}
        ],
        "local_eml_dumps": len(os.listdir("./intel_cache/incoming_mail")) if os.path.exists("./intel_cache/incoming_mail") else 0
    }


@app.post("/api/email/audit")
async def audit_email_account(req: GmailAuditRequest):
    """Executes a 30-60 day security audit for the specified Gmail address."""
    if req.app_password:
        report = gmail_auditor.audit_imap_account(req.account, req.app_password, days_back=req.days_back or 60)
    else:
        # Check local incoming emails or dumped security alerts
        local_results = gmail_auditor.audit_local_mail_dump()
        report = {
            "email_account": req.account,
            "status": "local_inspection",
            "message": "Audited local incoming mail drops. To scan live server inbox directly, supply Google App Password.",
            "audited_count": len(local_results),
            "results": local_results
        }
    return report


def start_monitors():
    """Starts background filesystem, network, and device sentinel threads."""
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        settings = json.load(f)

    # File Monitor
    fs_cfg = settings.get("monitoring", {}).get("file_system", {})
    if fs_cfg.get("enabled", True):
        fs_sentinel = FileSystemSentinel(
            watch_paths=fs_cfg.get("watch_paths", []),
            extensions=fs_cfg.get("extensions", []),
            on_file_detected=on_file_threat_detected
        )
        fs_sentinel.start()

    # Network Monitor
    net_cfg = settings.get("monitoring", {}).get("network", {})
    if net_cfg.get("enabled", True):
        net_sentinel = NetworkSentinel(
            suspicious_ports=net_cfg.get("suspicious_ports", []),
            poll_interval=net_cfg.get("poll_interval_seconds", 5),
            on_threat_detected=on_network_threat_detected
        )
        net_thread = threading.Thread(target=net_sentinel.run_loop, daemon=True)
        net_thread.start()

    # Device Monitor Periodic Sweep
    def device_loop():
        while True:
            try:
                device_hunter.check_for_unknown_devices()
            except Exception:
                pass
            time.sleep(settings.get("device_monitoring", {}).get("scan_interval_seconds", 30))

    dev_thread = threading.Thread(target=device_loop, daemon=True)
    dev_thread.start()


if __name__ == "__main__":
    start_monitors()
    logger.info("SentinelAegis-X Server online at http://127.0.0.1:8800")
    uvicorn.run(app, host="127.0.0.1", port=8800, log_level="info")

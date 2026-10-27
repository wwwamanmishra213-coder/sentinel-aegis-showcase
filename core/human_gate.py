"""
SentinelAegis-X - Human-in-the-Loop Approval Gate
Enforces strict operator authorization before executing any defensive remediation,
process kill, file quarantine, or network firewall block.
Zero autonomous destruction without explicit operator consent.
"""

import time
import uuid
from typing import Dict, Any, List, Optional


class IncidentStatus:
    PENDING = "PENDING_OPERATOR_APPROVAL"
    APPROVED_KILL = "APPROVED_KILL"
    APPROVED_QUARANTINE = "APPROVED_QUARANTINE"
    DISMISSED = "DISMISSED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class HumanGate:
    def __init__(self):
        self._incidents: Dict[str, Dict[str, Any]] = {}

    def register_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Registers a newly detected threat into the pending approval queue."""
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident = {
            "incident_id": incident_id,
            "created_at": time.time(),
            "timestamp_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": IncidentStatus.PENDING,
            "source": threat_data.get("source", "file_analyzer"),
            "target_path": threat_data.get("file_path"),
            "target_pid": threat_data.get("target_pid"),
            "target_ip": threat_data.get("target_ip"),
            "threat_score": threat_data.get("threat_score", 0),
            "classification": threat_data.get("classification", "UNKNOWN"),
            "summary": threat_data.get("reasons", []),
            "metadata": threat_data,
            "operator_action": None,
            "resolved_at": None,
            "execution_log": []
        }
        self._incidents[incident_id] = incident
        return incident

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self._incidents.get(incident_id)

    def list_incidents(self, filter_status: Optional[str] = None) -> List[Dict[str, Any]]:
        incidents = list(self._incidents.values())
        if filter_status:
            incidents = [inc for inc in incidents if inc["status"] == filter_status]
        # Sort newest first
        return sorted(incidents, key=lambda x: x["created_at"], reverse=True)

    def approve_action(self, incident_id: str, action: str, operator_name: str = "Operator") -> Dict[str, Any]:
        """
        Record operator decision. Valid actions: 'KILL', 'QUARANTINE', 'KILL_AND_QUARANTINE', 'DISMISS'.
        Remediation will only be triggered after this call.
        """
        incident = self._incidents.get(incident_id)
        if not incident:
            return {"success": False, "error": f"Incident {incident_id} not found."}

        if incident["status"] != IncidentStatus.PENDING:
            return {"success": False, "error": f"Incident {incident_id} is already in state {incident['status']}."}

        action_upper = action.upper()
        if action_upper in ["KILL", "QUARANTINE", "KILL_AND_QUARANTINE", "ISOLATE_IP"]:
            incident["status"] = f"APPROVED_{action_upper}"
            incident["operator_action"] = action_upper
        elif action_upper == "DISMISS":
            incident["status"] = IncidentStatus.DISMISSED
            incident["operator_action"] = "DISMISS"
            incident["resolved_at"] = time.time()
        else:
            return {"success": False, "error": f"Invalid action: {action}. Choose KILL, QUARANTINE, KILL_AND_QUARANTINE, or DISMISS."}

        incident["operator_name"] = operator_name
        return {"success": True, "incident": incident}

    def mark_executed(self, incident_id: str, success: bool, log_message: str):
        incident = self._incidents.get(incident_id)
        if incident:
            incident["status"] = IncidentStatus.EXECUTED if success else IncidentStatus.FAILED
            incident["resolved_at"] = time.time()
            incident["execution_log"].append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "success": success,
                "message": log_message
            })

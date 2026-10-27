"""
SentinelAegis-X - Phishing & Malicious Email Sentinel
Parses raw .eml emails, verifies SPF/DKIM flags, flags spoofed senders,
extracts malicious URLs, and triages attachments via the MalwareAnalyzer.
"""

import os
import re
import email
from email import policy
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class PhishingEmailParser:
    def __init__(self, rules_path: str = "config/rules.json", analyzer=None):
        self.rules_path = rules_path
        self.analyzer = analyzer
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, Any]:
        if os.path.exists(self.rules_path):
            import json
            with open(self.rules_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"phishing_indicators": {}}

    def parse_eml_file(self, eml_path: str, temp_sandbox_dir: str = "./intel_cache/sandbox") -> Dict[str, Any]:
        """Triage an incoming .eml file."""
        if not os.path.exists(eml_path):
            return {"error": f"EML file not found: {eml_path}"}

        os.makedirs(temp_sandbox_dir, exist_ok=True)

        with open(eml_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        subject = str(msg.get("subject", ""))
        sender = str(msg.get("from", ""))
        to = str(msg.get("to", ""))
        return_path = str(msg.get("return-path", ""))
        auth_results = str(msg.get("authentication-results", ""))

        body_text = ""
        html_text = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))

                if "attachment" in disposition or part.get_filename():
                    filename = part.get_filename() or "unknown_payload.bin"
                    payload = part.get_payload(decode=True)
                    if payload:
                        dump_path = os.path.join(temp_sandbox_dir, f"{os.path.basename(eml_path)}_{filename}")
                        with open(dump_path, "wb") as f_out:
                            f_out.write(payload)

                        att_info = {"filename": filename, "path": dump_path, "size": len(payload)}
                        if self.analyzer:
                            att_info["analysis"] = self.analyzer.analyze_file(dump_path)
                        attachments.append(att_info)
                elif content_type == "text/plain":
                    try:
                        body_text += part.get_content()
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        html_text += part.get_content()
                    except Exception:
                        pass
        else:
            try:
                body_text = msg.get_content()
            except Exception:
                pass

        # Extract URLs
        full_content = f"{body_text}\n{html_text}"
        urls = re.findall(r'https?://[^\s<>"\']+', full_content)

        # Phishing risk scoring
        threat_score = 0
        reasons = []

        phish_rules = self.rules.get("phishing_indicators", {})
        suspicious_keywords = phish_rules.get("suspicious_subject_keywords", [])
        for kw in suspicious_keywords:
            if kw in subject.lower():
                threat_score += 20
                reasons.append(f"Suspicious subject urgency keyword: '{kw}'")

        # Sender vs Return-path mismatch check
        if return_path and sender and (sender.strip("<>") not in return_path):
            threat_score += 25
            reasons.append(f"Sender spoofing anomaly: From '{sender}' differs from Return-Path '{return_path}'")

        # SPF/DKIM check
        if "spf=fail" in auth_results.lower() or "dkim=fail" in auth_results.lower():
            threat_score += 35
            reasons.append("Authentication check failed (SPF/DKIM fail header)")

        # Attachment threat propagation
        for att in attachments:
            an = att.get("analysis", {})
            att_threat = an.get("threat_score", 0)
            if att_threat >= 50:
                threat_score = max(threat_score, att_threat)
                reasons.append(f"Dangerous attachment identified: '{att['filename']}' ({an.get('classification')})")

        threat_score = min(100, threat_score)

        return {
            "source": "email_sentinel",
            "subject": subject,
            "sender": sender,
            "recipient": to,
            "urls_found": urls[:20],
            "attachments": attachments,
            "threat_score": threat_score,
            "classification": "PHISHING_EMAIL" if threat_score >= 50 else "BENIGN_EMAIL",
            "reasons": reasons,
            "requires_action": threat_score >= 50
        }

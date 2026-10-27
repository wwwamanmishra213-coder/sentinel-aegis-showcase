"""
SentinelAegis-X - Multi-Account Gmail & Security Alert Triage Engine
Scans 30-60 day email history for aman20770101@gmail.com, cornela778@gmail.com, and rammishra9991@gmail.com.
Identifies unauthorized device sign-ins, suspicious IP linkages, phishing links, and malicious attachments.
"""

import os
import sys
import json
import time
import email
import imaplib
import logging
from datetime import datetime, timedelta
from email.header import decode_header
from typing import Dict, Any, List, Optional

from core.monitors.mail_parser import PhishingEmailParser

logger = logging.getLogger("GmailFetcher")

TARGET_ACCOUNTS = [
    "aman20770101@gmail.com",
    "cornela778@gmail.com",
    "rammishra9991@gmail.com"
]


class GmailSecurityAuditor:
    def __init__(self, settings_path: str = "config/settings.json", mail_parser: Optional[PhishingEmailParser] = None):
        self.settings_path = settings_path
        self.mail_parser = mail_parser or PhishingEmailParser()
        self.target_accounts = TARGET_ACCOUNTS

    @staticmethod
    def decode_mime_header(header_value: str) -> str:
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for text, encoding in decoded_parts:
            if isinstance(text, bytes):
                try:
                    result.append(text.decode(encoding or "utf-8", errors="ignore"))
                except Exception:
                    result.append(text.decode("latin1", errors="ignore"))
            else:
                result.append(str(text))
        return " ".join(result)

    def extract_security_alert_details(self, subject: str, body: str) -> Dict[str, Any]:
        """
        Extracts device type, IP address, and location from Google Security alerts:
        e.g., 'New device signed in to your account', 'Suspicious activity', etc.
        """
        is_security_alert = any(k in subject.lower() for k in [
            "security alert", "new device", "sign-in", "login", "suspicious",
            "critical security", "verification code", "account recovered", "password change"
        ])

        extracted = {
            "is_security_alert": is_security_alert,
            "detected_device": "Unknown Device",
            "detected_ip": None,
            "detected_location": None,
            "risk_score": 85 if is_security_alert else 0
        }

        if is_security_alert:
            import re
            # Extract IP addresses
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
            filtered_ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("0.")]
            if filtered_ips:
                extracted["detected_ip"] = filtered_ips[0]

            # Detect common device mentions in Google alerts
            body_lower = body.lower()
            if "iphone" in body_lower or "ios" in body_lower:
                extracted["detected_device"] = "Apple iPhone / iOS Device"
            elif "android" in body_lower or "samsung" in body_lower or "xiaomi" in body_lower:
                extracted["detected_device"] = "Android Mobile Device"
            elif "linux" in body_lower or "kali" in body_lower:
                extracted["detected_device"] = "Linux Workstation / Server"
            elif "windows" in body_lower:
                extracted["detected_device"] = "Windows PC"

            # Detect location keywords
            loc_match = re.search(r'(?:near|from|location:?)\s+([A-Za-z\s,]+)(?:\.|\n|<)', body, re.IGNORECASE)
            if loc_match:
                extracted["detected_location"] = loc_match.group(1).strip()[:50]

        return extracted

    def audit_imap_account(self, email_address: str, app_password: str, days_back: int = 60) -> Dict[str, Any]:
        """
        Connects via secure IMAP (SSL 993) to Gmail and audits the past 30-60 days of messages.
        """
        report = {
            "email_account": email_address,
            "status": "pending",
            "total_scanned": 0,
            "security_alerts": [],
            "suspicious_emails": [],
            "error": None
        }

        try:
            logger.info(f"Connecting to Gmail IMAP for {email_address}...")
            mail = imaplib.IMAP4_SSL("imap.gmail.com", 993)
            mail.login(email_address, app_password)
            mail.select("inbox")

            # Calculate date filter (e.g. 60 days ago)
            cutoff_date = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
            search_criterion = f'(SINCE "{cutoff_date}")'

            status, msg_ids = mail.search(None, search_criterion)
            if status != "OK" or not msg_ids[0]:
                report["status"] = "clean"
                report["total_scanned"] = 0
                mail.logout()
                return report

            id_list = msg_ids[0].split()
            report["total_scanned"] = len(id_list)

            # Audit recent emails (up to 100 most recent within the window)
            for m_id in id_list[-100:]:
                res, data = mail.fetch(m_id, "(RFC822)")
                if res != "OK":
                    continue

                raw_msg = data[0][1]
                msg = email.message_from_bytes(raw_msg)

                subject = self.decode_mime_header(msg.get("Subject", ""))
                sender = self.decode_mime_header(msg.get("From", ""))
                date_str = str(msg.get("Date", ""))

                body_text = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body_text += part.get_payload(decode=True).decode(errors="ignore")
                            except Exception:
                                pass
                else:
                    try:
                        body_text = msg.get_payload(decode=True).decode(errors="ignore")
                    except Exception:
                        pass

                # Check for Google security / device alerts
                sec_alert = self.extract_security_alert_details(subject, body_text)
                if sec_alert["is_security_alert"]:
                    report["security_alerts"].append({
                        "subject": subject,
                        "sender": sender,
                        "date": date_str,
                        "details": sec_alert
                    })

                # Check general phishing / attachment risks
                temp_eml = f"./intel_cache/incoming_mail/{m_id.decode()}_{email_address}.eml"
                os.makedirs(os.path.dirname(temp_eml), exist_ok=True)
                with open(temp_eml, "wb") as f_out:
                    f_out.write(raw_msg)
                
                triage_res = self.mail_parser.parse_eml_file(temp_eml)
                if triage_res.get("threat_score", 0) >= 50:
                    report["suspicious_emails"].append(triage_res)

            mail.logout()
            report["status"] = "success"
        except Exception as e:
            report["status"] = "auth_required_or_failed"
            report["error"] = str(e)
            logger.warning(f"Could not connect to {email_address} via IMAP: {e}")

        return report

    def audit_local_mail_dump(self, mail_dir: str = "./intel_cache/incoming_mail") -> List[Dict[str, Any]]:
        """Audits any .eml emails downloaded or dropped from Microsoft Edge."""
        results = []
        if not os.path.exists(mail_dir):
            return results

        for fname in os.listdir(mail_dir):
            if fname.lower().endswith(".eml"):
                fpath = os.path.join(mail_dir, fname)
                res = self.mail_parser.parse_eml_file(fpath)
                results.append(res)
        return results

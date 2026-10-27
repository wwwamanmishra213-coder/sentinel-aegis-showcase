"""
SentinelAegis-X - Static & Heuristic File Analysis Engine
Performs entropy calculation, PE/ELF parsing, Win32 API heuristics,
and signature matching to evaluate threat levels without taking destructive actions.
"""

import math
import os
import re
import hashlib
import json
from typing import Dict, Any, List, Optional

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


class MalwareAnalyzer:
    def __init__(self, rules_path: str = "config/rules.json", settings_path: str = "config/settings.json"):
        self.rules_path = rules_path
        self.settings_path = settings_path
        self.rules = self._load_rules()
        self.settings = self._load_settings()

    def _load_settings(self) -> Dict[str, Any]:
        if os.path.exists(self.settings_path):
            try:
                with open(self.settings_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def is_whitelisted_developer_file(self, file_path: str, sha256: str) -> bool:
        """Determines if the file belongs to user's own tooling and should NOT be flagged."""
        wl = self.settings.get("developer_whitelist", {})
        trusted_hashes = set(wl.get("trusted_hashes", []))
        if sha256 in trusted_hashes:
            return True

        norm_path = os.path.abspath(file_path).lower().replace("/", "\\")
        for tp in wl.get("trusted_paths", []):
            clean_tp = os.path.abspath(os.path.expanduser(tp.replace("*", ""))).lower().replace("/", "\\")
            if clean_tp in norm_path:
                return True
        return False

    def _load_rules(self) -> Dict[str, Any]:
        if os.path.exists(self.rules_path):
            with open(self.rules_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"suspicious_apis": [], "malware_signatures": [], "phishing_indicators": {}}

    @staticmethod
    def calculate_hashes(file_path: str) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()
        }

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon Entropy (0.0 to 8.0). Values > 7.1 often indicate packing/encryption."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def analyze_pe(self, file_path: str) -> Dict[str, Any]:
        """Dissect Portable Executable (Windows .exe / .dll / .sys)."""
        pe_info: Dict[str, Any] = {
            "is_pe": False,
            "sections": [],
            "imported_apis": [],
            "suspicious_api_matches": [],
            "has_high_entropy_section": False,
            "compile_time": None
        }

        if not HAS_PEFILE:
            return pe_info

        try:
            pe = pefile.PE(file_path, fast_load=False)
            pe_info["is_pe"] = True
            pe_info["compile_time"] = pe.FILE_HEADER.TimeDateStamp

            # Check sections
            for section in pe.sections:
                sec_name = section.Name.decode(errors="ignore").strip("\x00")
                sec_data = section.get_data()
                sec_entropy = self.calculate_entropy(sec_data)
                pe_info["sections"].append({
                    "name": sec_name,
                    "entropy": sec_entropy,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData
                })
                if sec_entropy > 7.15:
                    pe_info["has_high_entropy_section"] = True

            # Check imported APIs
            suspicious_apis_set = set(self.rules.get("suspicious_apis", []))
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode(errors="ignore")
                            pe_info["imported_apis"].append(func_name)
                            if func_name in suspicious_apis_set:
                                pe_info["suspicious_api_matches"].append(func_name)

            pe.close()
        except Exception:
            pass

        return pe_info

    def analyze_elf(self, data: bytes) -> Dict[str, Any]:
        """Dissect Linux ELF binary header."""
        elf_info: Dict[str, Any] = {"is_elf": False, "bits": None, "endianness": None}
        if len(data) >= 4 and data[:4] == b"\x7fELF":
            elf_info["is_elf"] = True
            if len(data) >= 16:
                elf_info["bits"] = 64 if data[4] == 2 else 32
                elf_info["endianness"] = "little" if data[5] == 1 else "big"
        return elf_info

    def match_signatures(self, raw_content: str) -> List[Dict[str, Any]]:
        matches = []
        signatures = self.rules.get("malware_signatures", [])
        for sig in signatures:
            pattern = sig.get("pattern", "")
            try:
                if re.search(pattern, raw_content, re.IGNORECASE):
                    matches.append({
                        "name": sig.get("name"),
                        "severity": sig.get("severity", 50)
                    })
            except re.error:
                continue
        return matches

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Performs full static and heuristic triage on target file."""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        file_size = os.path.getsize(file_path)
        hashes = self.calculate_hashes(file_path)

        # Check self-created developer whitelist
        if self.is_whitelisted_developer_file(file_path, hashes.get("sha256", "")):
            return {
                "file_path": os.path.abspath(file_path),
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "hashes": hashes,
                "entropy": 0.0,
                "pe_metadata": {"is_pe": False},
                "elf_metadata": {"is_elf": False},
                "signature_matches": [],
                "threat_score": 0,
                "classification": "AUTHORIZED_SELF_DEVELOPER_PROGRAM",
                "verdict": "SAFE_SELF_CODE",
                "reasons": [
                    "Identified as user's authorized developer code / self-created tool",
                    "Protected by Developer Whitelist - Zero threat flagging"
                ],
                "requires_action": False,
                "is_self_program": True
            }

        with open(file_path, "rb") as f:
            raw_bytes = f.read(min(file_size, 50 * 1024 * 1024))

        entropy = self.calculate_entropy(raw_bytes)
        text_preview = raw_bytes.decode(errors="ignore")

        pe_info = self.analyze_pe(file_path)
        elf_info = self.analyze_elf(raw_bytes[:64])
        signature_matches = self.match_signatures(text_preview)

        # Threat Score computation (0-100 scale)
        threat_score = 0
        reasons = []

        # High Entropy (Packed/Encrypted)
        if entropy > 7.3:
            threat_score += 35
            reasons.append(f"Extremely high entropy ({entropy}) indicates packed/encrypted code")
        elif entropy > 6.8:
            threat_score += 15
            reasons.append(f"Elevated entropy ({entropy}) suggests compression or obfuscation")

        # PE Suspicious APIs
        sus_api_count = len(pe_info["suspicious_api_matches"])
        if sus_api_count > 0:
            api_score = min(40, sus_api_count * 10)
            threat_score += api_score
            reasons.append(f"Dangerous Win32 APIs detected ({sus_api_count}): {', '.join(pe_info['suspicious_api_matches'][:5])}")

        if pe_info["has_high_entropy_section"]:
            threat_score += 20
            reasons.append("PE section contains packed/encrypted payload")

        # Signature / Regex Matches
        for sig in signature_matches:
            threat_score += sig["severity"] // 2
            reasons.append(f"Signature match: {sig['name']} (severity: {sig['severity']})")

        # Linux ELF checks
        if elf_info["is_elf"] and "/bin/sh" in text_preview:
            threat_score += 25
            reasons.append("ELF executable contains embedded shell execution strings")

        # Normalize score
        threat_score = min(100, threat_score)

        if threat_score >= 80:
            classification = "CRITICAL_MALWARE"
            verdict = "MALICIOUS"
        elif threat_score >= 50:
            classification = "HIGH_RISK"
            verdict = "SUSPICIOUS"
        elif threat_score >= 25:
            classification = "LOW_RISK"
            verdict = "MONITOR"
        else:
            classification = "BENIGN"
            verdict = "SAFE"

        return {
            "file_path": os.path.abspath(file_path),
            "file_name": os.path.basename(file_path),
            "file_size": file_size,
            "hashes": hashes,
            "entropy": entropy,
            "pe_metadata": pe_info,
            "elf_metadata": elf_info,
            "signature_matches": signature_matches,
            "threat_score": threat_score,
            "classification": classification,
            "verdict": verdict,
            "reasons": reasons,
            "requires_action": threat_score >= 50
        }

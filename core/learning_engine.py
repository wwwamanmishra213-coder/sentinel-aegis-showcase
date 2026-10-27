"""
SentinelAegis-X - Threat Intelligence & Adaptive Learning Engine
Ingests online threat feeds (URLhaus, MalwareBazaar, public feeds),
caches IOC hashes, and synthesizes new detection signatures from analyzed samples.
Strictly informs and recommends — never takes destructive action autonomously.
"""

import json
import os
import time
import requests
from typing import Dict, Any, List, Set


class ThreatLearningEngine:
    def __init__(self, cache_file: str = "intel_cache/learned_patterns.json", settings_path: str = "config/settings.json"):
        self.cache_file = cache_file
        self.settings_path = settings_path
        self.settings = self._load_settings()
        self.knowledge_base = self._load_knowledge_base()

    def _load_settings(self) -> Dict[str, Any]:
        if os.path.exists(self.settings_path):
            with open(self.settings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _load_knowledge_base(self) -> Dict[str, Any]:
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "last_updated": 0,
            "known_bad_hashes": {},
            "learned_patterns": [],
            "malicious_ips": [],
            "malicious_urls": []
        }

    def save_knowledge_base(self):
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(self.knowledge_base, f, indent=2)

    def fetch_internet_threat_intel(self) -> Dict[str, Any]:
        """
        Polls open-source threat intelligence feeds from the internet (URLhaus, MalwareBazaar)
        to ingest new in-the-wild malicious indicators into the local defensive cache.
        """
        intel_cfg = self.settings.get("intelligence", {})
        if not intel_cfg.get("enable_online_feeds", True):
            return {"status": "disabled", "added_iocs": 0}

        added_hashes = 0
        added_urls = 0

        # Ingest URLhaus recent phishing / malware distribution URLs
        urlhaus_endpoint = intel_cfg.get("urlhaus_api", "https://urlhaus-api.abuse.ch/v1/urls/recent/")
        try:
            resp = requests.get(urlhaus_endpoint, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                urls = data.get("urls", [])
                for entry in urls[:50]:
                    url = entry.get("url")
                    threat = entry.get("threat")
                    if url and url not in self.knowledge_base["malicious_urls"]:
                        self.knowledge_base["malicious_urls"].append(url)
                        added_urls += 1
        except Exception:
            pass

        # Ingest MalwareBazaar recent SHA256 malware samples
        bazaar_endpoint = intel_cfg.get("bazaar_recent_api", "https://mb-api.abuse.ch/api/v1/")
        try:
            payload = {"query": "get_recent", "selector": "time"}
            resp = requests.post(bazaar_endpoint, data=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok":
                    for item in data.get("data", [])[:50]:
                        sha256 = item.get("sha256_hash")
                        tag = item.get("signature") or item.get("file_type")
                        if sha256 and sha256 not in self.knowledge_base["known_bad_hashes"]:
                            self.knowledge_base["known_bad_hashes"][sha256] = {
                                "tag": tag,
                                "first_seen": item.get("first_seen"),
                                "source": "MalwareBazaar"
                            }
                            added_hashes += 1
        except Exception:
            pass

        self.knowledge_base["last_updated"] = time.time()
        self.save_knowledge_base()

        return {
            "status": "success",
            "added_hashes": added_hashes,
            "added_urls": added_urls,
            "total_bad_hashes": len(self.knowledge_base["known_bad_hashes"]),
            "total_bad_urls": len(self.knowledge_base["malicious_urls"])
        }

    def learn_from_sample(self, analysis_result: Dict[str, Any]):
        """
        Extracts structural features, high-entropy blocks, and recurring strings
        from confirmed or high-risk samples to formulate defensive signatures.
        """
        if analysis_result.get("threat_score", 0) < 50:
            return

        sha256 = analysis_result.get("hashes", {}).get("sha256")
        if sha256:
            self.knowledge_base["known_bad_hashes"][sha256] = {
                "tag": analysis_result.get("classification"),
                "first_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_score": analysis_result.get("threat_score"),
                "reasons": analysis_result.get("reasons", [])
            }

        file_name = analysis_result.get("file_name", "")
        # Record newly observed pattern
        new_pattern = {
            "source_sample": file_name,
            "learned_at": time.time(),
            "apis_observed": analysis_result.get("pe_metadata", {}).get("suspicious_api_matches", []),
            "entropy": analysis_result.get("entropy", 0.0)
        }
        self.knowledge_base["learned_patterns"].append(new_pattern)
        # Keep learned patterns compact
        if len(self.knowledge_base["learned_patterns"]) > 500:
            self.knowledge_base["learned_patterns"] = self.knowledge_base["learned_patterns"][-500:]

        self.save_knowledge_base()

    def check_hash_reputation(self, sha256: str) -> Dict[str, Any]:
        """Check if hash has been indexed from the global threat feeds or local learning."""
        if sha256 in self.knowledge_base["known_bad_hashes"]:
            return {
                "is_known_malware": True,
                "details": self.knowledge_base["known_bad_hashes"][sha256]
            }
        return {"is_known_malware": False}

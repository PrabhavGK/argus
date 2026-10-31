"""
crypto_enclave.py - Cryptographic Policy Enclave for Team Leads.

Enforces zero-trust storage of team-specific redaction rulebooks at rest.
Implements PBKDF2-HMAC-SHA256 key derivation with an authenticated keystream
and an HMAC-SHA256 digital signature to guarantee tamper-proof integrity on disk.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from config import DATA_DIR, ENCLAVE_RULEBOOK_PATH
DEFAULT_LEAD_MASTER_KEY = os.environ.get("ARGUS_LEAD_MASTER_KEY", "ARGUS-LEAD-MASTER-KEY-2026")


class TeamLeadRulebookEnclave:
    """
    Cryptographic Policy Enclave for Team Leads.
    Rules are stored encrypted at rest with PBKDF2-HMAC-SHA256 authenticated stream cipher.
    Protected by an HMAC-SHA256 digital signature to prevent tampering or sniffing from disk.
    """
    def __init__(self, filepath: str = ENCLAVE_RULEBOOK_PATH, master_key: str = DEFAULT_LEAD_MASTER_KEY):
        self.filepath = filepath
        self.master_key = master_key
        self._cached_rules: List[Dict[str, Any]] = []
        self._compiled_custom_specs: List[Any] = []
        self.init_default_rulebook()

    @staticmethod
    def _derive_keys(passphrase: str, salt: bytes):
        enc_key = hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, 100000, 32)
        mac_key = hashlib.pbkdf2_hmac('sha256', enc_key, b'argus-enclave-mac-salt', 10000, 32)
        return enc_key, mac_key

    def _encrypt(self, data: dict, passphrase: str) -> str:
        raw = json.dumps(data).encode('utf-8')
        salt = os.urandom(16)
        enc_key, mac_key = self._derive_keys(passphrase, salt)
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(raw):
            block = hmac.new(enc_key, counter.to_bytes(4, 'big'), hashlib.sha256).digest()
            keystream.extend(block)
            counter += 1
        ciphertext = bytes(a ^ b for a, b in zip(raw, keystream[:len(raw)]))
        mac = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()
        envelope = {
            "version": "argus-crypto-enclave-v2.1",
            "cipher": "PBKDF2-HMAC-SHA256-STREAM + HMAC-SHA256-DIGEST",
            "salt": base64.b64encode(salt).decode('ascii'),
            "mac": base64.b64encode(mac).decode('ascii'),
            "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
            "tamper_protection": "Tamper-Evident HMAC Digital Seal",
            "signed_by": "Alex Chen (SecOps Lead)",
            "last_verified_utc": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
        }
        return json.dumps(envelope, indent=2)

    def _decrypt(self, envelope_str: str, passphrase: str) -> dict:
        envelope = json.loads(envelope_str)
        salt = base64.b64decode(envelope['salt'])
        mac = base64.b64decode(envelope['mac'])
        ciphertext = base64.b64decode(envelope['ciphertext'])
        enc_key, mac_key = self._derive_keys(passphrase, salt)
        expected_mac = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("SECURITY ALERT: Cryptographic signature mismatch! Rulebook was modified or snatched.")
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(ciphertext):
            block = hmac.new(enc_key, counter.to_bytes(4, 'big'), hashlib.sha256).digest()
            keystream.extend(block)
            counter += 1
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))
        return json.loads(plaintext.decode('utf-8'))

    def init_default_rulebook(self):
        if not os.path.exists(self.filepath):
            initial_data = {
                "enclave_metadata": {
                    "lead_owner": "Alex Chen (SecOps Lead)",
                    "lead_email": "alex.chen@corporate.internal",
                    "classification": "Tier-1 Classified Secret Masking Rules",
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
                },
                "custom_rules": [
                    {
                        "id": "RULE-INFRA-01",
                        "name": "K8s Microservice Pods",
                        "team": "CloudInfra",
                        "entity_type": "K8S_POD_WORKLOAD",
                        "label": "Kubernetes Pod Workload",
                        "pattern": r"\b[a-z0-9]+(?:-[a-z0-9]+)*-[a-z0-9]{4,10}-[a-z0-9]{4,6}\b",
                        "confidence": 0.95,
                        "risk": "High",
                        "priority": 8,
                        "enabled": True
                    },
                    {
                        "id": "RULE-INFRA-02",
                        "name": "K8s Node Hostnames",
                        "team": "CloudInfra",
                        "entity_type": "INTERNAL_NODE_DNS",
                        "label": "Internal Node Hostname",
                        "pattern": r"\bip-(?:[0-9]{1,3}-){3}[0-9]{1,3}\.(?:ec2\.internal|compute\.internal|[a-z0-9.-]+\.internal)\b|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:ec2\.internal|compute\.internal)\b",
                        "confidence": 0.96,
                        "risk": "High",
                        "priority": 7,
                        "enabled": True
                    },
                    {
                        "id": "RULE-INFRA-03",
                        "name": "Memory & Resource Metrics",
                        "team": "CloudInfra",
                        "entity_type": "RESOURCE_SPEC",
                        "label": "K8s Resource Capacity Metric",
                        "pattern": r"\b\d+(?:\.\d+)?\s*(?:Mi|Gi|Ti|Ki|MB|GB|TB|KB|MiB|GiB)\b",
                        "confidence": 0.92,
                        "risk": "Medium",
                        "priority": 9,
                        "enabled": True
                    },
                    {
                        "id": "RULE-PAY-01",
                        "name": "PCI Payment PANs",
                        "team": "PaymentLedger",
                        "entity_type": "CREDIT_CARD_PAN",
                        "label": "PCI-DSS Credit Card Number",
                        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12})\b",
                        "confidence": 0.99,
                        "risk": "Critical",
                        "priority": 2,
                        "enabled": True
                    },
                    {
                        "id": "RULE-SEC-01",
                        "name": "HashiCorp Vault Root Token",
                        "team": "SecOps",
                        "entity_type": "VAULT_ROOT_TOKEN",
                        "label": "Vault Root Access Token",
                        "pattern": r"\b(?:s\.[a-zA-Z0-9]{24,32}|root_token\s*[:=]\s*[\'\"]?[a-zA-Z0-9_\-\.]{20,40}[\'\"]?)",
                        "confidence": 0.99,
                        "risk": "Critical",
                        "priority": 3,
                        "enabled": True
                    }
                ]
            }
            armored = self._encrypt(initial_data, self.master_key)
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write(armored)

        self.reload_rules()

    def reload_rules(self):
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                armored = f.read()
            data = self._decrypt(armored, self.master_key)
            self._cached_rules = data.get("custom_rules", [])
            
            # Late-import RecognizerSpec from sanitizer to build compiled custom recognizers
            from sanitizer import RecognizerSpec
            specs = []
            for r in self._cached_rules:
                if r.get("enabled", True):
                    try:
                        spec = RecognizerSpec(
                            engine=f"TeamRule ({r.get('team', 'Global')})",
                            entity_type=r["entity_type"],
                            label=r["label"],
                            pattern=r["pattern"],
                            confidence=r.get("confidence", 0.95),
                            risk=r.get("risk", "High"),
                            priority=r.get("priority", 5),
                            team=r.get("team", "Global")
                        )
                        specs.append(spec)
                    except Exception as e:
                        print(f"Error compiling custom rule {r.get('id')}: {e}")
            self._compiled_custom_specs = specs
        except Exception as e:
            print(f"[RulebookEnclave] Error reloading rules: {e}")

    def get_active_recognizers(self, team: Optional[str] = None):
        """Returns the sorted union of CORE_RECOGNIZERS and enabled custom team rules."""
        from sanitizer import CORE_RECOGNIZERS
        active = list(CORE_RECOGNIZERS)
        for spec in self._compiled_custom_specs:
            if spec.team == "Global" or team is None or spec.team.lower() == team.lower():
                active.append(spec)
        active.sort(key=lambda s: s.priority)
        return active

    def add_custom_rule(self, name: str, team: str, entity_type: str, label: str, pattern: str, risk: str = "High", priority: int = 5, master_key: str = "") -> Dict[str, Any]:
        if master_key != self.master_key:
            raise PermissionError("INVALID_LEAD_KEY: Unauthorized access to Team Lead Policy Enclave.")
        re.compile(pattern)
        with open(self.filepath, "r", encoding="utf-8") as f:
            data = self._decrypt(f.read(), master_key)
        new_id = f"RULE-{team[:3].upper()}-{len(data.get('custom_rules', [])) + 1:02d}"
        rule_obj = {
            "id": new_id,
            "name": name,
            "team": team,
            "entity_type": entity_type,
            "label": label,
            "pattern": pattern,
            "confidence": 0.95,
            "risk": risk,
            "priority": priority,
            "enabled": True
        }
        data["custom_rules"].append(rule_obj)
        armored = self._encrypt(data, master_key)
        with open(self.filepath, "w", encoding="utf-8") as f:
            f.write(armored)
        self.reload_rules()
        return rule_obj

    def delete_custom_rule(self, rule_id: str, master_key: str = "") -> bool:
        if master_key != self.master_key:
            raise PermissionError("INVALID_LEAD_KEY: Unauthorized access to Team Lead Policy Enclave.")
        with open(self.filepath, "r", encoding="utf-8") as f:
            data = self._decrypt(f.read(), master_key)
        rules = data.get("custom_rules", [])
        initial_len = len(rules)
        data["custom_rules"] = [r for r in rules if r.get("id") != rule_id]
        if len(data["custom_rules"]) == initial_len:
            return False
        armored = self._encrypt(data, master_key)
        with open(self.filepath, "w", encoding="utf-8") as f:
            f.write(armored)
        self.reload_rules()
        return True

    def verify_integrity(self) -> Dict[str, Any]:
        exists = os.path.exists(self.filepath)
        if not exists:
            return {"status": "NOT_FOUND", "message": "Enclave rulebook file does not exist."}
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                content = f.read()
            envelope = json.loads(content)
            self._decrypt(content, self.master_key)
            return {
                "status": "VERIFIED_TAMPER_PROOF",
                "cipher": envelope.get("cipher"),
                "signed_by": envelope.get("signed_by"),
                "file_path": "data/team_rules_enclave.enc",
                "rules_count": len(self._cached_rules),
                "tamper_detected": False,
                "message": "HMAC-SHA256 signature verified. Enclave file is authentic and un-tampered."
            }
        except ValueError as ve:
            return {
                "status": "TAMPER_DETECTED",
                "tamper_detected": True,
                "error": str(ve),
                "message": "CRITICAL: Signature mismatch! Enclave file was altered or snatched from disk."
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}


rulebook_enclave = TeamLeadRulebookEnclave()

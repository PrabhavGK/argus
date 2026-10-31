---
id: KB-ARGUS-SOP-01
team: SecOps
title: "Emergency IAM Credential Revocation & Perimeter Quarantine"
created_at: "2026-10-20 08:10:00"
content_hash: 05e35aeacf37
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: IAM Credential Revocation
Severity: Critical | Author: Alex Chen

## Procedure:
1. When unauthorized activity is detected from <AWS_ACCESS_KEY_1> or secret <AWS_SECRET_KEY_1>:
2. Invoke AWS CLI to revoke current active STS sessions via <AWS_GATEWAY_1>.
3. Enforce perimeter firewall filter on gateway <INTERNAL_IP_1>.
4. Quarantine compromised worker pod <K8S_POD_1> in namespace <K8S_NAMESPACE_1>.

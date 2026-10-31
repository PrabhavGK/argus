---
id: KB-ARGUS-SOP-05
team: SecOps
title: "Perimeter Ingress DDoS Defense & BGP Null-Routing"
created_at: "2026-10-24 08:14:00"
content_hash: 8ad1057db00f
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Edge Volumetric Flood Mitigation
Severity: Critical | Author: Alex Chen

## Procedure:
1. Detect anomalous ingress spikes at border gateway <AWS_GATEWAY_1>.
2. Apply upstream BGP null-route on offending subnet <INTERNAL_IP_1>/24.
3. Rotate edge session auth tokens matching <JWT_TOKEN_1>.
4. Notify corporate security lead via webhook <SLACK_WEBHOOK_1>.

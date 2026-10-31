---
id: KB-ARGUS-SOP-08
team: SecOps
title: "Cross-Site Scripting & Bearer Session Invalidation"
created_at: "2026-10-27 08:17:00"
content_hash: 826f36b73c0e
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Session Hijacking Rapid Response
Severity: High | Author: Alex Chen

## Procedure:
1. Blacklist compromised session identifier <BEARER_AUTH_1> across border proxy <AWS_GATEWAY_1>.
2. Trigger force logout for identity <EMAIL_ADDRESS_1>.
3. Inspect API server logs on <CLUSTER_SERVICE_ENDPOINT_1>.

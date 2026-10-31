---
id: KB-ARGUS-SOP-02
team: CloudInfra
title: "PgBouncer Connection Starvation & Pool Draining SOP"
created_at: "2026-10-21 08:11:00"
content_hash: b966393075d1
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Database Connection Pool Exhaustion
Severity: High | Author: Marcus Vance

## Procedure:
1. Drain connection pools on host <INTERNAL_IP_1> and fallback endpoint <CLUSTER_SERVICE_ENDPOINT_1>.
2. Terminate hung backend queries consuming database connection string <DB_CONNECTION_STRING_1>.
3. Query metrics on observability agent <DATADOG_AGENT_1> to verify pool availability reaches > 30%.
4. Rotate connection credentials and alert oncall via <INTERNAL_DNS_HOST_1>.

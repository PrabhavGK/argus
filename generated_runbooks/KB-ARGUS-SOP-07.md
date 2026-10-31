---
id: KB-ARGUS-SOP-07
team: CloudInfra
title: "Datadog Telemetry Agent Drift & Pipe Stoppage"
created_at: "2026-10-26 08:16:00"
content_hash: 6e9be0acab9a
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Observability Agent Recovery
Severity: Medium | Author: Elena Rostova

## Procedure:
1. Inspect agent pod logs on daemonset <DATADOG_AGENT_1> across cluster <CLUSTER_SERVICE_ENDPOINT_1>.
2. Verify network egress path from node <INTERNAL_IP_1> to telemetry gateway.
3. Restart agent daemon and flush forwarder buffer.

---
id: KB-ARGUS-SOP-04
team: CloudInfra
title: "Kubernetes Pod OOMKilled & Eviction Remediation"
created_at: "2026-10-23 08:13:00"
content_hash: 81230b4a2734
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Kubernetes OOMKilled Emergency Handling
Severity: High | Author: Marcus Vance

## Procedure:
1. Inspect pods matching <K8S_POD_1> experiencing OOM termination in <K8S_NAMESPACE_1>.
2. Increase container resource capacity allocation to <RESOURCE_CAPACITY_1>.
3. Drain infected worker node <INTERNAL_DNS_HOST_1>.
4. Monitor Datadog agent <DATADOG_AGENT_1> for kernel OOM score anomalies.

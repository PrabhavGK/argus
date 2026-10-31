---
id: KB-ARGUS-SOP-10
team: CloudInfra
title: "Legacy Apache Cassandra 2.1 Ring Repair (Modernized)"
created_at: "2026-10-31 04:14:26"
content_hash: d0632eebb43a
storage_tier: "Local SQLite + ChromaDB (Modernized SOP)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "AI Modernized via Ollama qwen2.5:1.5b"
disk_filepath: "/home/gkprabhav/Prabhav/genai_fin/generated_runbooks/KB-ARGUS-SOP-10_modernized.md"
---

## Procedure:
1. Identify the affected Kubernetes worker node <INTERNAL_IP_1> experiencing a kernel panic.
2. Evict the workload pod <K8S_POD_1> from the node using the command:
   ```
   kubectl drain <INTERNAL_IP_1>
   ```
3. Increase the container resource capacity allocation to <RESOURCE_CAPACITY_1> for the affected pods in the <K8S_NAMESPACE_1> namespace.
4. Monitor the Datadog agent <DATADOG_AGENT_1> for any anomalies in the kernel OOM score.
5. If the issue persists, escalate the incident to the L2 SRE team for further investigation and remediation.

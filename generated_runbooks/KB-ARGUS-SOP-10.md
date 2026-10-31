---
id: KB-ARGUS-SOP-10
team: CloudInfra
title: "Legacy Apache Cassandra 2.1 Ring Repair (DEPRECATED)"
created_at: "2026-10-20 08:19:00"
content_hash: f6522a448183
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Cassandra Ring Repair [ARCHIVED 2021]
Severity: Low | Author: Dave Miller (Departed)

## Procedure:
Run nodetool repair -pr on outdated cluster nodes. Requires Python 2.7 runtime.
Warning: This runbook targets deprecated architecture and fails on modern Kubernetes clusters.

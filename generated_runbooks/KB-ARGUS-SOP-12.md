---
id: KB-ARGUS-SOP-12
team: PaymentLedger
title: "Direct Raw SQL Table Lock Injection on Master (UNSAFE)"
created_at: "2026-10-22 08:21:00"
content_hash: 2904b15c3940
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Direct Table Lock Intervention
Severity: Critical | Author: Anonymous

## Procedure:
Execute LOCK TABLES write directly in production ledger database without replication checks.
Warning: High risk of cascading outage. Downvoted by SRE leadership.

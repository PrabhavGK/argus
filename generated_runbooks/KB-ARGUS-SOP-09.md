---
id: KB-ARGUS-SOP-09
team: CloudInfra
title: "Kafka Broker Partition Rebalance & Zookeeper Sync"
created_at: "2026-10-28 08:18:00"
content_hash: a8cec7c177c5
storage_tier: "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Synchronized from SQLite & ChromaDB"
---

# Runbook: Kafka Partition Starvation
Severity: High | Author: Marcus Vance

## Procedure:
1. Identify under-replicated partitions on message broker <CLUSTER_SERVICE_ENDPOINT_1>.
2. Rebalance consumer groups subscribed to ingestion pipeline.
3. Verify broker heartbeat via internal host <INTERNAL_DNS_HOST_1>.

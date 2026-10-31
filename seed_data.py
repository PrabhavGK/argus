"""
seed_data.py - Enterprise Global Data Seeder for Argus.

Populates SQLite and ChromaDB with rich, interconnected production datasets:
- 22 Interconnected Sev-1/Critical Incidents & Authoritative Runbooks
- Heavy cross-linkage of deterministic infrastructure tokens:
  <AWS_GATEWAY_1>, <DATADOG_AGENT_1>, <INTERNAL_IP_1>, <K8S_POD_1>, <CLUSTER_SERVICE_ENDPOINT_1>
- Skewed Metadata for C-Suite Analytics:
  1. SecOps: 85% of incidents assigned to 'Alex Chen' (Triggers Bus Factor warning > 70%)
  2. Vendor SLA: <DATADOG_AGENT_1> and <AWS_GATEWAY_1> injected into multiple high-severity incidents
  3. Runbook Decay: Seeds explicit runbook_feedback with <0.5 similarity and negative RLHF votes for 3 SOPs.
"""

import hashlib
import os
import sqlite3
import time
from typing import Any, Dict, List

from config import DATA_DIR, DB_PATH, CHROMA_PERSIST_DIR, IS_VERCEL

try:
    import chromadb
    from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
    CHROMA_AVAILABLE = True
except Exception:
    CHROMA_AVAILABLE = False

# ---------------------------------------------------------------------
# Enterprise Seed Datasets
# ---------------------------------------------------------------------

# 12 Authoritative SOP Runbooks
SEED_RUNBOOKS = [
    {
        "id": "KB-ARGUS-SOP-01",
        "team": "SecOps",
        "title": "Emergency IAM Credential Revocation & Perimeter Quarantine",
        "content": (
            "# Runbook: IAM Credential Revocation\n"
            "Severity: Critical | Author: Alex Chen\n\n"
            "## Procedure:\n"
            "1. When unauthorized activity is detected from <AWS_ACCESS_KEY_1> or secret <AWS_SECRET_KEY_1>:\n"
            "2. Invoke AWS CLI to revoke current active STS sessions via <AWS_GATEWAY_1>.\n"
            "3. Enforce perimeter firewall filter on gateway <INTERNAL_IP_1>.\n"
            "4. Quarantine compromised worker pod <K8S_POD_1> in namespace <K8S_NAMESPACE_1>."
        ),
        "tokens_count": 6
    },
    {
        "id": "KB-ARGUS-SOP-02",
        "team": "CloudInfra",
        "title": "PgBouncer Connection Starvation & Pool Draining SOP",
        "content": (
            "# Runbook: Database Connection Pool Exhaustion\n"
            "Severity: High | Author: Marcus Vance\n\n"
            "## Procedure:\n"
            "1. Drain connection pools on host <INTERNAL_IP_1> and fallback endpoint <CLUSTER_SERVICE_ENDPOINT_1>.\n"
            "2. Terminate hung backend queries consuming database connection string <DB_CONNECTION_STRING_1>.\n"
            "3. Query metrics on observability agent <DATADOG_AGENT_1> to verify pool availability reaches > 30%.\n"
            "4. Rotate connection credentials and alert oncall via <INTERNAL_DNS_HOST_1>."
        ),
        "tokens_count": 5
    },
    {
        "id": "KB-ARGUS-SOP-03",
        "team": "PaymentLedger",
        "title": "Distributed Ledger Lock Recovery & Deadlock Clearance",
        "content": (
            "# Runbook: Distributed Transaction Deadlock\n"
            "Severity: Critical | Author: Priya Sharma\n\n"
            "## Procedure:\n"
            "1. Clear threadpool deadlocks on ledger coordinator host <INTERNAL_IP_2>.\n"
            "2. Invalidate expired settlement bearer tokens matching <BEARER_AUTH_1>.\n"
            "3. Route reconciliation traffic through ingress gateway <AWS_GATEWAY_1>.\n"
            "4. Re-verify PCI cryptographic integrity with enclave root <VAULT_ROOT_TOKEN_1>."
        ),
        "tokens_count": 4
    },
    {
        "id": "KB-ARGUS-SOP-04",
        "team": "CloudInfra",
        "title": "Kubernetes Pod OOMKilled & Eviction Remediation",
        "content": (
            "# Runbook: Kubernetes OOMKilled Emergency Handling\n"
            "Severity: High | Author: Marcus Vance\n\n"
            "## Procedure:\n"
            "1. Inspect pods matching <K8S_POD_1> experiencing OOM termination in <K8S_NAMESPACE_1>.\n"
            "2. Increase container resource capacity allocation to <RESOURCE_CAPACITY_1>.\n"
            "3. Drain infected worker node <INTERNAL_DNS_HOST_1>.\n"
            "4. Monitor Datadog agent <DATADOG_AGENT_1> for kernel OOM score anomalies."
        ),
        "tokens_count": 5
    },
    {
        "id": "KB-ARGUS-SOP-05",
        "team": "SecOps",
        "title": "Perimeter Ingress DDoS Defense & BGP Null-Routing",
        "content": (
            "# Runbook: Edge Volumetric Flood Mitigation\n"
            "Severity: Critical | Author: Alex Chen\n\n"
            "## Procedure:\n"
            "1. Detect anomalous ingress spikes at border gateway <AWS_GATEWAY_1>.\n"
            "2. Apply upstream BGP null-route on offending subnet <INTERNAL_IP_1>/24.\n"
            "3. Rotate edge session auth tokens matching <JWT_TOKEN_1>.\n"
            "4. Notify corporate security lead via webhook <SLACK_WEBHOOK_1>."
        ),
        "tokens_count": 4
    },
    {
        "id": "KB-ARGUS-SOP-06",
        "team": "PaymentLedger",
        "title": "PCI DSS Compliance Tokenization Key Rotation",
        "content": (
            "# Runbook: PCI PAN Secret Rotation\n"
            "Severity: Critical | Author: Priya Sharma\n\n"
            "## Procedure:\n"
            "1. Unseal Hardware Security Module utilizing <VAULT_ROOT_TOKEN_1>.\n"
            "2. Rekey all payment transit data masking <CREDIT_CARD_PAN_1> across database <DB_CONNECTION_STRING_1>.\n"
            "3. Verify zero unmasked transactions leaked to <INTERNAL_IP_2>."
        ),
        "tokens_count": 3
    },
    {
        "id": "KB-ARGUS-SOP-07",
        "team": "CloudInfra",
        "title": "Datadog Telemetry Agent Drift & Pipe Stoppage",
        "content": (
            "# Runbook: Observability Agent Recovery\n"
            "Severity: Medium | Author: Elena Rostova\n\n"
            "## Procedure:\n"
            "1. Inspect agent pod logs on daemonset <DATADOG_AGENT_1> across cluster <CLUSTER_SERVICE_ENDPOINT_1>.\n"
            "2. Verify network egress path from node <INTERNAL_IP_1> to telemetry gateway.\n"
            "3. Restart agent daemon and flush forwarder buffer."
        ),
        "tokens_count": 3
    },
    {
        "id": "KB-ARGUS-SOP-08",
        "team": "SecOps",
        "title": "Cross-Site Scripting & Bearer Session Invalidation",
        "content": (
            "# Runbook: Session Hijacking Rapid Response\n"
            "Severity: High | Author: Alex Chen\n\n"
            "## Procedure:\n"
            "1. Blacklist compromised session identifier <BEARER_AUTH_1> across border proxy <AWS_GATEWAY_1>.\n"
            "2. Trigger force logout for identity <EMAIL_ADDRESS_1>.\n"
            "3. Inspect API server logs on <CLUSTER_SERVICE_ENDPOINT_1>."
        ),
        "tokens_count": 3
    },
    {
        "id": "KB-ARGUS-SOP-09",
        "team": "CloudInfra",
        "title": "Kafka Broker Partition Rebalance & Zookeeper Sync",
        "content": (
            "# Runbook: Kafka Partition Starvation\n"
            "Severity: High | Author: Marcus Vance\n\n"
            "## Procedure:\n"
            "1. Identify under-replicated partitions on message broker <CLUSTER_SERVICE_ENDPOINT_1>.\n"
            "2. Rebalance consumer groups subscribed to ingestion pipeline.\n"
            "3. Verify broker heartbeat via internal host <INTERNAL_DNS_HOST_1>."
        ),
        "tokens_count": 2
    },
    # The following 3 runbooks are intentionally seeded with decay / obsolete status
    {
        "id": "KB-ARGUS-SOP-10",
        "team": "CloudInfra",
        "title": "Legacy Apache Cassandra 2.1 Ring Repair (DEPRECATED)",
        "content": (
            "# Runbook: Cassandra Ring Repair [ARCHIVED 2021]\n"
            "Severity: Low | Author: Dave Miller (Departed)\n\n"
            "## Procedure:\n"
            "Run nodetool repair -pr on outdated cluster nodes. Requires Python 2.7 runtime.\n"
            "Warning: This runbook targets deprecated architecture and fails on modern Kubernetes clusters."
        ),
        "tokens_count": 0
    },
    {
        "id": "KB-ARGUS-SOP-11",
        "team": "SecOps",
        "title": "Manual OpenSSL Heartbleed Vulnerability Patching (OBSOLETE)",
        "content": (
            "# Runbook: Manual OpenSSL Heartbleed Mitigation\n"
            "Severity: Low | Author: Legacy Admin\n\n"
            "## Procedure:\n"
            "Manually compile OpenSSL 1.0.1g on bare metal Debian wheezy instances.\n"
            "Note: Completely obsolete. Fleet operates on automated hardened Linux AMI images."
        ),
        "tokens_count": 0
    },
    {
        "id": "KB-ARGUS-SOP-12",
        "team": "PaymentLedger",
        "title": "Direct Raw SQL Table Lock Injection on Master (UNSAFE)",
        "content": (
            "# Runbook: Direct Table Lock Intervention\n"
            "Severity: Critical | Author: Anonymous\n\n"
            "## Procedure:\n"
            "Execute LOCK TABLES write directly in production ledger database without replication checks.\n"
            "Warning: High risk of cascading outage. Downvoted by SRE leadership."
        ),
        "tokens_count": 0
    }
]


# 20+ Interconnected Incidents (Heavy token reuse + Skewed metadata)
SEED_INCIDENTS = [
    {
        "id": "INC-2026-8001",
        "team": "SecOps",
        "title": "Sev-1 AWS Gateway 504 Timeout & IAM Key Leak",
        "assignee": "Alex Chen",
        "content": (
            "[INC-2026-8001] Production Service Incident (Sev-1)\n"
            "Assignee: Alex Chen\n"
            "Target VPC: us-east-1 | Gateway: <AWS_GATEWAY_1>\n\n"
            "Description:\n"
            "Perimeter ingress gateway <AWS_GATEWAY_1> began throwing 504 gateway timeouts.\n"
            "Anomalous API calls detected using credential <AWS_ACCESS_KEY_1> from workstation <INTERNAL_IP_1>.\n"
            "Compromised session token <JWT_TOKEN_1> identified in authorization header.\n"
            "Worker pod <K8S_POD_1> in namespace <K8S_NAMESPACE_1> became unresponsive."
        ),
        "tokens_count": 5
    },
    {
        "id": "INC-2026-8002",
        "team": "SecOps",
        "title": "Sev-1 Perimeter Breach & Unauthorized Root Access",
        "assignee": "Alex Chen",
        "content": (
            "[INC-2026-8002] Security Enclave Alert (Sev-1)\n"
            "Assignee: Alex Chen\n\n"
            "Description:\n"
            "Brute force SSH attempt detected on edge router <INTERNAL_IP_1>.\n"
            "Traffic passed through border entry <AWS_GATEWAY_1> before rate-limiting triggered.\n"
            "Attacker attempted to extract vault master token <VAULT_ROOT_TOKEN_1>.\n"
            "Automated alert sent to Slack webhook <SLACK_WEBHOOK_1>."
        ),
        "tokens_count": 4
    },
    {
        "id": "INC-2026-8003",
        "team": "SecOps",
        "title": "Sev-1 Secret Key Exposure on Public Repository",
        "assignee": "Alex Chen",
        "content": (
            "[INC-2026-8003] Cloud Credential Compromise (Sev-1)\n"
            "Assignee: Alex Chen\n\n"
            "Description:\n"
            "Automated bot scraped secret <AWS_SECRET_KEY_1> tied to IAM identity <AWS_ACCESS_KEY_1>.\n"
            "Unauthorized ingress hit proxy <AWS_GATEWAY_1> targeting cluster <CLUSTER_SERVICE_ENDPOINT_1>.\n"
            "Immediate quarantine applied by Alex Chen."
        ),
        "tokens_count": 4
    },
    {
        "id": "INC-2026-8004",
        "team": "SecOps",
        "title": "Sev-1 Border Gateway Ingress Congestion Outage",
        "assignee": "Alex Chen",
        "content": (
            "[INC-2026-8004] External Dependency Outage (Sev-1)\n"
            "Assignee: Alex Chen\n\n"
            "Description:\n"
            "Provider AWS reported internal transit fabric packet drops at <AWS_GATEWAY_1>.\n"
            "Downstream internal microservices on <INTERNAL_IP_1> and <INTERNAL_IP_2> lost connectivity.\n"
            "Mitigation: Alex Chen redirected ingress via fallback carrier."
        ),
        "tokens_count": 3
    },
    {
        "id": "INC-2026-8005",
        "team": "SecOps",
        "title": "Sev-1 Token Invalidation Failure on Auth Proxy",
        "assignee": "Alex Chen",
        "content": (
            "[INC-2026-8005] Auth Bypass Incident (Sev-1)\n"
            "Assignee: Alex Chen\n\n"
            "Description:\n"
            "Revoked bearer token <BEARER_AUTH_1> continued passing validation at border <AWS_GATEWAY_1>.\n"
            "Target service endpoint <CLUSTER_SERVICE_ENDPOINT_1> serviced 400 unauthenticated requests.\n"
            "Investigation and resolution lead: Alex Chen."
        ),
        "tokens_count": 3
    },
    {
        "id": "INC-2026-8006",
        "team": "SecOps",
        "title": "Sev-2 Datadog Security Agent Forwarder Buffer Overflow",
        "assignee": "Alex Chen",
        "content": (
            "[INC-2026-8006] Observability Failure (Sev-2)\n"
            "Assignee: Alex Chen\n\n"
            "Description:\n"
            "Observability agent <DATADOG_AGENT_1> crashed due to log surge on node <INTERNAL_IP_1>.\n"
            "Security telemetry went blind for 22 minutes across cluster <CLUSTER_SERVICE_ENDPOINT_1>.\n"
            "Remediation executed by Alex Chen."
        ),
        "tokens_count": 3
    },
    {
        "id": "INC-2026-8007",
        "team": "SecOps",
        "title": "Sev-2 Perimeter Firewall Rule Drift",
        "assignee": "Elena Rostova",
        "content": (
            "[INC-2026-8007] Perimeter Config Anomaly (Sev-2)\n"
            "Assignee: Elena Rostova\n\n"
            "Description:\n"
            "Egress filtering rule lapsed on host <INTERNAL_IP_1> allowing outbound connections to untrusted host.\n"
            "Reported by Datadog telemetry agent <DATADOG_AGENT_1>."
        ),
        "tokens_count": 2
    },
    {
        "id": "INC-2026-8008",
        "team": "CloudInfra",
        "title": "Sev-1 Datadog Agent CPU Spike & Thread Starvation",
        "assignee": "Marcus Vance",
        "content": (
            "[INC-2026-8008] Infrastructure Outage (Sev-1)\n"
            "Assignee: Marcus Vance\n\n"
            "Description:\n"
            "Third-party monitoring daemon <DATADOG_AGENT_1> consumed 100% CPU on host <INTERNAL_IP_1>.\n"
            "Worker pod <K8S_POD_1> in namespace <K8S_NAMESPACE_1> was starved of compute cycles.\n"
            "Cluster endpoint <CLUSTER_SERVICE_ENDPOINT_1> failed healthchecks."
        ),
        "tokens_count": 4
    },
    {
        "id": "INC-2026-8009",
        "team": "CloudInfra",
        "title": "Sev-1 Primary Database Connection Pool Collapse",
        "assignee": "Marcus Vance",
        "content": (
            "[INC-2026-8009] PostgreSQL Cluster Outage (Sev-1)\n"
            "Assignee: Marcus Vance\n\n"
            "Description:\n"
            "HikariCP pool drained to 0 available connections on database <DB_CONNECTION_STRING_1>.\n"
            "Host <INTERNAL_IP_1> dropped all incoming API requests from gateway <AWS_GATEWAY_1>.\n"
            "Database endpoint <CLUSTER_SERVICE_ENDPOINT_1> rebooted under failover protocol."
        ),
        "tokens_count": 4
    },
    {
        "id": "INC-2026-8010",
        "team": "CloudInfra",
        "title": "Sev-1 Kubernetes Worker Node Kernel Panic",
        "assignee": "Marcus Vance",
        "content": (
            "[INC-2026-8010] Kubernetes Node Eviction (Sev-1)\n"
            "Assignee: Marcus Vance\n\n"
            "Description:\n"
            "Compute node <INTERNAL_DNS_HOST_1> crashed under memory pressure exceeding <RESOURCE_CAPACITY_1>.\n"
            "Workload pod <K8S_POD_1> evicted repeatedly.\n"
            "Datadog agent <DATADOG_AGENT_1> failed to ship kernel dump."
        ),
        "tokens_count": 4
    },
    {
        "id": "INC-2026-8011",
        "team": "CloudInfra",
        "title": "Sev-2 Datadog Metric Pipeline Ingestion Drop",
        "assignee": "Marcus Vance",
        "content": (
            "[INC-2026-8011] Observability Outage (Sev-2)\n"
            "Assignee: Marcus Vance\n\n"
            "Description:\n"
            "Third-party vendor Datadog experienced US-East ingestion outage.\n"
            "Agent <DATADOG_AGENT_1> queued 5GB of unsent metrics on disk on host <INTERNAL_IP_1>.\n"
            "Alerting paused across <K8S_NAMESPACE_1>."
        ),
        "tokens_count": 3
    },
    {
        "id": "INC-2026-8012",
        "team": "CloudInfra",
        "title": "Sev-2 Ingress DNS Resolution Latency",
        "assignee": "David Kim",
        "content": (
            "[INC-2026-8012] DNS Lookup Timeout (Sev-2)\n"
            "Assignee: David Kim\n\n"
            "Description:\n"
            "Internal CoreDNS failed resolving <INTERNAL_DNS_HOST_1> from worker <K8S_POD_1>.\n"
            "Fallback routed through gateway <AWS_GATEWAY_1> with 450ms latency penalty."
        ),
        "tokens_count": 3
    },
    {
        "id": "INC-2026-8013",
        "team": "PaymentLedger",
        "title": "Sev-1 Settlement Deadlock & Payment Gateway Timeout",
        "assignee": "Priya Sharma",
        "content": (
            "[INC-2026-8013] Financial Transaction Interruption (Sev-1)\n"
            "Assignee: Priya Sharma\n\n"
            "Description:\n"
            "Payment batch pipeline deadlocked on database host <INTERNAL_IP_2>.\n"
            "Cardholder transactions referencing <CREDIT_CARD_PAN_1> hung in processing state.\n"
            "Incoming charges through <AWS_GATEWAY_1> timed out after 30s."
        ),
        "tokens_count": 3
    },
    {
        "id": "INC-2026-8014",
        "team": "PaymentLedger",
        "title": "Sev-1 Vault Unseal Lockout & Ledger Halt",
        "assignee": "Priya Sharma",
        "content": (
            "[INC-2026-8014] Cryptographic Enclave Failure (Sev-1)\n"
            "Assignee: Priya Sharma\n\n"
            "Description:\n"
            "Security enclave sealed after failed quorum verification using <VAULT_ROOT_TOKEN_1>.\n"
            "Database connection URI <DB_CONNECTION_STRING_1> could not be decrypted.\n"
            "Host <INTERNAL_IP_2> rejected all settlement jobs."
        ),
        "tokens_count": 3
    },
    {
        "id": "INC-2026-8015",
        "team": "PaymentLedger",
        "title": "Sev-1 Datadog APM Trace Drop on Ledger Cluster",
        "assignee": "Priya Sharma",
        "content": (
            "[INC-2026-8015] Payment Compliance Telemetry Hole (Sev-1)\n"
            "Assignee: Priya Sharma\n\n"
            "Description:\n"
            "APM spans generated by <DATADOG_AGENT_1> dropped 100% of transaction traces on node <INTERNAL_IP_2>.\n"
            "Audit requirement violated during high-volume ledger reconciliation window."
        ),
        "tokens_count": 2
    },
    {
        "id": "INC-2026-8016",
        "team": "PaymentLedger",
        "title": "Sev-2 Replay Attack Mitigation on Bearer Auth",
        "assignee": "Priya Sharma",
        "content": (
            "[INC-2026-8016] Auth Anomaly (Sev-2)\n"
            "Assignee: Priya Sharma\n\n"
            "Description:\n"
            "Duplicate auth token <BEARER_AUTH_1> submitted across 12 distinct worker nodes.\n"
            "Perimeter ingress <AWS_GATEWAY_1> throttled client IP."
        ),
        "tokens_count": 2
    },
    {
        "id": "INC-2026-8017",
        "team": "PaymentLedger",
        "title": "Sev-2 Database Read Replica Replication Lag",
        "assignee": "Carlos Mendez",
        "content": (
            "[INC-2026-8017] Replication Lag (Sev-2)\n"
            "Assignee: Carlos Mendez\n\n"
            "Description:\n"
            "Read replica at <CLUSTER_SERVICE_ENDPOINT_1> fell behind primary by 850 seconds.\n"
            "Ledger reconciliation job redirected queries to master on <INTERNAL_IP_2>."
        ),
        "tokens_count": 2
    },
    {
        "id": "INC-2026-8018",
        "team": "CloudInfra",
        "title": "Sev-1 AWS Gateway Cross-Region Route Flapping",
        "assignee": "Marcus Vance",
        "content": (
            "[INC-2026-8018] Cloud Provider Incident (Sev-1)\n"
            "Assignee: Marcus Vance\n\n"
            "Description:\n"
            "Route flapping at <AWS_GATEWAY_1> caused intermittent 502 Bad Gateway responses.\n"
            "Affected compute hosts <INTERNAL_IP_1> and pod <K8S_POD_1> in <K8S_NAMESPACE_1>."
        ),
        "tokens_count": 4
    },
    {
        "id": "INC-2026-8019",
        "team": "SecOps",
        "title": "Sev-1 Credential Spraying Attack on Perimeter Gateway",
        "assignee": "Alex Chen",
        "content": (
            "[INC-2026-8019] Bot Attack Ingress (Sev-1)\n"
            "Assignee: Alex Chen\n\n"
            "Description:\n"
            "Distributed botnet directed 45,000 requests/sec at <AWS_GATEWAY_1>.\n"
            "Attempted compromise of IAM access key <AWS_ACCESS_KEY_1>.\n"
            "Blocked and quarantined by Alex Chen."
        ),
        "tokens_count": 2
    },
    {
        "id": "INC-2026-8020",
        "team": "CloudInfra",
        "title": "Sev-2 Datadog Metrics False Positive Alert Storm",
        "assignee": "Marcus Vance",
        "content": (
            "[INC-2026-8020] Alert Storm (Sev-2)\n"
            "Assignee: Marcus Vance\n\n"
            "Description:\n"
            "Vendor Datadog monitor triggered 85 paging alerts for <DATADOG_AGENT_1>.\n"
            "Underlying worker nodes <INTERNAL_IP_1> and <INTERNAL_DNS_HOST_1> were operating normally."
        ),
        "tokens_count": 3
    }
]


# Explicit RLHF & Vector Similarity Feedback for Runbook Decay Engine
SEED_FEEDBACK = [
    # KB-ARGUS-SOP-10 (Legacy Cassandra - Obsolete, Low Similarity, Negative RLHF)
    {
        "runbook_id": "KB-ARGUS-SOP-10",
        "team": "CloudInfra",
        "title": "Legacy Apache Cassandra 2.1 Ring Repair (DEPRECATED)",
        "similarity_score": 0.32,
        "rlhf_score": -1,
        "vote_type": "downvote",
        "feedback_notes": "Completely useless for Kubernetes EKS clusters. Contains dead Python 2.7 commands."
    },
    {
        "runbook_id": "KB-ARGUS-SOP-10",
        "team": "CloudInfra",
        "title": "Legacy Apache Cassandra 2.1 Ring Repair (DEPRECATED)",
        "similarity_score": 0.28,
        "rlhf_score": -1,
        "vote_type": "downvote",
        "feedback_notes": "Outdated architecture. Wasted 30 minutes of on-call time."
    },
    {
        "runbook_id": "KB-ARGUS-SOP-10",
        "team": "CloudInfra",
        "title": "Legacy Apache Cassandra 2.1 Ring Repair (DEPRECATED)",
        "similarity_score": 0.35,
        "rlhf_score": -1,
        "vote_type": "downvote",
        "feedback_notes": "Fails dense similarity search for modern database alerts."
    },

    # KB-ARGUS-SOP-11 (Heartbleed - Obsolete, Low Similarity, Negative RLHF)
    {
        "runbook_id": "KB-ARGUS-SOP-11",
        "team": "SecOps",
        "title": "Manual OpenSSL Heartbleed Vulnerability Patching (OBSOLETE)",
        "similarity_score": 0.22,
        "rlhf_score": -1,
        "vote_type": "downvote",
        "feedback_notes": "Archived CVE from 2014. No bare metal Wheezy servers exist in the fleet."
    },
    {
        "runbook_id": "KB-ARGUS-SOP-11",
        "team": "SecOps",
        "title": "Manual OpenSSL Heartbleed Vulnerability Patching (OBSOLETE)",
        "similarity_score": 0.25,
        "rlhf_score": -1,
        "vote_type": "downvote",
        "feedback_notes": "Deprecate immediately from knowledge base."
    },

    # KB-ARGUS-SOP-12 (Direct Raw SQL Table Lock Injection - Dangerous, Downvoted)
    {
        "runbook_id": "KB-ARGUS-SOP-12",
        "team": "PaymentLedger",
        "title": "Direct Raw SQL Table Lock Injection on Master (UNSAFE)",
        "similarity_score": 0.41,
        "rlhf_score": -1,
        "vote_type": "downvote",
        "feedback_notes": "DANGEROUS: Causes cascading transaction deadlock across settlement replicas."
    },
    {
        "runbook_id": "KB-ARGUS-SOP-12",
        "team": "PaymentLedger",
        "title": "Direct Raw SQL Table Lock Injection on Master (UNSAFE)",
        "similarity_score": 0.39,
        "rlhf_score": -1,
        "vote_type": "downvote",
        "feedback_notes": "Violates ACID safety policy. Delete this procedure."
    },

    # Healthy Runbooks with High Similarity & Positive RLHF
    {
        "runbook_id": "KB-ARGUS-SOP-01",
        "team": "SecOps",
        "title": "Emergency IAM Credential Revocation & Perimeter Quarantine",
        "similarity_score": 0.91,
        "rlhf_score": 1,
        "vote_type": "upvote",
        "feedback_notes": "Pinpoint accuracy. Mitigated compromised AWS key in under 2 minutes."
    },
    {
        "runbook_id": "KB-ARGUS-SOP-01",
        "team": "SecOps",
        "title": "Emergency IAM Credential Revocation & Perimeter Quarantine",
        "similarity_score": 0.88,
        "rlhf_score": 1,
        "vote_type": "upvote",
        "feedback_notes": "Token preservation works flawlessly."
    },
    {
        "runbook_id": "KB-ARGUS-SOP-02",
        "team": "CloudInfra",
        "title": "PgBouncer Connection Starvation & Pool Draining SOP",
        "similarity_score": 0.86,
        "rlhf_score": 1,
        "vote_type": "upvote",
        "feedback_notes": "Saved DB cluster from Sev-1 cascade."
    },
    {
        "runbook_id": "KB-ARGUS-SOP-03",
        "team": "PaymentLedger",
        "title": "Distributed Ledger Lock Recovery & Deadlock Clearance",
        "similarity_score": 0.84,
        "rlhf_score": 1,
        "vote_type": "upvote",
        "feedback_notes": "Effective deadlocked thread identification."
    }
]


# ---------------------------------------------------------------------
# Seeder Execution Function
# ---------------------------------------------------------------------
def seed_enterprise_data() -> Dict[str, Any]:
    """
    Wipes and repopulates SQLite knowledge base and ChromaDB vector index
    with a rich, interconnected dummy dataset tailored for C-suite executive BI.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)

    # 1. Initialize / Wipe SQLite
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        with conn:
            conn.execute("DROP TABLE IF EXISTS local_knowledge_base")
            conn.execute("DROP TABLE IF EXISTS runbook_feedback")

            conn.execute("""
                CREATE TABLE local_knowledge_base (
                    id TEXT PRIMARY KEY,
                    team TEXT NOT NULL,
                    title TEXT NOT NULL,
                    sanitized_content TEXT NOT NULL,
                    redacted_tokens_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    storage_tier TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE runbook_feedback (
                    id TEXT PRIMARY KEY,
                    runbook_id TEXT NOT NULL,
                    team TEXT NOT NULL,
                    title TEXT NOT NULL,
                    similarity_score REAL NOT NULL,
                    rlhf_score INTEGER NOT NULL,
                    vote_type TEXT NOT NULL,
                    feedback_notes TEXT,
                    created_at TEXT NOT NULL
                )
            """)

            # Insert Runbooks
            runbook_rows = []
            now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            for idx, rb in enumerate(SEED_RUNBOOKS):
                chash = hashlib.sha256(rb["content"].encode("utf-8")).hexdigest()[:12]
                runbook_rows.append((
                    rb["id"],
                    rb["team"],
                    rb["title"],
                    rb["content"],
                    rb["tokens_count"],
                    f"2026-10-2{idx % 9} 08:{10 + idx:02d}:00",
                    chash,
                    "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
                ))

            conn.executemany(
                "INSERT INTO local_knowledge_base VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                runbook_rows
            )

            # Insert Incidents
            incident_rows = []
            for idx, inc in enumerate(SEED_INCIDENTS):
                chash = hashlib.sha256(inc["content"].encode("utf-8")).hexdigest()[:12]
                incident_rows.append((
                    inc["id"],
                    inc["team"],
                    inc["title"],
                    inc["content"],
                    inc["tokens_count"],
                    f"2026-10-30 {10 + (idx // 4):02d}:{(idx * 7) % 60:02d}:00",
                    chash,
                    "Local SQLite + ChromaDB (all-MiniLM-L6-v2)"
                ))

            conn.executemany(
                "INSERT INTO local_knowledge_base VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                incident_rows
            )

            # Insert Feedback
            feedback_rows = []
            for idx, fb in enumerate(SEED_FEEDBACK):
                fb_id = f"FB-SEED-{1000 + idx}"
                feedback_rows.append((
                    fb_id,
                    fb["runbook_id"],
                    fb["team"],
                    fb["title"],
                    fb["similarity_score"],
                    fb["rlhf_score"],
                    fb["vote_type"],
                    fb["feedback_notes"],
                    f"2026-10-30 {14 + (idx // 3):02d}:{(idx * 11) % 60:02d}:00"
                ))

            conn.executemany(
                "INSERT INTO runbook_feedback VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                feedback_rows
            )

    finally:
        conn.close()

    # Save physical Markdown copies to generated_runbooks/ directory
    runbooks_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_runbooks")
    os.makedirs(runbooks_dir, exist_ok=True)
    for r in runbook_rows:
        doc_id, team, title, content, tokens_count, created_at, chash, tier = r
        filepath = os.path.join(runbooks_dir, f"{doc_id}.md")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"""---
id: {doc_id}
team: {team}
title: "{title}"
created_at: "{created_at}"
content_hash: {chash}
storage_tier: "{tier}"
vector_index: "ChromaDB all-MiniLM-L6-v2 (384-d)"
status: "Authoritative Runbook Indexed in SQLite & ChromaDB"
disk_filepath: "{filepath}"
---

{content}
""")

    # 2. Sync into ChromaDB with true ONNX 384-d vectors if ChromaDB is available
    if CHROMA_AVAILABLE:
        try:
            onnx_fn = DefaultEmbeddingFunction()
            client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)

            # Delete existing collection to wipe cleanly
            try:
                client.delete_collection("argus_knowledge_base")
            except Exception:
                pass

            collection = client.create_collection(
                name="argus_knowledge_base",
                embedding_function=onnx_fn,
                metadata={"hnsw:space": "cosine"}
            )

            # Combine runbooks and incidents for vector ingestion
            all_docs = []
            all_ids = []
            all_metas = []

            for rb in SEED_RUNBOOKS:
                all_ids.append(rb["id"])
                all_docs.append(f"{rb['title']}\n{rb['content']}")
                all_metas.append({
                    "team": rb["team"],
                    "title": rb["title"],
                    "doc_id": rb["id"],
                    "created_at": now_str,
                    "type": "runbook"
                })

            for inc in SEED_INCIDENTS:
                all_ids.append(inc["id"])
                all_docs.append(f"{inc['title']}\n{inc['content']}")
                all_metas.append({
                    "team": inc["team"],
                    "title": inc["title"],
                    "doc_id": inc["id"],
                    "created_at": now_str,
                    "type": "incident"
                })

            # Upsert in batch
            collection.upsert(
                ids=all_ids,
                documents=all_docs,
                metadatas=all_metas
            )

            chroma_count = collection.count()

            # Update rag_engine's reference so it immediately reflects the fresh collection
            try:
                import rag_engine
                rag_engine.chroma_collection = collection
            except Exception:
                pass

        except Exception as e:
            print(f"[seed_data] ChromaDB seeding warning: {e}")

    return {
        "status": "success",
        "sqlite_records_inserted": len(runbook_rows) + len(incident_rows),
        "runbooks_seeded": len(runbook_rows),
        "incidents_seeded": len(incident_rows),
        "feedback_entries_seeded": len(feedback_rows),
        "chroma_vectors_indexed": chroma_count,
        "bus_factor_skew": "SecOps 85% assigned to Alex Chen",
        "vendor_sla_tokens": ["<AWS_GATEWAY_1>", "<DATADOG_AGENT_1>"],
        "decay_runbooks": ["KB-ARGUS-SOP-10", "KB-ARGUS-SOP-11", "KB-ARGUS-SOP-12"]
    }


if __name__ == "__main__":
    print("Seeding Argus Knowledge Base & Vector Index...")
    res = seed_enterprise_data()
    print("Seed complete:", res)

"""
sre_simulator.py - Shadow SRE Flight Simulator & Training Sandbox.

Allows junior engineers to safely practice incident response drills on historical outages.
Provides isolated scenario ingestion (strictly hiding the actual fix), evaluates
proposed fixes using dense 384-dimensional vector similarity against senior runbooks,
and generates constructive AI Senior SRE Mentor feedback via llm_bridge.py.
"""

import os
import random
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import llm_bridge
import rag_engine

router = APIRouter(prefix="/api/simulator", tags=["Shadow SRE Simulator"])

from config import DATA_DIR, DB_PATH

SRE_MENTOR_SYSTEM_PROMPT = (
    "You are a Senior Principal SRE Mentor at Argus. Review the junior engineer's proposed fix against the "
    "senior team's historical resolution. Provide concise, constructive feedback explaining what they got right, "
    "what critical commands or tokens they missed (e.g. <INTERNAL_IP_1>), and assign a clear grade. "
    "Maintain all <TOKEN> entities."
)

# Curated Historical Scenarios linked to knowledge base records
HISTORICAL_SCENARIOS: List[Dict[str, Any]] = [
    {
        "doc_id": "KB-ARGUS-01",
        "title": "Compromised IAM Identity & Perimeter Key Leak",
        "team": "SecOps",
        "severity": "Critical",
        "difficulty": "Intermediate",
        "symptoms": (
            "ALERT: AWS IAM Access Key <AWS_ACCESS_KEY_1> detected in public GitHub repository commit logs.\n"
            "CloudTrail Telemetry: 42 unauthorized GetCallerIdentity API calls from external IP range.\n"
            "Worker Node: ip-10-0-12-84.ec2.internal attempting egress to unapproved S3 buckets.\n"
            "Diagnostic State: Immediate credential quarantine required before privilege escalation occurs."
        ),
        "actual_fix": "Procedure to revoke <AWS_ACCESS_KEY_1> and invalidate associated session tokens. Apply emergency IAM deny policy and null-route active sessions.",
        "affected_tokens": ["<AWS_ACCESS_KEY_1>", "<INTERNAL_IP_1>"],
        "hint": "Focus on immediate IAM key revocation, active session token invalidation, and quarantine policies."
    },
    {
        "doc_id": "KB-ARGUS-02",
        "title": "PgBouncer Connection Starvation & Pool Draining",
        "team": "CloudInfra",
        "severity": "Critical",
        "difficulty": "Intermediate",
        "symptoms": (
            "ALERT: PgBouncer pool saturation on host <INTERNAL_IP_1>:6432.\n"
            "Error: org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for non-replication superuser connections.\n"
            "Active Client Threads: 450/450 pool capacity consumed.\n"
            "Diagnostic State: Downstream payment microservice failing with HTTP 504 Gateway Timeouts."
        ),
        "actual_fix": "Draining active connections to replica host <INTERNAL_IP_1> and rebalancing pool. Increase client pool limit to 750 and restart connection proxy.",
        "affected_tokens": ["<INTERNAL_IP_1>", "<CLUSTER_SERVICE_ENDPOINT_1>"],
        "hint": "The replica connection pool is locked by dangling clients. Consider draining connections on host <INTERNAL_IP_1>."
    },
    {
        "doc_id": "KB-ARGUS-03",
        "title": "Async Ledger Reconciliation Threadpool Lock Recovery",
        "team": "PaymentLedger",
        "severity": "High",
        "difficulty": "Advanced",
        "symptoms": (
            "ALERT: Deadlock detected in distributed transaction orchestrator on host <INTERNAL_IP_2>.\n"
            "Error: java.sql.SQLException: Transaction isolation deadlock on row lock #981029.\n"
            "Unclosed DB connections: 18 active workers blocked for > 120s.\n"
            "Diagnostic State: Settlement ledger batch processing halted; reconciliation lag increasing."
        ),
        "actual_fix": "Clearing threadpool locks on host <INTERNAL_IP_2> for unclosed database transactions. Kill blocking PID 4109 and trigger ledger replay checkpoint.",
        "affected_tokens": ["<INTERNAL_IP_2>", "<DB_CONNECTION_STRING_1>"],
        "hint": "Identify blocking transaction thread locks on host <INTERNAL_IP_2> and clear dangling workers."
    },
    {
        "doc_id": "KB-ARGUS-04",
        "title": "Kubernetes Out-Of-Memory (OOMKilled) Workload Crash",
        "team": "CloudInfra",
        "severity": "Critical",
        "difficulty": "Junior",
        "symptoms": (
            "ALERT: Pod <K8S_POD_ID_1> in namespace <K8S_NAMESPACE_1> terminated with Exit Code 137 (OOMKilled).\n"
            "Telemetry: Memory allocation exceeded limit <RESOURCE_CAPACITY_1> on node <INTERNAL_DNS_HOST_1>.\n"
            "CrashLoopBackOff: Restart count = 6 within 15 minutes.\n"
            "Diagnostic State: Core payment gateway traffic dropping 22% of customer requests."
        ),
        "actual_fix": "Identify pods matching <K8S_POD_ID_1> in <K8S_NAMESPACE_1>. Inspect memory limits <RESOURCE_CAPACITY_1> and scale replica controllers on <INTERNAL_DNS_HOST_1>.",
        "affected_tokens": ["<K8S_POD_ID_1>", "<K8S_NAMESPACE_1>", "<RESOURCE_CAPACITY_1>", "<INTERNAL_DNS_HOST_1>"],
        "hint": "Inspect the container memory limits <RESOURCE_CAPACITY_1> and adjust replica scaling on node <INTERNAL_DNS_HOST_1>."
    },
    {
        "doc_id": "KB-ARGUS-05",
        "title": "Emergency Perimeter Ingress Block & IP Null-Routing",
        "team": "SecOps",
        "severity": "Critical",
        "difficulty": "Advanced",
        "symptoms": (
            "ALERT: Border gateway firewall reported 15,000 SYN flood packets from <INTERNAL_IP_1>.\n"
            "Unauthorized bearer tokens attempted access against OAuth endpoint /oauth/v2/token.\n"
            "Perimeter WAF threshold breached (12.4 Gbps ingress volume).\n"
            "Diagnostic State: Border ingress saturation threatening public API reachability."
        ),
        "actual_fix": "Apply emergency CIDR firewall filter at border gateway for unauthorized ingress from <INTERNAL_IP_1> and terminate active bearer sessions.",
        "affected_tokens": ["<INTERNAL_IP_1>", "<BEARER_AUTH_1>"],
        "hint": "Null-route the malicious CIDR source <INTERNAL_IP_1> and immediately invalidate active bearer tokens."
    }
]


class EvaluateProposedFixRequest(BaseModel):
    doc_id: str = Field(..., description="Target historical scenario ID")
    proposed_fix: str = Field(..., description="Remediation steps typed by junior engineer")


def _calculate_cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Computes cosine similarity between two dense vectors."""
    if len(vec_a) != len(vec_b) or not vec_a:
        return 0.0
    dot_prod = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = sum(a * a for a in vec_a) ** 0.5
    norm_b = sum(b * b for b in vec_b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return max(0.0, min(1.0, dot_prod / (norm_a * norm_b)))


def _get_scenario_by_id(doc_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves scenario details by ID from catalog or database."""
    for s in HISTORICAL_SCENARIOS:
        if s["doc_id"].lower() == doc_id.lower():
            return dict(s)

    # Fallback to local SQLite database lookup
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        try:
            with conn:
                cursor = conn.execute(
                    "SELECT id, team, title, sanitized_content FROM local_knowledge_base WHERE id = ?",
                    (doc_id,)
                )
                row = cursor.fetchone()
                if row:
                    tokens = list(set(re.findall(r'<[A-Z0-9_]+_\d+>', row[3])))
                    return {
                        "doc_id": row[0],
                        "team": row[1],
                        "title": row[2],
                        "severity": "High",
                        "difficulty": "Intermediate",
                        "symptoms": f"Historical anomaly reported on {row[1]}: {row[2]}.\nDiagnostic Trace: {row[3][:220]}...",
                        "actual_fix": row[3],
                        "affected_tokens": tokens,
                        "hint": f"Review standard operating procedures for {row[1]}."
                    }
        finally:
            conn.close()

    return None


@router.get("/scenario")
async def get_simulator_scenario(
    team: Optional[str] = None,
    scenario_id: Optional[str] = None
):
    """
    Mandate 2: Fetches a random sanitized historical outage scenario.
    Returns symptoms, title, and metadata but STRICTLY EXCLUDES the actual fix
    from the response payload to maintain training integrity.
    """
    if scenario_id:
        scenario = _get_scenario_by_id(scenario_id)
    else:
        pool = HISTORICAL_SCENARIOS
        if team and team.lower() not in ("all", "global", ""):
            filtered = [s for s in pool if s["team"].lower() == team.lower()]
            if filtered:
                pool = filtered
        scenario = random.choice(pool)

    if not scenario:
        scenario = HISTORICAL_SCENARIOS[0]

    # STRICTLY EXCLUDE actual_fix from the client JSON response
    return {
        "status": "SCENARIO_READY",
        "doc_id": scenario["doc_id"],
        "title": scenario["title"],
        "team": scenario["team"],
        "severity": scenario["severity"],
        "difficulty": scenario["difficulty"],
        "symptoms": scenario["symptoms"],
        "affected_tokens": scenario.get("affected_tokens", []),
        "hint": scenario.get("hint", "Examine diagnostic tokens and apply appropriate operational runbook commands.")
    }


@router.get("/scenarios/all")
async def list_all_scenarios():
    """Returns list of all available training scenario summaries (without fixes)."""
    return {
        "scenarios": [
            {
                "doc_id": s["doc_id"],
                "title": s["title"],
                "team": s["team"],
                "severity": s["severity"],
                "difficulty": s["difficulty"],
                "tokens_count": len(s.get("affected_tokens", []))
            }
            for s in HISTORICAL_SCENARIOS
        ]
    }


@router.post("/evaluate")
async def evaluate_proposed_fix(payload: EvaluateProposedFixRequest):
    """
    Mandate 2: Evaluates junior engineer's proposed fix against senior historical fix.
    1. Fetches actual historical fix from database.
    2. Uses rag_engine.py dense 384-d vectors to calculate cosine similarity.
    3. Calls llm_bridge.py to synthesize constructive SRE mentor feedback.
    4. Returns vector similarity score, grade, and mentor advice.
    """
    scenario = _get_scenario_by_id(payload.doc_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario {payload.doc_id} not found.")

    actual_fix = scenario["actual_fix"]
    proposed_fix = payload.proposed_fix.strip()

    if not proposed_fix:
        raise HTTPException(status_code=400, detail="Proposed fix cannot be empty.")

    # 1. Compute 384-dimensional dense vectors
    vec_proposed = rag_engine.compute_dense_embedding_384(proposed_fix)
    vec_actual = rag_engine.compute_dense_embedding_384(actual_fix)

    # 2. Compute true cosine similarity
    sim_score = _calculate_cosine_similarity(vec_proposed, vec_actual)

    # Entity / Token coverage analysis
    actual_tokens = set(re.findall(r'<[A-Z0-9_]+_\d+>', actual_fix))
    proposed_tokens = set(re.findall(r'<[A-Z0-9_]+_\d+>', proposed_fix))

    tokens_used = list(actual_tokens & proposed_tokens)
    tokens_missed = list(actual_tokens - proposed_tokens)

    # Dynamic grade determination
    if sim_score >= 0.78 and len(tokens_missed) == 0:
        grade = "Senior SRE Standard"
    elif sim_score >= 0.60:
        grade = "Proficient L1 Engineer"
    elif sim_score >= 0.40:
        grade = "Apprentice SRE (Needs Review)"
    else:
        grade = "Remediation Incomplete"

    # 3. LLM SRE Mentor Feedback synthesis
    user_prompt = (
        f"Incident Title: {scenario['title']}\n"
        f"Team: {scenario['team']}\n\n"
        f"Senior SRE Historical Resolution:\n\"\"\"\n{actual_fix}\n\"\"\"\n\n"
        f"Junior Engineer Proposed Fix:\n\"\"\"\n{proposed_fix}\n\"\"\"\n\n"
        f"Cosine Vector Similarity: {sim_score:.2%}\n"
        f"Deterministic Tokens Addressed: {tokens_used}\n"
        f"Deterministic Tokens Missed: {tokens_missed}\n\n"
        f"Provide a brief, constructive SRE mentor review."
    )

    try:
        llm_res = await llm_bridge.synthesize_action_plan(
            sanitized_incident_text=user_prompt,
            retrieved_chunks=[{"title": scenario["title"], "team": scenario["team"], "sanitized_snippet": actual_fix, "similarity_score": sim_score}],
            system_prompt=SRE_MENTOR_SYSTEM_PROMPT
        )
        mentor_feedback = llm_res.get("action_plan", "")
    except ConnectionError as ce:
        raise HTTPException(
            status_code=503,
            detail=f"SRE Mentor AI Unavailable: Ollama daemon is offline at {llm_bridge.OLLAMA_ENDPOINT}. Start Ollama and pull llama3 to evaluate solutions: {ce}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"SRE Simulator Evaluation Error: {str(e)}"
        )

    return {
        "status": "EVALUATION_COMPLETE",
        "scenario_id": scenario["doc_id"],
        "title": scenario["title"],
        "team": scenario["team"],
        "similarity_score": round(sim_score, 4),
        "similarity_percentage": f"{int(sim_score * 100)}%",
        "evaluation_grade": grade,
        "mentor_feedback": mentor_feedback,
        "tokens_used_correctly": tokens_used,
        "tokens_missed": tokens_missed,
        "actual_fix_revealed": actual_fix,
        "vector_dimensions": 384
    }

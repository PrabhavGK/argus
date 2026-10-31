"""
graph_engine.py - Semantic Graph Engine & Incident Topology Mapper.

Constructs an in-memory knowledge graph (NetworkX-style Node/Edge structure)
mapping relationships between Runbooks, Incident Tickets, and Deterministic Tokens
(e.g., <INTERNAL_IP_1>, <AWS_ACCESS_KEY_1>) stored in the local SQLite knowledge base.
Maintains 100% zero-leakage: queries exclusively from sanitized database chunks.
"""

import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from fastapi import APIRouter, HTTPException, Query
import networkx as nx

router = APIRouter(prefix="/api/graph", tags=["Semantic Graph Engine"])

from config import DATA_DIR, DB_PATH


TOKEN_REGEX = re.compile(r'<([A-Z0-9_]+)_(\d+)>')


ENTITY_CATEGORY_MAP = {
    "AWS_ACCESS_KEY": {"label": "AWS IAM Key", "category": "Cloud Credential", "risk": "Critical", "color": "#f59e0b"},
    "AWS_SECRET_KEY": {"label": "AWS Secret Key", "category": "Cloud Credential", "risk": "Critical", "color": "#ef4444"},
    "JWT_TOKEN": {"label": "JSON Web Token", "category": "Auth Token", "risk": "Critical", "color": "#8b5cf6"},
    "BEARER_AUTH": {"label": "Bearer Auth Token", "category": "Auth Token", "risk": "Critical", "color": "#ec4899"},
    "DB_CONNECTION_STRING": {"label": "Database Credential", "category": "Database URI", "risk": "Critical", "color": "#dc2626"},
    "HIGH_ENTROPY_SECRET": {"label": "Secret / API Key", "category": "Credential", "risk": "Critical", "color": "#b91c1c"},
    "SLACK_WEBHOOK": {"label": "Webhook URL", "category": "Perimeter Integration", "risk": "High", "color": "#06b6d4"},
    "CLUSTER_SERVICE_ENDPOINT": {"label": "Cluster Host:Port", "category": "Cluster Endpoint", "risk": "High", "color": "#3b82f6"},
    "INTERNAL_DNS_HOST": {"label": "Internal DNS Host", "category": "Compute Node", "risk": "High", "color": "#2563eb"},
    "K8S_POD_ID": {"label": "K8s Pod Workload", "category": "Kubernetes Workload", "risk": "Medium", "color": "#10b981"},
    "RESOURCE_CAPACITY": {"label": "Resource Metric", "category": "Compute Metric", "risk": "Medium", "color": "#64748b"},
    "K8S_NAMESPACE": {"label": "K8s Namespace", "category": "Kubernetes Namespace", "risk": "Medium", "color": "#14b8a6"},
    "INTERNAL_IP": {"label": "IPv4 Network Address", "category": "Network Host", "risk": "High", "color": "#059669"},
    "PERSON_NAME": {"label": "Person Name", "category": "PII Identity", "risk": "Medium", "color": "#a855f7"},
    "EMAIL_ADDRESS": {"label": "Email Address", "category": "PII Contact", "risk": "Medium", "color": "#6366f1"},
    "PHONE_NUMBER": {"label": "Phone Number", "category": "PII Contact", "risk": "Medium", "color": "#d97706"},
    "CREDIT_CARD_PAN": {"label": "PCI PAN", "category": "Financial Credential", "risk": "Critical", "color": "#e11d48"},
    "VAULT_ROOT_TOKEN": {"label": "Vault Root Token", "category": "Security Enclave", "risk": "Critical", "color": "#991b1b"},
}


def _classify_document_type(doc_id: str, title: str) -> str:
    """
    Classifies a record as 'runbook' (authoritative SOP) or 'incident' (crash dump/ticket).
    """
    title_lower = title.lower()
    doc_id_upper = doc_id.upper()

    # Initial seed knowledge base runbooks
    if doc_id_upper.startswith("KB-ARGUS-SOP") or doc_id_upper in ("KB-ARGUS-01", "KB-ARGUS-02", "KB-ARGUS-03", "KB-ARGUS-04", "KB-ARGUS-05"):
        return "runbook"

    if "sop" in title_lower or "runbook" in title_lower or "procedure" in title_lower or "mitigation" in title_lower or "quarantine" in title_lower:
        return "runbook"

    if title.startswith("Vault") or "incident" in title_lower or "crash" in title_lower or "outage" in title_lower or "alert" in title_lower:
        return "incident"

    return "incident"


def build_semantic_topology(team_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Scans sanitized local knowledge base, extracts all deterministic tokens,
    and builds a bipartite NetworkX graph connecting Incident and Runbook documents
    through their shared deterministic infrastructure tokens.
    """
    if not os.path.exists(DB_PATH):
        return {
            "nodes": [],
            "links": [],
            "stats": {"total_nodes": 0, "total_edges": 0, "runbooks": 0, "incidents": 0, "tokens": 0},
            "security_guarantee": "Zero raw PII entered graph plane."
        }

    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        with conn:
            cursor = conn.execute(
                "SELECT id, team, title, sanitized_content, redacted_tokens_count, created_at, hash FROM local_knowledge_base"
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    G = nx.Graph()

    # Track relations for fast lookup
    token_to_docs: Dict[str, List[Dict[str, Any]]] = {}
    doc_metadata: Dict[str, Dict[str, Any]] = {}

    # 1. Parse documents and add Document nodes
    for r in rows:
        doc_id, team, title, sanitized_content, token_count, created_at, chash = r

        # Apply optional team filter
        if team_filter and team_filter.lower() not in ("all", "global", ""):
            if team.lower() != team_filter.lower():
                continue

        doc_type = _classify_document_type(doc_id, title)
        snippet = sanitized_content[:180] + ("..." if len(sanitized_content) > 180 else "")

        doc_meta = {
            "id": doc_id,
            "label": f"{doc_id}: {title[:32]}",
            "name": title,
            "type": doc_type,  # 'runbook' or 'incident'
            "team": team,
            "created_at": created_at,
            "fingerprint": chash,
            "snippet": snippet,
            "tokens_count": token_count
        }
        doc_metadata[doc_id] = doc_meta
        G.add_node(doc_id, **doc_meta)

        # 2. Extract deterministic tokens matching <ENTITY_TYPE_N>
        found_tokens = list(set(TOKEN_REGEX.findall(sanitized_content)))
        for entity_raw, counter in found_tokens:
            token_str = f"<{entity_raw}_{counter}>"

            if token_str not in token_to_docs:
                token_to_docs[token_str] = []
            token_to_docs[token_str].append(doc_meta)

            # Add Token node if not already present
            if not G.has_node(token_str):
                ent_info = ENTITY_CATEGORY_MAP.get(entity_raw, {
                    "label": entity_raw.replace("_", " ").title(),
                    "category": "Generic Identifier",
                    "risk": "Medium",
                    "color": "#10b981"
                })
                G.add_node(
                    token_str,
                    id=token_str,
                    label=token_str,
                    name=token_str,
                    type="token",  # 'token'
                    team=team,
                    entity_type=entity_raw,
                    entity_label=ent_info["label"],
                    category=ent_info["category"],
                    risk=ent_info["risk"],
                    color=ent_info["color"]
                )

            # Add edge between Document and Token
            edge_id = f"{doc_id}->{token_str}"
            G.add_edge(
                doc_id,
                token_str,
                id=edge_id,
                source=doc_id,
                target=token_str,
                relationship="references_entity",
                team=team
            )

    # 3. Enrich Token nodes with exact lists of connected Runbooks and Incidents
    for node_id, data in list(G.nodes(data=True)):
        if data.get("type") == "token":
            connected_docs = token_to_docs.get(node_id, [])
            incidents = [d for d in connected_docs if d["type"] == "incident"]
            runbooks = [d for d in connected_docs if d["type"] == "runbook"]

            teams_set = list(set(d["team"] for d in connected_docs))
            effective_team = teams_set[0] if len(teams_set) == 1 else "Shared"

            G.nodes[node_id]["connected_incidents"] = [
                {"id": inc["id"], "title": inc["name"], "team": inc["team"]} for inc in incidents
            ]
            G.nodes[node_id]["connected_runbooks"] = [
                {"id": rb["id"], "title": rb["name"], "team": rb["team"]} for rb in runbooks
            ]
            G.nodes[node_id]["incident_count"] = len(incidents)
            G.nodes[node_id]["runbook_count"] = len(runbooks)
            G.nodes[node_id]["degree"] = G.degree(node_id)
            G.nodes[node_id]["team"] = effective_team
            G.nodes[node_id]["is_shared_hub"] = (len(incidents) > 1 or (len(incidents) >= 1 and len(runbooks) >= 1))

        elif data.get("type") in ("runbook", "incident"):
            neighbors = list(G.neighbors(node_id))
            token_neighbors = [n for n in neighbors if G.nodes[n].get("type") == "token"]
            G.nodes[node_id]["degree"] = len(neighbors)
            G.nodes[node_id]["linked_tokens"] = token_neighbors

    # 4. Generate structured Nodes & Links payload for D3.js force simulation
    nodes_list = []
    for node_id, data in G.nodes(data=True):
        nodes_list.append(data)

    links_list = []
    for u, v, data in G.edges(data=True):
        links_list.append({
            "source": u,
            "target": v,
            "relationship": data.get("relationship", "references"),
            "team": data.get("team", "Global")
        })

    # Summary metrics
    runbook_nodes = [n for n in nodes_list if n.get("type") == "runbook"]
    incident_nodes = [n for n in nodes_list if n.get("type") == "incident"]
    token_nodes = [n for n in nodes_list if n.get("type") == "token"]
    shared_tokens = [n for n in token_nodes if n.get("is_shared_hub", False)]

    # Compute cross-incident correlations (incident pairs linked through identical tokens)
    correlations = []
    for tok in shared_tokens:
        incs = tok.get("connected_incidents", [])
        if len(incs) > 1:
            for i in range(len(incs)):
                for j in range(i + 1, len(incs)):
                    correlations.append({
                        "token": tok["id"],
                        "entity_type": tok.get("entity_label", "Unknown"),
                        "incident_a": incs[i]["id"],
                        "incident_b": incs[j]["id"],
                        "title_a": incs[i]["title"],
                        "title_b": incs[j]["title"]
                    })

    return {
        "status": "success",
        "nodes": nodes_list,
        "links": links_list,
        "stats": {
            "total_nodes": len(nodes_list),
            "total_links": len(links_list),
            "runbooks_count": len(runbook_nodes),
            "incidents_count": len(incident_nodes),
            "tokens_count": len(token_nodes),
            "shared_hubs_count": len(shared_tokens),
            "cross_incident_correlations_count": len(correlations)
        },
        "shared_token_hubs": [
            {
                "token": t["id"],
                "entity": t.get("entity_label"),
                "risk": t.get("risk"),
                "incidents": len(t.get("connected_incidents", [])),
                "runbooks": len(t.get("connected_runbooks", []))
            }
            for t in shared_tokens
        ],
        "correlations": correlations[:12],
        "security_guarantee": "Strictly derived from sanitized volatile SQLite database; zero raw PII entered graph plane.",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    }


# ---------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------
@router.get("/topology")
async def get_graph_topology(team: Optional[str] = Query(None, description="Optional team filter (SecOps, CloudInfra, PaymentLedger)")):
    """
    Returns the complete Force-Directed Incident & Runbook Topology graph.
    Nodes are typed as 'runbook' (Blue square), 'incident' (Red circle), or 'token' (Green hexagon).
    Links represent shared masked infrastructure references.
    """
    data = build_semantic_topology(team_filter=team)
    return data


@router.get("/tokens/shared")
async def get_shared_tokens():
    """
    Returns high-degree deterministic tokens that form infrastructure hubs
    bridging across multiple incident tickets and runbooks.
    """
    topology = build_semantic_topology()
    return {
        "shared_hubs": topology.get("shared_token_hubs", []),
        "correlations": topology.get("correlations", []),
        "total_shared": len(topology.get("shared_token_hubs", []))
    }

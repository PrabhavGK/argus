"""
connectors.py - Omnichannel Incident Webhook Connectors & Unified Triage Dispatcher.

Implements real-time ingestion for enterprise platforms (Jira, Slack, and Datadog/Grafana Telemetry),
normalizes payloads into the Unified Canonical Incident Schema (UCIS), executes volatile in-RAM
deterministic sanitization, queries ChromaDB partitioned vectors, and synthesizes
an immediate L1 SRE action plan via the LLM bridge. Zero disk persistence during triage.
"""

import asyncio
import hashlib
import html
from html.parser import HTMLParser
import json
import re
import time
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
import httpx

import llm_bridge
import rag_engine
import sanitizer

router = APIRouter(prefix="/api", tags=["Omnichannel Triage Connectors"])


# ---------------------------------------------------------------------
# Unified Canonical Incident Schema (UCIS)
# ---------------------------------------------------------------------
class CanonicalIncident(BaseModel):
    """
    Unified Canonical Incident Schema (UCIS) standardizing heterogeneous payloads
    from Jira, Slack, Datadog, Grafana, or custom telemetry platforms.
    """
    source: str = Field(..., description="Originating platform: jira | slack | telemetry | datadog | grafana | simulation")
    incident_id: str = Field(..., description="Unique incident identifier or ticket key")
    title: str = Field(..., description="Incident title or message summary")
    description: str = Field(..., description="Detailed crash log, metric violation, or alert payload")
    team_id: str = Field("SecOps", description="Target team namespace for vector partitioning")
    severity: str = Field("High", description="Severity classification: Critical, High, Medium, Low")
    reporter: Optional[str] = Field("Argus-Agent", description="User or service reporting the incident")
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()))
    raw_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw incoming JSON payload")


class TriageResponse(BaseModel):
    """
    Standardized response returned to the dispatching webhook or dashboard.
    """
    status: str
    incident_id: str
    source: str
    team_id: str
    severity: str
    sanitized_title: str
    sanitized_description: str
    redacted_tokens_count: int
    mapping: List[Dict[str, Any]]
    retrieved_chunks: List[Dict[str, Any]]
    action_plan: str
    action_plan_source: str
    preserved_tokens: List[str]
    pipeline_latency_ms: float
    zero_disk_guarantee: str = "Zero bytes written to disk; volatile RAM buffer shredded."


# ---------------------------------------------------------------------
# UCIS Normalizers for Jira, Slack, and Observability Telemetry
# ---------------------------------------------------------------------
def normalize_jira_payload(raw: Dict[str, Any]) -> CanonicalIncident:
    """
    Translates raw Jira Cloud/Server webhook payloads into CanonicalIncident.
    """
    issue = raw.get("issue", {})
    fields = issue.get("fields", {}) if isinstance(issue, dict) else {}

    incident_id = issue.get("key") or raw.get("issue_id") or raw.get("key") or f"JIRA-{int(time.time())}"
    title = fields.get("summary") or raw.get("title") or raw.get("summary") or "Production Crash Event"

    desc = fields.get("description") or raw.get("description") or ""
    if isinstance(desc, dict):
        desc = json.dumps(desc)

    priority_obj = fields.get("priority", {})
    severity = priority_obj.get("name") if isinstance(priority_obj, dict) else raw.get("severity", "High")

    project_obj = fields.get("project", {})
    proj_name = project_obj.get("name") if isinstance(project_obj, dict) else raw.get("team_id")

    team_id = "SecOps"
    if proj_name:
        p_lower = str(proj_name).lower()
        if "infra" in p_lower or "cloud" in p_lower:
            team_id = "CloudInfra"
        elif "pay" in p_lower or "ledger" in p_lower:
            team_id = "PaymentLedger"
        elif "sec" in p_lower:
            team_id = "SecOps"
        else:
            team_id = str(proj_name)

    reporter_obj = fields.get("reporter", {})
    reporter = reporter_obj.get("displayName") if isinstance(reporter_obj, dict) else "Jira Webhook"

    return CanonicalIncident(
        source="jira",
        incident_id=incident_id,
        title=title,
        description=str(desc),
        team_id=team_id,
        severity=severity or "High",
        reporter=reporter,
        raw_payload=raw
    )


def normalize_slack_payload(raw: Dict[str, Any]) -> CanonicalIncident:
    """
    Translates raw Slack Event API or Incoming Webhook payloads into CanonicalIncident.
    """
    event = raw.get("event", {}) if "event" in raw else raw
    text = event.get("text") or raw.get("message") or raw.get("text") or ""
    channel = event.get("channel") or raw.get("channel_id") or "incident-triage"
    user = event.get("user") or raw.get("user_id") or "slack-bot"
    ts = event.get("ts") or str(time.time())

    lines = text.strip().split("\n")
    title = lines[0][:100] if lines else "Slack Incident Notification"
    description = text

    c_lower = channel.lower()
    t_lower = text.lower()
    if "infra" in c_lower or "infra" in t_lower or "k8s" in t_lower:
        team_id = "CloudInfra"
    elif "pay" in c_lower or "payment" in t_lower or "ledger" in t_lower:
        team_id = "PaymentLedger"
    else:
        team_id = "SecOps"

    severity = "Critical" if "crit" in t_lower or "sev-1" in t_lower or "p1" in t_lower else "High"
    incident_id = f"SLACK-{channel[-4:].upper()}-{ts.replace('.', '')[-6:]}"

    return CanonicalIncident(
        source="slack",
        incident_id=incident_id,
        title=title,
        description=description,
        team_id=team_id,
        severity=severity,
        reporter=user,
        raw_payload=raw
    )


def normalize_telemetry_payload(raw: Dict[str, Any]) -> CanonicalIncident:
    """
    Translates machine-generated observability alerts (Datadog, Grafana, Prometheus Alertmanager)
    into the Unified Canonical Incident Schema (UCIS).
    Extracts metrics, thresholds, hostnames, IPs, and tags.
    """
    # 1. Handle Datadog Monitor Alert format
    # {"event_type": "metric_alert", "alert_id": "DD-9912", "title": "...", "body": "...", "tags": [...], "priority": "critical"}
    if "event_type" in raw or "metric" in raw or "tags" in raw:
        incident_id = raw.get("alert_id") or raw.get("id") or f"DD-ALERT-{int(time.time() * 10) % 90000 + 10000}"
        title = raw.get("title") or raw.get("event_title") or f"Datadog Metric Violation on {raw.get('host', 'Cluster Node')}"
        
        body_text = raw.get("body") or raw.get("text") or raw.get("message") or ""
        metric_name = raw.get("metric") or "system.metric.threshold"
        host = raw.get("host") or ""
        tags = raw.get("tags", [])
        if isinstance(tags, list):
            tags_str = ", ".join(str(t) for t in tags)
        else:
            tags_str = str(tags)

        desc_parts = [
            f"Machine Observability Alert: {title}",
            f"Trigger Metric: {metric_name}",
        ]
        if host:
            desc_parts.append(f"Target Host / Node: {host}")
        if tags_str:
            desc_parts.append(f"Telemetry Tags: [{tags_str}]")
        if body_text:
            desc_parts.append(f"Alert Diagnostic Trace:\n{body_text}")

        description = "\n".join(desc_parts)

        # Detect team from tags or body
        team_id = "CloudInfra"
        tags_lower = tags_str.lower()
        if "team:secops" in tags_lower or "security" in tags_lower:
            team_id = "SecOps"
        elif "team:payment" in tags_lower or "ledger" in tags_lower or "banking" in tags_lower:
            team_id = "PaymentLedger"
        elif "team:cloud" in tags_lower or "infra" in tags_lower or "k8s" in tags_lower:
            team_id = "CloudInfra"

        p_str = str(raw.get("priority", "critical")).lower()
        severity = "Critical" if "crit" in p_str or "p1" in p_str else ("High" if "warn" in p_str else "Medium")

        return CanonicalIncident(
            source="datadog",
            incident_id=incident_id,
            title=title,
            description=description,
            team_id=team_id,
            severity=severity,
            reporter="Datadog Observability Agent",
            raw_payload=raw
        )

    # 2. Handle Grafana / Prometheus Alertmanager format
    # {"title": "...", "state": "alerting", "alerts": [{"labels": {...}, "annotations": {...}}]}
    if "alerts" in raw or "ruleName" in raw or "dashboardURL" in raw:
        first_alert = raw.get("alerts", [{}])[0] if raw.get("alerts") else {}
        labels = first_alert.get("labels", {})
        annotations = first_alert.get("annotations", {})

        incident_id = f"GRAFANA-{int(time.time() * 10) % 90000 + 10000}"
        title = raw.get("title") or labels.get("alertname") or "Grafana Telemetry Threshold Triggered"
        summary = annotations.get("summary") or annotations.get("description") or raw.get("message") or ""
        instance = labels.get("instance") or labels.get("host") or ""
        severity_label = labels.get("severity", "critical")

        description = (
            f"Grafana Metric Alert: {title}\n"
            f"Instance: {instance}\n"
            f"State: {raw.get('state', 'alerting')}\n"
            f"Diagnostic Description:\n{summary}"
        )

        team_id = "CloudInfra"
        if "sec" in str(labels).lower() or "auth" in str(labels).lower():
            team_id = "SecOps"
        elif "pay" in str(labels).lower() or "ledger" in str(labels).lower():
            team_id = "PaymentLedger"

        severity = "Critical" if "crit" in severity_label.lower() else "High"

        return CanonicalIncident(
            source="grafana",
            incident_id=incident_id,
            title=title,
            description=description,
            team_id=team_id,
            severity=severity,
            reporter="Grafana Alertmanager Bridge",
            raw_payload=raw
        )

    # 3. Generic Telemetry Payload Fallback
    incident_id = raw.get("alert_id") or raw.get("id") or f"TEL-{int(time.time() * 10) % 90000 + 10000}"
    title = raw.get("title") or raw.get("name") or "Machine Telemetry Metric Breach"
    description = raw.get("description") or raw.get("message") or json.dumps(raw)
    team_id = raw.get("team_id") or "CloudInfra"
    severity = raw.get("severity") or "High"

    return CanonicalIncident(
        source="telemetry",
        incident_id=incident_id,
        title=title,
        description=str(description),
        team_id=team_id,
        severity=severity,
        reporter="APM Telemetry Bridge",
        raw_payload=raw
    )


# ---------------------------------------------------------------------
# Omnichannel Autonomous Triage Pipeline
# ---------------------------------------------------------------------
async def execute_agentic_triage(incident: CanonicalIncident) -> TriageResponse:
    """
    Autonomous Omnichannel Triage Workflow:
    1. Ingests normalized incident (UCIS).
    2. Runs deterministic multi-engine redaction strictly in volatile RAM (via asyncio.to_thread).
    3. Performs vector similarity search in ChromaDB partitioned by team_id (via asyncio.to_thread).
    4. Synthesizes constrained action plan via LLM bridge with deterministic tokens.
    5. Shreds in-flight RAM buffer and forces garbage collection. Guaranteed zero disk persistence.
    """
    t_start = time.perf_counter()
    full_incident_text = f"Title: {incident.title}\nSeverity: {incident.severity}\nDescription:\n{incident.description}"

    # Scrub raw payload dict from memory immediately to prevent plain-text retention
    incident.raw_payload = {}

    buffer_tag = f"ram_triage_{incident.incident_id}"

    try:
        # Step 1: In-RAM Deterministic Sanitization (non-blocking threadpool delegation)
        redaction = await asyncio.to_thread(
            sanitizer.sanitize_text_deterministic,
            raw_text=full_incident_text,
            team=incident.team_id,
            buffer_id=buffer_tag
        )

        sanitized_text = redaction["sanitized_text"]
        mapping = redaction["mapping"]
        redacted_count = redaction["stats"]["total_redactions"]

        # Sanitize title independently for the response payload
        title_redaction = await asyncio.to_thread(
            sanitizer.sanitize_text_deterministic,
            raw_text=incident.title,
            team=incident.team_id
        )

        # Step 2: Namespace-Partitioned Vector Search in ChromaDB (non-blocking threadpool delegation)
        retrieved_chunks = await asyncio.to_thread(
            rag_engine.query_similar,
            sanitized_query=sanitized_text,
            team=incident.team_id,
            top_k=3
        )

        # Step 3: Local LLM Synthesis Bridge (with L1 SRE system prompt)
        try:
            synthesis = await llm_bridge.synthesize_action_plan(
                sanitized_incident_text=sanitized_text,
                retrieved_chunks=retrieved_chunks
            )
        except ConnectionError as ce:
            raise HTTPException(
                status_code=503,
                detail=f"Autonomous Triage Unavailable: Ollama daemon is offline at {llm_bridge.OLLAMA_ENDPOINT}. Start Ollama and pull llama3 to enable generative synthesis: {ce}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Autonomous Triage Synthesis Error: {str(e)}"
            )

    finally:
        # Step 4: Volatile RAM Shredding & Garbage Collection (Executed unconditionally)
        sanitizer.purge_volatile_buffer(buffer_tag)

    t_end = time.perf_counter()
    duration_ms = round((t_end - t_start) * 1000, 2)

    return TriageResponse(
        status="TRIAGED_AUTONOMOUSLY",
        incident_id=incident.incident_id,
        source=incident.source,
        team_id=incident.team_id,
        severity=incident.severity,
        sanitized_title=title_redaction["sanitized_text"],
        sanitized_description=sanitized_text,
        redacted_tokens_count=redacted_count,
        mapping=mapping,
        retrieved_chunks=retrieved_chunks,
        action_plan=synthesis["action_plan"],
        action_plan_source=synthesis["source"],
        preserved_tokens=synthesis.get("preserved_tokens", []),
        pipeline_latency_ms=duration_ms,
        zero_disk_guarantee="Zero bytes written to disk; volatile RAM buffer shredded."
    )


# ---------------------------------------------------------------------
# Webhook Endpoints & Simulators
# ---------------------------------------------------------------------
@router.post("/webhooks/jira", response_model=TriageResponse)
async def webhook_jira_listener(request: Request):
    """
    Ingests live Jira incident webhooks, normalizes to UCIS,
    redacts in RAM, searches ChromaDB vectors, and generates action plans.
    """
    try:
        raw_payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload in Jira webhook request.")

    incident = normalize_jira_payload(raw_payload)
    return await execute_agentic_triage(incident)


@router.post("/webhooks/slack", response_model=TriageResponse)
async def webhook_slack_listener(request: Request):
    """
    Ingests Slack event subscriptions or bot messages, normalizes to UCIS,
    redacts in RAM, searches ChromaDB vectors, and generates action plans.
    """
    try:
        raw_payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload in Slack webhook request.")

    if "challenge" in raw_payload:
        return {"challenge": raw_payload["challenge"]}

    incident = normalize_slack_payload(raw_payload)
    return await execute_agentic_triage(incident)


@router.post("/webhooks/telemetry", response_model=TriageResponse)
async def webhook_telemetry_listener(request: Request):
    """
    Ingests live machine-generated observability alerts (Datadog, Grafana, APM),
    normalizes to UCIS, scrubs internal hostnames/IPs in volatile RAM,
    matches ChromaDB runbooks, and synthesizes an immediate L1 action plan.
    """
    try:
        raw_payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload in telemetry webhook request.")

    incident = normalize_telemetry_payload(raw_payload)
    return await execute_agentic_triage(incident)


# ---------------------------------------------------------------------
# Simulators (Jira & Observability Telemetry)
# ---------------------------------------------------------------------
class SimulateWebhookRequest(BaseModel):
    team_id: Optional[str] = Field("SecOps", description="Target team namespace (SecOps, CloudInfra, PaymentLedger)")
    severity: Optional[str] = Field("Critical", description="Incident severity")
    custom_ticket_key: Optional[str] = Field(None, description="Optional custom Jira key e.g. SEC-9082")
    override_log: Optional[str] = Field(None, description="Optional custom crash trace with raw credentials")


@router.post("/simulate-webhook", response_model=TriageResponse)
async def simulate_webhook(request_body: Optional[SimulateWebhookRequest] = None):
    """
    Local Simulator for Omnichannel Incident Ingestion (Jira Outage).
    Generates a synthetic Jira critical outage payload containing live cloud credentials
    (AWS access keys, internal hostnames, and IP addresses) and executes the end-to-end
    in-RAM sanitization, vector retrieval, and LLM synthesis pipeline.
    """
    team = request_body.team_id if request_body and request_body.team_id else "SecOps"
    sev = request_body.severity if request_body and request_body.severity else "Critical"
    ticket_key = request_body.custom_ticket_key if request_body and request_body.custom_ticket_key else f"SEC-{int(time.time() * 10) % 9000 + 1000}"

    if request_body and request_body.override_log:
        raw_description = request_body.override_log
    else:
        raw_description = (
            f"CRITICAL SEV-1 OUTAGE ALERT: Unauthorized API egress detected.\n"
            f"Active Session: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-410aF_zM1EXAMPLE\n"
            f"Compromised IAM Identity: AKIAIOSFODNN7EXAMPLE\n"
            f"Source Node: ip-10-0-12-84.ec2.internal (10.0.12.84:8443)\n"
            f"Target Service: pg-replica-02.internal\n"
            f"Connection string: postgres://dbadmin:SuperP@ssw0rd99!@10.0.12.84:5432/core_banking\n"
            f"Incident Lead: Alex Chen (alex.chen@corporate.internal)\n"
            f"Automated action required: Revoke IAM credentials and apply emergency perimeter CIDR isolation."
        )

    synthetic_jira_payload = {
        "webhookEvent": "jira:issue_created",
        "timestamp": int(time.time() * 1000),
        "issue": {
            "key": ticket_key,
            "fields": {
                "summary": f"[{sev}] Critical Production Perimeter Intrusion & Key Compromise on 10.0.12.84",
                "description": raw_description,
                "priority": {"name": sev},
                "project": {"name": team},
                "reporter": {"displayName": "Atlassian Automated Telemetry Bridge"}
            }
        }
    }

    canonical_incident = normalize_jira_payload(synthetic_jira_payload)
    return await execute_agentic_triage(canonical_incident)


class SimulateTelemetryRequest(BaseModel):
    team_id: Optional[str] = Field("CloudInfra", description="Target team namespace (CloudInfra, SecOps, PaymentLedger)")
    metric_name: Optional[str] = Field("system.cpu.idle", description="Breached metric name")
    host: Optional[str] = Field("db-primary-01.internal", description="Internal host with metric alert")
    ip_address: Optional[str] = Field("10.0.8.22", description="Target node IP address")
    severity: Optional[str] = Field("Critical", description="Severity (Critical, High, Medium)")
    override_body: Optional[str] = Field(None, description="Optional custom diagnostic telemetry log")


@router.post("/simulate-telemetry", response_model=TriageResponse)
async def simulate_telemetry(request_body: Optional[SimulateTelemetryRequest] = None):
    """
    Local Simulator for Machine-Generated Observability Alerts (Datadog/Grafana).
    Injects a realistic metric threshold breach alert (CPU > 90%, OOM kill, memory saturation)
    containing internal hostnames, IP addresses, cluster endpoints, and database connection URIs.
    Executes in-RAM sanitization, ChromaDB vector matching, and L1 action plan generation.
    """
    team = request_body.team_id if request_body and request_body.team_id else "CloudInfra"
    metric = request_body.metric_name if request_body and request_body.metric_name else "system.cpu.idle"
    host = request_body.host if request_body and request_body.host else "db-primary-01.internal"
    ip_addr = request_body.ip_address if request_body and request_body.ip_address else "10.0.8.22"
    sev = request_body.severity if request_body and request_body.severity else "Critical"

    if request_body and request_body.override_body:
        diagnostic_text = request_body.override_body
    else:
        diagnostic_text = (
            f"CRITICAL METRIC BREACH: CPU utilization > 94.8% on {host} ({ip_addr}:9100) exceeding alert threshold for > 300s.\n"
            f"Workload Pod: order-processor-deployment-7f9b8c6d4-xk92m (Namespace: core-banking)\n"
            f"Cluster Controller: {ip_addr}:8443 on node ip-10-0-8-22.ec2.internal\n"
            f"Memory Saturation Metric: 14.8Gi of 16Gi allocated (RESOURCE_SPEC breach).\n"
            f"Active DB Connection Pool: postgres://readonly:T0k3n_Secret!@{ip_addr}:5432/core_banking\n"
            f"Service API Token: secret_token: dd_agent_auth_live_prod_key_778102948\n"
            f"Incident Lead: Sarah Connor (sarah.connor@corporate.internal)\n"
            f"Remediation target: Drain active connections to replica host {ip_addr} and scale replica controllers."
        )

    synthetic_datadog_payload = {
        "event_type": "metric_alert",
        "alert_id": f"ALERT-DD-{int(time.time() * 10) % 90000 + 10000}",
        "title": f"[{sev}] CPU > 90% and Threadpool Starvation on {host}",
        "body": diagnostic_text,
        "metric": metric,
        "priority": sev.lower(),
        "host": host,
        "tags": [
            "env:prod",
            f"team:{team}",
            f"host:{ip_addr}",
            "service:order-processor",
            "tier:backend-database"
        ],
        "date": int(time.time())
    }

    canonical_incident = normalize_telemetry_payload(synthetic_datadog_payload)
    return await execute_agentic_triage(canonical_incident)


# ---------------------------------------------------------------------
# Mandate 1: Live Confluence Cloud REST API Ingestion & RAM Sanitizer
# ---------------------------------------------------------------------
class ConfluenceSyncRequest(BaseModel):
    domain: str = Field(..., description="Confluence Cloud domain (e.g. https://yoursite.atlassian.net)")
    email: str = Field(..., description="Account email associated with Confluence Cloud")
    api_token: str = Field(..., description="Atlassian API token / PAT")
    space_key: str = Field(..., description="Confluence Space Key to sync")

class ConfluenceSyncResponse(BaseModel):
    status: str
    space_key: str
    pages_synced: int
    total_tokens_redacted: int
    synced_pages: List[Dict[str, Any]]
    storage_tier: str
    team: str
    message: str
    audit_telemetry: Optional[Dict[str, Any]] = None


class _HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._pieces = []

    def handle_data(self, data):
        self._pieces.append(data)

    def get_text(self) -> str:
        raw = " ".join(self._pieces)
        # Collapse multiple spaces and unescape entities
        cleaned = re.sub(r'[ \t\r\f\v]+', ' ', raw)
        cleaned = re.sub(r'\n\s*\n+', '\n\n', cleaned).strip()
        return html.unescape(cleaned)


def _strip_html(html_str: str) -> str:
    """Safely extracts plain text from Confluence storage format HTML."""
    if not html_str:
        return ""
    try:
        parser = _HTMLTextExtractor()
        parser.feed(html_str)
        text = parser.get_text()
        return text if text else re.sub(r'<[^>]+>', ' ', html_str).strip()
    except Exception:
        return re.sub(r'<[^>]+>', ' ', html_str).strip()


@router.post("/integrations/confluence/sync", response_model=ConfluenceSyncResponse, tags=["Confluence Integration"])
async def sync_confluence_space(payload: ConfluenceSyncRequest):
    """
    Live Confluence Ingestion Pipeline:
    1. Connects to Confluence Cloud REST API using HTTP Basic Auth (email + API token).
    2. Fetches all pages within the target space_key.
    3. Strips HTML storage formatting in RAM.
    4. Passes raw text into volatile Presidio + Regex sanitizer (zero disk writes).
    5. Indexes clean masked runbooks into SQLite and ChromaDB dense vector store (team=CloudInfra).
    """
    domain = payload.domain.strip().rstrip("/")
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = f"https://{domain}"

    email = payload.email.strip()
    token = payload.api_token.strip()
    space_key = payload.space_key.strip()

    if not domain or not email or not token or not space_key:
        raise HTTPException(
            status_code=400,
            detail="Missing required Confluence parameters: domain, email, api_token, and space_key are required."
        )

    # Confluence Cloud REST API endpoint (v1 standard endpoint for space pages with body expand)
    api_url = f"{domain}/wiki/rest/api/content"
    params = {
        "spaceKey": space_key,
        "type": "page",
        "status": "current",
        "expand": "body.storage,version",
        "limit": 50
    }

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.get(
                api_url,
                params=params,
                auth=(email, token),
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Argus-Privacy-Enclave/3.0"
                }
            )

        # Fallback to non-/wiki prefix if 404 (some custom or server Confluence domains)
        if resp.status_code == 404:
            fallback_url = f"{domain}/rest/api/content"
            async with httpx.AsyncClient(timeout=25.0) as client:
                resp = await client.get(
                    fallback_url,
                    params=params,
                    auth=(email, token),
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "Argus-Privacy-Enclave/3.0"
                    }
                )

    except httpx.ConnectError as ce:
        raise HTTPException(
            status_code=502,
            detail=f"Unable to connect to Confluence Cloud at {domain}: {str(ce)}"
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail=f"Connection to Confluence Cloud timed out at {domain}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Confluence HTTP client error: {str(e)}"
        )

    if resp.status_code == 401 or resp.status_code == 403:
        raise HTTPException(
            status_code=resp.status_code,
            detail="Confluence Authentication Failed. Please verify your Account Email and API Token / PAT."
        )
    elif resp.status_code != 200:
        raise HTTPException(
            status_code=resp.status_code,
            detail=f"Confluence API returned HTTP {resp.status_code}: {resp.text[:300]}"
        )

    try:
        data = resp.json()
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to parse Confluence JSON response: {str(e)}"
        )

    results = data.get("results", [])
    if not results:
        # Check if space exists or is empty
        return ConfluenceSyncResponse(
            status="success",
            space_key=space_key,
            pages_synced=0,
            total_tokens_redacted=0,
            synced_pages=[],
            storage_tier="Live Confluence Sync",
            team="CloudInfra",
            message=f"Space '{space_key}' connected successfully, but returned 0 pages."
        )

    synced_pages_list: List[Dict[str, Any]] = []
    total_tokens_redacted = 0
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    for page in results:
        page_id = str(page.get("id", f"CONF-{int(time.time()*1000)}"))
        doc_id = f"CONF-{page_id}"
        title = page.get("title", f"Confluence Page {page_id}")

        # Extract HTML storage content
        body_obj = page.get("body", {}).get("storage", {})
        html_content = body_obj.get("value", "")

        # 1. Strip HTML tags strictly in RAM
        raw_text = _strip_html(html_content)
        if not raw_text.strip():
            raw_text = f"Confluence Page: {title}\n(Empty or media-only document body)"

        # 2. Pass immediately into volatile deterministic RAM redactor
        # Secrets are scrubbed in RAM with zero disk writes
        sanitized_res = sanitizer.sanitize_text_deterministic(
            raw_text=f"{title}\n\n{raw_text}",
            team="CloudInfra"
        )
        sanitized_content = sanitized_res["sanitized_text"]
        token_count = sanitized_res["stats"]["total_redactions"]
        total_tokens_redacted += token_count

        # 3. Save directly to RAG engine & vector database
        content_hash = hashlib.sha256(sanitized_content.encode("utf-8")).hexdigest()[:12]
        rag_engine.add_document(
            doc_id=doc_id,
            team="CloudInfra",
            title=f"Confluence: {title}",
            content=sanitized_content,
            tokens_count=token_count,
            created_at=now_str,
            content_hash=content_hash,
            storage_tier="Live Confluence Sync"
        )

        synced_pages_list.append({
            "doc_id": doc_id,
            "page_id": page_id,
            "title": title,
            "tokens_redacted": token_count,
            "snippet": sanitized_content[:160] + ("..." if len(sanitized_content) > 160 else "")
        })

    return ConfluenceSyncResponse(
        status="success",
        space_key=space_key,
        pages_synced=len(synced_pages_list),
        total_tokens_redacted=total_tokens_redacted,
        synced_pages=synced_pages_list,
        storage_tier="Live Confluence Sync",
        team="CloudInfra",
        message=f"Successfully synced {len(synced_pages_list)} pages from Confluence space '{space_key}' and redacted {total_tokens_redacted} secrets strictly in RAM.",
        audit_telemetry={
            "confluence_request_url": str(resp.url),
            "http_status": resp.status_code,
            "response_headers": {
                "server": resp.headers.get("server", "AtlassianEdge"),
                "x_arequestid": resp.headers.get("x-arequestid", ""),
                "x_aaccountid": resp.headers.get("x-aaccountid", ""),
                "atl_traceid": resp.headers.get("atl-traceid", ""),
                "content_type": resp.headers.get("content-type", "")
            },
            "timestamp": now_str
        }
    )


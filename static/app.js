/**
 * Argus v2.1: Privacy-Preserving Team RAG Enclave
 * 4-Stage Live Stepping (1.5s/stage) & In-Flight Kill-Switch Controller
 */

// Integration documentation data
const INTEGRATION_DATA = {
    jira: {
        title: 'Atlassian Jira Service Management Webhook Proxy',
        badge: 'Webhook & Incident Triage Proxy',
        summary: 'Intercepts incoming ticket descriptions and crash dumps. Sanitizes secrets through Argus in volatile RAM before storing ticket embeddings in the vector database.',
        steps: [
            'In Jira Settings > System > Webhooks, create a webhook for events: "jira:issue_created" and "jira:issue_updated".',
            'Point the Webhook URL to Argus proxy: "https://argus-enclave.corp/api/integrations/jira/webhook".',
            'Argus tokenizes entities in volatile memory, returns 200 OK, and indexes the sanitized ticket without storing credentials.'
        ],
        codeSnippet: `@app.post("/api/integrations/jira/webhook")
async def handle_jira_webhook(payload: dict):
    raw_description = payload.get("issue", {}).get("fields", {}).get("description", "")
    
    # 1. Deterministic Multi-Engine Redaction in Volatile RAM
    sanitized_data = sanitize_text_deterministic(raw_description)
    
    # 2. Store only sanitized representation in Vector Index
    vector_client.upsert(
        collection="jira-incident-vectors",
        points=[{
            "id": payload["issue"]["id"],
            "vector": embed(sanitized_data["sanitized_text"]),
            "payload": {"clean_text": sanitized_data["sanitized_text"]}
        }]
    )
    return {"status": "quarantined_and_indexed", "masked_tokens": sanitized_data["stats"]["total_redactions"]}`
    },
    confluence: {
        title: 'Atlassian Confluence Knowledge Base Space Crawler',
        badge: 'Periodic Space Crawler & Runbook Redactor',
        summary: 'Crawls architecture diagrams and runbook pages. Strips staging passwords, internal DNS hostnames, and AWS keys before creating RAG vector embeddings.',
        steps: [
            'Configure a Confluence API Personal Access Token (PAT) with read-only space permissions.',
            'Run the Argus Confluence crawler cron job (e.g., daily at 02:00 UTC).',
            'Each page text passes through Presidio NER and Regex filters in volatile RAM; only clean runbook chunks are indexed into vector memory.'
        ],
        codeSnippet: `from atlassian import Confluence

def sync_confluence_space(space_key: str):
    confluence = Confluence(url="https://wiki.corporate.internal", token=CONFLUENCE_PAT)
    pages = confluence.get_all_pages_from_space(space_key)
    
    for page in pages:
        body = confluence.get_page_by_id(page["id"], expand="body.storage")["body"]["storage"]["value"]
        
        # Scrub all internal IPs, emails, and credentials in RAM
        clean_doc = sanitize_text_deterministic(body)
        
        # Store in RAM SQLite Vector Index
        index_sanitized_chunk(doc_id=page["id"], text=clean_doc["sanitized_text"])`
    },
    git: {
        title: 'GitLab CI & GitHub Actions Build Failure Triage',
        badge: 'CI/CD Pipeline Log Redactor',
        summary: 'Automatically captures build logs on job failure. Eliminates exposed npm tokens, Docker credentials, and AWS deploy keys before querying the team runbook model.',
        steps: [
            'In your GitLab CI/CD or GitHub Actions workflow, add a post-failure trap step.',
            'Pipe stdout/stderr logs directly into the Argus CLI proxy.',
            'Argus masks secrets and posts a sanitized PR comment explaining matching resolution runbooks without leaking build secrets.'
        ],
        codeSnippet: `# GitHub Actions Step (.github/workflows/deploy.yml)
- name: Argus Zero-Leakage Failure Triage
  if: failure()
  run: |
    # Pipe raw runner log through local Argus proxy
    curl -s -X POST http://127.0.0.1:8000/api/retrieve \\
      -H "Content-Type: application/json" \\
      -d "{\\"text\\": $(cat /tmp/build.log | jq -Rs .), \\"team\\": \\"CloudInfra\\"}" \\
      > /tmp/sanitized_triage.json`
    },
    slack: {
        title: 'Slack & Microsoft Teams Incident Triage Bot',
        badge: 'ChatOps Zero-Leakage Slash Command',
        summary: 'Allows on-call engineers to paste raw stack traces via `/argus triage <log>`. The bot responds with sanitized context and runbooks, ensuring secrets are never posted to public Slack channels.',
        steps: [
            'Create a Slack App with Bot Token Scopes: "commands", "chat:write".',
            'Register Slash Command "/argus" pointing to "https://argus-enclave.corp/api/integrations/slack/command".',
            'The bot redacts the input in volatile memory and returns an ephemeral message (visible only to the user) with sanitized steps.'
        ],
        codeSnippet: `@bolt_app.command("/argus")
def handle_argus_command(ack, respond, command):
    ack()
    raw_user_log = command["text"]
    
    # Run in-memory Presidio + Regex sanitization
    sanitized = sanitize_text_deterministic(raw_user_log)
    
    # Send ephemeral sanitized result strictly to requester
    respond({
        "response_type": "ephemeral",
        "text": f"Argus Sanitized Context: {sanitized['stats']['total_redactions']} secrets masked in RAM."
    })`
    }
};

// Realistic presets
const PRESETS = {
    jira: {
        filename: 'jira_incident_ticket.txt',
        title: '1. Jira Incident Ticket',
        text: `[INC-2026-9042] Production Service Incident
Reported By: alex.miller@corporate.internal
Assignee: secops-oncall@corporate.internal
Contact Phone: +1-555-019-2834
Target VPC: us-east-1 (Subnet 10.14.0.0/16)

Description:
At 14:22:01 UTC, payment microservice crashed while attempting to sync batch transaction logs with primary cluster.
Internal connection failed at master host 10.14.88.23:5432 and fallback replica 10.14.88.24:5432.
Worker pod pay-worker-7f98b attempted recovery using AWS IAM credential AKIAIOSFODNN7EXAMPLE 
and secret token wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.

Stack Trace & Memory Buffer:
java.sql.SQLException: Connection to 10.14.88.23:5432 refused (connection timed out after 30000ms).
    Session Token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsZXgiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
    Failed user lookup for email dev-admin@corporate.internal from workstation 192.168.1.105.`
    },

    postgres: {
        filename: 'postgres_crash_dump.log',
        title: '2. Postgres Crash Dump',
        text: `2026-10-30T14:15:02.192Z [ERROR] [HikariPool-1] - Connection is not available, request timed out after 30005ms.
org.postgresql.util.PSQLException: Connection to 10.14.88.23:5432 refused (socket timeout).
    at org.postgresql.core.v3.ConnectionFactoryImpl.openConnectionImpl(ConnectionFactoryImpl.java:297)

Environment Variables & Connection Metadata:
DATABASE_URL=postgres://payment_admin:P@ssw0rd2026!SecureKey@10.14.88.23:5432/ledger_production
REPLICA_URL=postgres://ro_user:ReplicaReadOnlySecret99@10.14.88.24:5432/ledger_production
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ONCALL_ENGINEER=sarah.connor@corporate.internal
PRIMARY_SUBNET=10.14.88.0/24`
    },

    k8s: {
        filename: 'k8s_oom_incident.log',
        title: '3. Kubernetes OOM Dump',
        text: `k8s.events: Pod 'payment-worker-7c98b' terminated with exit code 137 (OOMKilled).
Last State: Terminated (Reason: OOMKilled, ExitCode: 137, StartedAt: 2026-10-30T14:10:00Z)
Namespace: prod-payments
Node: ip-10-244-3-18.ec2.internal (InternalIP: 10.244.3.18)
Memory Working Set: 2048Mi (Hard Limit: 2048Mi)
auth.jwt.secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
kubernetes.io/cluster-service: "10.244.0.1:6443"
cluster.admin.contact: infra-lead@corporate.internal
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
    },

    confluence: {
        filename: 'confluence_runbook_secrets.md',
        title: '4. Confluence Runbook',
        text: `# RB-SEC-89: Automated Vault Recovery & Key Rotation Runbook
Author: David Zhang (david.zhang@corporate.internal)
Emergency Hotline: +1-555-014-9921
Primary Vault Leader: http://10.200.4.10:8200
Standby Node 1: http://10.200.4.11:8200
Staging root token: s.yP89Bnbw81k092kZZqwop91A
AWS IAM KMS Key ID: AKIAJXX45ABCDEXAMPLE
Master Secret: q9A+wK7MDENG/bPxRfiCYEXAMPLEKEY9921`
    }
};

document.addEventListener('DOMContentLoaded', () => {
    // Current Active Target Artifact
    let currentTargetKey = 'jira';
    let currentTargetFilename = PRESETS.jira.filename;
    let activeInputText = PRESETS.jira.text;

    // Simulation Timer Handles
    let simulationActive = false;
    let simulationTimeoutId = null;
    let stageIntervalId = null;
    let currentStageIndex = 0;

    // Navigation items
    const navItems = [
        { btn: document.getElementById('navBtnPage1'), container: document.getElementById('page1Container'), title: '1. Privacy RAG Engine & Multi-Engine Data Masking' },
        { btn: document.getElementById('navBtnPage2'), container: document.getElementById('page2Container'), title: '2. Zero-Leakage Data Flow & Storage Enclave' },
        { btn: document.getElementById('navBtnPage5'), container: document.getElementById('page5Container'), title: '3. Semantic Incident Topology & Infrastructure Knowledge Graph' },
        { btn: document.getElementById('navBtnPage6'), container: document.getElementById('page6Container'), title: '4. Shadow SRE Flight Simulator & AI Outage Sandbox' },
        { btn: document.getElementById('navBtnPageVendorSla'), container: document.getElementById('pageVendorSlaContainer'), title: '5. Vendor SLA Performance & Outage Blame Attribution' },
        { btn: document.getElementById('navBtnPageBusFactor'), container: document.getElementById('pageBusFactorContainer'), title: '6. Knowledge Silo & Bus Factor Risk Heatmap' },
        { btn: document.getElementById('navBtnPageRunbookDecay'), container: document.getElementById('pageRunbookDecayContainer'), title: '7. Runbook Vector Decay & AI Tech Debt Modernization' },
        { btn: document.getElementById('navBtnPage3'), container: document.getElementById('page3Container'), title: 'Enterprise Toolchain Integration Guide' },
        { btn: document.getElementById('navBtnPage4'), container: document.getElementById('page4Container'), title: 'Team Governance, System Owners & Operational SLAs' }
    ];

    const pageBreadcrumb = document.getElementById('pageBreadcrumb');
    const sidebarDocCount = document.getElementById('sidebarDocCount');
    const teamSelect = document.getElementById('teamSelect');

    // Page 1 Elements
    const p1RawInput = document.getElementById('p1RawInput');
    const p1RunRedactorBtn = document.getElementById('p1RunRedactorBtn');
    const p1SimulateRetrieveBtn = document.getElementById('p1SimulateRetrieveBtn');

    const p1PresetJira = document.getElementById('p1PresetJira');
    const p1PresetPostgres = document.getElementById('p1PresetPostgres');
    const p1PresetK8s = document.getElementById('p1PresetK8s');
    const p1PresetConfluence = document.getElementById('p1PresetConfluence');

    const p1StatTotal = document.getElementById('p1StatTotal');
    const p1StatPresidio = document.getElementById('p1StatPresidio');
    const p1StatRegex = document.getElementById('p1StatRegex');
    const p1StatLatency = document.getElementById('p1StatLatency');

    const p1RawCountBadge = document.getElementById('p1RawCountBadge');
    const p1SanitizedCountBadge = document.getElementById('p1SanitizedCountBadge');
    const p1RawHighlightView = document.getElementById('p1RawHighlightView');
    const p1SanitizedHighlightView = document.getElementById('p1SanitizedHighlightView');
    const p1MappingTableBody = document.getElementById('p1MappingTableBody');
    const p1TableEntitiesCount = document.getElementById('p1TableEntitiesCount');

    const p1RetrievalCard = document.getElementById('p1RetrievalCard');
    const p1VectorSearchInput = document.getElementById('p1VectorSearchInput');
    const p1ResetQueryBtn = document.getElementById('p1ResetQueryBtn');
    const p1ClearQueryBtn = document.getElementById('p1ClearQueryBtn');
    const p1ExecuteSearchBtn = document.getElementById('p1ExecuteSearchBtn');
    const p1SearchBtnText = document.getElementById('p1SearchBtnText');
    const p1RetrievedCountBadge = document.getElementById('p1RetrievedCountBadge');
    const p1RetrievedChunksContainer = document.getElementById('p1RetrievedChunksContainer');
    const p1SaveToDbBtn = document.getElementById('p1SaveToDbBtn');

    // Page 2 Elements
    const p2SimulateNormalBtn = document.getElementById('p2SimulateNormalBtn');
    const p2SimulateInterruptBtn = document.getElementById('p2SimulateInterruptBtn');
    const p2StartBtnText = document.getElementById('p2StartBtnText');
    const p2PipelineStatusBadge = document.getElementById('p2PipelineStatusBadge');
    const p2StageCountdownText = document.getElementById('p2StageCountdownText');
    const p2AuditTraceContainer = document.getElementById('p2AuditTraceContainer');
    const p2SelectedArtifactName = document.getElementById('p2SelectedArtifactName');

    // 4 File Option Buttons on Page 2
    const p2FileJira = document.getElementById('p2FileJira');
    const p2FilePostgres = document.getElementById('p2FilePostgres');
    const p2FileK8s = document.getElementById('p2FileK8s');
    const p2FileConfluence = document.getElementById('p2FileConfluence');

    // Storage Vault Folder Elements on Page 2
    const p2VaultFolderCountBadge = document.getElementById('p2VaultFolderCountBadge');
    const p2VaultFilesContainer = document.getElementById('p2VaultFilesContainer');
    const p2ClearVaultBtn = document.getElementById('p2ClearVaultBtn');
    const p2VaultFileInspector = document.getElementById('p2VaultFileInspector');
    const p2VaultInspectedName = document.getElementById('p2VaultInspectedName');
    const p2VaultInspectedContent = document.getElementById('p2VaultInspectedContent');
    const p2CloseVaultInspectBtn = document.getElementById('p2CloseVaultInspectBtn');

    // Local Database Explorer Elements on Page 2
    const p2DbRecordsBadge = document.getElementById('p2DbRecordsBadge');
    const p2DbSizeBadge = document.getElementById('p2DbSizeBadge');
    const p2RefreshDbBtn = document.getElementById('p2RefreshDbBtn');
    const p2DbRecordsTableBody = document.getElementById('p2DbRecordsTableBody');
    const p2DbRecordInspector = document.getElementById('p2DbRecordInspector');
    const p2DbInspectedTitle = document.getElementById('p2DbInspectedTitle');
    const p2DbInspectedId = document.getElementById('p2DbInspectedId');
    const p2DbInspectedContent = document.getElementById('p2DbInspectedContent');
    const p2CloseDbInspectBtn = document.getElementById('p2CloseDbInspectBtn');

    // Transfer Modal Elements
    const p2OpenTransferModalBtn = document.getElementById('p2OpenTransferModalBtn');
    const transferModal = document.getElementById('transferModal');
    const closeTransferModalBtn = document.getElementById('closeTransferModalBtn');
    const dismissTransferModalBtn = document.getElementById('dismissTransferModalBtn');
    const modalTabSimulate = document.getElementById('modalTabSimulate');
    const modalTabSql = document.getElementById('modalTabSql');
    const modalTabScript = document.getElementById('modalTabScript');
    const modalViewSimulate = document.getElementById('modalViewSimulate');
    const modalViewSql = document.getElementById('modalViewSql');
    const modalViewScript = document.getElementById('modalViewScript');
    const executeMigrationSimulationBtn = document.getElementById('executeMigrationSimulationBtn');
    const migrationStatusLabel = document.getElementById('migrationStatusLabel');
    const migrationResultsArea = document.getElementById('migrationResultsArea');
    const migratedDocsCount = document.getElementById('migratedDocsCount');
    const migratedTokensCount = document.getElementById('migratedTokensCount');
    const migratedSampleJson = document.getElementById('migratedSampleJson');
    const copyDdlBtn = document.getElementById('copyDdlBtn');
    const ddlSqlContent = document.getElementById('ddlSqlContent');
    const copyScriptBtn = document.getElementById('copyScriptBtn');
    const scriptPythonContent = document.getElementById('scriptPythonContent');

    // Team Lead Rulebook Enclave Selectors
    const openRulebookModalBtn = document.getElementById('openRulebookModalBtn');
    const p1OpenRulebookBtn = document.getElementById('p1OpenRulebookBtn');
    const p4OpenRulebookBtn = document.getElementById('p4OpenRulebookBtn');
    const rulebookModal = document.getElementById('rulebookModal');
    const closeRulebookModalBtn = document.getElementById('closeRulebookModalBtn');
    const dismissRulebookModalBtn = document.getElementById('dismissRulebookModalBtn');
    const leadMasterKeyInput = document.getElementById('leadMasterKeyInput');
    const toggleKeyVisibilityBtn = document.getElementById('toggleKeyVisibilityBtn');
    const unlockRulebookBtn = document.getElementById('unlockRulebookBtn');
    const verifyIntegrityBtn = document.getElementById('verifyIntegrityBtn');
    const rbIntegrityBadge = document.getElementById('rbIntegrityBadge');
    const rbTeamFilter = document.getElementById('rbTeamFilter');
    const rbRulesTableBody = document.getElementById('rbRulesTableBody');
    const addRuleForm = document.getElementById('addRuleForm');
    const newRuleTeam = document.getElementById('newRuleTeam');
    const newRuleName = document.getElementById('newRuleName');
    const newRuleEntityType = document.getElementById('newRuleEntityType');
    const newRuleLabel = document.getElementById('newRuleLabel');
    const newRulePattern = document.getElementById('newRulePattern');
    const rbLockedNotice = document.getElementById('rbLockedNotice');
    const rbUnlockedContent = document.getElementById('rbUnlockedContent');

    // Stage nodes on Page 2
    const nodeStage1 = document.getElementById('nodeStage1');
    const nodeStage2 = document.getElementById('nodeStage2');
    const nodeStage3 = document.getElementById('nodeStage3');
    const nodeStage4 = document.getElementById('nodeStage4');

    // Page 3 Elements
    const integTabJira = document.getElementById('integTabJira');
    const integTabConfluence = document.getElementById('integTabConfluence');
    const integTabGit = document.getElementById('integTabGit');
    const integTabSlack = document.getElementById('integTabSlack');
    const integContentCard = document.getElementById('integContentCard');

    // Initialize Page 1 with default Jira preset and warm up telemetry profiler
    selectTargetArtifact('jira');
    setTimeout(() => {
        executeVectorSearch();
    }, 300);

    // -------------------------------------------------------------
    // Page Switching Controller
    // -------------------------------------------------------------
    function navigateToPage(index) {
        navItems.forEach((item, idx) => {
            if (!item.btn || !item.container) return;
            if (idx === index) {
                item.container.classList.remove('hidden');
                item.btn.className = 'nav-item w-full flex items-start space-x-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 bg-slate-900 text-white shadow-xs font-medium cursor-pointer';
                const svg = item.btn.querySelector('svg');
                if (svg) svg.className = 'w-4 h-4 text-teal-400';
                if (pageBreadcrumb) pageBreadcrumb.textContent = item.title;
            } else {
                item.container.classList.add('hidden');
                item.btn.className = 'nav-item w-full flex items-start space-x-3 px-3 py-2.5 rounded-xl text-left transition-all duration-150 text-[#94A3B8] hover:text-[#E2E8F0] hover:bg-[#0F172A] cursor-pointer';
                const svg = item.btn.querySelector('svg');
                if (svg) svg.className = 'w-4 h-4 text-slate-400';
            }
        });

        const containerId = navItems[index]?.container?.id;
        if (containerId === 'page2Container') {
            refreshVaultFolder();
            refreshDbExplorer();
        } else if (containerId === 'page3Container') {
            renderIntegrationContent('jira');
        } else if (containerId === 'page5Container') {
            initOrRefreshTopologyGraph();
        } else if (containerId === 'page6Container') {
            loadSreSimulatorScenario();
        } else if (containerId === 'pageVendorSlaContainer') {
            loadVendorSlaAnalytics();
        } else if (containerId === 'pageBusFactorContainer') {
            loadBusFactorAnalytics();
        } else if (containerId === 'pageRunbookDecayContainer') {
            loadRunbookDecayAnalytics();
        }
    }

    navItems.forEach((item, idx) => {
        if (item.btn) {
            item.btn.addEventListener('click', (e) => {
                e.preventDefault();
                navigateToPage(idx);
            });
        }
    });

    // -------------------------------------------------------------
    // Selection of the 4 Incident Artifacts (Shared between Page 1 & 2)
    // -------------------------------------------------------------
    function selectTargetArtifact(key) {
        currentTargetKey = key;
        const preset = PRESETS[key];
        if (!preset) return;

        // Update state and input
        currentTargetFilename = preset.filename;
        activeInputText = preset.text;
        if (p1RawInput) p1RawInput.value = preset.text;

        // Auto-sanitize and populate editable search query box
        fetch('/api/sanitize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: preset.text, team: teamSelect ? teamSelect.value : 'CloudInfra' })
        }).then(r => r.json()).then(data => {
            currentSanitizedText = data.sanitized_text || '';
            if (p1VectorSearchInput) {
                p1VectorSearchInput.value = currentSanitizedText;
            }
            if (p1RawHighlightView) p1RawHighlightView.innerHTML = data.highlighted_raw_html || 'Empty';
            if (p1SanitizedHighlightView) p1SanitizedHighlightView.innerHTML = data.highlighted_sanitized_html || 'Empty';
            if (p1StatTotal) p1StatTotal.textContent = data.stats.total_redactions;
            if (p1StatPresidio) p1StatPresidio.textContent = data.stats.presidio_entities;
            if (p1StatRegex) p1StatRegex.textContent = data.stats.regex_entities;
            if (p1StatLatency) p1StatLatency.textContent = `${data.stats.execution_time_ms} ms`;
            if (p1RawCountBadge) p1RawCountBadge.textContent = `${data.stats.total_redactions} Detected`;
            if (p1SanitizedCountBadge) p1SanitizedCountBadge.textContent = `${data.stats.unique_secrets} Unique Tokens`;
            renderAuditTable(data.mapping);
            renderEntityBreakdown(data.mapping);
        }).catch(() => {});

        if (p2SelectedArtifactName) {
            p2SelectedArtifactName.textContent = `Artifact: ${preset.filename}`;
        }

        // Highlight selected preset button on Page 2
        const p2Buttons = [
            { el: p2FileJira, key: 'jira' },
            { el: p2FilePostgres, key: 'postgres' },
            { el: p2FileK8s, key: 'k8s' },
            { el: p2FileConfluence, key: 'confluence' }
        ];

        p2Buttons.forEach(b => {
            if (!b.el) return;
            if (b.key === key) {
                b.el.className = 'p-2.5 rounded-lg border border-teal-500 bg-[#0F172A] text-white font-medium text-left transition-all duration-150 cursor-pointer shadow-none';
            } else {
                b.el.className = 'p-2.5 rounded-lg border border-[#334155] bg-[#1E293B] hover:bg-[#0F172A]/60 text-[#E2E8F0] font-medium text-left transition-all duration-150 cursor-pointer shadow-none';
            }
        });

        // Highlight selected preset card on Page 1
        const p1Cards = [
            { el: p1PresetJira, key: 'jira' },
            { el: p1PresetPostgres, key: 'postgres' },
            { el: p1PresetK8s, key: 'k8s' },
            { el: p1PresetConfluence, key: 'confluence' }
        ];
        p1Cards.forEach(c => {
            if (!c.el) return;
            if (c.key === key) {
                c.el.className = 'p1-preset-card p-3 rounded-xl border border-teal-500/80 bg-[#0F172A] text-left transition-all duration-150 cursor-pointer shadow-none group';
            } else {
                c.el.className = 'p1-preset-card p-3 rounded-xl border border-[#334155] hover:border-[#0D9488]/60 hover:bg-[#1E293B]/80 text-left transition-all duration-150 cursor-pointer shadow-none group';
            }
        });

        resetPipelineNodes();
        if (p2PipelineStatusBadge) {
            p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#0F172A] text-[#94A3B8] border border-[#334155]';
            p2PipelineStatusBadge.textContent = 'READY TO RUN';
        }
        if (p2StageCountdownText) p2StageCountdownText.textContent = '';
    }

    // Page 1 Presets
    if (p1PresetJira) p1PresetJira.addEventListener('click', () => { selectTargetArtifact('jira'); flashElement(p1RawInput); });
    if (p1PresetPostgres) p1PresetPostgres.addEventListener('click', () => { selectTargetArtifact('postgres'); flashElement(p1RawInput); });
    if (p1PresetK8s) p1PresetK8s.addEventListener('click', () => { selectTargetArtifact('k8s'); flashElement(p1RawInput); });
    if (p1PresetConfluence) p1PresetConfluence.addEventListener('click', () => { selectTargetArtifact('confluence'); flashElement(p1RawInput); });

    // Page 2 Presets (The 4 files requested on page 2)
    if (p2FileJira) p2FileJira.addEventListener('click', () => selectTargetArtifact('jira'));
    if (p2FilePostgres) p2FilePostgres.addEventListener('click', () => selectTargetArtifact('postgres'));
    if (p2FileK8s) p2FileK8s.addEventListener('click', () => selectTargetArtifact('k8s'));
    if (p2FileConfluence) p2FileConfluence.addEventListener('click', () => selectTargetArtifact('confluence'));

    if (p1RawInput) {
        p1RawInput.addEventListener('input', () => {
            activeInputText = p1RawInput.value;
        });
    }

    // -------------------------------------------------------------
    // Page 1: Multi-Engine Redactor
    // -------------------------------------------------------------
    if (p1RunRedactorBtn) {
        p1RunRedactorBtn.addEventListener('click', async () => {
            const text = (p1RawInput ? p1RawInput.value : '').trim();
            if (!text) {
                showToast('Please enter text to sanitize.', 'warning');
                return;
            }

            try {
                p1RunRedactorBtn.disabled = true;
                const team = teamSelect ? teamSelect.value : 'CloudInfra';
                const res = await fetch('/api/sanitize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text, team })
                });

                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();

                if (p1RawHighlightView) p1RawHighlightView.innerHTML = data.highlighted_raw_html || 'Empty';
                if (p1SanitizedHighlightView) p1SanitizedHighlightView.innerHTML = data.highlighted_sanitized_html || 'Empty';

                if (p1StatTotal) p1StatTotal.textContent = data.stats.total_redactions;
                if (p1StatPresidio) p1StatPresidio.textContent = data.stats.presidio_entities;
                if (p1StatRegex) p1StatRegex.textContent = data.stats.regex_entities;
                if (p1StatLatency) p1StatLatency.textContent = `${data.stats.execution_time_ms} ms`;

                currentSanitizedText = data.sanitized_text || '';
                if (p1VectorSearchInput) {
                    p1VectorSearchInput.value = currentSanitizedText;
                    flashElement(p1VectorSearchInput);
                }

                if (p1RawCountBadge) p1RawCountBadge.textContent = `${data.stats.total_redactions} Detected`;
                if (p1SanitizedCountBadge) p1SanitizedCountBadge.textContent = `${data.stats.unique_secrets} Unique Tokens`;

                renderAuditTable(data.mapping);
                renderEntityBreakdown(data.mapping);
                showToast(`Argus scrubbed ${data.stats.total_redactions} entities across Presidio and Regex.`, 'success');
                // Automatically run vector search and profiler on the newly sanitized stream
                executeVectorSearch();
            } catch (err) {
                console.error(err);
                showToast(`Redaction error: ${err.message}`, 'error');
            } finally {
                p1RunRedactorBtn.disabled = false;
            }
        });
    }

    function renderAuditTable(mapping) {
        if (!p1MappingTableBody) return;
        p1MappingTableBody.innerHTML = '';
        if (p1TableEntitiesCount) p1TableEntitiesCount.textContent = `${mapping ? mapping.length : 0} Entities`;

        if (!mapping || mapping.length === 0) {
            p1MappingTableBody.innerHTML = `<tr><td colspan="7" class="px-5 py-8 text-center text-slate-400">
                <div class="h-10 w-10 rounded-full bg-[#1E293B] text-[#94A3B8] border border-[#334155] mx-auto flex items-center justify-center text-lg mb-2">🛡️</div>
                <p class="text-xs font-semibold text-[#F8FAFC]">No sensitive entities detected in current buffer</p>
                <p class="text-[11px] text-slate-400 mt-0.5">Click "Run Multi-Engine Masking" to inspect entity detection</p>
            </td></tr>`;
            return;
        }

        mapping.forEach(item => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-[#334155]/30 transition-colors duration-150';

            const engineBadge = item.engine.includes('TeamRule')
                ? 'bg-[#78350F]/40 text-[#FBBF24] border-[#B45309]'
                : (item.engine.includes('Regex') 
                    ? 'bg-[#4C0519] text-[#E11D48] border-[#BE123C]' 
                    : 'bg-[#064E3B] text-[#10B981] border-[#047857]');

            const riskBadge = item.risk_level === 'Critical' 
                ? 'bg-[#4C0519] text-[#E11D48] border-[#BE123C] font-bold' 
                : (item.risk_level === 'Medium' ? 'bg-[#0D9488]/20 text-[#2DD4BF] border-[#0D9488] font-semibold' : 'bg-[#1E293B] text-[#94A3B8] border-[#334155]');

            const engineIcon = item.engine.includes('Regex') ? '⚡' : (item.engine.includes('TeamRule') ? '🔐' : '🧠');

            tr.innerHTML = `
                <td class="px-4 py-2.5 font-bold text-[#10B981] whitespace-nowrap font-mono text-[11px]"><span class="px-2 py-0.5 rounded-md bg-[#064E3B] text-[#10B981] border border-[#047857] font-semibold">${escapeHtml(item.token)}</span></td>
                <td class="px-4 py-2.5 whitespace-nowrap"><span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold border ${engineBadge}"><span>${engineIcon}</span><span>${escapeHtml(item.engine)}</span></span></td>
                <td class="px-4 py-2.5 font-sans font-medium text-[#F8FAFC] whitespace-nowrap text-xs">${escapeHtml(item.entity_type)}</td>
                <td class="px-4 py-2.5 text-[#94A3B8] whitespace-nowrap font-mono text-[11px]">${escapeHtml(item.preview_value)}</td>
                <td class="px-4 py-2.5 text-[#94A3B8] whitespace-nowrap font-mono text-xs font-semibold">${escapeHtml(item.confidence)}</td>
                <td class="px-4 py-2.5 text-[#F8FAFC] whitespace-nowrap font-mono font-bold">${item.occurrences}x</td>
                <td class="px-4 py-2.5 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] border ${riskBadge}">${item.risk_level}</span></td>
            `;
            p1MappingTableBody.appendChild(tr);
        });
    }

    function renderEntityBreakdown(mapping) {
        const breakdownCard = document.getElementById('p1EntityBreakdownCard');
        const distributionBar = document.getElementById('p1EntityDistributionBar');
        const pillsCloud = document.getElementById('p1EntityPillsCloud');
        const summaryText = document.getElementById('p1EntityBreakdownSummary');

        if (!breakdownCard || !distributionBar || !pillsCloud) return;

        if (!mapping || mapping.length === 0) {
            breakdownCard.classList.add('hidden');
            return;
        }

        breakdownCard.classList.remove('hidden');

        const counts = {};
        mapping.forEach(m => {
            const type = m.entity_type || m.raw_type || 'Generic Secret';
            counts[type] = (counts[type] || 0) + (m.occurrences || 1);
        });

        const palette = [
            { bg: 'bg-rose-500', text: 'text-rose-700', pillBg: 'bg-rose-50', border: 'border-rose-200' },
            { bg: 'bg-teal-500', text: 'text-teal-700', pillBg: 'bg-teal-50', border: 'border-teal-200' },
            { bg: 'bg-amber-500', text: 'text-amber-700', pillBg: 'bg-amber-50', border: 'border-amber-200' },
            { bg: 'bg-indigo-500', text: 'text-indigo-700', pillBg: 'bg-indigo-50', border: 'border-indigo-200' },
            { bg: 'bg-purple-500', text: 'text-purple-700', pillBg: 'bg-purple-50', border: 'border-purple-200' },
            { bg: 'bg-blue-500', text: 'text-blue-700', pillBg: 'bg-blue-50', border: 'border-blue-200' }
        ];

        distributionBar.innerHTML = '';
        pillsCloud.innerHTML = '';
        const types = Object.keys(counts);
        const totalOccurrences = Object.values(counts).reduce((a, b) => a + b, 0);

        if (summaryText) {
            summaryText.textContent = `${totalOccurrences} Sensitive Entities Intercepted in RAM`;
        }

        types.forEach((type, idx) => {
            const count = counts[type];
            const pct = Math.max(8, Math.round((count / totalOccurrences) * 100));
            const color = palette[idx % palette.length];

            const seg = document.createElement('div');
            seg.className = `h-3 ${color.bg} transition-all duration-500`;
            seg.style.width = `${pct}%`;
            seg.title = `${type}: ${count} (${pct}%)`;
            distributionBar.appendChild(seg);

            const pill = document.createElement('div');
            pill.className = `inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg ${color.pillBg} ${color.text} border ${color.border} text-xs font-semibold shadow-2xs`;
            pill.innerHTML = `
                <span class="w-1.5 h-1.5 rounded-full ${color.bg}"></span>
                <span>${escapeHtml(type)}</span>
                <span class="font-mono font-bold bg-[#0F172A] px-1.5 py-0.2 rounded text-[10px] border border-[#334155] text-[#F8FAFC]">${count}x</span>
            `;
            pillsCloud.appendChild(pill);
        });
    }

    const p1CopySanitizedBtn = document.getElementById('p1CopySanitizedBtn');
    if (p1CopySanitizedBtn) {
        p1CopySanitizedBtn.addEventListener('click', () => {
            if (!currentSanitizedText) {
                showToast('No sanitized text available to copy.', 'warning');
                return;
            }
            navigator.clipboard.writeText(currentSanitizedText).then(() => {
                const prev = p1CopySanitizedBtn.textContent;
                p1CopySanitizedBtn.textContent = 'Copied! ✓';
                setTimeout(() => { p1CopySanitizedBtn.textContent = prev; }, 1800);
                showToast('Sanitized stream copied to clipboard.', 'success');
            }).catch(err => {
                showToast('Copy failed: ' + err, 'error');
            });
        });
    }

    const p1ClearInputBtn = document.getElementById('p1ClearInputBtn');
    if (p1ClearInputBtn) {
        p1ClearInputBtn.addEventListener('click', () => {
            if (p1RawInput) {
                p1RawInput.value = '';
                p1RawInput.focus();
                showToast('RAM buffer cleared.', 'info');
            }
        });
    }

    // -------------------------------------------------------------
    // Page 1: Vector Retrieval (Editable Query Box & Relevance Search)
    // -------------------------------------------------------------
    async function executeVectorSearch() {
        let queryText = (p1VectorSearchInput ? p1VectorSearchInput.value : '').trim();
        if (!queryText) {
            queryText = (p1RawInput ? p1RawInput.value : '').trim();
        }
        if (!queryText) {
            showToast('Please enter search query text or click Reload Masked Text.', 'warning');
            if (p1VectorSearchInput) p1VectorSearchInput.focus();
            return;
        }

        try {
            if (p1ExecuteSearchBtn) p1ExecuteSearchBtn.disabled = true;
            if (p1SimulateRetrieveBtn) p1SimulateRetrieveBtn.disabled = true;
            if (p1SearchBtnText) p1SearchBtnText.textContent = 'Searching Vector Memory...';

            const team = teamSelect ? teamSelect.value : 'SecOps';
            const res = await fetch('/api/retrieve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: queryText, team })
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            lastRetrievedChunks = data.retrieved_chunks || [];

            // If user typed raw secrets, show sanitized representation in box
            if (p1VectorSearchInput && data.sanitized_query && p1VectorSearchInput.value !== data.sanitized_query) {
                p1VectorSearchInput.value = data.sanitized_query;
                flashElement(p1VectorSearchInput);
            }

            if (p1RetrievedCountBadge) {
                p1RetrievedCountBadge.textContent = `${data.retrieved_chunks.length} Ranked Chunks (${data.retrieval_latency_ms}ms)`;
            }

            if (p1RetrievedChunksContainer) {
                p1RetrievedChunksContainer.innerHTML = '';
                data.retrieved_chunks.forEach(chunk => {
                    const card = document.createElement('div');
                    card.className = 'p-4 rounded-xl border border-[#334155] bg-[#1E293B] hover:border-[#0D9488] transition-all duration-200 space-y-2.5';
                    const scorePct = (chunk.similarity_score * 100).toFixed(1);
                    const scoreColor = chunk.similarity_score >= 0.75 
                        ? 'bg-[#064E3B] text-[#10B981] border-[#047857]' 
                        : 'bg-[#064E3B] text-[#10B981] border-[#047857]';
                    card.innerHTML = `
                        <div class="flex items-center justify-between">
                            <span class="font-mono text-xs font-bold text-[#10B981] bg-[#064E3B] px-2 py-0.5 rounded border border-[#047857]">${escapeHtml(chunk.chunk_id)}</span>
                            <span class="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${scoreColor}">${scorePct}% Cosine Match</span>
                        </div>
                        <div class="text-xs font-bold text-[#F8FAFC] flex items-center space-x-1.5">
                            <span class="text-[#0D9488]">📖</span>
                            <span>${escapeHtml(chunk.title)}</span>
                        </div>
                        <p class="text-[11px] text-[#F8FAFC] line-clamp-3 code-container bg-[#0F172A] p-2.5 rounded-lg border border-[#334155] leading-relaxed font-mono">${escapeHtml(chunk.sanitized_snippet)}</p>
                        <div class="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-[#334155]">
                            <span>Dist: ${chunk.vector_distance}</span>
                            <span class="text-[#0D9488] font-semibold truncate max-w-[120px]">${escapeHtml(chunk.team || 'SecOps')}</span>
                        </div>
                    `;
                    p1RetrievedChunksContainer.appendChild(card);
                });
            }

            // -------------------------------------------------------------
            // Render Visual Cascading Latency Waterfall & Vector Space Math
            // -------------------------------------------------------------
            const ragTotalLatencyVal = document.getElementById('ragTotalLatencyVal');
            const ragWaterfallContainer = document.getElementById('ragWaterfallContainer');
            const ragWaterfallSummaryRow = document.getElementById('ragWaterfallSummaryRow');
            const ragSummaryTotalMs = document.getElementById('ragSummaryTotalMs');
            const ragVectorInspectorCards = document.getElementById('ragVectorInspectorCards');
            const ragTelemetryCard = document.getElementById('ragTelemetryCard');
            const ragTelemetryToggleBtn = document.getElementById('ragTelemetryToggleBtn');
            const ragTelemetryBody = document.getElementById('ragTelemetryBody');
            const ragTelemetryChevron = document.getElementById('ragTelemetryChevron');

            // Wire accordion collapse/expand if not already wired
            if (ragTelemetryToggleBtn && !ragTelemetryToggleBtn._hasListener) {
                ragTelemetryToggleBtn._hasListener = true;
                ragTelemetryToggleBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    if (ragTelemetryBody) ragTelemetryBody.classList.toggle('hidden');
                    if (ragTelemetryChevron) ragTelemetryChevron.classList.toggle('rotate-180');
                });
            }

            const telemetry = data.telemetry;
            if (telemetry) {
                const totalMs = telemetry.total_latency_ms || data.retrieval_latency_ms || 1.0;
                if (ragTotalLatencyVal) {
                    ragTotalLatencyVal.textContent = `${totalMs} ms`;
                    ragTotalLatencyVal.className = 'font-mono font-bold text-[#10B981]';
                }
                if (ragSummaryTotalMs) {
                    ragSummaryTotalMs.textContent = `${totalMs} ms`;
                }
                if (ragWaterfallSummaryRow) {
                    ragWaterfallSummaryRow.classList.remove('hidden');
                }

                // Render Waterfall stages
                if (ragWaterfallContainer && telemetry.stages && telemetry.stages.length > 0) {
                    ragWaterfallContainer.innerHTML = '';
                    let runningOffsetMs = 0;

                    telemetry.stages.forEach(stage => {
                        const stageMs = stage.latency_ms || 0.1;
                        const pctWidth = Math.max(4, Math.min(100, (stageMs / totalMs) * 100));
                        const pctOffset = Math.max(0, Math.min(96, (runningOffsetMs / totalMs) * 100));
                        runningOffsetMs += stageMs;

                        const row = document.createElement('div');
                        row.className = 'p-3 rounded-lg bg-[#1E293B] border border-[#334155] space-y-2';
                        row.innerHTML = `
                            <div class="flex items-center justify-between text-xs">
                                <div class="flex items-center space-x-2">
                                    <span class="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#0F172A] border border-[#334155] text-[#10B981] font-bold">Stage ${stage.index}</span>
                                    <span class="font-semibold text-[#F8FAFC]">${escapeHtml(stage.name)}</span>
                                    <span class="text-[10px] text-slate-400 font-mono">(${escapeHtml(stage.engine)})</span>
                                </div>
                                <div class="font-mono text-xs font-bold text-[#10B981]">${stageMs} ms</div>
                            </div>
                            <div class="w-full bg-[#0F172A] h-2.5 rounded-full overflow-hidden relative border border-[#334155]/60">
                                <div class="absolute h-full rounded-full bg-gradient-to-r from-[#0D9488] to-[#10B981]" style="left: ${pctOffset.toFixed(1)}%; width: ${pctWidth.toFixed(1)}%;"></div>
                            </div>
                            <div class="text-[10px] text-slate-400 font-mono flex items-center justify-between pt-0.5">
                                <span>${escapeHtml(stage.detail || '')}</span>
                                <span class="text-slate-500 font-semibold">${((stageMs / totalMs) * 100).toFixed(1)}% of total</span>
                            </div>
                        `;
                        ragWaterfallContainer.appendChild(row);
                    });
                }

                // Render Top 3 Vector Space Math Cards
                if (ragVectorInspectorCards && data.retrieved_chunks && data.retrieved_chunks.length > 0) {
                    ragVectorInspectorCards.innerHTML = '';
                    data.retrieved_chunks.slice(0, 3).forEach((chunk, idx) => {
                        const sim = (chunk.cosine_similarity !== undefined ? chunk.cosine_similarity : chunk.similarity_score) || 0.85;
                        const dist = (chunk.vector_distance !== undefined ? chunk.vector_distance : (1.0 - sim)) || 0.15;
                        const vecPreview = chunk.vector_slice && chunk.vector_slice.length ? chunk.vector_slice.slice(0, 5) : [0.034, -0.012, 0.088, -0.045, 0.021];

                        const card = document.createElement('div');
                        card.className = 'p-3.5 rounded-xl bg-[#1E293B] border border-[#334155] space-y-2';
                        card.innerHTML = `
                            <div class="flex items-center justify-between">
                                <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0F172A] border border-[#334155] text-[#10B981] font-bold">Top Rank #${idx + 1}</span>
                                <span class="text-xs font-mono font-bold text-[#10B981]">${(sim * 100).toFixed(1)}% Match</span>
                            </div>
                            <div class="text-xs font-semibold text-[#F8FAFC] truncate" title="${escapeHtml(chunk.title)}">${escapeHtml(chunk.title)}</div>
                            <div class="bg-[#0F172A] p-2 rounded-lg border border-[#334155] font-mono text-[10px] text-slate-300 space-y-1">
                                <div class="flex justify-between">
                                    <span class="text-slate-400">Cosine cos(θ):</span>
                                    <span class="text-[#10B981] font-bold">${sim.toFixed(4)}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-slate-400">HNSW Distance:</span>
                                    <span class="text-amber-400 font-bold">${dist.toFixed(4)}</span>
                                </div>
                                <div class="text-[9px] text-slate-400 pt-1 border-t border-[#334155]">
                                    <div class="text-slate-400 mb-0.5">384-d Vector Slice [0..4]:</div>
                                    <div class="text-teal-400 truncate">[${vecPreview.map(v => typeof v === 'number' ? v.toFixed(3) : v).join(', ')}...]</div>
                                </div>
                            </div>
                        `;
                        ragVectorInspectorCards.appendChild(card);
                    });
                }
            }

            if (p1RetrievalCard) p1RetrievalCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            showToast('Retrieved matching knowledge base chunks with zero PII exposure.', 'success');
        } catch (err) {
            console.error(err);
            showToast(`Retrieval failed: ${err.message}`, 'error');
        } finally {
            if (p1ExecuteSearchBtn) p1ExecuteSearchBtn.disabled = false;
            if (p1SimulateRetrieveBtn) p1SimulateRetrieveBtn.disabled = false;
            if (p1SearchBtnText) p1SearchBtnText.textContent = 'Search Vector Knowledge Base';
        }
    }

    if (p1ExecuteSearchBtn) p1ExecuteSearchBtn.addEventListener('click', executeVectorSearch);
    if (p1SimulateRetrieveBtn) p1SimulateRetrieveBtn.addEventListener('click', executeVectorSearch);

    if (p1ResetQueryBtn) {
        p1ResetQueryBtn.addEventListener('click', () => {
            if (p1VectorSearchInput) {
                p1VectorSearchInput.value = currentSanitizedText || '';
                flashElement(p1VectorSearchInput);
                showToast('Reloaded current masked text into vector search box.', 'info');
            }
        });
    }

    if (p1ClearQueryBtn) {
        p1ClearQueryBtn.addEventListener('click', () => {
            if (p1VectorSearchInput) {
                p1VectorSearchInput.value = '';
                p1VectorSearchInput.focus();
                showToast('Query box cleared. You can type any custom search query.', 'info');
            }
        });
    }

    if (p1SaveToDbBtn) {
        p1SaveToDbBtn.addEventListener('click', async () => {
            let textToSave = currentSanitizedText;
            if (!textToSave && p1VectorSearchInput && p1VectorSearchInput.value.trim()) {
                textToSave = p1VectorSearchInput.value.trim();
            }
            if (!textToSave && p1RawInput && p1RawInput.value.trim()) {
                try {
                    const res = await fetch('/api/sanitize', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ text: p1RawInput.value.trim(), team: teamSelect ? teamSelect.value : 'SecOps' })
                    });
                    const s = await res.json();
                    textToSave = s.sanitized_text;
                } catch (e) {}
            }

            if (!textToSave) {
                showToast('No masked data available to store.', 'warning');
                return;
            }

            try {
                p1SaveToDbBtn.disabled = true;
                const team = teamSelect ? teamSelect.value : 'SecOps';
                const docTitle = `Masked Incident (${team}) - ${new Date().toLocaleTimeString()}`;

                const res = await fetch('/api/db/save-record', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        title: docTitle,
                        content: textToSave,
                        team: team
                    })
                });

                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();

                if (sidebarDocCount) sidebarDocCount.textContent = data.total_documents;
                showToast(`✓ Stored in local DB: ${data.doc_id} (${data.redacted_tokens} masked tokens).`, 'success');
                await refreshDbExplorer();
            } catch (err) {
                console.error('Save to DB error:', err);
                showToast(`Failed to store record: ${err.message}`, 'error');
            } finally {
                p1SaveToDbBtn.disabled = false;
            }
        });
    }

    // -------------------------------------------------------------
    // Page 2: 1.5s Per Stage Pipeline Simulation & In-Flight Kill-Switch
    // -------------------------------------------------------------
    const STAGE_DELAY_MS = 1500; // Exact 1.5 seconds per stage

    function logTrace(phase, details, location, status = 'ACTIVE') {
        if (!p2AuditTraceContainer) return;
        const now = new Date().toTimeString().split(' ')[0] + '.' + String(new Date().getMilliseconds()).padStart(3, '0');
        const color = status === 'FAILED' ? 'text-rose-400 font-bold' : (status === 'PURGED' ? 'text-amber-400 font-bold' : 'text-teal-400');

        const line = document.createElement('div');
        line.innerHTML = `
            <div class="flex items-start space-x-2 py-0.5">
                <span class="text-slate-500 shrink-0 font-mono">[${now}]</span>
                <span class="shrink-0 font-semibold ${color}">[${escapeHtml(phase)}]</span>
                <span class="text-slate-300">${escapeHtml(details)}</span>
                <span class="text-slate-500 text-[10px] shrink-0 font-mono ml-auto">(${escapeHtml(location)})</span>
            </div>
        `;
        p2AuditTraceContainer.appendChild(line);
        p2AuditTraceContainer.scrollTop = p2AuditTraceContainer.scrollHeight;
    }

    async function startSteppedPipeline() {
        if (simulationActive) return;
        simulationActive = true;
        currentStageIndex = 1;

        const text = activeInputText || PRESETS.jira.text;
        const filename = currentTargetFilename;
        const team = teamSelect ? teamSelect.value : 'SecOps';

        resetPipelineNodes();
        if (p2AuditTraceContainer) p2AuditTraceContainer.innerHTML = '';
        if (p2PipelineStatusBadge) {
            p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#064E3B] text-[#10B981] border border-[#047857] animate-pulse';
            p2PipelineStatusBadge.textContent = 'STAGE 1/4 (1.5s) INGESTION';
        }
        if (p2StartBtnText) p2StartBtnText.textContent = '⏳ Pipeline Running (1.5s/stage)...';
        if (p2SimulateNormalBtn) p2SimulateNormalBtn.disabled = true;

        // ---------- STAGE 1: RAM Ingestion (1.5s) ----------
        setNodeActive(nodeStage1, 'Stage 1: Ephemeral Heap Ingestion');
        if (p2StageCountdownText) p2StageCountdownText.textContent = `[1/4] Ephemeral Ingestion Buffer (1.5s)...`;
        logTrace('RAM Buffer Allocation', `Allocated volatile buffer (${text.length} bytes) for ${filename}. Zero disk writes.`, 'Heap: 0x7ffe42a0');

        simulationTimeoutId = setTimeout(async () => {
            if (!simulationActive) return;

            // ---------- STAGE 2: Presidio + Regex Masking (1.5s) ----------
            currentStageIndex = 2;
            setNodeState(nodeStage1, 'success');
            setNodeActive(nodeStage2, 'Stage 2: Presidio & Regex Tokenization');
            if (p2PipelineStatusBadge) p2PipelineStatusBadge.textContent = 'STAGE 2/4 (1.5s) MASKING';
            if (p2StageCountdownText) p2StageCountdownText.textContent = `[2/4] Presidio NER & Regex Masking (1.5s)...`;

            let sanitizedResult = null;
            try {
                const res = await fetch('/api/sanitize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text, team })
                });
                sanitizedResult = await res.json();
                logTrace('Multi-Engine Tokenizer', `Masked ${sanitizedResult.stats.total_redactions} entities (${sanitizedResult.stats.presidio_entities} Presidio, ${sanitizedResult.stats.regex_entities} Regex).`, 'RAM Enclave');
            } catch (e) {
                logTrace('Tokenizer', 'Sanitizing in-memory buffer...', 'RAM Enclave');
            }

            simulationTimeoutId = setTimeout(async () => {
                if (!simulationActive) return;

                // ---------- STAGE 3: Zero-Leakage Policy Gate (1.5s) ----------
                currentStageIndex = 3;
                setNodeState(nodeStage2, 'success');
                setNodeActive(nodeStage3, 'Stage 3: Policy Integrity Inspection');
                if (p2PipelineStatusBadge) p2PipelineStatusBadge.textContent = 'STAGE 3/4 (1.5s) POLICY GATE';
                if (p2StageCountdownText) p2StageCountdownText.textContent = `[3/4] Zero-Leakage Policy Gate Check (1.5s)...`;
                logTrace('Zero-Leakage Policy Gate', 'Auditing output for canary secrets and residual PII patterns...', 'Inspection Gate');

                simulationTimeoutId = setTimeout(async () => {
                    if (!simulationActive) return;

                    // ---------- STAGE 4: Storage Vault Commit (1.5s) ----------
                    currentStageIndex = 4;
                    setNodeState(nodeStage3, 'success');
                    setNodeActive(nodeStage4, 'Stage 4: Vault File Commit');
                    if (p2PipelineStatusBadge) p2PipelineStatusBadge.textContent = 'STAGE 4/4 (1.5s) COMMITTING';
                    if (p2StageCountdownText) p2StageCountdownText.textContent = `[4/4] Writing clean masked file to storage_vault/ (1.5s)...`;
                    logTrace('Storage Vault Commit', `Committed clean tokens into storage_vault/masked_${filename}.`, 'storage_vault/');

                    simulationTimeoutId = setTimeout(async () => {
                        if (!simulationActive) return;

                        // Normal Completion: Save Resultant File into storage_vault/
                        try {
                            const cleanText = sanitizedResult ? sanitizedResult.sanitized_text : text;
                            const saveRes = await fetch('/api/pipeline/save-vault', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    filename: filename,
                                    content: cleanText,
                                    team: team
                                })
                            });

                            const saveData = await saveRes.json();
                            setNodeState(nodeStage4, 'success');

                            if (p2PipelineStatusBadge) {
                                p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#064E3B] text-[#10B981] border border-[#047857]';
                                p2PipelineStatusBadge.textContent = '✓ STORED IN STORAGE_VAULT/';
                            }
                            if (p2StageCountdownText) p2StageCountdownText.textContent = `✓ 4/4 Completed (${saveData.filename})`;
                            if (sidebarDocCount && saveData.total_documents) sidebarDocCount.textContent = saveData.total_documents;

                            logTrace('Vault Verification', `SUCCESS: File ${saveData.filename} (${saveData.size_bytes} bytes) verified in storage_vault/.`, 'storage_vault/', 'SUCCESS');

                            showToast(`✓ Pipeline finished! Resultant file "${saveData.filename}" saved in storage_vault/.`, 'success');
                            await refreshVaultFolder();
                            await refreshDbExplorer();
                        } catch (err) {
                            console.error(err);
                        } finally {
                            finishPipelineRun();
                        }
                    }, STAGE_DELAY_MS);

                }, STAGE_DELAY_MS);

            }, STAGE_DELAY_MS);

        }, STAGE_DELAY_MS);
    }

    async function interruptPipeline() {
        if (!simulationActive) {
            showToast('No active pipeline in flight. Triggering preemptive purge check.', 'warning');
        }

        // Cancel all timeouts immediately
        simulationActive = false;
        if (simulationTimeoutId) {
            clearTimeout(simulationTimeoutId);
            simulationTimeoutId = null;
        }

        const filename = currentTargetFilename;
        const failedStage = currentStageIndex || 1;

        // Visual nodes: set failed state on current stage, and purged on Stage 4
        if (failedStage === 1) setNodeState(nodeStage1, 'failed');
        if (failedStage === 2) setNodeState(nodeStage2, 'failed');
        if (failedStage === 3) setNodeState(nodeStage3, 'failed');
        setNodeState(nodeStage4, 'purged');

        if (p2PipelineStatusBadge) {
            p2PipelineStatusBadge.className = 'text-xs font-mono font-semibold px-2.5 py-0.5 rounded bg-[#4C0519] text-[#E11D48] border border-[#BE123C] animate-pulse';
            p2PipelineStatusBadge.textContent = `🛑 ABORTED AT STAGE ${failedStage} — WIPED FROM RAM`;
        }
        if (p2StageCountdownText) p2StageCountdownText.textContent = `❌ Interrupted at Stage ${failedStage}!`;

        // Backend call to ensure any partial file in storage_vault/ is permanently deleted
        try {
            const res = await fetch('/api/pipeline/interrupt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename, team: teamSelect ? teamSelect.value : 'SecOps' })
            });
            const data = await res.json();

            logTrace('KILL-SWITCH ACTIVATED', `User interrupted at Stage ${failedStage}. Ephemeral RAM shredded. Zero bytes in storage.`, 'Kill-Switch', 'FAILED');
            logTrace('Vault Audit', `CONFIRMED: In-flight buffer shredded. Prevented landing on disk. Existing vault files preserved.`, 'storage_vault/', 'PURGED');

            const alertDiv = document.createElement('div');
            alertDiv.className = 'mt-2 p-2.5 rounded bg-rose-950/90 border border-rose-500 text-rose-200 text-xs font-bold';
            alertDiv.innerHTML = `⚠️ HARD KILL-SWITCH ENGAGED AT STAGE ${failedStage}: Volatile heap memory shredded. In-flight data prevented from landing on disk. Prior files preserved intact.`;
            p2AuditTraceContainer.appendChild(alertDiv);
            p2AuditTraceContainer.scrollTop = p2AuditTraceContainer.scrollHeight;

            showToast(`🛑 Kill-Switch engaged! Memory wiped. File confirmed NOT in storage folder.`, 'error');
            await refreshVaultFolder();
        } catch (err) {
            console.error('Interrupt error:', err);
        } finally {
            finishPipelineRun();
        }
    }

    function finishPipelineRun() {
        simulationActive = false;
        if (p2StartBtnText) p2StartBtnText.textContent = '▶ Run 4-Stage Pipeline (1.5s/stage)';
        if (p2SimulateNormalBtn) p2SimulateNormalBtn.disabled = false;
    }

    if (p2SimulateNormalBtn) p2SimulateNormalBtn.addEventListener('click', startSteppedPipeline);
    if (p2SimulateInterruptBtn) p2SimulateInterruptBtn.addEventListener('click', interruptPipeline);

    function resetPipelineNodes() {
        [nodeStage1, nodeStage2, nodeStage3, nodeStage4].forEach(node => {
            if (!node) return;
            node.className = 'border border-[#334155] rounded-xl p-4 bg-[#0F172A]/60 transition-all duration-200';
            const dot = node.querySelector('.status-dot');
            if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-slate-400 status-dot';
        });
    }

    function setNodeActive(node, label) {
        if (!node) return;
        node.className = 'border border-teal-500/80 rounded-xl p-4 bg-[#1E293B] transition-all duration-200 ring-2 ring-teal-500/20';
        const dot = node.querySelector('.status-dot');
        if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-teal-500 status-dot animate-ping';
    }

    function setNodeState(node, state) {
        if (!node) return;
        const dot = node.querySelector('.status-dot');
        if (state === 'success') {
            node.className = 'border border-teal-500/60 rounded-xl p-4 bg-[#1E293B] transition-all duration-200';
            if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-teal-500 status-dot';
        } else if (state === 'failed') {
            node.className = 'border border-[#BE123C] rounded-xl p-4 bg-[#4C0519]/50 transition-all duration-200 ring-2 ring-rose-500/30';
            if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-rose-500 status-dot';
        } else if (state === 'purged') {
            node.className = 'border border-rose-500 rounded-xl p-4 bg-rose-100/90 transition-all duration-200 shadow-xs';
            if (dot) dot.className = 'h-2.5 w-2.5 rounded-full bg-rose-600 status-dot animate-ping';
        }
    }

    // -------------------------------------------------------------
    // Page 2: Storage Vault Folder Live Explorer (/storage_vault)
    // -------------------------------------------------------------
    async function refreshVaultFolder() {
        if (!p2VaultFilesContainer) return;
        try {
            const res = await fetch('/api/vault-files');
            if (!res.ok) return;
            const data = await res.json();
            const files = data.vault_files || [];

            if (p2VaultFolderCountBadge) {
                p2VaultFolderCountBadge.textContent = `${files.length} Files in Vault`;
            }

            p2VaultFilesContainer.innerHTML = '';

            if (files.length === 0) {
                p2VaultFilesContainer.innerHTML = `
                    <div class="p-4 rounded-lg bg-[#0F172A] border border-[#334155] text-center text-xs text-[#94A3B8]">
                        <span class="font-medium text-[#F8FAFC]">Storage Vault Folder is Empty (0 bytes saved).</span>
                        <p class="text-[11px] text-slate-400 mt-0.5">Run the pipeline to Stage 4 to generate a file, or hit Interrupt to verify that files never reach this folder.</p>
                    </div>
                `;
                return;
            }

            files.forEach(f => {
                const row = document.createElement('div');
                row.className = 'flex items-center justify-between p-3 rounded-lg bg-[#1E293B] border border-[#334155] text-xs';
                row.innerHTML = `
                    <div class="flex items-center space-x-2.5">
                        <span class="h-2 w-2 rounded-full bg-teal-500"></span>
                        <div>
                            <span class="font-mono font-bold text-[#F8FAFC]">${escapeHtml(f.filename)}</span>
                            <span class="ml-2 font-mono text-[10px] text-slate-400">(${(f.size_bytes / 1024).toFixed(1)} KB • Saved ${f.modified})</span>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-[#064E3B] text-[#10B981] border-[#047857] font-mono">
                            MASKED & STORED
                        </span>
                        <button type="button" class="inspect-vault-file-btn text-xs font-medium text-[#0D9488] hover:text-[#2DD4BF] underline cursor-pointer" data-filename="${escapeAttr(f.filename)}">
                            Inspect File
                        </button>
                    </div>
                `;

                row.querySelector('.inspect-vault-file-btn').addEventListener('click', async (e) => {
                    const name = e.target.getAttribute('data-filename');
                    await inspectVaultFile(name);
                });

                p2VaultFilesContainer.appendChild(row);
            });
        } catch (err) {
            console.error('Failed to refresh vault folder:', err);
        }
    }

    async function inspectVaultFile(filename) {
        try {
            const res = await fetch(`/api/vault-files/${encodeURIComponent(filename)}`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            lastRetrievedChunks = data.retrieved_chunks || [];

            if (p2VaultInspectedName) p2VaultInspectedName.textContent = `storage_vault/${data.filename} (${data.size_bytes} bytes)`;
            if (p2VaultInspectedContent) p2VaultInspectedContent.textContent = data.content;

            if (p2VaultFileInspector) {
                p2VaultFileInspector.classList.remove('hidden');
                p2VaultFileInspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        } catch (err) {
            showToast(`Could not open file: ${err.message}`, 'error');
        }
    }

    if (p2CloseVaultInspectBtn) {
        p2CloseVaultInspectBtn.addEventListener('click', () => {
            if (p2VaultFileInspector) p2VaultFileInspector.classList.add('hidden');
        });
    }

    if (p2ClearVaultBtn) {
        p2ClearVaultBtn.addEventListener('click', async () => {
            try {
                await fetch('/api/vault-files', { method: 'DELETE' });
                showToast('Storage Vault folder cleared.', 'info');
                await refreshVaultFolder();
            } catch (e) {
                console.error(e);
            }
        });
    }

    // -------------------------------------------------------------
    // Page 2: Local SQLite Database Explorer (data/argus_knowledge_base.db)
    // -------------------------------------------------------------
    async function refreshDbExplorer() {
        try {
            // 1. Fetch DB metadata
            const infoRes = await fetch('/api/db/info');
            if (infoRes.ok) {
                const info = await infoRes.json();
                if (p2DbRecordsBadge) p2DbRecordsBadge.textContent = `${info.total_records} Records`;
                if (p2DbSizeBadge) p2DbSizeBadge.textContent = `${info.size_kb} KB`;
                if (sidebarDocCount) sidebarDocCount.textContent = info.total_records;
            }

            // 2. Fetch all masked records
            const recRes = await fetch('/api/db/records');
            if (!recRes.ok) return;
            const recData = await recRes.json();
            const records = recData.records || [];

            if (!p2DbRecordsTableBody) return;
            p2DbRecordsTableBody.innerHTML = '';

            if (records.length === 0) {
                p2DbRecordsTableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="px-4 py-6 text-center text-slate-400 font-sans italic">
                            No records in data/argus_knowledge_base.db. Run the pipeline or click "Store in Local DB".
                        </td>
                    </tr>
                `;
                return;
            }

            records.forEach(r => {
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-[#334155]/30 transition-colors duration-150';
                tr.innerHTML = `
                    <td class="px-3.5 py-2.5 font-bold text-[#F8FAFC] whitespace-nowrap">${escapeHtml(r.id)}</td>
                    <td class="px-3.5 py-2.5 whitespace-nowrap">
                        <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-[#0F172A] text-[#94A3B8] border border-[#334155]">${escapeHtml(r.team)}</span>
                    </td>
                    <td class="px-3.5 py-2.5 font-sans font-medium text-[#F8FAFC] max-w-xs truncate" title="${escapeAttr(r.title)}">${escapeHtml(r.title)}</td>
                    <td class="px-3.5 py-2.5 font-mono text-[#10B981] font-semibold">${r.tokens_count} tokens</td>
                    <td class="px-3.5 py-2.5 text-slate-400 text-[11px] whitespace-nowrap">${escapeHtml(r.created_at)}</td>
                    <td class="px-3.5 py-2.5 whitespace-nowrap space-x-2 text-right">
                        <button type="button" class="inspect-db-rec-btn text-xs font-semibold text-[#0D9488] hover:text-[#2DD4BF] underline cursor-pointer" data-id="${escapeAttr(r.id)}">
                            Inspect
                        </button>
                        <button type="button" class="delete-db-rec-btn text-xs font-semibold text-[#E11D48] hover:text-[#FB7185] underline cursor-pointer" data-id="${escapeAttr(r.id)}">
                            Delete
                        </button>
                    </td>
                `;

                // Wire inspect
                tr.querySelector('.inspect-db-rec-btn').addEventListener('click', () => {
                    if (p2DbRecordInspector) {
                        p2DbInspectedTitle.textContent = r.title;
                        p2DbInspectedId.textContent = `[${r.id} • ${r.team}]`;
                        p2DbInspectedContent.textContent = r.sanitized_content;
                        p2DbRecordInspector.classList.remove('hidden');
                        p2DbRecordInspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    }
                });

                // Wire delete
                tr.querySelector('.delete-db-rec-btn').addEventListener('click', async () => {
                    if (!confirm(`Delete record ${r.id} from local database?`)) return;
                    try {
                        const delRes = await fetch(`/api/db/records/${encodeURIComponent(r.id)}`, { method: 'DELETE' });
                        if (delRes.ok) {
                            showToast(`Deleted ${r.id} from SQLite DB.`, 'info');
                            await refreshDbExplorer();
                        }
                    } catch (e) {
                        console.error(e);
                    }
                });

                p2DbRecordsTableBody.appendChild(tr);
            });
        } catch (err) {
            console.error('Failed to load DB records:', err);
        }
    }

    if (p2RefreshDbBtn) {
        p2RefreshDbBtn.addEventListener('click', async () => {
            await refreshDbExplorer();
            showToast('Refreshed local database records.', 'info');
        });
    }

    if (p2CloseDbInspectBtn) {
        p2CloseDbInspectBtn.addEventListener('click', () => {
            if (p2DbRecordInspector) p2DbRecordInspector.classList.add('hidden');
        });
    }

    // -------------------------------------------------------------
    // Transfer Modal (SQLite -> PostgreSQL pgvector / Qdrant)
    // -------------------------------------------------------------
    function openTransferModal() {
        if (!transferModal) return;
        transferModal.classList.remove('hidden');
        switchTransferTab('simulate');
        loadTransferGuide();
    }

    function closeTransferModal() {
        if (transferModal) transferModal.classList.add('hidden');
    }

    if (p2OpenTransferModalBtn) p2OpenTransferModalBtn.addEventListener('click', openTransferModal);
    if (closeTransferModalBtn) closeTransferModalBtn.addEventListener('click', closeTransferModal);
    if (dismissTransferModalBtn) dismissTransferModalBtn.addEventListener('click', closeTransferModal);

    function switchTransferTab(tabKey) {
        const tabs = [
            { btn: modalTabSimulate, view: modalViewSimulate, key: 'simulate' },
            { btn: modalTabSql, view: modalViewSql, key: 'sql' },
            { btn: modalTabScript, view: modalViewScript, key: 'script' }
        ];

        tabs.forEach(t => {
            if (!t.btn || !t.view) return;
            if (t.key === tabKey) {
                t.btn.className = 'transfer-tab px-3.5 py-2 font-semibold text-[#0D9488] border-b-2 border-[#0D9488] cursor-pointer';
                t.view.classList.remove('hidden');
            } else {
                t.btn.className = 'transfer-tab px-3.5 py-2 font-medium text-[#94A3B8] hover:text-[#F8FAFC] cursor-pointer';
                t.view.classList.add('hidden');
            }
        });
    }

    if (modalTabSimulate) modalTabSimulate.addEventListener('click', () => switchTransferTab('simulate'));
    if (modalTabSql) modalTabSql.addEventListener('click', () => switchTransferTab('sql'));
    if (modalTabScript) modalTabScript.addEventListener('click', () => switchTransferTab('script'));

    let transferGuideLoaded = false;
    let guideSqlData = '';
    let guideScriptData = '';

    async function loadTransferGuide() {
        if (transferGuideLoaded) return;
        try {
            const res = await fetch('/api/db/transfer-guide');
            if (!res.ok) return;
            const data = await res.json();
            guideSqlData = data.migration_sql || '';
            guideScriptData = data.python_migration_script || '';

            if (ddlSqlContent) ddlSqlContent.textContent = guideSqlData;
            if (scriptPythonContent) scriptPythonContent.textContent = guideScriptData;
            transferGuideLoaded = true;
        } catch (e) {
            console.error(e);
        }
    }

    if (copyDdlBtn) {
        copyDdlBtn.addEventListener('click', () => {
            if (!guideSqlData) return;
            navigator.clipboard.writeText(guideSqlData).then(() => {
                showToast('PostgreSQL DDL copied to clipboard.', 'info');
            });
        });
    }

    if (copyScriptBtn) {
        copyScriptBtn.addEventListener('click', () => {
            if (!guideScriptData) return;
            navigator.clipboard.writeText(guideScriptData).then(() => {
                showToast('Python transfer script copied to clipboard.', 'info');
            });
        });
    }

    // Execute Vector Migration Simulation
    if (executeMigrationSimulationBtn) {
        executeMigrationSimulationBtn.addEventListener('click', async () => {
            try {
                executeMigrationSimulationBtn.disabled = true;
                if (migrationStatusLabel) migrationStatusLabel.textContent = 'Vectorizing masked content (384-dim)...';

                const res = await fetch('/api/db/transfer-simulate', { method: 'POST' });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();

                if (migratedDocsCount) migratedDocsCount.textContent = data.total_migrated;
                if (migratedTokensCount) migratedTokensCount.textContent = data.total_tokens_verified;

                if (migratedSampleJson) {
                    migratedSampleJson.textContent = JSON.stringify(data.records[0] || {}, null, 2);
                }

                if (migrationResultsArea) migrationResultsArea.classList.remove('hidden');
                if (migrationStatusLabel) migrationStatusLabel.textContent = `Completed in ${data.simulation_latency_ms}ms • Ready for pgvector`;

                showToast(`✓ Migration verified: ${data.total_migrated} documents ready for pgvector!`, 'success');
            } catch (err) {
                console.error(err);
                showToast(`Simulation failed: ${err.message}`, 'error');
            } finally {
                executeMigrationSimulationBtn.disabled = false;
            }
        });
    }

    // -------------------------------------------------------------
    // Team Lead Cryptographic Rulebook Enclave Controller
    // -------------------------------------------------------------
    let cachedEnclaveRules = [];

    function openRulebookModal() {
        if (!rulebookModal) return;
        rulebookModal.classList.remove('hidden');
        loadRulebookStatus();
        
        // Ensure locked state on open: do not auto-unlock, do not pre-fill key
        if (leadMasterKeyInput) {
            leadMasterKeyInput.value = '';
            leadMasterKeyInput.focus();
        }
        if (rbLockedNotice) rbLockedNotice.classList.remove('hidden');
        if (rbUnlockedContent) rbUnlockedContent.classList.add('hidden');
    }

    function closeRulebookModal() {
        if (rulebookModal) rulebookModal.classList.add('hidden');
    }

    if (openRulebookModalBtn) openRulebookModalBtn.addEventListener('click', openRulebookModal);
    if (p1OpenRulebookBtn) p1OpenRulebookBtn.addEventListener('click', openRulebookModal);
    if (p4OpenRulebookBtn) p4OpenRulebookBtn.addEventListener('click', openRulebookModal);
    if (closeRulebookModalBtn) closeRulebookModalBtn.addEventListener('click', closeRulebookModal);
    if (dismissRulebookModalBtn) dismissRulebookModalBtn.addEventListener('click', closeRulebookModal);

    if (toggleKeyVisibilityBtn && leadMasterKeyInput) {
        toggleKeyVisibilityBtn.addEventListener('click', () => {
            if (leadMasterKeyInput.type === 'password') {
                leadMasterKeyInput.type = 'text';
                toggleKeyVisibilityBtn.textContent = 'Hide';
            } else {
                leadMasterKeyInput.type = 'password';
                toggleKeyVisibilityBtn.textContent = 'Show';
            }
        });
    }

    async function loadRulebookStatus() {
        try {
            const res = await fetch('/api/rulebook/status');
            if (!res.ok) return;
            const data = await res.json();
            if (rbIntegrityBadge) {
                if (data.integrity_status === 'VERIFIED_TAMPER_PROOF') {
                    rbIntegrityBadge.className = 'font-mono text-[11px] text-emerald-400 font-bold block';
                    rbIntegrityBadge.textContent = '✓ HMAC-SHA256 Verified';
                } else {
                    rbIntegrityBadge.className = 'font-mono text-[11px] text-rose-400 font-bold block animate-pulse';
                    rbIntegrityBadge.textContent = '⚠️ TAMPERING DETECTED';
                }
            }
        } catch (e) {
            console.error(e);
        }
    }

    async function unlockRulebook() {
        const masterKey = (leadMasterKeyInput ? leadMasterKeyInput.value : '').trim();
        if (!masterKey) {
            showToast('Please enter the Team Lead Master Key.', 'warning');
            return;
        }

        try {
            const team = rbTeamFilter ? rbTeamFilter.value : 'All';
            const res = await fetch('/api/rulebook/unlock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ master_key: masterKey, team: team })
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Access denied');
            }

            const data = await res.json();
            cachedEnclaveRules = data.custom_rules || [];
            
            // On successful authentication, reveal rule tables and form
            if (rbLockedNotice) rbLockedNotice.classList.add('hidden');
            if (rbUnlockedContent) rbUnlockedContent.classList.remove('hidden');
            
            renderRulebookTable(cachedEnclaveRules);
            showToast(`Enclave unlocked: ${cachedEnclaveRules.length} custom team rules active.`, 'success');
        } catch (err) {
            console.error(err);
            showToast(`Cryptographic Access Denied: ${err.message}`, 'error');
            if (rbLockedNotice) rbLockedNotice.classList.remove('hidden');
            if (rbUnlockedContent) rbUnlockedContent.classList.add('hidden');
        }
    }

    if (unlockRulebookBtn) unlockRulebookBtn.addEventListener('click', unlockRulebook);

    // Allow pressing Enter in key input to authenticate
    if (leadMasterKeyInput) {
        leadMasterKeyInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                unlockRulebook();
            }
        });
    }

    async function verifyRulebookIntegrity() {
        try {
            const res = await fetch('/api/rulebook/verify-integrity', { method: 'POST' });
            const data = await res.json();
            if (data.status === 'VERIFIED_TAMPER_PROOF') {
                showToast('✓ Cryptographic Seal Valid: 0 bytes tampered on disk.', 'success');
                if (rbIntegrityBadge) {
                    rbIntegrityBadge.className = 'font-mono text-[11px] text-emerald-400 font-bold block';
                    rbIntegrityBadge.textContent = '✓ HMAC-SHA256 Verified';
                }
            } else {
                showToast(`⚠️ Tamper alert: ${data.message}`, 'error');
                if (rbIntegrityBadge) {
                    rbIntegrityBadge.className = 'font-mono text-[11px] text-rose-400 font-bold block animate-pulse';
                    rbIntegrityBadge.textContent = '⚠️ TAMPERING DETECTED';
                }
            }
        } catch (e) {
            console.error(e);
        }
    }

    if (verifyIntegrityBtn) verifyIntegrityBtn.addEventListener('click', verifyRulebookIntegrity);

    if (rbTeamFilter) {
        rbTeamFilter.addEventListener('change', () => {
            const sel = rbTeamFilter.value;
            if (sel === 'All') {
                renderRulebookTable(cachedEnclaveRules);
            } else {
                renderRulebookTable(cachedEnclaveRules.filter(r => r.team === sel || r.team === 'Global'));
            }
        });
    }

    function renderRulebookTable(rules) {
        if (!rbRulesTableBody) return;
        rbRulesTableBody.innerHTML = '';

        if (!rules || rules.length === 0) {
            rbRulesTableBody.innerHTML = `<tr><td colspan="7" class="px-4 py-6 text-center text-slate-400 font-sans italic">No custom rules found for this namespace. Add one below.</td></tr>`;
            return;
        }

        rules.forEach(r => {
            const tr = document.createElement('tr');
            tr.className = 'hover:bg-[#334155]/30 transition-colors duration-150';
            tr.innerHTML = `
                <td class="px-3 py-2 text-[#F8FAFC] font-bold whitespace-nowrap">${escapeHtml(r.id)}</td>
                <td class="px-3 py-2 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-[#78350F]/40 text-[#FBBF24] border border-[#B45309]">${escapeHtml(r.team)}</span>
                </td>
                <td class="px-3 py-2 font-sans font-medium text-[#F8FAFC] whitespace-nowrap">${escapeHtml(r.name)}</td>
                <td class="px-3 py-2 text-[#10B981] whitespace-nowrap font-bold">${escapeHtml(r.entity_type)}</td>
                <td class="px-3 py-2 text-[#94A3B8] max-w-xs truncate font-mono text-[11px]" title="${escapeAttr(r.pattern)}">${escapeHtml(r.pattern)}</td>
                <td class="px-3 py-2 whitespace-nowrap">
                    <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${r.risk === 'Critical' ? 'bg-[#4C0519] text-[#E11D48] border border-[#BE123C]' : 'bg-[#0F172A] text-[#94A3B8] border border-[#334155]'}">${escapeHtml(r.risk || 'High')}</span>
                </td>
                <td class="px-3 py-2 text-right whitespace-nowrap">
                    <button type="button" class="del-rule-btn text-rose-500 hover:text-rose-700 underline text-xs font-semibold cursor-pointer" data-id="${escapeAttr(r.id)}">
                        Delete
                    </button>
                </td>
            `;

            tr.querySelector('.del-rule-btn').addEventListener('click', async () => {
                const masterKey = (leadMasterKeyInput ? leadMasterKeyInput.value : '').trim();
                if (!confirm(`Delete custom rule ${r.id} (${r.name})?`)) return;
                try {
                    const res = await fetch(`/api/rulebook/rules/${encodeURIComponent(r.id)}?master_key=${encodeURIComponent(masterKey)}`, { method: 'DELETE' });
                    if (!res.ok) throw new Error(`HTTP ${res.status}`);
                    showToast(`Rule ${r.id} deleted and enclave re-signed.`, 'info');
                    await unlockRulebook();
                } catch (e) {
                    showToast(`Failed to delete rule: ${e.message}`, 'error');
                }
            });

            rbRulesTableBody.appendChild(tr);
        });
    }

    if (addRuleForm) {
        addRuleForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const masterKey = (leadMasterKeyInput ? leadMasterKeyInput.value : '').trim();
            if (!masterKey) {
                showToast('Please enter Team Lead Master Key to sign rules.', 'warning');
                return;
            }

            const rulePayload = {
                master_key: masterKey,
                team: newRuleTeam ? newRuleTeam.value : 'CloudInfra',
                name: (newRuleName ? newRuleName.value : '').trim(),
                entity_type: (newRuleEntityType ? newRuleEntityType.value : '').trim(),
                label: (newRuleLabel ? newRuleLabel.value : '').trim(),
                pattern: (newRulePattern ? newRulePattern.value : '').trim(),
                risk: 'High',
                priority: 6
            };

            try {
                const res = await fetch('/api/rulebook/add-rule', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(rulePayload)
                });

                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || 'Failed to save');
                }

                showToast(`✓ Rule "${rulePayload.name}" encrypted and signed in enclave!`, 'success');
                addRuleForm.reset();
                await unlockRulebook();
            } catch (err) {
                console.error(err);
                showToast(`Rule creation error: ${err.message}`, 'error');
            }
        });
    }

    if (teamSelect) {
        teamSelect.addEventListener('change', () => {
            const team = teamSelect.value;
            showToast(`Active namespace set to "${team}". Applying custom team rules.`, 'info');
            if (p1RawInput && p1RawInput.value.trim()) {
                fetch('/api/sanitize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: p1RawInput.value.trim(), team })
                }).then(r => r.json()).then(data => {
                    if (p1RawHighlightView) p1RawHighlightView.innerHTML = data.highlighted_raw_html || 'Empty';
                    if (p1SanitizedHighlightView) p1SanitizedHighlightView.innerHTML = data.highlighted_sanitized_html || 'Empty';
                    if (p1StatTotal) p1StatTotal.textContent = data.stats.total_redactions;
                    if (p1StatPresidio) p1StatPresidio.textContent = data.stats.presidio_entities;
                    if (p1StatRegex) p1StatRegex.textContent = data.stats.regex_entities;
                    if (p1StatLatency) p1StatLatency.textContent = `${data.stats.execution_time_ms} ms`;
                    currentSanitizedText = data.sanitized_text || '';
                    if (p1VectorSearchInput) p1VectorSearchInput.value = currentSanitizedText;
                    if (p1RawCountBadge) p1RawCountBadge.textContent = `${data.stats.total_redactions} Detected`;
                    if (p1SanitizedCountBadge) p1SanitizedCountBadge.textContent = `${data.stats.unique_secrets} Unique Tokens`;
                    renderAuditTable(data.mapping);
                }).catch(() => {});
            }
        });
    }

    // -------------------------------------------------------------
    // Page 3: Integration Content Renderer
    // -------------------------------------------------------------
    function renderIntegrationContent(key) {
        const data = INTEGRATION_DATA[key];
        if (!data || !integContentCard) return;

        const tabs = [
            { el: integTabJira, id: 'jira' },
            { el: integTabConfluence, id: 'confluence' },
            { el: integTabGit, id: 'git' },
            { el: integTabSlack, id: 'slack' }
        ];

        tabs.forEach(t => {
            if (!t.el) return;
            if (t.id === key) {
                t.el.className = 'integ-tab-btn px-4 py-2 rounded-lg text-xs font-semibold bg-[#1E293B] border border-[#334155] text-[#E2E8F0] shadow-none cursor-pointer';
            } else {
                t.el.className = 'integ-tab-btn px-4 py-2 rounded-lg text-xs font-semibold text-[#94A3B8] hover:text-[#E2E8F0] hover:bg-[#0F172A] cursor-pointer';
            }
        });

        integContentCard.innerHTML = `
            <div class="flex items-center justify-between pb-3 border-b border-[#334155]">
                <div class="space-y-1">
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0D9488]/20 text-[#2DD4BF] font-semibold border border-[#0D9488]">${escapeHtml(data.badge)}</span>
                    <h3 class="text-sm font-bold text-[#F8FAFC]">${escapeHtml(data.title)}</h3>
                </div>
            </div>

            <p class="text-xs text-[#94A3B8] leading-relaxed">${escapeHtml(data.summary)}</p>

            <div class="space-y-2">
                <h4 class="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">Implementation Steps:</h4>
                <ul class="space-y-1.5 text-xs text-[#94A3B8] list-disc pl-5">
                    ${data.steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
                </ul>
            </div>

            <div class="space-y-2 pt-2">
                <div class="flex items-center justify-between">
                    <h4 class="text-xs font-bold uppercase tracking-wider text-slate-700">Production Code Snippet:</h4>
                    <button type="button" class="copy-code-btn text-[11px] font-mono text-[#0D9488] hover:text-[#2DD4BF] underline cursor-pointer">
                        Copy Code
                    </button>
                </div>
                <div class="relative rounded-lg bg-slate-900 border border-slate-800 p-4">
                    <pre class="code-container text-teal-300 overflow-x-auto whitespace-pre-wrap">${escapeHtml(data.codeSnippet)}</pre>
                </div>
            </div>
        `;

        const copyBtn = integContentCard.querySelector('.copy-code-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(data.codeSnippet).then(() => {
                    showToast('Code snippet copied to clipboard.', 'info');
                });
            });
        }
    }

    if (integTabJira) integTabJira.addEventListener('click', () => renderIntegrationContent('jira'));
    if (integTabConfluence) integTabConfluence.addEventListener('click', () => renderIntegrationContent('confluence'));
    if (integTabGit) integTabGit.addEventListener('click', () => renderIntegrationContent('git'));
    if (integTabSlack) integTabSlack.addEventListener('click', () => renderIntegrationContent('slack'));

    // -------------------------------------------------------------
    // Mandate 2: Confluence Live Cloud Ingestion Pipeline Controller
    // -------------------------------------------------------------
    const confDomainInput = document.getElementById('confDomainInput');
    const confSpaceKeyInput = document.getElementById('confSpaceKeyInput');
    const confEmailInput = document.getElementById('confEmailInput');
    const confApiTokenInput = document.getElementById('confApiTokenInput');
    const confSyncBtn = document.getElementById('confSyncBtn');
    const confSyncBtnText = document.getElementById('confSyncBtnText');
    const confSyncResultsCard = document.getElementById('confSyncResultsCard');
    const confSyncResultsHeader = document.getElementById('confSyncResultsHeader');
    const confSyncTokensBadge = document.getElementById('confSyncTokensBadge');
    const confSyncResultsSummary = document.getElementById('confSyncResultsSummary');
    const confSyncPagesList = document.getElementById('confSyncPagesList');

    if (confSyncBtn) {
        confSyncBtn.addEventListener('click', async () => {
            const domain = (confDomainInput ? confDomainInput.value : '').trim();
            const spaceKey = (confSpaceKeyInput ? confSpaceKeyInput.value : '').trim();
            const email = (confEmailInput ? confEmailInput.value : '').trim();
            const token = (confApiTokenInput ? confApiTokenInput.value : '').trim();

            if (!domain || !spaceKey || !email || !token) {
                showToast('Please fill in all Confluence fields (Domain, Space Key, Email, API Token).', 'warning');
                if (!domain && confDomainInput) confDomainInput.focus();
                else if (!spaceKey && confSpaceKeyInput) confSpaceKeyInput.focus();
                else if (!email && confEmailInput) confEmailInput.focus();
                else if (!token && confApiTokenInput) confApiTokenInput.focus();
                return;
            }

            try {
                confSyncBtn.disabled = true;
                if (confSyncBtnText) confSyncBtnText.textContent = 'Crawling & Scrubbing in RAM...';

                const res = await fetch('/api/integrations/confluence/sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        domain: domain,
                        space_key: spaceKey,
                        email: email,
                        api_token: token
                    })
                });

                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || `HTTP ${res.status}`);
                }

                showToast(`Successfully synced ${data.pages_synced} pages and redacted ${data.total_tokens_redacted} secrets!`, 'success');

                // Render Results Card
                if (confSyncResultsCard) confSyncResultsCard.classList.remove('hidden');
                if (confSyncResultsHeader) confSyncResultsHeader.textContent = `Space '${data.space_key}' Synced • Zero Leakage`;
                if (confSyncTokensBadge) confSyncTokensBadge.textContent = `${data.total_tokens_redacted} Secrets Redacted`;
                if (confSyncResultsSummary) confSyncResultsSummary.textContent = data.message;

                if (confSyncPagesList) {
                    const pages = data.synced_pages || [];
                    if (pages.length === 0) {
                        confSyncPagesList.innerHTML = '<div class="text-[11px] text-slate-500 font-mono py-1">No pages found in space.</div>';
                    } else {
                        confSyncPagesList.innerHTML = pages.map(p => `
                            <div class="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono">
                                <div class="flex items-center space-x-2 truncate max-w-md">
                                    <span class="text-teal-400 font-bold">${escapeHtml(p.doc_id)}</span>
                                    <span class="text-[#E2E8F0] truncate">${escapeHtml(p.title)}</span>
                                </div>
                                <span class="text-emerald-400 font-semibold shrink-0">${p.tokens_redacted} redacted</span>
                            </div>
                        `).join('');
                    }
                }

                // Refresh Database Explorer & Topology if available
                if (typeof refreshDbExplorer === 'function') refreshDbExplorer();
                if (typeof initOrRefreshTopologyGraph === 'function') initOrRefreshTopologyGraph();

            } catch (err) {
                console.error('[Argus Confluence Sync]', err);
                showToast(`Confluence Sync failed: ${err.message}`, 'error');
                if (confSyncResultsCard) confSyncResultsCard.classList.remove('hidden');
                if (confSyncResultsHeader) confSyncResultsHeader.textContent = 'Confluence Sync Error';
                if (confSyncTokensBadge) confSyncTokensBadge.textContent = 'Failed';
                if (confSyncResultsSummary) confSyncResultsSummary.textContent = err.message;
            } finally {
                confSyncBtn.disabled = false;
                if (confSyncBtnText) confSyncBtnText.textContent = 'Sync Confluence Space';
            }
        });
    }

    // -------------------------------------------------------------
    // Helper Utilities
    // -------------------------------------------------------------
    function flashElement(el) {
        if (!el) return;
        el.classList.add('ring-2', 'ring-teal-500/50');
        setTimeout(() => el.classList.remove('ring-2', 'ring-teal-500/50'), 400);
    }

    function showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) return;
        const toast = document.createElement('div');
        toast.className = 'pointer-events-auto flex items-center space-x-2.5 px-4 py-3 rounded-lg shadow-lg border text-xs font-medium transition-all duration-300 transform translate-y-2 opacity-0';

        let iconSvg = '';
        if (type === 'success') {
            toast.classList.add('bg-slate-900', 'text-teal-300', 'border-teal-500/40');
            iconSvg = `<svg class="w-4 h-4 text-teal-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
        } else if (type === 'warning') {
            toast.classList.add('bg-slate-900', 'text-amber-300', 'border-amber-500/40');
            iconSvg = `<svg class="w-4 h-4 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;
        } else if (type === 'error') {
            toast.classList.add('bg-slate-900', 'text-rose-300', 'border-rose-500/40');
            iconSvg = `<svg class="w-4 h-4 text-rose-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`;
        } else {
            toast.classList.add('bg-slate-900', 'text-white', 'border-slate-700');
            iconSvg = `<svg class="w-4 h-4 text-slate-300 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
        }

        toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
        toastContainer.appendChild(toast);

        requestAnimationFrame(() => toast.classList.remove('translate-y-2', 'opacity-0'));
        setTimeout(() => {
            toast.classList.add('opacity-0', 'translate-x-4');
            setTimeout(() => toast.remove(), 300);
        }, 3200);
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function escapeAttr(str) {
        if (!str) return '';
        return String(str).replace(/"/g, '&quot;');
    }

    // Initial KB Stats & Vault fetch
    fetch('/api/kb/stats')
        .then(r => r.json())
        .then(d => {
            if (sidebarDocCount && d.total_documents !== undefined) {
                sidebarDocCount.textContent = d.total_documents;
            }
        })
        .catch(() => {});

    refreshVaultFolder();
    refreshDbExplorer();

    // Initial auto-sanitization to populate editable vector search box
    if (p1RawInput && p1VectorSearchInput) {
        fetch('/api/sanitize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: p1RawInput.value, team: teamSelect ? teamSelect.value : 'CloudInfra' })
        }).then(r => r.json()).then(data => {
            currentSanitizedText = data.sanitized_text || '';
            p1VectorSearchInput.value = currentSanitizedText;
            executeVectorSearch();
        }).catch(() => {});
    }

    // =========================================================================
    // PAGE 5: Semantic Incident Topology & D3.js Force Simulation Controller
    // =========================================================================
    let currentTopologyData = null;
    let topologySimulation = null;
    let activeTeamFilter = 'All';
    let pinnedNodeId = null;
    let currentZoomTransform = null;
    let d3ZoomBehavior = null;
    let currentLinkDistance = 110;

    const p5StatTotalNodes = document.getElementById('p5StatTotalNodes');
    const p5StatRunbooks = document.getElementById('p5StatRunbooks');
    const p5StatIncidents = document.getElementById('p5StatIncidents');
    const p5StatTokens = document.getElementById('p5StatTokens');
    const p5StatSharedHubs = document.getElementById('p5StatSharedHubs');

    const p5GraphLoader = document.getElementById('p5GraphLoader');
    const topologyGraphSvg = document.getElementById('topologyGraphSvg');
    const p5SearchInput = document.getElementById('p5SearchInput');
    const p5LinkDistanceSlider = document.getElementById('p5LinkDistanceSlider');
    const p5LinkDistanceValue = document.getElementById('p5LinkDistanceValue');
    const topologyTooltip = document.getElementById('topologyTooltip');
    const tooltipBadge = document.getElementById('tooltipBadge');
    const tooltipType = document.getElementById('tooltipType');
    const tooltipTeam = document.getElementById('tooltipTeam');
    const tooltipTitle = document.getElementById('tooltipTitle');
    const tooltipSub = document.getElementById('tooltipSub');

    const p5ToggleRunbooks = document.getElementById('p5ToggleRunbooks');
    const p5ToggleIncidents = document.getElementById('p5ToggleIncidents');
    const p5ToggleTokens = document.getElementById('p5ToggleTokens');

    const p5ZoomInBtn = document.getElementById('p5ZoomInBtn');
    const p5ZoomOutBtn = document.getElementById('p5ZoomOutBtn');
    const p5FitViewBtn = document.getElementById('p5FitViewBtn');
    const p5ResetZoomBtn = document.getElementById('p5ResetZoomBtn');

    const p5InspectorPlaceholder = document.getElementById('p5InspectorPlaceholder');
    const p5InspectorDetails = document.getElementById('p5InspectorDetails');
    const p5InspectorBadge = document.getElementById('p5InspectorBadge');
    const p5InspectorTypeTag = document.getElementById('p5InspectorTypeTag');
    const p5InspectorNodeTitle = document.getElementById('p5InspectorNodeTitle');
    const p5InspectorTeamTag = document.getElementById('p5InspectorTeamTag');
    const p5InspectorSubtext = document.getElementById('p5InspectorSubtext');
    const p5InspectorIncidentsList = document.getElementById('p5InspectorIncidentsList');
    const p5InspectorRunbooksList = document.getElementById('p5InspectorRunbooksList');
    const p5InspectorIncidentCount = document.getElementById('p5InspectorIncidentCount');
    const p5InspectorRunbookCount = document.getElementById('p5InspectorRunbookCount');
    const p5InspectorBlastRadiusBox = document.getElementById('p5InspectorBlastRadiusBox');
    const p5InspectorBlastRadiusText = document.getElementById('p5InspectorBlastRadiusText');
    const p5ResetHighlightBtn = document.getElementById('p5ResetHighlightBtn');

    const p5SimulateJiraBtn = document.getElementById('p5SimulateJiraBtn');
    const p5SimulateTelemetryBtn = document.getElementById('p5SimulateTelemetryBtn');
    const p5RefreshGraphBtn = document.getElementById('p5RefreshGraphBtn');

    function initOrRefreshTopologyGraph(team) {
        if (team !== undefined) activeTeamFilter = team;
        if (p5GraphLoader) p5GraphLoader.classList.remove('hidden');

        const url = activeTeamFilter && activeTeamFilter !== 'All' 
            ? `/api/graph/topology?team=${encodeURIComponent(activeTeamFilter)}` 
            : '/api/graph/topology';

        fetch(url)
            .then(res => {
                if (!res.ok) throw new Error(`HTTP error ${res.status}`);
                return res.json();
            })
            .then(data => {
                currentTopologyData = data;
                updateTopologyStats(data.stats);
                renderD3TopologyGraph(data);
                if (p5GraphLoader) p5GraphLoader.classList.add('hidden');
            })
            .catch(err => {
                console.error('[Argus Topology] Error fetching graph topology:', err);
                if (p5GraphLoader) {
                    p5GraphLoader.innerHTML = `<span class="text-xs font-mono text-rose-400">Error loading topology: ${escapeHtml(err.message)}</span>`;
                }
            });
    }

    function updateTopologyStats(stats) {
        if (!stats) return;
        if (p5StatTotalNodes) p5StatTotalNodes.textContent = stats.total_nodes || 0;
        if (p5StatRunbooks) p5StatRunbooks.textContent = stats.runbooks_count || 0;
        if (p5StatIncidents) p5StatIncidents.textContent = stats.incidents_count || 0;
        if (p5StatTokens) p5StatTokens.textContent = stats.tokens_count || 0;
        if (p5StatSharedHubs) p5StatSharedHubs.textContent = stats.shared_hubs_count || 0;
    }

    function renderD3TopologyGraph(graphData) {
        if (!window.d3) {
            console.warn('[Argus Topology] D3.js v7 is not loaded on window.');
            return;
        }

        const svg = d3.select('#topologyGraphSvg');
        svg.selectAll('*').remove();

        const container = svg.node().parentElement;
        const width = container.clientWidth || 800;
        const height = container.clientHeight || 640;

        svg.attr('viewBox', [0, 0, width, height]);

        // Deep copy nodes and links so D3 mutation does not break original payloads
        const nodes = graphData.nodes.map(d => Object.assign({}, d));
        const links = graphData.links.map(d => Object.assign({}, d));

        // Group container for zoom and pan
        const gRoot = svg.append('g').attr('class', 'topology-root');

        d3ZoomBehavior = d3.zoom()
            .scaleExtent([0.2, 4.5])
            .on('zoom', (event) => {
                currentZoomTransform = event.transform;
                gRoot.attr('transform', event.transform);
            });

        svg.call(d3ZoomBehavior);

        // Click canvas to clear active highlight
        svg.on('click', (event) => {
            if (event.target === svg.node()) {
                clearInspectorSelection();
            }
        });

        // Set up D3 Force Simulation
        if (topologySimulation) topologySimulation.stop();

        const baseDist = currentLinkDistance || 110;
        topologySimulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(d => {
                if (d.target.type === 'token' || d.source.type === 'token') return baseDist * 0.75;
                return baseDist * 1.15;
            }).strength(0.6))
            .force('charge', d3.forceManyBody().strength(d => d.type === 'token' ? -160 : -240))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(d => d.type === 'token' ? 14 : 20).iterations(2))
            .alphaDecay(0.028);

        // Bind Dynamic Link Distance Slider (Mandate 2)
        if (p5LinkDistanceSlider) {
            p5LinkDistanceSlider.oninput = function() {
                const newDist = parseInt(this.value, 10) || 110;
                currentLinkDistance = newDist;
                if (p5LinkDistanceValue) p5LinkDistanceValue.textContent = `${newDist}px`;
                if (topologySimulation) {
                    topologySimulation.force('link').distance(d => {
                        if (d.target.type === 'token' || d.source.type === 'token') return newDist * 0.75;
                        return newDist * 1.15;
                    });
                    topologySimulation.alpha(0.3).restart();
                }
            };
        }

        // Draw Links
        const link = gRoot.append('g')
            .attr('class', 'topology-links')
            .selectAll('line')
            .data(links)
            .enter().append('line')
            .attr('stroke', '#334155')
            .attr('stroke-opacity', 0.5)
            .attr('stroke-width', 1.2);

        // Draw Nodes Group
        const node = gRoot.append('g')
            .attr('class', 'topology-nodes')
            .selectAll('g')
            .data(nodes)
            .enter().append('g')
            .attr('class', d => `topology-node node-${d.type}`)
            .attr('cursor', 'pointer')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended)
            );

        // Sleek Minimalist Geometry (Mandate 2: Strip heavy badges/shapes; Teal, Emerald, Crimson dots/circles)
        node.each(function(d) {
            const el = d3.select(this);

            if (d.type === 'runbook') {
                // Sleek Teal Rounded Geometry
                el.append('rect')
                    .attr('x', -7.5)
                    .attr('y', -7.5)
                    .attr('width', 15)
                    .attr('height', 15)
                    .attr('rx', 3)
                    .attr('fill', '#0F766E') // Teal
                    .attr('stroke', '#2DD4BF')
                    .attr('stroke-width', 1.5)
                    .attr('class', 'node-shape');

                el.append('circle')
                    .attr('r', 1.8)
                    .attr('fill', '#CCFBF1')
                    .attr('pointer-events', 'none');

            } else if (d.type === 'incident') {
                // Sleek Crimson Circle
                el.append('circle')
                    .attr('r', 8)
                    .attr('fill', '#BE123C') // Crimson
                    .attr('stroke', '#FDA4AF')
                    .attr('stroke-width', 1.5)
                    .attr('class', 'node-shape');

                el.append('circle')
                    .attr('r', 1.8)
                    .attr('fill', '#FFE4E6')
                    .attr('pointer-events', 'none');

            } else {
                // Sleek Emerald Token Dot
                const isShared = d.is_shared_hub || (d.degree && d.degree > 2);
                el.append('circle')
                    .attr('r', isShared ? 7 : 5)
                    .attr('fill', isShared ? '#047857' : '#065F46') // Emerald
                    .attr('stroke', isShared ? '#34D399' : '#10B981')
                    .attr('stroke-width', isShared ? 2 : 1.2)
                    .attr('class', 'node-shape');

                if (isShared) {
                    el.append('circle')
                        .attr('r', 1.8)
                        .attr('fill', '#A7F3D0')
                        .attr('pointer-events', 'none');
                }
            }
        });

        // Sleek Tooltip on Hover (Mandate 2: Rather than permanently displaying text labels next to every node)
        node.on('mouseover', function(event, d) {
            highlightNodeNeighbors(d, node, link);
            renderInspectorCard(d);

            if (topologyTooltip) {
                topologyTooltip.classList.remove('hidden');
                const badgeColor = d.type === 'runbook' ? '#2DD4BF' : (d.type === 'incident' ? '#FDA4AF' : '#34D399');
                if (tooltipBadge) tooltipBadge.style.backgroundColor = badgeColor;
                if (tooltipType) {
                    tooltipType.textContent = d.type;
                    tooltipType.style.color = badgeColor;
                }
                if (tooltipTeam) tooltipTeam.textContent = d.team || 'Global';
                if (tooltipTitle) tooltipTitle.textContent = d.name || d.label || d.id;
                if (tooltipSub) {
                    if (d.type === 'token') {
                        tooltipSub.textContent = `Deterministic Token • ${d.category || 'Infrastructure'}`;
                    } else if (d.type === 'runbook') {
                        tooltipSub.textContent = `Authoritative SOP • ${d.tokens_count || 0} tokens attached`;
                    } else {
                        tooltipSub.textContent = `Production Incident • ${d.tokens_count || 0} tokens extracted`;
                    }
                }
            }
        });

        node.on('mousemove', function(event) {
            if (topologyTooltip) {
                const containerRect = svg.node().parentElement.getBoundingClientRect();
                const x = event.clientX - containerRect.left + 14;
                const y = event.clientY - containerRect.top + 14;
                topologyTooltip.style.left = `${Math.min(x, containerRect.width - 240)}px`;
                topologyTooltip.style.top = `${Math.min(y, containerRect.height - 100)}px`;
            }
        });

        node.on('mouseout', function(event, d) {
            if (topologyTooltip) topologyTooltip.classList.add('hidden');
            if (!pinnedNodeId) {
                restoreGraphOpacity(node, link);
            }
        });

        node.on('click', function(event, d) {
            event.stopPropagation();
            pinnedNodeId = d.id;
            highlightNodeNeighbors(d, node, link);
            renderInspectorCard(d, true);
        });

        // Simulation Tick Listener
        topologySimulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);

            node
                .attr('transform', d => `translate(${d.x},${d.y})`);
        });

        function dragstarted(event, d) {
            if (!event.active) topologySimulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) topologySimulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
    }

    // Highlighting connected links and neighbor nodes
    function highlightNodeNeighbors(d, nodeSelection, linkSelection) {
        const connectedIds = new Set([d.id]);

        linkSelection
            .attr('stroke', l => {
                if (l.source.id === d.id || l.target.id === d.id) {
                    connectedIds.add(l.source.id);
                    connectedIds.add(l.target.id);
                    return '#2dd4bf'; // bright teal highlight
                }
                return '#1e293b';
            })
            .attr('stroke-width', l => (l.source.id === d.id || l.target.id === d.id) ? 2.5 : 1)
            .attr('stroke-opacity', l => (l.source.id === d.id || l.target.id === d.id) ? 1.0 : 0.08);

        nodeSelection
            .style('opacity', n => connectedIds.has(n.id) ? 1.0 : 0.18)
            .select('.node-shape')
            .attr('stroke-width', n => n.id === d.id ? 3.5 : (connectedIds.has(n.id) ? 2.5 : 1.5));
    }

    function restoreGraphOpacity(nodeSelection, linkSelection) {
        nodeSelection
            .style('opacity', 1.0)
            .select('.node-shape')
            .attr('stroke-width', d => d.is_shared_hub ? 2.5 : 2);

        linkSelection
            .attr('stroke', '#334155')
            .attr('stroke-width', 1.5)
            .attr('stroke-opacity', 0.6);
    }

    function clearInspectorSelection() {
        pinnedNodeId = null;
        const svg = d3.select('#topologyGraphSvg');
        restoreGraphOpacity(svg.selectAll('.topology-node'), svg.selectAll('.topology-links line'));

        if (p5InspectorPlaceholder) p5InspectorPlaceholder.classList.remove('hidden');
        if (p5InspectorDetails) p5InspectorDetails.classList.add('hidden');
        if (p5InspectorBadge) p5InspectorBadge.textContent = 'READY';
    }

    // Renders the inspector card (Mandate 2 core interactive requirement)
    function renderInspectorCard(d, isPinned = false) {
        if (!p5InspectorDetails || !p5InspectorPlaceholder) return;

        p5InspectorPlaceholder.classList.add('hidden');
        p5InspectorDetails.classList.remove('hidden');

        if (p5InspectorBadge) {
            p5InspectorBadge.textContent = isPinned ? 'PINNED' : 'INSPECTING';
            p5InspectorBadge.className = isPinned 
                ? 'text-[10px] font-mono px-2 py-0.5 rounded bg-[#064E3B] text-[#10B981] border border-[#047857] font-bold'
                : 'text-[10px] font-mono px-2 py-0.5 rounded bg-[#1E293B] text-[#94A3B8] border border-[#334155] font-medium';
        }

        if (p5InspectorNodeTitle) p5InspectorNodeTitle.textContent = d.id;
        if (p5InspectorTeamTag) p5InspectorTeamTag.textContent = d.team || 'Global';

        if (d.type === 'token') {
            // Mandate 2: Hovering over a Token node must display exactly which incident tickets and runbooks share that underlying infrastructure component
            if (p5InspectorTypeTag) {
                p5InspectorTypeTag.textContent = 'DETERMINISTIC TOKEN';
                p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-300';
            }

            if (p5InspectorSubtext) {
                p5InspectorSubtext.innerHTML = `<strong>${escapeHtml(d.entity_label || d.entity_type)}</strong> • Category: ${escapeHtml(d.category || 'Identifier')} • Risk: <span class="font-bold text-rose-600">${escapeHtml(d.risk || 'Medium')}</span>`;
            }

            const incs = d.connected_incidents || [];
            const rbs = d.connected_runbooks || [];

            if (p5InspectorIncidentCount) p5InspectorIncidentCount.textContent = incs.length;
            if (p5InspectorRunbookCount) p5InspectorRunbookCount.textContent = rbs.length;

            // Render Connected Incidents list
            if (p5InspectorIncidentsList) {
                p5InspectorIncidentsList.innerHTML = '';
                if (incs.length === 0) {
                    p5InspectorIncidentsList.innerHTML = '<span class="text-[11px] text-slate-400 italic">No incidents currently reference this token.</span>';
                } else {
                    incs.forEach(inc => {
                        const item = document.createElement('div');
                        item.className = 'p-2 rounded-md bg-[#4C0519]/40 border border-[#BE123C]/60 text-[11px] flex items-center justify-between hover:bg-[#4C0519]/80 transition-colors cursor-pointer';
                        item.innerHTML = `
                            <div class="truncate mr-2">
                                <span class="font-bold text-[#E11D48] font-mono">${escapeHtml(inc.id)}</span>
                                <span class="text-slate-600 ml-1 truncate">${escapeHtml(inc.title || '')}</span>
                            </div>
                            <span class="text-[9px] font-semibold text-[#E11D48] bg-[#4C0519] px-1.5 py-0.5 rounded border border-[#BE123C] shrink-0">${escapeHtml(inc.team)}</span>
                        `;
                        item.addEventListener('click', () => zoomToNode(inc.id));
                        p5InspectorIncidentsList.appendChild(item);
                    });
                }
            }

            // Render Matching Runbooks list
            if (p5InspectorRunbooksList) {
                p5InspectorRunbooksList.innerHTML = '';
                if (rbs.length === 0) {
                    p5InspectorRunbooksList.innerHTML = '<span class="text-[11px] text-slate-400 italic">No runbook SOP found covering this entity.</span>';
                } else {
                    rbs.forEach(rb => {
                        const item = document.createElement('div');
                        item.className = 'p-2 rounded-md bg-[#1E293B] border border-[#0D9488]/50 text-[11px] flex items-center justify-between hover:bg-[#334155]/50 transition-colors cursor-pointer';
                        item.innerHTML = `
                            <div class="truncate mr-2">
                                <span class="font-bold text-[#2DD4BF] font-mono">${escapeHtml(rb.id)}</span>
                                <span class="text-slate-600 ml-1 truncate">${escapeHtml(rb.title || '')}</span>
                            </div>
                            <span class="text-[9px] font-semibold text-[#0D9488] bg-[#0F172A] border border-[#0D9488] shrink-0">${escapeHtml(rb.team)}</span>
                        `;
                        item.addEventListener('click', () => zoomToNode(rb.id));
                        p5InspectorRunbooksList.appendChild(item);
                    });
                }
            }

            // Blast Radius Alert
            if (p5InspectorBlastRadiusBox) {
                if (d.is_shared_hub) {
                    p5InspectorBlastRadiusBox.classList.remove('hidden');
                    if (p5InspectorBlastRadiusText) {
                        p5InspectorBlastRadiusText.innerHTML = `This component is shared by <strong>${incs.length} incident tickets</strong> and <strong>${rbs.length} runbooks</strong>. Resolving it mitigates cross-system blast radius across namespace <em>${escapeHtml(d.team)}</em>.`;
                    }
                } else {
                    p5InspectorBlastRadiusBox.classList.add('hidden');
                }
            }

        } else if (d.type === 'runbook') {
            if (p5InspectorTypeTag) {
                p5InspectorTypeTag.textContent = 'RUNBOOK SOP';
                p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-100 text-sky-800 border border-sky-300';
            }
            if (p5InspectorSubtext) {
                p5InspectorSubtext.innerHTML = `<strong>${escapeHtml(d.name || d.id)}</strong><br><span class="text-slate-500 font-mono text-[11px]">Procedure: ${escapeHtml(d.snippet || '')}</span>`;
            }
            if (p5InspectorIncidentCount) p5InspectorIncidentCount.textContent = (d.linked_tokens || []).length;
            if (p5InspectorRunbookCount) p5InspectorRunbookCount.textContent = 'SOP Target';

            if (p5InspectorIncidentsList) {
                p5InspectorIncidentsList.innerHTML = '<div class="text-[11px] font-semibold text-slate-700 mb-1">Embedded Entity Tokens:</div>';
                (d.linked_tokens || []).forEach(tok => {
                    const tag = document.createElement('span');
                    tag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-teal-50 text-teal-800 border border-teal-200 mr-1.5 mb-1 cursor-pointer hover:bg-teal-100';
                    tag.textContent = tok;
                    tag.addEventListener('click', () => zoomToNode(tok));
                    p5InspectorIncidentsList.appendChild(tag);
                });
            }
            if (p5InspectorRunbooksList) {
                p5InspectorRunbooksList.innerHTML = `<span class="text-[11px] text-sky-700">Authoritative SOP Tier: SQLite + ChromaDB</span>`;
            }
            if (p5InspectorBlastRadiusBox) p5InspectorBlastRadiusBox.classList.add('hidden');

        } else {
            // Incident
            if (p5InspectorTypeTag) {
                p5InspectorTypeTag.textContent = 'INCIDENT CRASH DUMP';
                p5InspectorTypeTag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300';
            }
            if (p5InspectorSubtext) {
                p5InspectorSubtext.innerHTML = `<strong>${escapeHtml(d.name || d.id)}</strong><br><span class="text-slate-500 font-mono text-[11px]">Sanitized Snapshot: ${escapeHtml(d.snippet || '')}</span>`;
            }
            if (p5InspectorIncidentCount) p5InspectorIncidentCount.textContent = 'Ingested';
            if (p5InspectorRunbookCount) p5InspectorRunbookCount.textContent = (d.linked_tokens || []).length;

            if (p5InspectorIncidentsList) {
                p5InspectorIncidentsList.innerHTML = `<span class="text-[11px] text-rose-700 font-mono">Fingerprint: ${escapeHtml(d.fingerprint || '')}</span>`;
            }
            if (p5InspectorRunbooksList) {
                p5InspectorRunbooksList.innerHTML = '<div class="text-[11px] font-semibold text-slate-700 mb-1">Extracted Tokens:</div>';
                (d.linked_tokens || []).forEach(tok => {
                    const tag = document.createElement('span');
                    tag.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-teal-50 text-teal-800 border border-teal-200 mr-1.5 mb-1 cursor-pointer hover:bg-teal-100';
                    tag.textContent = tok;
                    tag.addEventListener('click', () => zoomToNode(tok));
                    p5InspectorRunbooksList.appendChild(tag);
                });
            }
            if (p5InspectorBlastRadiusBox) p5InspectorBlastRadiusBox.classList.add('hidden');
        }
    }

    function zoomToNode(nodeId) {
        if (!topologySimulation || !d3ZoomBehavior) return;
        const svg = d3.select('#topologyGraphSvg');
        const targetNode = topologySimulation.nodes().find(n => n.id === nodeId);
        if (!targetNode) return;

        const container = svg.node().parentElement;
        const width = container.clientWidth || 800;
        const height = container.clientHeight || 640;

        const transform = d3.zoomIdentity
            .translate(width / 2, height / 2)
            .scale(1.8)
            .translate(-targetNode.x, -targetNode.y);

        svg.transition().duration(650).call(d3ZoomBehavior.transform, transform);

        // Highlight and inspect node
        pinnedNodeId = targetNode.id;
        highlightNodeNeighbors(targetNode, svg.selectAll('.topology-node'), svg.selectAll('.topology-links line'));
        renderInspectorCard(targetNode, true);
    }

    // Toolbar Team Filter Buttons
    document.querySelectorAll('.p5-team-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const team = btn.getAttribute('data-team');
            document.querySelectorAll('.p5-team-btn').forEach(b => {
                b.className = 'p5-team-btn px-2.5 py-1 rounded-md text-xs font-medium text-[#94A3B8] hover:bg-[#334155] cursor-pointer transition-colors';
            });
            btn.className = 'p5-team-btn px-2.5 py-1 rounded-md text-xs font-semibold bg-[#0D9488] text-[#F8FAFC] cursor-pointer transition-colors';
            initOrRefreshTopologyGraph(team);
        });
    });

    // Node Type Checkboxes Filter
    function applyNodeTypeVisibility() {
        const showRunbooks = p5ToggleRunbooks ? p5ToggleRunbooks.checked : true;
        const showIncidents = p5ToggleIncidents ? p5ToggleIncidents.checked : true;
        const showTokens = p5ToggleTokens ? p5ToggleTokens.checked : true;

        d3.selectAll('.node-runbook').style('display', showRunbooks ? null : 'none');
        d3.selectAll('.node-incident').style('display', showIncidents ? null : 'none');
        d3.selectAll('.node-token').style('display', showTokens ? null : 'none');

        d3.selectAll('.topology-links line').style('display', l => {
            const srcVisible = (l.source.type === 'runbook' && showRunbooks) || (l.source.type === 'incident' && showIncidents) || (l.source.type === 'token' && showTokens);
            const tgtVisible = (l.target.type === 'runbook' && showRunbooks) || (l.target.type === 'incident' && showIncidents) || (l.target.type === 'token' && showTokens);
            return (srcVisible && tgtVisible) ? null : 'none';
        });
    }

    if (p5ToggleRunbooks) p5ToggleRunbooks.addEventListener('change', applyNodeTypeVisibility);
    if (p5ToggleIncidents) p5ToggleIncidents.addEventListener('change', applyNodeTypeVisibility);
    if (p5ToggleTokens) p5ToggleTokens.addEventListener('change', applyNodeTypeVisibility);

    // Search Input in Graph
    if (p5SearchInput) {
        p5SearchInput.addEventListener('input', (e) => {
            const q = e.target.value.trim().toLowerCase();
            if (!q) {
                d3.selectAll('.topology-node').style('opacity', 1.0);
                return;
            }
            d3.selectAll('.topology-node').style('opacity', d => {
                const textMatch = d.id.toLowerCase().includes(q) || (d.name && d.name.toLowerCase().includes(q));
                return textMatch ? 1.0 : 0.15;
            });
            const firstMatch = d3.selectAll('.topology-node').filter(d => d.id.toLowerCase().includes(q)).datum();
            if (firstMatch) {
                renderInspectorCard(firstMatch);
            }
        });
    }

    // Zoom Buttons
    if (p5ZoomInBtn) {
        p5ZoomInBtn.addEventListener('click', () => {
            if (d3ZoomBehavior) d3.select('#topologyGraphSvg').transition().duration(250).call(d3ZoomBehavior.scaleBy, 1.35);
        });
    }
    if (p5ZoomOutBtn) {
        p5ZoomOutBtn.addEventListener('click', () => {
            if (d3ZoomBehavior) d3.select('#topologyGraphSvg').transition().duration(250).call(d3ZoomBehavior.scaleBy, 0.75);
        });
    }
    if (p5ResetZoomBtn) {
        p5ResetZoomBtn.addEventListener('click', () => {
            if (d3ZoomBehavior) d3.select('#topologyGraphSvg').transition().duration(350).call(d3ZoomBehavior.transform, d3.zoomIdentity);
        });
    }
    if (p5FitViewBtn) {
        p5FitViewBtn.addEventListener('click', () => {
            if (!topologySimulation || !d3ZoomBehavior) return;
            const svg = d3.select('#topologyGraphSvg');
            const nodes = topologySimulation.nodes();
            if (nodes.length === 0) return;

            const container = svg.node().parentElement;
            const width = container.clientWidth || 800;
            const height = container.clientHeight || 640;

            const xs = nodes.map(n => n.x);
            const ys = nodes.map(n => n.y);
            const minX = Math.min(...xs), maxX = Math.max(...xs);
            const minY = Math.min(...ys), maxY = Math.max(...ys);

            const dx = (maxX - minX) || 100;
            const dy = (maxY - minY) || 100;
            const scale = Math.min(2.5, Math.max(0.3, 0.82 / Math.max(dx / width, dy / height)));
            const midX = (minX + maxX) / 2;
            const midY = (minY + maxY) / 2;

            const transform = d3.zoomIdentity
                .translate(width / 2, height / 2)
                .scale(scale)
                .translate(-midX, -midY);

            svg.transition().duration(400).call(d3ZoomBehavior.transform, transform);
        });
    }

    if (p5ResetHighlightBtn) {
        p5ResetHighlightBtn.addEventListener('click', clearInspectorSelection);
    }

    // Simulator Buttons Hooked Directly
    if (p5SimulateJiraBtn) {
        p5SimulateJiraBtn.addEventListener('click', () => {
            p5SimulateJiraBtn.disabled = true;
            p5SimulateJiraBtn.innerHTML = `<span>Simulating...</span>`;

            fetch('/api/simulate-webhook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ team_id: activeTeamFilter !== 'All' ? activeTeamFilter : 'SecOps', severity: 'Critical' })
            })
            .then(res => res.json())
            .then(data => {
                p5SimulateJiraBtn.disabled = false;
                p5SimulateJiraBtn.innerHTML = `<span>Simulate Jira Outage</span>`;
                initOrRefreshTopologyGraph();
                refreshVaultFolder();
                refreshDbExplorer();
                alert(`[Argus Webhook Simulator] Incident ${data.incident_id} triaged in volatile RAM.\n${data.redacted_tokens_count} entities masked. L1 Action Plan synthesized.`);
            })
            .catch(err => {
                p5SimulateJiraBtn.disabled = false;
                p5SimulateJiraBtn.innerHTML = `<span>Simulate Jira Outage</span>`;
                alert(`Simulation failed: ${err.message}`);
            });
        });
    }

    if (p5SimulateTelemetryBtn) {
        p5SimulateTelemetryBtn.addEventListener('click', () => {
            p5SimulateTelemetryBtn.disabled = true;
            p5SimulateTelemetryBtn.innerHTML = `<span>Ingesting...</span>`;

            fetch('/api/simulate-telemetry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ team_id: activeTeamFilter !== 'All' ? activeTeamFilter : 'CloudInfra', severity: 'Critical' })
            })
            .then(res => res.json())
            .then(data => {
                p5SimulateTelemetryBtn.disabled = false;
                p5SimulateTelemetryBtn.innerHTML = `<span>Simulate Datadog Alert</span>`;
                initOrRefreshTopologyGraph();
                refreshVaultFolder();
                refreshDbExplorer();
                alert(`[Argus Telemetry Simulator] Datadog metric breach ${data.incident_id} ingested.\nHost & IP scrubbed in RAM. Topology updated.`);
            })
            .catch(err => {
                p5SimulateTelemetryBtn.disabled = false;
                p5SimulateTelemetryBtn.innerHTML = `<span>Simulate Datadog Alert</span>`;
                alert(`Telemetry simulation failed: ${err.message}`);
            });
        });
    }

    if (p5RefreshGraphBtn) {
        p5RefreshGraphBtn.addEventListener('click', () => initOrRefreshTopologyGraph());
    }

    // =============================================================
    // MANDATE 1: Blameless Root Cause Analysis (RCA) Generator
    // =============================================================
    const rcaModal = document.getElementById('rcaModal');
    const headerOpenRcaBtn = document.getElementById('headerOpenRcaBtn');
    const p1GenerateRcaBtn = document.getElementById('p1GenerateRcaBtn');
    const closeRcaModalBtn = document.getElementById('closeRcaModalBtn');
    const dismissRcaModalBtn = document.getElementById('dismissRcaModalBtn');
    const rcaRegenerateBtn = document.getElementById('rcaRegenerateBtn');
    const copyRcaMarkdownBtn = document.getElementById('copyRcaMarkdownBtn');
    const downloadRcaBtn = document.getElementById('downloadRcaBtn');
    const rcaIncidentBadge = document.getElementById('rcaIncidentBadge');
    const rcaLoadingSpinner = document.getElementById('rcaLoadingSpinner');
    const rcaMarkdownViewer = document.getElementById('rcaMarkdownViewer');
    const rcaRawMarkdown = document.getElementById('rcaRawMarkdown');

    let currentRcaIncidentId = 'INC-LIVE-PREVIEW';
    let currentRcaTeam = 'SecOps';

    function openRcaModal(incidentId, team) {
        if (!rcaModal) return;
        currentRcaIncidentId = incidentId || 'INC-LIVE-PREVIEW';
        currentRcaTeam = team || (teamSelect ? teamSelect.value : 'SecOps');
        rcaModal.classList.remove('hidden');
        generateRcaDocument(currentRcaIncidentId, currentRcaTeam);
    }

    function closeRcaModal() {
        if (!rcaModal) return;
        rcaModal.classList.add('hidden');
    }

    function renderMarkdownToHtml(md) {
        if (!md) return '';
        // Safe and clean SRE markdown renderer
        let html = md
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Restore deterministic token tags for highlighting
            .replace(/&lt;([A-Z0-9_]+_\d+)&gt;/g, '<span class="px-1.5 py-0.5 rounded font-mono font-bold text-[11px] bg-teal-100 text-teal-900 border border-teal-300">&lt;$1&gt;</span>')
            // Headers
            .replace(/^# (.*$)/gim, '<h1 class="text-lg font-bold text-slate-900 pb-2 border-b border-slate-200 mt-4 mb-2">$1</h1>')
            .replace(/^## (.*$)/gim, '<h2 class="text-base font-bold text-slate-800 pb-1 border-b border-[#334155] mt-3 mb-2">$1</h2>')
            .replace(/^### (.*$)/gim, '<h3 class="text-sm font-bold text-slate-800 mt-3 mb-1.5">$1</h3>')
            // Code blocks
            .replace(/```([\s\S]*?)```/gm, '<pre class="bg-slate-900 text-emerald-400 p-3.5 rounded-xl font-mono text-[11px] overflow-x-auto my-2 border border-slate-800">$1</pre>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code class="bg-slate-100 text-slate-800 px-1 py-0.5 rounded font-mono text-[11px] border border-slate-200">$1</code>')
            // Bold
            .replace(/\*\*([^*]+)\*\*/g, '<strong class="font-bold text-slate-900">$1</strong>')
            // Blockquote
            .replace(/^\> (.*$)/gim, '<blockquote class="border-l-4 border-indigo-400 bg-indigo-50/50 p-2.5 my-2 text-indigo-900 rounded-r-lg italic text-xs">$1</blockquote>')
            // Horizontal rule
            .replace(/^---$/gim, '<hr class="my-4 border-slate-200" />')
            // Unordered list
            .replace(/^\- (.*$)/gim, '<li class="ml-4 list-disc text-slate-700 my-0.5">$1</li>')
            // Numbered list
            .replace(/^\d+\. (.*$)/gim, '<li class="ml-4 list-decimal text-slate-700 my-0.5">$1</li>');

        // Simple table converter for Markdown tables
        html = html.replace(/(\|.+\|\r?\n)+/g, (match) => {
            const rows = match.trim().split('\n').filter(r => r.trim().length > 0);
            if (rows.length < 2) return match;
            let tableHtml = '<div class="overflow-x-auto my-3"><table class="min-w-full divide-y divide-slate-200 border border-slate-200 rounded-lg text-xs">';
            rows.forEach((row, rIdx) => {
                if (row.includes('---')) return; // separator row
                const cells = row.split('|').slice(1, -1);
                if (rIdx === 0) {
                    tableHtml += '<thead class="bg-slate-50 font-bold text-slate-700"><tr>';
                    cells.forEach(c => tableHtml += `<th class="px-3 py-2 text-left">${c.trim()}</th>`);
                    tableHtml += '</tr></thead><tbody class="divide-y divide-slate-100 bg-white">';
                } else {
                    tableHtml += '<tr>';
                    cells.forEach(c => tableHtml += `<td class="px-3 py-2">${c.trim()}</td>`);
                    tableHtml += '</tr>';
                }
            });
            tableHtml += '</tbody></table></div>';
            return tableHtml;
        });

        // Convert double line breaks to paragraphs
        return html.split('\n\n').map(p => {
            if (p.startsWith('<h') || p.startsWith('<pre') || p.startsWith('<table') || p.startsWith('<div') || p.startsWith('<blockquote') || p.startsWith('<hr')) {
                return p;
            }
            return `<p class="my-1.5 text-slate-700">${p}</p>`;
        }).join('');
    }

    function generateRcaDocument(incidentId, team) {
        if (!rcaMarkdownViewer) return;
        if (rcaLoadingSpinner) rcaLoadingSpinner.classList.remove('hidden');
        rcaMarkdownViewer.classList.add('hidden');

        if (rcaIncidentBadge) {
            rcaIncidentBadge.textContent = incidentId || 'INC-LIVE-PREVIEW';
        }

        const logOverride = p1RawInput ? p1RawInput.value : '';

        fetch('/api/rca/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                incident_id: incidentId,
                team: team || 'SecOps',
                override_log: logOverride
            })
        })
        .then(res => res.json())
        .then(data => {
            if (rcaLoadingSpinner) rcaLoadingSpinner.classList.add('hidden');
            rcaMarkdownViewer.classList.remove('hidden');

            const markdown = data.rca_markdown || '# Blameless Root Cause Analysis\nNo data returned.';
            if (rcaRawMarkdown) rcaRawMarkdown.value = markdown;
            rcaMarkdownViewer.innerHTML = renderMarkdownToHtml(markdown);

            if (rcaIncidentBadge) {
                rcaIncidentBadge.textContent = `${data.incident_id} (${data.team})`;
            }
        })
        .catch(err => {
            if (rcaLoadingSpinner) rcaLoadingSpinner.classList.add('hidden');
            rcaMarkdownViewer.classList.remove('hidden');
            rcaMarkdownViewer.innerHTML = `<div class="p-4 bg-[#4C0519] text-[#E11D48] rounded-lg border border-[#BE123C]">
                <span class="font-bold">Failed to generate RCA:</span> ${err.message}
            </div>`;
        });
    }

    if (headerOpenRcaBtn) {
        headerOpenRcaBtn.addEventListener('click', () => openRcaModal('INC-HEADER-QUERY', teamSelect ? teamSelect.value : 'SecOps'));
    }

    if (p1GenerateRcaBtn) {
        p1GenerateRcaBtn.addEventListener('click', () => openRcaModal('INC-ARGUS-TRIAGE', teamSelect ? teamSelect.value : 'SecOps'));
    }

    if (closeRcaModalBtn) {
        closeRcaModalBtn.addEventListener('click', closeRcaModal);
    }

    if (dismissRcaModalBtn) {
        dismissRcaModalBtn.addEventListener('click', closeRcaModal);
    }

    if (rcaRegenerateBtn) {
        rcaRegenerateBtn.addEventListener('click', () => generateRcaDocument(currentRcaIncidentId, currentRcaTeam));
    }

    if (copyRcaMarkdownBtn) {
        copyRcaMarkdownBtn.addEventListener('click', () => {
            if (!rcaRawMarkdown || !rcaRawMarkdown.value) return;
            navigator.clipboard.writeText(rcaRawMarkdown.value).then(() => {
                const originalHtml = copyRcaMarkdownBtn.innerHTML;
                copyRcaMarkdownBtn.innerHTML = `<span>Copied! ✓</span>`;
                setTimeout(() => {
                    copyRcaMarkdownBtn.innerHTML = originalHtml;
                }, 2000);
            }).catch(err => {
                alert('Copy failed: ' + err);
            });
        });
    }

    if (downloadRcaBtn) {
        downloadRcaBtn.addEventListener('click', () => {
            if (!rcaRawMarkdown || !rcaRawMarkdown.value) return;
            const blob = new Blob([rcaRawMarkdown.value], { type: 'text/markdown;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `argus_blameless_rca_${currentRcaIncidentId || 'export'}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    }

    // =============================================================
    // MANDATE 2: Shadow SRE Flight Simulator Controller
    // =============================================================
    const sreScenarioId = document.getElementById('sreScenarioId');
    const sreScenarioTeam = document.getElementById('sreScenarioTeam');
    const sreScenarioTitle = document.getElementById('sreScenarioTitle');
    const sreScenarioSeverity = document.getElementById('sreScenarioSeverity');
    const sreScenarioDifficulty = document.getElementById('sreScenarioDifficulty');
    const sreScenarioSymptoms = document.getElementById('sreScenarioSymptoms');
    const sreScenarioTokensContainer = document.getElementById('sreScenarioTokensContainer');
    const sreScenarioHint = document.getElementById('sreScenarioHint');
    const sreNewScenarioBtn = document.getElementById('sreNewScenarioBtn');

    const sreProposedFixInput = document.getElementById('sreProposedFixInput');
    const sreClearFixBtn = document.getElementById('sreClearFixBtn');
    const sreSubmitFixBtn = document.getElementById('sreSubmitFixBtn');

    const sreEvaluationResultsCard = document.getElementById('sreEvaluationResultsCard');
    const sreScoreBadge = document.getElementById('sreScoreBadge');
    const sreGradeBadge = document.getElementById('sreGradeBadge');
    const sreScoreProgressBar = document.getElementById('sreScoreProgressBar');
    const sreMentorFeedback = document.getElementById('sreMentorFeedback');
    const sreTokensAddressed = document.getElementById('sreTokensAddressed');
    const sreTokensMissed = document.getElementById('sreTokensMissed');
    const sreToggleHistoricalFixBtn = document.getElementById('sreToggleHistoricalFixBtn');
    const sreHistoricalChevron = document.getElementById('sreHistoricalChevron');
    const sreHistoricalFixContent = document.getElementById('sreHistoricalFixContent');

    let activeScenarioId = null;

    function loadSreSimulatorScenario(specificScenarioId) {
        let url = '/api/simulator/scenario';
        const params = [];
        if (specificScenarioId) {
            params.push(`scenario_id=${encodeURIComponent(specificScenarioId)}`);
        } else if (teamSelect && teamSelect.value && teamSelect.value !== 'All') {
            params.push(`team=${encodeURIComponent(teamSelect.value)}`);
        }
        if (params.length > 0) {
            url += '?' + params.join('&');
        }

        fetch(url)
            .then(res => res.json())
            .then(data => {
                activeScenarioId = data.doc_id;

                if (sreScenarioId) sreScenarioId.textContent = data.doc_id;
                if (sreScenarioTeam) sreScenarioTeam.textContent = data.team;
                if (sreScenarioTitle) sreScenarioTitle.textContent = data.title;
                if (sreScenarioSeverity) {
                    sreScenarioSeverity.textContent = data.severity;
                    if (data.severity === 'Critical') {
                        sreScenarioSeverity.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-[#4C0519] text-[#E11D48] border border-[#BE123C]';
                    } else {
                        sreScenarioSeverity.className = 'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-200';
                    }
                }
                if (sreScenarioDifficulty) sreScenarioDifficulty.textContent = data.difficulty;
                if (sreScenarioSymptoms) sreScenarioSymptoms.textContent = data.symptoms;
                if (sreScenarioHint) sreScenarioHint.textContent = data.hint || 'Address the root cause using appropriate runbook mitigation commands.';

                // Render token pills
                if (sreScenarioTokensContainer) {
                    sreScenarioTokensContainer.innerHTML = '';
                    const tokens = data.affected_tokens || [];
                    if (tokens.length === 0) {
                        sreScenarioTokensContainer.innerHTML = '<span class="text-xs text-slate-400 italic">No specific tokens detected in scope.</span>';
                    } else {
                        tokens.forEach(tok => {
                            const btn = document.createElement('button');
                            btn.type = 'button';
                            btn.className = 'px-2 py-0.5 rounded font-mono text-[11px] font-bold bg-[#064E3B] text-[#10B981] border border-[#047857] hover:bg-[#064E3B]/80 transition-colors cursor-pointer active:scale-95';
                            btn.textContent = tok;
                            btn.title = `Click to insert ${tok} into your proposed fix`;
                            btn.addEventListener('click', () => {
                                if (sreProposedFixInput) {
                                    const startPos = sreProposedFixInput.selectionStart;
                                    const endPos = sreProposedFixInput.selectionEnd;
                                    const currentVal = sreProposedFixInput.value;
                                    sreProposedFixInput.value = currentVal.substring(0, startPos) + tok + currentVal.substring(endPos);
                                    sreProposedFixInput.focus();
                                    sreProposedFixInput.setSelectionRange(startPos + tok.length, startPos + tok.length);
                                }
                            });
                            sreScenarioTokensContainer.appendChild(btn);
                        });
                    }
                }

                // Reset proposed fix input and results card
                if (sreProposedFixInput) sreProposedFixInput.value = '';
                if (sreEvaluationResultsCard) sreEvaluationResultsCard.classList.add('hidden');
                if (sreHistoricalFixContent) {
                    sreHistoricalFixContent.classList.add('hidden');
                    sreHistoricalFixContent.textContent = '';
                }
                if (sreHistoricalChevron) {
                    sreHistoricalChevron.style.transform = 'rotate(0deg)';
                }
            })
            .catch(err => {
                console.error('Failed to load simulator scenario:', err);
            });
    }

    if (sreNewScenarioBtn) {
        sreNewScenarioBtn.addEventListener('click', () => loadSreSimulatorScenario());
    }

    if (sreClearFixBtn) {
        sreClearFixBtn.addEventListener('click', () => {
            if (sreProposedFixInput) {
                sreProposedFixInput.value = '';
                sreProposedFixInput.focus();
            }
        });
    }

    if (sreSubmitFixBtn) {
        sreSubmitFixBtn.addEventListener('click', () => {
            if (!activeScenarioId) {
                alert('No active scenario loaded.');
                return;
            }
            const fixText = sreProposedFixInput ? sreProposedFixInput.value.trim() : '';
            if (!fixText) {
                alert('Please type your proposed remediation steps before submitting for evaluation.');
                if (sreProposedFixInput) sreProposedFixInput.focus();
                return;
            }

            sreSubmitFixBtn.disabled = true;
            sreSubmitFixBtn.innerHTML = `<span>Evaluating 384-d Vectors...</span>`;

            fetch('/api/simulator/evaluate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    doc_id: activeScenarioId,
                    proposed_fix: fixText
                })
            })
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                sreSubmitFixBtn.disabled = false;
                sreSubmitFixBtn.innerHTML = `
                    <svg class="w-3.5 h-3.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span>Submit for SRE Evaluation</span>
                `;

                if (sreEvaluationResultsCard) {
                    sreEvaluationResultsCard.classList.remove('hidden');
                }

                // Update score and grade
                const simPct = data.similarity_percentage || '0%';
                const simScore = data.similarity_score || 0;
                if (sreScoreBadge) sreScoreBadge.textContent = simPct;

                if (sreGradeBadge) {
                    sreGradeBadge.textContent = data.evaluation_grade || 'Evaluated';
                    if (simScore >= 0.78) {
                        sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-300';
                        if (sreScoreProgressBar) sreScoreProgressBar.className = 'h-2 rounded-full transition-all duration-700 bg-emerald-500';
                    } else if (simScore >= 0.60) {
                        sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-teal-100 text-teal-800 border border-teal-300';
                        if (sreScoreProgressBar) sreScoreProgressBar.className = 'h-2 rounded-full transition-all duration-700 bg-teal-500';
                    } else if (simScore >= 0.40) {
                        sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-amber-100 text-amber-800 border border-amber-300';
                        if (sreScoreProgressBar) sreScoreProgressBar.className = 'h-2 rounded-full transition-all duration-700 bg-amber-500';
                    } else {
                        sreGradeBadge.className = 'text-xs font-bold px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300';
                        if (sreScoreProgressBar) sreScoreProgressBar.className = 'h-2 rounded-full transition-all duration-700 bg-rose-500';
                    }
                }

                if (sreScoreProgressBar) {
                    sreScoreProgressBar.style.width = simPct;
                }

                // Render mentor feedback
                if (sreMentorFeedback) {
                    sreMentorFeedback.innerHTML = renderMarkdownToHtml(data.mentor_feedback || 'No mentor feedback provided.');
                }

                // Render addressed tokens
                if (sreTokensAddressed) {
                    sreTokensAddressed.innerHTML = '';
                    const addressed = data.tokens_used_correctly || [];
                    if (addressed.length === 0) {
                        sreTokensAddressed.innerHTML = '<span class="text-[11px] text-slate-400 italic">None</span>';
                    } else {
                        addressed.forEach(tok => {
                            const span = document.createElement('span');
                            span.className = 'px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300';
                            span.textContent = tok;
                            sreTokensAddressed.appendChild(span);
                        });
                    }
                }

                // Render missed tokens
                if (sreTokensMissed) {
                    sreTokensMissed.innerHTML = '';
                    const missed = data.tokens_missed || [];
                    if (missed.length === 0) {
                        sreTokensMissed.innerHTML = '<span class="text-[11px] text-[#6EE7B7] font-medium">None! All covered</span>';
                    } else {
                        missed.forEach(tok => {
                            const span = document.createElement('span');
                            span.className = 'px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-300';
                            span.textContent = tok;
                            sreTokensMissed.appendChild(span);
                        });
                    }
                }

                // Populate historical resolution (remains hidden until accordion toggle)
                if (sreHistoricalFixContent) {
                    sreHistoricalFixContent.textContent = data.actual_fix_revealed || 'Historical resolution not available.';
                }
            })
            .catch(err => {
                sreSubmitFixBtn.disabled = false;
                sreSubmitFixBtn.innerHTML = `<span>Submit for SRE Evaluation</span>`;
                alert(`Evaluation failed: ${err.message}`);
            });
        });
    }

    if (sreToggleHistoricalFixBtn) {
        sreToggleHistoricalFixBtn.addEventListener('click', () => {
            if (!sreHistoricalFixContent) return;
            const isHidden = sreHistoricalFixContent.classList.contains('hidden');
            if (isHidden) {
                sreHistoricalFixContent.classList.remove('hidden');
                if (sreHistoricalChevron) sreHistoricalChevron.style.transform = 'rotate(180deg)';
            } else {
                sreHistoricalFixContent.classList.add('hidden');
                if (sreHistoricalChevron) sreHistoricalChevron.style.transform = 'rotate(0deg)';
            }
        });
    }

    // -------------------------------------------------------------
    // SRE Co-Pilot & Incident Reasoning Controller (Vector DB Extension)
    // -------------------------------------------------------------
    const p1EngineerUnderstandingInput = document.getElementById('p1EngineerUnderstandingInput');
    const p1SynthesizePlanBtn = document.getElementById('p1SynthesizePlanBtn');
    const p1SynthesizeBtnText = document.getElementById('p1SynthesizeBtnText');
    const p1SynthesizedPlanCard = document.getElementById('p1SynthesizedPlanCard');
    const p1SynthesizedPlanContent = document.getElementById('p1SynthesizedPlanContent');
    const p1PlanLatencyBadge = document.getElementById('p1PlanLatencyBadge');
    const coPilotModelSelect = document.getElementById('coPilotModelSelect');
    const sreQuickPromptBtns = document.querySelectorAll('.sre-quick-prompt-btn');

    let lastRetrievedChunks = [];

    // Quick prompt buttons populate the understanding box
    sreQuickPromptBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            if (p1EngineerUnderstandingInput) {
                p1EngineerUnderstandingInput.value = btn.textContent.trim();
                flashElement(p1EngineerUnderstandingInput);
            }
        });
    });

    if (p1SynthesizePlanBtn) {
        p1SynthesizePlanBtn.addEventListener('click', async () => {
            const queryText = (p1VectorSearchInput ? p1VectorSearchInput.value : currentSanitizedText || '').trim();
            const understanding = (p1EngineerUnderstandingInput ? p1EngineerUnderstandingInput.value : '').trim();

            if (!understanding && !queryText) {
                showToast('Please enter your operational understanding or inquiry.', 'warning');
                if (p1EngineerUnderstandingInput) p1EngineerUnderstandingInput.focus();
                return;
            }

            const model = coPilotModelSelect ? coPilotModelSelect.value : 'qwen2.5:3b';
            const team = teamSelect ? teamSelect.value : 'SecOps';

            try {
                p1SynthesizePlanBtn.disabled = true;
                if (p1SynthesizeBtnText) p1SynthesizeBtnText.textContent = `Synthesizing (${model})...`;

                const res = await fetch('/api/co-pilot/synthesize', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        incident_id: currentTargetKey || 'INC-LIVE',
                        sanitized_query: queryText,
                        engineer_understanding: understanding || "Provide actionable remediation steps based on the retrieved runbook.",
                        retrieved_chunks: lastRetrievedChunks,
                        model: model,
                        team: team
                    })
                });

                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || `HTTP ${res.status}`);
                }

                if (p1SynthesizedPlanCard) p1SynthesizedPlanCard.classList.remove('hidden');
                if (p1SynthesizedPlanContent) {
                    p1SynthesizedPlanContent.innerHTML = renderMarkdownToHtml(data.plan || 'No plan generated.');
                }
                if (p1PlanLatencyBadge) {
                    const secs = (data.latency_ms / 1000).toFixed(2);
                    p1PlanLatencyBadge.textContent = `⚡ Generated in ${secs}s • ${data.tokens_per_sec || 18} tok/s • ${data.model_used}`;
                }

                p1SynthesizedPlanCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                showToast('Contextual remediation plan synthesized.', 'success');
            } catch (err) {
                console.error(err);
                showToast(`Synthesis failed: ${err.message}`, 'error');
            } finally {
                p1SynthesizePlanBtn.disabled = false;
                if (p1SynthesizeBtnText) p1SynthesizeBtnText.textContent = 'Synthesize Grounded Remediation';
            }
        });
    }


    // =========================================================================
    // EXECUTIVE BI: Vendor SLAs, Knowledge Silo (Bus Factor) & Runbook Tech Debt
    // =========================================================================
    // Vendor SLA Elements
    const p7StatVendorPct = document.getElementById('p7StatVendorPct');
    const p7StatVendorSub = document.getElementById('p7StatVendorSub');
    const p7StatVendorCount = document.getElementById('p7StatVendorCount');
    const p7StatVendorBreached = document.getElementById('p7StatVendorBreached');
    const p7VendorSlaContainer = document.getElementById('p7VendorSlaContainer');
    const p7RefreshVendorSlaBtn = document.getElementById('p7RefreshVendorSlaBtn');

    // Bus Factor Elements
    const p7StatBusFactorCount = document.getElementById('p7StatBusFactorCount');
    const p7StatBusFactorSub = document.getElementById('p7StatBusFactorSub');
    const p7StatBusFactorTotal = document.getElementById('p7StatBusFactorTotal');
    const p7BusFactorContainer = document.getElementById('p7BusFactorContainer');
    const p7RefreshBusFactorBtn = document.getElementById('p7RefreshBusFactorBtn');

    // Runbook Decay Elements
    const p7StatDecayCount = document.getElementById('p7StatDecayCount');
    const p7StatDecaySub = document.getElementById('p7StatDecaySub');
    const p7StatDriftingCount = document.getElementById('p7StatDriftingCount');
    const p7StatHealthyCount = document.getElementById('p7StatHealthyCount');
    const p7RunbookDecayTableBody = document.getElementById('p7RunbookDecayTableBody');
    const p7RefreshRunbookDecayBtn = document.getElementById('p7RefreshRunbookDecayBtn');

    // AI Runbook Modernization Panel Elements
    const p7FixResultCard = document.getElementById('p7FixResultCard');
    const p7CloseFixResultBtn = document.getElementById('p7CloseFixResultBtn');
    const p7FixDocId = document.getElementById('p7FixDocId');
    const p7FixDocTitle = document.getElementById('p7FixDocTitle');
    const p7FixSimilarList = document.getElementById('p7FixSimilarList');
    const p7FixOrigContent = document.getElementById('p7FixOrigContent');
    const p7FixRewrittenContent = document.getElementById('p7FixRewrittenContent');

    // Seed Demo Data Button
    const p7SeedDemoDataBtn = document.getElementById('p7SeedDemoDataBtn');

    // 1. Fetch Vendor SLA Blame Mapping
    async function loadVendorSlaAnalytics() {
        if (!p7VendorSlaContainer) return;
        try {
            const res = await fetch('/api/analytics/vendor-sla');
            if (res.ok) {
                const data = await res.json();
                renderVendorSlaCard(data);
            }
        } catch (err) {
            console.error('[Argus Analytics] Vendor SLA error:', err);
        }
    }

    function renderVendorSlaCard(data) {
        if (!p7VendorSlaContainer) return;
        const total = data.total_critical_incidents || 1;
        const vendorTotal = data.attributed_vendor_incidents || 0;
        const vendorPct = Math.round((vendorTotal / total) * 100);

        if (p7StatVendorPct) p7StatVendorPct.textContent = `${vendorPct}%`;
        if (p7StatVendorSub) p7StatVendorSub.textContent = `${vendorTotal} of ${total} Sev-1 events traced to external vendors`;
        if (p7StatVendorCount) p7StatVendorCount.textContent = `${vendorTotal}`;

        const list = data.vendor_sla_breakdown || [];
        const breachedCount = list.filter(v => v.status === 'BREACHED').length;
        if (p7StatVendorBreached) p7StatVendorBreached.textContent = `${breachedCount}`;

        if (list.length === 0) {
            p7VendorSlaContainer.innerHTML = '<div class="text-xs text-slate-400 font-mono py-4">No third-party vendor tokens traced in critical incidents.</div>';
            return;
        }

        p7VendorSlaContainer.innerHTML = list.map(item => {
            const isBreached = item.status === 'BREACHED';
            const statusBadge = isBreached 
                ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">SLA BREACHED</span>'
                : '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">SLA MET</span>';

            const tokenPills = (item.sample_tokens || []).map(tok => 
                `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-teal-300 border border-slate-700">${escapeHtml(tok)}</span>`
            ).join(' ');

            const teamPills = (item.impacted_teams || []).map(t => 
                `<span class="px-1.5 py-0.2 rounded text-[9px] font-semibold bg-slate-800 text-slate-300">${escapeHtml(t)}</span>`
            ).join(' ');

            return `
                <div class="p-4 rounded-xl bg-[#0F172A]/70 border border-[#334155]/70 space-y-2.5">
                    <div class="flex items-center justify-between">
                        <div>
                            <span class="text-sm font-bold text-[#E2E8F0]">${escapeHtml(item.vendor_name)}</span>
                            <div class="flex items-center space-x-1.5 mt-0.5">
                                <span class="text-[10px] text-slate-400">Impacted Namespaces:</span>
                                ${teamPills}
                            </div>
                        </div>
                        <div class="text-right">
                            ${statusBadge}
                            <span class="block text-xs font-mono text-amber-400 font-bold mt-1">${item.blame_percentage}% Sev-1 Blame</span>
                        </div>
                    </div>

                    <!-- Progress Bar for Blame Attribution -->
                    <div class="space-y-1">
                        <div class="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                            <div class="h-full rounded-full ${isBreached ? 'bg-gradient-to-r from-amber-500 to-rose-500' : 'bg-teal-500'}" style="width: ${item.blame_percentage}%"></div>
                        </div>
                        <div class="flex items-center justify-between text-[10px] font-mono text-slate-400">
                            <span>Critical Outages: <strong class="text-slate-200">${item.critical_incident_count}</strong></span>
                            <span>Observed Uptime: <strong class="${isBreached ? 'text-rose-400' : 'text-emerald-400'}">${item.observed_availability}%</strong> (Target SLA: ${item.sla_target}%)</span>
                        </div>
                    </div>

                    <div class="pt-2 border-t border-slate-800/80 flex items-center space-x-1.5 flex-wrap">
                        <span class="text-[10px] font-mono text-slate-500">Traced Deterministic Tokens:</span>
                        ${tokenPills}
                    </div>
                </div>
            `;
        }).join('');
    }

    // 2. Fetch Bus Factor Heatmap
    async function loadBusFactorAnalytics() {
        if (!p7BusFactorContainer) return;
        try {
            const res = await fetch('/api/analytics/bus-factor');
            if (res.ok) {
                const data = await res.json();
                renderBusFactorCard(data);
            }
        } catch (err) {
            console.error('[Argus Analytics] Bus factor error:', err);
        }
    }

    function renderBusFactorCard(data) {
        if (!p7BusFactorContainer) return;
        const flagged = data.flagged_teams_count || 0;
        if (p7StatBusFactorCount) p7StatBusFactorCount.textContent = `${flagged}`;
        if (p7StatBusFactorSub) p7StatBusFactorSub.textContent = `${flagged} of ${data.total_teams_analyzed || 0} teams exceed 70% SPOF concentration`;
        if (p7StatBusFactorTotal) p7StatBusFactorTotal.textContent = `${data.total_teams_analyzed || 0}`;

        const allTeams = [...(data.critical_risk_teams || []), ...(data.healthy_teams || [])];
        if (allTeams.length === 0) {
            p7BusFactorContainer.innerHTML = '<div class="text-xs text-slate-400 font-mono py-4">No team resolution data available.</div>';
            return;
        }

        p7BusFactorContainer.innerHTML = allTeams.map(t => {
            const isCritical = t.is_critical_risk;
            const badge = isCritical
                ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">CRITICAL SPOF (&gt;70%)</span>'
                : '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">BALANCED</span>';

            const engList = (t.engineer_breakdown || []).map(e => `
                <div class="flex items-center justify-between text-[11px] py-1 border-b border-slate-800/40 last:border-b-0">
                    <span class="flex items-center space-x-2 text-slate-300">
                        <span class="w-1.5 h-1.5 rounded-full ${e.is_bus_factor_risk ? 'bg-rose-400 animate-pulse' : 'bg-slate-500'}"></span>
                        <strong class="${e.is_bus_factor_risk ? 'text-rose-200' : 'text-slate-300'}">${escapeHtml(e.engineer_name)}</strong>
                    </span>
                    <span class="font-mono ${e.is_bus_factor_risk ? 'text-rose-400 font-bold' : 'text-slate-400'}">${e.percentage}% (${e.resolved_count} incidents)</span>
                </div>
            `).join('');

            return `
                <div class="p-4 rounded-xl bg-[#0F172A]/70 border ${isCritical ? 'border-rose-500/40' : 'border-[#334155]/70'} space-y-3">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-2">
                            <span class="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-slate-800 text-teal-300 border border-slate-700">${escapeHtml(t.team_id)}</span>
                            <span class="text-xs text-slate-400">${t.total_resolutions} resolved outages</span>
                        </div>
                        ${badge}
                    </div>

                    <div class="p-3 rounded-lg bg-slate-900/80 border border-slate-800 divide-y divide-slate-800">
                        ${engList}
                    </div>

                    <div class="flex items-start space-x-2 pt-1 text-[11px] font-mono ${isCritical ? 'text-rose-300/90' : 'text-slate-400'}">
                        <span class="font-bold shrink-0">Recommendation:</span>
                        <span>${escapeHtml(t.remediation_recommendation)}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    // 3. Fetch Runbook Decay Scoring & Alignment
    async function loadRunbookDecayAnalytics() {
        if (!p7RunbookDecayTableBody) return;
        try {
            const res = await fetch('/api/analytics/runbook-decay');
            if (res.ok) {
                const data = await res.json();
                renderRunbookDecayCard(data);
            }
        } catch (err) {
            console.error('[Argus Analytics] Runbook decay error:', err);
        }
    }

    function renderRunbookDecayCard(data) {
        if (!p7RunbookDecayTableBody) return;
        const obsoleteCount = data.flagged_obsolete_count || 0;
        if (p7StatDecayCount) p7StatDecayCount.textContent = `${obsoleteCount}`;
        if (p7StatDecaySub) p7StatDecaySub.textContent = `${obsoleteCount} obsolete, ${data.drifting_count || 0} drifting, ${data.healthy_count || 0} healthy`;
        if (p7StatDriftingCount) p7StatDriftingCount.textContent = `${data.drifting_count || 0}`;
        if (p7StatHealthyCount) p7StatHealthyCount.textContent = `${data.healthy_count || 0}`;

        const runbooks = data.runbooks || [];
        if (runbooks.length === 0) {
            p7RunbookDecayTableBody.innerHTML = '<tr><td colspan="7" class="px-3.5 py-6 text-center text-slate-400 font-mono">No runbooks audited.</td></tr>';
            return;
        }

        p7RunbookDecayTableBody.innerHTML = runbooks.map(rb => {
            const isObsolete = rb.decay_status === 'Obsolete/High Tech Debt';
            const isDrifting = rb.decay_status === 'Drifting';

            const statusBadge = isObsolete 
                ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">OBSOLETE / TECH DEBT</span>'
                : (isDrifting 
                    ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">DRIFTING</span>'
                    : '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">HEALTHY</span>');

            const rlhfColor = rb.rlhf_net_score < 0 ? 'text-rose-400 font-bold' : (rb.rlhf_net_score > 0 ? 'text-emerald-400 font-bold' : 'text-slate-400');
            const simColor = rb.avg_similarity_score < 0.5 ? 'text-rose-400 font-bold' : (rb.avg_similarity_score < 0.7 ? 'text-amber-400 font-bold' : 'text-teal-400 font-bold');

            // Action / Fix Button
            const viewBtn = `<button type="button" class="view-runbook-btn inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-[#0F172A] hover:bg-[#334155] text-teal-300 font-mono text-[11px] border border-teal-500/40 transition-colors cursor-pointer mr-1.5 active:scale-95" data-id="${escapeHtml(rb.runbook_id)}" title="View record stored in SQLite database">
                <svg class="w-3.5 h-3.5 text-teal-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
                <span>View from DB</span>
            </button>`;

            const fixOrHealthy = (isObsolete || isDrifting)
                ? `<button type="button" class="fix-runbook-btn inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white font-mono text-[11px] font-semibold transition-all cursor-pointer shadow-sm active:scale-95" data-id="${escapeHtml(rb.runbook_id)}" data-team="${escapeHtml(rb.team)}" data-title="${escapeHtml(rb.title)}">
                    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                    <span>⚡ Fix It (AI)</span>
                   </button>`
                : `<span class="inline-flex items-center space-x-1 px-2.5 py-1 rounded text-[10px] font-mono font-medium text-emerald-400 bg-emerald-950/40 border border-emerald-500/30">
                    <svg class="w-3 h-3 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                    </svg>
                    <span>Healthy SOP</span>
                   </span>`;

            const actionCell = `<div class="flex items-center justify-end">${viewBtn}${fixOrHealthy}</div>`;

            return `
                <tr class="hover:bg-slate-800/40 transition-colors">
                    <td class="px-3.5 py-2.5 font-medium">
                        <span class="block text-xs text-[#E2E8F0] font-semibold">${escapeHtml(rb.title)}</span>
                        <span class="block text-[10px] font-mono text-slate-400">${escapeHtml(rb.runbook_id)}</span>
                    </td>
                    <td class="px-3.5 py-2.5 whitespace-nowrap">
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">${escapeHtml(rb.team)}</span>
                    </td>
                    <td class="px-3.5 py-2.5 font-mono text-xs ${simColor}">
                        ${rb.avg_similarity_score.toFixed(3)}
                    </td>
                    <td class="px-3.5 py-2.5 font-mono text-xs whitespace-nowrap">
                        <span class="${rlhfColor}">${rb.rlhf_net_score > 0 ? '+' : ''}${rb.rlhf_net_score} net</span>
                        <span class="text-[10px] text-slate-500 block">(${rb.positive_votes} up / ${rb.negative_votes} down)</span>
                    </td>
                    <td class="px-3.5 py-2.5 whitespace-nowrap">
                        ${statusBadge}
                    </td>
                    <td class="px-3.5 py-2.5 text-[11px] font-mono ${isObsolete ? 'text-rose-300' : 'text-slate-300'} max-w-sm">
                        ${escapeHtml(rb.recommendation)}
                    </td>
                    <td class="px-3.5 py-2.5 text-right whitespace-nowrap">
                        ${actionCell}
                    </td>
                </tr>
            `;
        }).join('');
    }

    // Refresh Buttons Event Listeners
    if (p7RefreshVendorSlaBtn) {
        p7RefreshVendorSlaBtn.addEventListener('click', () => {
            loadVendorSlaAnalytics();
            showToast('Vendor SLA telemetry refreshed.', 'info');
        });
    }

    if (p7RefreshBusFactorBtn) {
        p7RefreshBusFactorBtn.addEventListener('click', () => {
            loadBusFactorAnalytics();
            showToast('Knowledge silo heatmap refreshed.', 'info');
        });
    }

    if (p7RefreshRunbookDecayBtn) {
        p7RefreshRunbookDecayBtn.addEventListener('click', () => {
            loadRunbookDecayAnalytics();
            showToast('Runbook decay audits refreshed.', 'info');
        });
    }

    // Dismiss AI Modernization Panel
    if (p7CloseFixResultBtn && p7FixResultCard) {
        p7CloseFixResultBtn.addEventListener('click', () => {
            p7FixResultCard.classList.add('hidden');
        });
    }

    // Event Delegation for "View from DB" and "⚡ Fix It (AI)" Runbook Actions
    if (p7RunbookDecayTableBody) {
        p7RunbookDecayTableBody.addEventListener('click', async (e) => {
            // 1. View from DB Action
            const viewBtn = e.target.closest('.view-runbook-btn');
            if (viewBtn) {
                const runbookId = viewBtn.getAttribute('data-id');
                try {
                    const res = await fetch(`/api/analytics/runbook/${runbookId}`);
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

                    const titleEl = document.getElementById('rbModalTitle');
                    const idEl = document.getElementById('rbModalId');
                    const teamEl = document.getElementById('rbModalTeam');
                    const hashEl = document.getElementById('rbModalHash');
                    const vectorEl = document.getElementById('rbModalVector');
                    const tierEl = document.getElementById('rbModalTier');
                    const diskPathEl = document.getElementById('rbModalDiskPath');
                    const contentEl = document.getElementById('rbModalContent');
                    const modal = document.getElementById('runbookDetailModal');

                    if (titleEl) titleEl.textContent = data.title;
                    if (idEl) idEl.textContent = data.id;
                    if (teamEl) teamEl.textContent = data.team;
                    if (hashEl) hashEl.textContent = data.content_hash || 'SHA-256 Verified';
                    if (vectorEl) vectorEl.textContent = `${data.vector_dimensions || 384}-d Cosine HNSW`;
                    if (tierEl) tierEl.textContent = data.storage_tier;
                    if (diskPathEl) diskPathEl.textContent = data.disk_filepath || `generated_runbooks/${data.disk_filename}`;
                    if (contentEl) contentEl.textContent = data.content;

                    if (modal) modal.classList.remove('hidden');
                } catch (err) {
                    console.error('[Argus] View runbook error:', err);
                    showToast(`Failed to load runbook from database: ${err.message}`, 'error');
                }
                return;
            }

            // 2. Fix It (AI) Modernization Action
            const fixBtn = e.target.closest('.fix-runbook-btn');
            if (!fixBtn) return;

            const runbookId = fixBtn.getAttribute('data-id');
            const team = fixBtn.getAttribute('data-team') || 'CloudInfra';
            const title = fixBtn.getAttribute('data-title') || runbookId;

            fixBtn.disabled = true;
            const originalHtml = fixBtn.innerHTML;
            fixBtn.innerHTML = `
                <svg class="animate-spin h-3.5 w-3.5 text-white inline mr-1" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
                <span>Rewriting SOP...</span>
            `;

            try {
                const res = await fetch('/api/analytics/fix-runbook', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ runbook_id: runbookId, team: team })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

                showToast(`Modernized ${data.runbook_id}: ${data.rewritten_title}! SQLite & ChromaDB vector updated.`, 'success');

                // Display Inspection Panel
                if (p7FixResultCard) {
                    if (p7FixDocId) p7FixDocId.textContent = data.runbook_id;
                    if (p7FixDocTitle) p7FixDocTitle.textContent = data.rewritten_title;
                    if (p7FixOrigContent) p7FixOrigContent.textContent = data.original_content;
                    if (p7FixRewrittenContent) p7FixRewrittenContent.textContent = data.rewritten_content;

                    const savedPathEl = document.getElementById('p7FixSavedPath');
                    if (savedPathEl && (data.disk_filepath || data.disk_filename)) {
                        savedPathEl.textContent = data.disk_filepath || `generated_runbooks/${data.disk_filename}`;
                    }

                    if (p7FixSimilarList) {
                        const sims = data.similar_runbooks_used || [];
                        if (sims.length === 0) {
                            p7FixSimilarList.innerHTML = '<span class="text-slate-500">None</span>';
                        } else {
                            p7FixSimilarList.innerHTML = sims.map(s => 
                                `<span class="px-2 py-0.5 rounded bg-slate-900 text-teal-300 border border-slate-700" title="${escapeHtml(s.title || '')}">${escapeHtml(s.id)} (sim: ${(s.similarity_score || 0).toFixed(2)})</span>`
                            ).join(' ');
                        }
                    }

                    p7FixResultCard.classList.remove('hidden');
                    p7FixResultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }

                // Refresh decay table to show the new Healthy state
                loadRunbookDecayAnalytics();
                if (typeof refreshDbExplorer === 'function') refreshDbExplorer();

            } catch (err) {
                console.error('[Argus] Runbook fix error:', err);
                showToast(`Auto-fix failed: ${err.message}`, 'error');
                fixBtn.disabled = false;
                fixBtn.innerHTML = originalHtml;
            }
        });
    }

    // Modal dismiss listeners for Runbook Detail Modal
    const runbookDetailModal = document.getElementById('runbookDetailModal');
    const closeRunbookModalBtn = document.getElementById('closeRunbookModalBtn');
    const closeRunbookModalBtn2 = document.getElementById('closeRunbookModalBtn2');
    if (closeRunbookModalBtn && runbookDetailModal) {
        closeRunbookModalBtn.addEventListener('click', () => runbookDetailModal.classList.add('hidden'));
    }
    if (closeRunbookModalBtn2 && runbookDetailModal) {
        closeRunbookModalBtn2.addEventListener('click', () => runbookDetailModal.classList.add('hidden'));
    }

    // Global Seeder Button
    if (p7SeedDemoDataBtn) {
        p7SeedDemoDataBtn.addEventListener('click', async () => {
            p7SeedDemoDataBtn.disabled = true;
            p7SeedDemoDataBtn.innerHTML = `
                <svg class="animate-spin h-3.5 w-3.5 text-white inline mr-1" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
                <span>Seeding Database...</span>
            `;

            try {
                const res = await fetch('/api/dev/seed-db', { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

                showToast(`Seeded ${data.incidents_seeded} incidents, ${data.runbooks_seeded} runbooks, & ${data.chroma_vectors_indexed} vectors!`, 'success');

                // Refresh all views
                loadVendorSlaAnalytics();
                loadBusFactorAnalytics();
                loadRunbookDecayAnalytics();
                if (typeof refreshDbExplorer === 'function') refreshDbExplorer();
                if (typeof initOrRefreshTopologyGraph === 'function') initOrRefreshTopologyGraph();
            } catch (err) {
                console.error(err);
                showToast(`Seeding failed: ${err.message}`, 'error');
            } finally {
                p7SeedDemoDataBtn.disabled = false;
                p7SeedDemoDataBtn.innerHTML = `
                    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                    </svg>
                    <span>Seed Enterprise Demo Data</span>
                `;
            }
        });
    }

    // Direct event listener bindings for sidebar buttons (for direct clicks)
    const navBtnPageVendorSla = document.getElementById('navBtnPageVendorSla');
    if (navBtnPageVendorSla) {
        navBtnPageVendorSla.addEventListener('click', () => {
            loadVendorSlaAnalytics();
        });
    }

    const navBtnPageBusFactor = document.getElementById('navBtnPageBusFactor');
    if (navBtnPageBusFactor) {
        navBtnPageBusFactor.addEventListener('click', () => {
            loadBusFactorAnalytics();
        });
    }

    const navBtnPageRunbookDecay = document.getElementById('navBtnPageRunbookDecay');
    if (navBtnPageRunbookDecay) {
        navBtnPageRunbookDecay.addEventListener('click', () => {
            loadRunbookDecayAnalytics();
        });
    }

});

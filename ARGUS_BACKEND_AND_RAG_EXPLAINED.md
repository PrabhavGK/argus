# Argus: System Architecture, Privacy Pipeline & RAG Vectorization Guide

> **System Name:** Argus (Privacy-Preserving Team RAG Enclave)  
> **Classification:** Technical Reference & System Architecture  
> **Status:** Active / Production-Ready Reference  

---

## Table of Contents
1. [Executive Summary & Core Philosophy](#1-executive-summary--core-philosophy)
2. [Project File Map & Exact Directory Naming](#2-project-file-map--exact-directory-naming)
3. [The Multi-Engine Redaction Architecture](#3-the-multi-engine-redaction-architecture)
4. [4-Stage Stepping Pipeline & In-Flight Kill-Switch](#4-4-stage-stepping-pipeline--in-flight-kill-switch)
5. [Database Architecture & Persistence Strategy](#5-database-architecture--persistence-strategy)
6. [Vectorization & Embedding Models Explained](#6-vectorization--embedding-models-explained)
7. [How Privacy-Preserving RAG Works in Argus](#7-how-privacy-preserving-rag-works-in-argus)
8. [Libraries, Frameworks & Tech Stack](#8-libraries-frameworks--tech-stack)
9. [Production Migration Guide (SQLite to pgvector)](#9-production-migration-guide-sqlite-to-pgvector)

---

## 1. Executive Summary & Core Philosophy

**Argus** is an enterprise-grade, privacy-preserving Retrieval-Augmented Generation (RAG) platform. In traditional RAG systems, raw documents—including production crash dumps, database connection strings, API keys, customer PII, and employee credentials—are embedded directly into vector indices and transmitted to third-party Large Language Models (LLMs). This introduces major data leakage risks (SOC 2, GDPR, HIPAA, and PCI-DSS violations).

Argus eliminates this vector by enforcing **Zero-Leakage Ingestion Enclaves**:
* **Volatile RAM-Only Processing:** Incoming logs and queries are processed strictly in volatile system memory (heap buffers). No raw unmasked data touches non-volatile SSD/disk storage.
* **Deterministic Token Masking:** Sensitive entities (e.g., `10.14.88.23`, `AKIAIOSFODNN7EXAMPLE`) are substituted with deterministic synthetic tokens (e.g., `<INTERNAL_IP_1>`, `<AWS_ACCESS_KEY_1>`). If an IP appears 50 times across a document, it maps identically to `<INTERNAL_IP_1>`, preserving contextual and structural semantic utility for vector embeddings while neutralizing all security risks.
* **In-Flight Kill-Switch:** If an ingestion pipeline is halted midway or fails policy checks, volatile memory is instantly shredded and 0 bytes land on disk.
* **Local Persistent Storage with Cloud Vector DB Migration:** Masked data is saved inside the local project folder (`data/argus_knowledge_base.db` and `storage_vault/`), with an automated migration pathway to enterprise vector stores (**PostgreSQL 16 + pgvector** or **Qdrant**).

---

## 2. Project File Map & Exact Directory Naming

Below is the exact folder structure and purpose of every file in the Argus workspace:

```text
/home/gkprabhav/Prabhav/genai_fin/
│
├── app.py                             # Core FastAPI application server & backend engine
├── requirements.txt                   # Python library dependencies
├── ARGUS_BACKEND_AND_RAG_EXPLAINED.md # This architecture and technical documentation file
│
├── data/                              # Local database directory
│   ├── argus_knowledge_base.db        # Persistent SQLite database storing sanitized records
│   └── team_rules_enclave.enc         # Cryptographic Team Lead rulebook (PBKDF2 + AES Stream + HMAC-SHA256)
│
├── storage_vault/                     # Persistent clean storage folder
│   ├── sanitized_jira_incident_ticket.txt
│   ├── sanitized_postgres_crash_dump.log
│   └── sanitized_k8s_oom_incident.log
│
├── sample_docs/                       # Real-world incident presets for testing
│   ├── jira_incident_ticket.txt       # Incident containing AWS IAM keys, emails, IPs, JWTs
│   ├── postgres_crash_dump.log        # DB stack trace with PostgreSQL URI & root passwords
│   ├── k8s_oom_incident.log           # Pod termination event with internal IPs & secrets
│   └── confluence_runbook_secrets.md  # Runbook with Vault root tokens & KMS keys
│
├── scripts/                           # Production migration and utility scripts
│   └── transfer_to_pgvector.py        # Python script to vectorize SQLite rows into PostgreSQL pgvector
│
├── templates/                         # HTML UI templates
│   └── index.html                     # Enterprise 4-page responsive interface (Tailwind CSS)
│
└── static/                            # Client-side assets
    └── app.js                         # Vanilla ES6+ client controller (stepping, kill-switch, DB UI)
```

### File-by-File Breakdown:
1. **`app.py`**:
   - Contains the FastAPI REST API, deterministic multi-engine recognizers (`Presidio NER` + `Enterprise Regex`), volatile RAM pipeline, SQLite persistence engine, and dynamic vector similarity search.
   - Exposes REST endpoints: `/api/sanitize`, `/api/retrieve`, `/api/pipeline/save-vault`, `/api/pipeline/interrupt`, `/api/db/info`, `/api/db/records`, `/api/db/save-record`, and `/api/db/transfer-simulate`.
2. **`data/argus_knowledge_base.db`**:
   - The on-disk SQLite database file storing sanitized, zero-PII knowledge base entries.
   - Holds table `local_knowledge_base` with schema: `(id, team, title, sanitized_content, redacted_tokens_count, created_at, hash, storage_tier)`.
3. **`storage_vault/`**:
   - The directory where clean, masked artifacts land upon successful completion of the 4-stage ingestion pipeline.
   - Employs non-overwriting, auto-incrementing naming (`sanitized_<name>.txt`, `sanitized_<name>_2.txt`).
4. **`sample_docs/`**:
   - Pre-packaged production logs containing synthetic high-risk enterprise secrets for testing recognizer accuracy.
5. **`scripts/transfer_to_pgvector.py`**:
   - Production-grade ETL script. Connects to `data/argus_knowledge_base.db`, verifies 0 PII leaks, generates 384-dimensional dense embeddings, and commits rows to PostgreSQL pgvector.
6. **`templates/index.html`**:
   - Single-page application template featuring an enterprise sidebar with 4 views:
     - **Page 1:** Privacy RAG & Masking with editable vector search query box.
     - **Page 2:** Data Flow, 1.5s Stepping, Kill-Switch, and Local Database Explorer (`data/argus_knowledge_base.db`).
     - **Page 3:** Toolchain Integration Guide (Jira, Confluence, GitLab, Slack).
     - **Page 4:** Team Governance, System Owners, and On-Call SLAs.
7. **`static/app.js`**:
   - Client-side execution engine managing timer-based pipeline stepping (1,500ms per stage), memory tracing, in-flight kill-switch cancellation, and dynamic vector search ranking.

---

## 3. The Multi-Engine Redaction Architecture

Argus runs a **two-tier recognition pipeline** directly in volatile system memory:

```mermaid
flowchart LR
    A["Raw Incident Input (RAM)"] --> B["Multi-Engine Scanner"]
    B --> C["Engine 1: Microsoft Presidio NER (Names, Emails, Phone, IPs)"]
    B --> D["Engine 2: Enterprise Regex Recognizers (AWS Keys, JWT, DB URIs)"]
    C --> E["Conflict Resolver & Priority Matrix"]
    D --> E
    E --> F["Deterministic Token Registry"]
    F --> G["Sanitized Output (<ENTITY_N>)"]
```

### 1. Recognizer Engines
* **Microsoft Presidio NER Simulation**: Scans for human PII (Alex Miller, Sarah Connor), RFC 5322 Email Addresses (`alex.miller@corporate.internal`), E.164 Phone Numbers (`+1-555-019-2834`), and IPv4 internal subnets (`10.14.88.23`, `192.168.1.105`).
* **Enterprise High-Entropy Recognizers**: Identifies AWS IAM Access Keys (`AKIA...`), AWS Secret Access Keys (`AWS_SECRET_ACCESS_KEY=...`), JSON Web Tokens (`eyJ...`), Bearer authorization headers, Database URI credentials (`postgres://user:password@host/db`), Slack webhooks, and high-entropy API secrets.
* **Cloud & Infrastructure Recognizers**:
  - **Kubernetes Pod Workloads**: `\b[a-z0-9]+(?:-[a-z0-9]+)*-[a-z0-9]{4,10}-[a-z0-9]{4,6}\b` (e.g. `payment-worker-7c98b`) $\rightarrow$ `<K8S_POD_ID_N>`.
  - **Internal Node Hostnames / AWS EC2 DNS**: `ip-10-244-3-18.ec2.internal` $\rightarrow$ `<INTERNAL_DNS_HOST_N>`.
  - **Cluster Service Endpoints (Host:Port)**: `10.244.0.1:6443` $\rightarrow$ `<CLUSTER_SERVICE_ENDPOINT_N>` (evaluates with higher priority than raw IP to prevent port leakage).
  - **Memory & Resource Metrics**: `2048Mi`, `4GiB` $\rightarrow$ `<RESOURCE_CAPACITY_N>`.
  - **K8s Namespaces**: `prod-payments` $\rightarrow$ `<K8S_NAMESPACE_N>`.

### 2. Team Lead Cryptographic Rulebook Enclave (`data/team_rules_enclave.enc`)
To support team-specific masking rules without risking that proprietary patterns are snatched or leaked:
* **Storage Location**: Resides directly on the team lead's host in `data/team_rules_enclave.enc`.
* **Cipher At Rest**: Encrypted using **PBKDF2-HMAC-SHA256** key derivation with 100,000 iterations and continuous stream cipher encryption.
* **Tamper-Evident HMAC Digital Seal**: Every revision is signed with an **HMAC-SHA256 signature** using the Team Lead Master Key (`ARGUS-LEAD-MASTER-KEY-2026`). If an attacker or insider modifies the file on disk, Argus detects the signature mismatch, raises a security alert, and refuses to load unverified rules.
* **Namespace Isolation**: Rules are scoped to specific teams (`CloudInfra`, `SecOps`, `PaymentLedger`, `DataPlatform`) or apply globally.
* **Live In-Memory Integration**: When unlocked, rules are compiled in volatile RAM and evaluated seamlessly alongside core recognizers.

### 3. Conflict Resolution & Overlap Sorting
If an IP address is embedded inside a Database Connection URI or Cluster Endpoint, naive regex substitution would corrupt the token. Argus sorts all recognizer matches by:
$$\text{Sort Key} = (\text{Start Offset ASC}, \text{Priority ASC}, \text{Match Length DESC})$$
Overlapping sub-matches are rejected, ensuring clean, contiguous token bounds.

### 4. Deterministic Substitution
Tokens are indexed using an in-memory dictionary `value_to_token[(entity_type, raw_value)]`.
* If `10.14.88.23` is discovered at offset 120 and again at offset 840, both are mapped to `<INTERNAL_IP_1>`.
* If `2048Mi` appears under `Working Set` and `Hard Limit`, both map identically to `<RESOURCE_SPEC_1>`.
* This preserves the graph-theoretic co-reference structure of incident logs without exposing the actual values.

---

## 4. 4-Stage Stepping Pipeline & In-Flight Kill-Switch

The data flow enclave in **Page 2** executes with intentional **1.5-second (1,500 ms) stage latency** so operators and auditors can observe the exact memory lifecycle and test emergency aborts.

```text
[ Stage 1: Heap Ingestion ] ──> [ Stage 2: Tokenizer ] ──> [ Stage 3: Policy Gate ] ──> [ Stage 4: Commit ]
         (1.5s)                        (1.5s)                     (1.5s)                      (1.5s)
           │                             │                          │                            │
           └─────────────────────────────┴──────────────────────────┴──> [🛑 EMERGENCY KILL-SWITCH]
                                                                                   │
                                                                         [PURGE RAM & ABORT]
                                                                         Zero bytes reach disk.
```

### Stage Breakdown:
1. **Stage 1 — Ephemeral Heap Ingestion Buffer (1.5s)**:
   - Data is allocated strictly in volatile user-space RAM (Heap address: `0x7ffe42a0`). Zero disk I/O operations are permitted.
2. **Stage 2 — Presidio & Regex Masking (1.5s)**:
   - Recognizers scan the volatile buffer and substitute secrets with `<ENTITY_N>` tokens.
3. **Stage 3 — Zero-Leakage Policy Gate (1.5s)**:
   - A secondary validation gate inspects the sanitized buffer to ensure no unmasked credentials or canary tokens survived.
4. **Stage 4 — Storage Vault Commit (1.5s)**:
   - Once all 3 previous stages pass, the sanitized file is written to `storage_vault/` and inserted into `data/argus_knowledge_base.db`.

### How the Kill-Switch Operates:
* If the operator hits **🛑 EMERGENCY INTERRUPT** at any point during Stages 1, 2, or 3:
  1. The client immediately aborts all pending JavaScript timers (`clearTimeout(simulationTimeoutId)`).
  2. The client fires an immediate `POST /api/pipeline/interrupt` request to the backend.
  3. The backend halts processing in RAM, drops the buffer from memory, and verifies that no partial file was written.
  4. Previously saved files from prior runs remain intact; the interrupted run results in **0 bytes written to disk**.

---

## 5. Database Architecture & Persistence Strategy

Argus implements a two-tier database strategy:

```mermaid
flowchart TD
    subgraph Current_Local_Tier ["Current Local Tier (In Project Folder)"]
        A["Volatile Sanitization Engine"] -->|Stage 4 Commit| B["SQLite Database<br/>(data/argus_knowledge_base.db)"]
        A -->|Stage 4 Commit| C["Storage Vault Folder<br/>(storage_vault/sanitized_*.txt)"]
    end
    
    subgraph Target_Enterprise_Tier ["Target Enterprise Tier (Production)"]
        B -->|scripts/transfer_to_pgvector.py| D["PostgreSQL 16 + pgvector"]
        D --> E["Table: enterprise_rag_vectors"]
        E --> F["HNSW Cosine Vector Index"]
    end
```

### Local SQLite Schema (`data/argus_knowledge_base.db`):
```sql
CREATE TABLE IF NOT EXISTS local_knowledge_base (
    id TEXT PRIMARY KEY,                       -- Unique identifier e.g. KB-ARGUS-01
    team TEXT NOT NULL,                        -- Owning namespace (SecOps, CloudInfra, etc.)
    title TEXT NOT NULL,                       -- Human-readable incident title
    sanitized_content TEXT NOT NULL,           -- Masked text with deterministic tokens
    redacted_tokens_count INTEGER NOT NULL,    -- Count of replaced secrets
    created_at TEXT NOT NULL,                  -- ISO 8601 UTC timestamp
    hash TEXT NOT NULL,                        -- SHA-256 fingerprint (first 12 chars)
    storage_tier TEXT NOT NULL                 -- Storage tier label
);
```

### Why SQLite for Local Storage?
* **Zero External Dependencies:** Runs natively via Python's standard library `sqlite3` without installing Docker, local Postgres instances, or cloud accounts.
* **Single-Folder Portability:** The entire state is contained within `/home/gkprabhav/Prabhav/genai_fin/data/argus_knowledge_base.db`.
* **ACID Transactions:** Thread-safe inserts ensure that when a sanitized run completes, data is safely persisted.

---

## 6. Vectorization & Embedding Models Explained

### What is Vectorization?
Machine learning models and similarity search algorithms cannot understand raw text directly. **Vectorization** (or text embedding) is the mathematical process of transforming variable-length strings of text into fixed-length arrays of continuous floating-point numbers (dense vectors).

```text
"Connection to <INTERNAL_IP_1> timed out" ──> [0.0412, -0.0931, 0.1284, ..., -0.0195] (384 floats)
```

In this vector space, documents with similar semantic meanings are positioned close to one another, even if they use different words.

### The Embedding Model Used
In Argus, the recommended production embedding model is **`BAAI/bge-small-en-v1.5`** (or OpenAI's `text-embedding-3-small`).

| Specification | BAAI/bge-small-en-v1.5 | text-embedding-3-small |
| :--- | :--- | :--- |
| **Vector Dimension** | **384 dimensions** | 1536 dimensions |
| **Max Sequence Length** | 512 tokens | 8191 tokens |
| **Normalization** | Unit length ($\|v\|_2 = 1.0$) | Unit length ($\|v\|_2 = 1.0$) |
| **Distance Metric** | Cosine Similarity / Dot Product | Cosine Similarity |
| **Inference Hardware** | CPU-friendly / Lightweight | Cloud API |
| **HuggingFace Hub ID** | `BAAI/bge-small-en-v1.5` | `text-embedding-3-small` |

### How Dense Vectorization Works Step-by-Step:
1. **Subword Tokenization:** The clean sanitized text is broken into subword tokens using WordPiece or Byte-Pair Encoding (BPE).
2. **Transformer Encoding:** Tokens pass through 12 transformer encoder layers with multi-head self-attention, capturing grammatical and operational context.
3. **Mean Pooling:** The hidden state representations of all tokens are averaged into a single 384-dimensional vector.
4. **L2 Normalization:** The vector is scaled so its Euclidean norm equals 1:
   $$\vec{v}_{\text{norm}} = \frac{\vec{v}}{\|\vec{v}\|_2} = \frac{\vec{v}}{\sqrt{\sum_{i=1}^{d} v_i^2}}$$

### Vector Distance & Similarity Metrics:
Because the embeddings are L2-normalized, the **Cosine Similarity** between query vector $\vec{q}$ and document vector $\vec{d}$ is simply the dot product:
$$\text{Cosine Similarity}(\vec{q}, \vec{d}) = \cos(\theta) = \sum_{i=1}^{384} q_i \cdot d_i$$
* **Similarity Score $\approx 1.0$:** Documents are semantically identical.
* **Similarity Score $\approx 0.0$:** Documents are orthogonal / completely unrelated.
* **Vector Distance:** Defined as $1.0 - \text{Similarity Score}$.

---

## 7. How Privacy-Preserving RAG Works in Argus

Traditional RAG systems pose severe privacy vulnerabilities because raw queries and documents leak into vector stores and LLM logs. Argus re-architects RAG into a **Privacy-First Search Plane**:

```mermaid
sequenceDiagram
    autonumber
    actor Engineer as On-Call Engineer
    participant RAM as Volatile RAM Enclave
    participant DB as SQLite / pgvector Store
    participant UI as Argus Dashboard

    Engineer->>RAM: Submits Raw Query with Secrets (e.g., "Timeout on 10.14.88.23 with AKIA...")
    Note over RAM: Step 1: Detects & masks secrets in RAM<br/>Replaces with <INTERNAL_IP_1>, <AWS_ACCESS_KEY_1>
    RAM->>RAM: Step 2: Generates dense vector on SANITIZED query
    RAM->>DB: Step 3: Queries vector index using clean vector
    DB-->>RAM: Returns Top-K matching runbook chunks (already sanitized)
    RAM->>UI: Displays matched knowledge chunks without PII
    Note over UI: Resolution answer generation decoupled<br/>to prevent generative hallucination & model leakage
```

### Why Answer Resolution is Decoupled:
In Phase 1 of Argus, generative answer resolution (e.g. generating a ChatGPT paragraph) was deliberately removed as requested. In critical enterprise operations (payments, Kubernetes, cloud security), hallucinated commands generated by an LLM can cause downtime. Argus instead surfaces **exact, verified runbook chunks** with high similarity ranking, ensuring operators see the exact procedures authored by team maintainers.

---

## 8. Libraries, Frameworks & Tech Stack

### Backend Libraries (`Python 3.14`):
* **`fastapi` (v0.115+)**: High-performance asynchronous web framework used for API routing, validation, and serialization.
* **`uvicorn` (v0.34+)**: Lightning-fast ASGI web server implementation.
* **`pydantic` (v2.10+)**: Data validation and type enforcement for incoming API request payloads.
* **`starlette`**: Provides foundational HTTP primitives, request handling, and `FileResponse`.
* **`re` (Python Built-in)**: High-speed regular expression engine compiled with `re.IGNORECASE` flags for enterprise secret detection.
* **`sqlite3` (Python Built-in)**: Zero-dependency ACID relational database engine powering `data/argus_knowledge_base.db`.
* **`hashlib` (Python Built-in)**: Cryptographic SHA-256 calculation for immutable document verification fingerprints.

### Optional Production Vector Dependencies:
* **`sentence-transformers`**: HuggingFace library for downloading and executing `BAAI/bge-small-en-v1.5` embeddings locally.
* **`psycopg2-binary`**: PostgreSQL database driver for executing pgvector upserts.

### Frontend Technologies:
* **Vanilla ES6+ JavaScript**: Lightweight, reactive client code with 0 build steps (no npm/Webpack/Vite required).
* **Tailwind CSS (CDN)**: Modern utility-first CSS framework providing dark-mode capable enterprise styling.
* **Google Fonts (`Inter` & `JetBrains Mono`)**: Clean typography optimized for system logs and code readability.

---

## 9. Production Migration Guide (SQLite to pgvector)

When moving from local folder evaluation to production, Argus provides a turnkey path to PostgreSQL with the `pgvector` extension.

### Step 1: PostgreSQL DDL Schema
Execute the following SQL in your PostgreSQL 16 cluster:

```sql
-- 1. Enable the pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- 2. Create the enterprise sanitized knowledge base table
CREATE TABLE IF NOT EXISTS enterprise_rag_vectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_id VARCHAR(64) UNIQUE NOT NULL,
    team VARCHAR(64) NOT NULL,
    title TEXT NOT NULL,
    sanitized_content TEXT NOT NULL,
    embedding vector(384),                          -- 384-dimensional dense vector
    redacted_tokens_count INT NOT NULL,
    content_hash VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Build an HNSW index for sub-millisecond approximate nearest neighbor search
CREATE INDEX ON enterprise_rag_vectors USING hnsw (embedding vector_cosine_ops);
```

### Step 2: Running the Transfer Script
The migration script is located at:
[`scripts/transfer_to_pgvector.py`](scripts/transfer_to_pgvector.py)

To run the migration:
```bash
python3 scripts/transfer_to_pgvector.py
```

### What the Script Executes:
1. Connects to `data/argus_knowledge_base.db`.
2. Fetches all rows from `local_knowledge_base`.
3. Runs a strict PII containment audit to assert no unmasked AWS keys or passwords exist.
4. Generates 384-dimensional dense vectors on the sanitized text.
5. Upserts records into PostgreSQL, updating embeddings without leaking cleartext credentials.

---

*Authored for Argus Enterprise RAG Enclave — Google DeepMind Antigravity Pair Programming Session.*




# PHANTOM AI: Python FastAPI Backend Architecture & Implementation Plan

> **System:** PHANTOM AI — Network Traffic Telemetry Analyzer & Shadow AI Governance  
> **Team:** TECH TITANS  
> **Target Runtime:** Python 3.11+ / FastAPI / Pydantic v2 / SQLAlchemy (async) / PostgreSQL / Zeek Ingestion  

---

## 1. Architecture Overview

The PHANTOM AI architecture separates high-speed network telemetry collection, real-time signature matching, and security policy evaluation into a decoupled FastAPI backend with persistent PostgreSQL storage, connected to the React SPA frontend via typed REST endpoints.

```
┌────────────────────────────────────────────────────────┐
│                   Data Ingestion Sources               │
│  - Zeek Logs (conn.log, dns.log, ssl.log, http.log)    │
│  - CSV / JSON batch exports from SIEM / PCAP           │
│  - Live Zeek broker / Kafka stream (optional future)   │
└──────────────────────────┬─────────────────────────────┘
                           │ HTTP POST / Stream
                           ▼
┌────────────────────────────────────────────────────────┐
│            FastAPI Backend Service (:8000)             │
│                                                        │
│  ┌─────────────────────────┐ ┌──────────────────────┐  │
│  │ Zeek Parser & Normalizer│ │ Provider Signature   │  │
│  │ (regex/TSV/JSON parser) │ │ Engine (SNI/DNS/Host)│  │
│  └────────────┬────────────┘ └──────────┬───────────┘  │
│               │                         │              │
│               ▼                         ▼              │
│  ┌─────────────────────────┐ ┌──────────────────────┐  │
│  │ Risk Scorer & Policy    │ │ Inventory & Alert    │  │
│  │ Evaluation Engine       │ │ Tracking Service     │  │
│  └────────────┬────────────┘ └──────────┬───────────┘  │
│               │                         │              │
│               ▼                         ▼              │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Synthetic Evaluation & Ground-Truth Benchmarking │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────┬─────────────────────────────┘
                           │
                 SQLAlchemy Async ORM
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│               PostgreSQL Database (:5432)              │
│  - endpoints_inventory    - risk_alerts & audit_log    │
│  - traffic_flows          - policy_rules & approved    │
│  - evaluation_benchmarks  - detection_signatures       │
└────────────────────────────────────────────────────────┘
```

---

## 2. Python Backend Module Breakdown

The planned Python backend directory structure is organized into clean domain modules:

```
backend/
├── app/
│   ├── main.py                  # FastAPI initialization, CORS, middleware, router mounts
│   ├── config.py                # Pydantic BaseSettings (DATABASE_URL, CORS_ORIGINS, etc.)
│   ├── db/
│   │   ├── session.py           # Async engine & sessionmaker (asyncpg)
│   │   ├── base.py              # DeclarativeBase model registry
│   │   └── models.py            # SQLAlchemy models (Inventory, Flow, Alert, Policy)
│   ├── schemas/                 # Pydantic request/response schemas matching apiTypes.ts
│   │   ├── health.py
│   │   ├── dashboard.py
│   │   ├── inventory.py
│   │   ├── traffic.py
│   │   ├── alerts.py
│   │   ├── policies.py
│   │   ├── simulations.py
│   │   └── evaluations.py
│   ├── services/
│   │   ├── parser.py            # Zeek TSV parser, CSV/JSON parser & normalizer
│   │   ├── classifier.py        # SNI, Host, Port & Header regex provider matcher
│   │   ├── risk_scorer.py       # Deterministic explainable risk score calculator
│   │   ├── policy_engine.py     # Policy rule evaluator (Allow/Warn/Review/Simulated Block)
│   │   ├── inventory_svc.py     # Endpoint aggregation & user tracking
│   │   ├── alert_svc.py         # Alert generation, triage state & audit logging
│   │   └── evaluation_svc.py    # Isolated synthetic benchmark runner & metrics
│   └── routers/
│       ├── health.py            # GET /api/health
│       ├── dashboard.py         # GET /api/dashboard/summary
│       ├── inventory.py         # GET /api/inventory, GET /api/inventory/{id}
│       ├── traffic.py           # POST /api/traffic/analyze
│       ├── alerts.py            # GET /api/alerts, PATCH /api/alerts/{id}
│       ├── policies.py          # GET /api/policies, PUT /api/policies
│       ├── simulations.py       # POST /api/simulations
│       └── evaluations.py       # POST /api/evaluations/run, GET /api/evaluations/latest
├── tests/
│   ├── test_parser.py           # Unit tests for Zeek conn/dns/ssl/http parsing
│   ├── test_classifier.py       # Detection signature tests against known AI & local models
│   ├── test_policy_engine.py    # Policy evaluation and risk scoring unit tests
│   └── test_benchmark.py        # Synthetic dataset evaluation metrics verification
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## 3. Core Implementation Specifications

### Module 1: Traffic Parsing and Normalization (`services/parser.py`)
- **Zeek TSV Format Support:**
  - Handles Zeek `#separator \x09`, `#fields`, `#types` headers with tab delimiter.
  - Supports `conn.log` (`id.orig_h`, `id.resp_h`, `id.resp_p`, `orig_bytes`, `resp_bytes`).
  - Supports `dns.log` (`query`, `qtype_name`, `answers`).
  - Supports `ssl.log` (`server_name`, `subject`, `issuer`).
  - Supports `http.log` (`host`, `uri`, `user_agent`, `method`).
- **CSV & JSON Support:**
  - Standardizes headers (`hostname`, `domain`, `src_ip`, `dest_ip`, `port`, `bytes_sent`).
- **Normalization:** Converts IP addresses, ports, protocol names, and extracts fully-qualified domain names (FQDN) or SNI strings.

### Module 2: Provider Classification (`services/classifier.py`)
- **Signature Matching:**
  - Compares FQDN/SNI patterns against regex signatures:
    - OpenAI: `(?i)(api\.openai\.com|chatgpt\.com|.*\.oaistatic\.com)`
    - Anthropic: `(?i)(api\.anthropic\.com|claude\.ai)`
    - Google Gemini: `(?i)(generativelanguage\.googleapis\.com|gemini\.google\.com)`
    - Azure OpenAI: `(?i)(.*\.openai\.azure\.com)`
    - AWS Bedrock: `(?i)(bedrock-runtime\..*\.amazonaws\.com)`
    - Cohere: `(?i)(api\.cohere\.(ai|com))`
    - Mistral AI: `(?i)(api\.mistral\.ai|chat\.mistral\.ai)`
    - Hugging Face: `(?i)(api-inference\.huggingface\.co|huggingface\.co)`
  - Local Model Endpoints: Detects RFC 1918 / loopback IPs paired with default model server ports (`11434` for Ollama, `8000` for vLLM, `1234` for LM Studio).
- **Classification Output:**
  - Emits classification (`LIKELY_AI`, `LIKELY_NON_AI`, `UNKNOWN`), confidence (0.0 - 1.0), matched signature ID, and detection evidence string.

### Module 3: Risk Scoring & Policy Evaluation (`services/risk_scorer.py` & `services/policy_engine.py`)
- **Risk Score Formula:**
  - Provider Trust (0-25)
  - Data Upload Volume (0-30): scaled by uploaded MB
  - Approval Status (0-25): 25 if unapproved/shadow, 0 if sanctioned
  - Department Sensitivity (0-10): Finance/Legal/R&D weight higher
  - Exposure / User Count (0-10)
  - Total Risk = `Sum(factors)` (0-100), mapped to Low (<35), Medium (35-64), High (65-84), Critical (≥85).
- **Policy Decision Matrix:**
  - Evaluates enabled policy rules in priority order.
  - Unsanctioned endpoint + High Risk → `Review` or `Simulated Block`.
  - Non-AI endpoint → `Allow`.
  - High data volume on approved provider → `Warn`.

### Module 4: Evaluation & Test Metrics (`services/evaluation_svc.py`)
- Runs ground-truth evaluation over the 50-item reproducible synthetic dataset.
- Keeps ground truth labels completely isolated from classifier input.
- Computes standard formulas with zero-denominator safety:
  - Precision: `TP / (TP + FP)` (if `TP + FP == 0`, returns 0.0)
  - Recall: `TP / (TP + FN)` (if `TP + FN == 0`, returns 0.0)
  - F1 Score: `2 * P * R / (P + R)` (if `P + R == 0`, returns 0.0)
  - False Positive Rate: `FP / (FP + TN)` (if `FP + TN == 0`, returns 0.0)
  - Confusion Matrix: 10x10 provider-level breakdown.

---

## 4. PostgreSQL Persistence Schema

```sql
CREATE TABLE endpoints_inventory (
    id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL UNIQUE,
    provider VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    classification VARCHAR(50) NOT NULL,
    approval_status VARCHAR(50) NOT NULL DEFAULT 'Shadow AI',
    confidence VARCHAR(20) NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    users_count INTEGER DEFAULT 1,
    data_sent_mb NUMERIC(10, 2) DEFAULT 0,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    detection_method VARCHAR(100),
    departments TEXT[] DEFAULT '{}',
    client_ips TEXT[] DEFAULT '{}',
    flag_reasons TEXT[] DEFAULT '{}',
    compliance_impact TEXT[] DEFAULT '{}',
    risk_breakdown JSONB
);

CREATE TABLE traffic_flows (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    provider VARCHAR(100),
    classification VARCHAR(50) NOT NULL,
    confidence NUMERIC(3, 2) NOT NULL,
    evidence TEXT,
    detection_method VARCHAR(100),
    bytes_up BIGINT DEFAULT 0,
    bytes_down BIGINT DEFAULT 0,
    risk_level VARCHAR(20) NOT NULL,
    approval_status VARCHAR(50) NOT NULL
);

CREATE TABLE risk_alerts (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Open',
    risk_level VARCHAR(20) NOT NULL,
    risk_score INTEGER NOT NULL,
    endpoint_hostname VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    trigger_reason TEXT NOT NULL,
    evidence TEXT NOT NULL,
    approval_status VARCHAR(50) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    department VARCHAR(100),
    users_affected INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE alert_audit_log (
    id VARCHAR(64) PRIMARY KEY,
    alert_id VARCHAR(64) REFERENCES risk_alerts(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notes TEXT
);

CREATE TABLE alert_comments (
    id VARCHAR(64) PRIMARY KEY,
    alert_id VARCHAR(64) REFERENCES risk_alerts(id) ON DELETE CASCADE,
    author VARCHAR(100) NOT NULL,
    text TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE policy_rules (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    action VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    priority INTEGER NOT NULL,
    criteria_summary TEXT NOT NULL
);
```

---

## 5. Deployment & Connection Instructions

### Step 1: Run the Backend with Docker Compose
Create `docker-compose.yml` in the root or `backend/` directory:

```yaml
version: '3.8'

services:
  db:
    image: postgres:16-alpine
    restart: always
    environment:
      POSTGRES_USER: phantom
      POSTGRES_PASSWORD: phantom_secure_password
      POSTGRES_DB: phantom_ai
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  api:
    build:
      context: ./backend
      dockerfile: Dockerfile
    restart: always
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://phantom:phantom_secure_password@db:5432/phantom_ai
      - CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]
    depends_on:
      - db

volumes:
  postgres_data:
```

### Step 2: Start the FastAPI Service
```bash
# In the backend directory:
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Step 3: Connect the Frontend
In the root directory, configure `.env`:
```bash
VITE_API_BASE_URL="http://localhost:8000"
```
Restart the frontend server:
```bash
npm run dev
```
The header badge will transition from **Demo Mode (Client Engine)** to **FastAPI Connected**, routing live traffic ingestion, policy management, and alert operations to your persistent Python backend.

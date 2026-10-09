# PHANTOM AI: Production Integration & Deployment Guide

> **Project:** PHANTOM AI — Network Traffic Telemetry Analyzer & Shadow AI Governance  
> **Backend Service:** Python 3.11+ / FastAPI / SQLAlchemy 2.0 / Alembic / PostgreSQL 16  
> **Frontend Client:** React 19 / TypeScript / Vite / Tailwind CSS  
> **Security Notice:** Zeek live network ingestion and firewall enforcement are disabled by default. Live packet capture requires explicit operational authorization.

---

## 1. Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │          Enterprise Network Telemetry        │
                      └──────────────────────┬───────────────────────┘
                                             │
                        ┌────────────────────┴────────────────────┐
                        │ Authorized Batch Logs (conn, ssl, etc.)  │
                        └────────────────────┬────────────────────┘
                                             ▼
┌─────────────────────────────────┐     ┌────────────────────────────────────────────────────────┐
│  React Frontend (Port 3000)     │     │             FastAPI Backend (Port 8000)                │
│  - Dashboard & Endpoints        │     │  - REST API & OpenAPI docs (/docs)                     │
│  - Risk Alerts & Reviews        │────▶│  - Provider Classifier (OpenAI, Anthropic, Local Ports)│
│  - Block Simulator (Interactive)│     │  - Policy Engine (Allow, Warn, Review, Simulated Block)│
│  - Evaluation Benchmark Report  │     │  - Zeek Streaming Parser (conn, dns, ssl, http)        │
│  - Backend Connection Indicator │     │  - Temporary Log Discard & Privacy Redaction           │
└─────────────────────────────────┘     └───────────────────────────┬────────────────────────────┘
                                                                    │
                                                                    ▼
                                        ┌────────────────────────────────────────────────────────┐
                                        │               PostgreSQL 16 Persistence                │
                                        │  - endpoints                 - policies                │
                                        │  - traffic_observations      - incident_review_records │
                                        │  - risk_alerts               - audit_events            │
                                        │  - provider_registry         - evaluation_runs         │
                                        └────────────────────────────────────────────────────────┘
```

---

## 2. PostgreSQL Database Schema & Alembic Migrations

The database models are implemented using **SQLAlchemy 2.0** declarative mapping in `backend/app/models/` and managed with **Alembic** migrations in `backend/alembic/versions/001_initial_schema.py`.

### Database Tables Specification

| Table Name | Primary Key | Key Attributes | UTC Timestamp Controls |
| :--- | :--- | :--- | :--- |
| `endpoints` | `id` (UUID) | `hostname`, `ip_address`, `port`, `provider_name`, `classification`, `approval_status`, `risk_score`, `risk_level`, `confidence`, `bytes_sent`, `bytes_received` | `first_seen_utc`, `last_seen_utc` |
| `traffic_observations` | `id` (UUID) | `endpoint_id`, `source_ip`, `destination_host`, `destination_port`, `bytes_sent`, `bytes_received`, `duration_sec`, `log_type`, `raw_uid`, `sni` | `timestamp_utc` |
| `risk_alerts` | `id` (UUID) | `alert_id` (Unique), `hostname`, `provider_name`, `severity`, `risk_score`, `rule_triggered`, `reason`, `evidence`, `review_status`, `reviewer_notes` | `first_seen_utc`, `resolved_at_utc` |
| `provider_registry` | `id` (String) | `name`, `category`, `is_approved`, `domain_signatures`, `sni_patterns`, `port_signatures`, `base_risk`, `enterprise_patterns` | `created_at_utc`, `updated_at_utc` |
| `policies` | `id` (String) | `name`, `category`, `enabled`, `action` (ALLOW, WARN, REVIEW, SIMULATED_BLOCK, ESCALATE), `severity`, `risk_weight`, `condition_rules` | `created_at_utc`, `updated_at_utc` |
| `incident_review_records`| `id` (UUID) | `alert_id`, `action_type`, `reviewer`, `previous_status`, `new_status`, `comments` | `created_at_utc` |
| `audit_events` | `id` (UUID) | `event_type`, `actor`, `target_resource`, `details` (JSON), `ip_address` | `created_at_utc` |
| `evaluation_runs` | `id` (UUID) | `dataset_version`, `total_samples`, `accuracy`, `precision`, `recall`, `f1_score`, `false_positive_rate`, `confusion_matrix`, `format_metrics` | `run_at_utc` |

### Timestamp & Metric Storage Policies
- **Strict UTC Timestamps:** All datetime columns use timezone-aware UTC (`DateTime(timezone=True)`).
- **Conditional Traffic Metrics:** Volumetric columns (`bytes_sent`, `bytes_received`, `duration_sec`) are nullable and populated *only when present* in the raw telemetry source (e.g., from `conn.log` `orig_bytes`).
- **Temporary Upload Retention:** Uploaded raw log files are streamed directly into the normalized parser in memory or transient storage (`/tmp/phantom_uploads`) and **deleted immediately after parsing**. Only minimal metadata (host, SNI, IP, port, timestamps) is preserved in `traffic_observations`.

---

## 3. Zeek Network Telemetry Ingestion

### Supported Zeek Log Types
The parser (`backend/app/services/zeek_parser.py`) supports standard Zeek TSV (`#fields` header) and JSON formats:
1. `conn.log`: Connection flows, source/destination IP, port, protocol, byte volumes, duration, connection state.
2. `ssl.log`: TLS handshake metadata, Server Name Indication (`server_name`), cipher suite, certificate validation.
3. `dns.log`: DNS query resolution (`query`), answers, transaction IDs.
4. `http.log`: HTTP request telemetry (`host`, `uri`, HTTP verb, status code).

### Ingestion Controls & Safety Guardrails
- **Deduplication:** Uses Zeek `uid` and timestamp tracking to prevent duplicate ingestion of identical sessions.
- **Data Validation & Parsing Error Reporting:** Malformed lines or missing schema fields produce structured validation notices with line numbers rather than crashing the pipeline.
- **Why Automated Live Capture is Disabled:**
  - Automated network packet capture (`pcap`), promiscuous interfaces, and SPAN/TAP mirror ports require explicit infrastructure security authorization and legal compliance in corporate environments.
  - Setting `ZEEK_LIVE_INGESTION_ENABLED="false"` ensures PHANTOM AI operates strictly on authorized, user-provided logs by default.
  - Live ingestion requires explicit enterprise authorization and dedicated sensor deployment.
  - **No Automated Blocking:** Simulation results evaluate policy impacts without altering firewalls or interrupting traffic.

---

## 4. Local Development with Docker Compose

### Prerequisites
- Docker Engine 24.0+
- Docker Compose v2.20+

### Step-by-Step Setup

1. **Clone repository and configure environment variables:**
   ```bash
   cp .env.example .env
   ```

2. **Verify `.env` configuration:**
   ```ini
   # PostgreSQL
   POSTGRES_USER=phantom
   POSTGRES_PASSWORD=phantom_secure_pass_2026
   POSTGRES_DB=phantom_ai
   POSTGRES_PORT=5432

   # Backend API
   DATABASE_URL=postgresql+asyncpg://phantom:phantom_secure_pass_2026@postgres:5432/phantom_ai
   SYNC_DATABASE_URL=postgresql+psycopg2://phantom:phantom_secure_pass_2026@postgres:5432/phantom_ai
   CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
   APP_ENV=development
   LOG_LEVEL=INFO
   ZEEK_LIVE_INGESTION_ENABLED=false

   # Frontend
   VITE_API_BASE_URL=http://localhost:8000
   ```

3. **Launch all services via Docker Compose:**
   ```bash
   docker compose up --build
   ```

   Docker Compose will:
   - Start the PostgreSQL 16 container with healthchecks enabled.
   - Wait for PostgreSQL to become healthy.
   - Build the FastAPI container (`backend/Dockerfile`).
   - Run Alembic migrations automatically: `alembic upgrade head`.
   - Start Uvicorn on port `8000`.

4. **Verify Backend Health:**
   ```bash
   curl -s http://localhost:8000/api/health | jq
   ```
   Interactive Swagger docs are available at `http://localhost:8000/docs`.

5. **Start Frontend:**
   ```bash
   npm run dev
   ```
   Open `http://localhost:3000`. The **Backend Connection Indicator** in the header will show a green **Connected** badge pointing to `http://localhost:8000`.

---

## 5. Cloud Deployment Guide

### Option A: Google Cloud Run & Cloud SQL (PostgreSQL)

1. **Provision Cloud SQL Instance:**
   ```bash
   gcloud sql instances create phantom-db \
       --database-version=POSTGRES_16 \
       --tier=db-custom-2-7680 \
       --region=us-central1

   gcloud sql databases create phantom_ai --instance=phantom-db
   gcloud sql users create phantom --instance=phantom-db --password=SECURE_DB_PASSWORD
   ```

2. **Build & Push Backend Container to Google Artifact Registry:**
   ```bash
   gcloud artifacts repositories create phantom-repo --repository-format=docker --location=us-central1

   docker build -t us-central1-docker.pkg.dev/PROJECT_ID/phantom-repo/backend:latest ./backend
   docker push us-central1-docker.pkg.dev/PROJECT_ID/phantom-repo/backend:latest
   ```

3. **Deploy Backend to Cloud Run with Cloud SQL Connection:**
   ```bash
   gcloud run deploy phantom-backend \
       --image=us-central1-docker.pkg.dev/PROJECT_ID/phantom-repo/backend:latest \
       --platform=managed \
       --region=us-central1 \
       --allow-unauthenticated \
       --add-cloudsql-instances=PROJECT_ID:us-central1:phantom-db \
       --set-env-vars="APP_ENV=production,POSTGRES_USER=phantom,POSTGRES_DB=phantom_ai,ZEEK_LIVE_INGESTION_ENABLED=false,CORS_ORIGINS=https://YOUR_FRONTEND_DOMAIN.run.app" \
       --set-secrets="POSTGRES_PASSWORD=phantom_db_password:latest"
   ```

4. **Connect Frontend to Cloud Run URL:**
   Set the Cloud Run URL as `VITE_API_BASE_URL` in the frontend environment:
   ```bash
   VITE_API_BASE_URL=https://phantom-backend-abc-uc.a.run.app
   ```

---

## 6. Running the Automated Test Suite

The backend includes tests for classifier precision, policy simulations, Zeek ingestion, and REST API routing:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run all tests with coverage
pytest app/tests/ -v
```

---

## 7. Important Operational Disclaimers

1. **Synthetic Evaluation Dataset:** The benchmark reports generated on the Test Report page evaluate model detection rules against a reproducible labeled synthetic dataset. While synthetic evaluation demonstrates algorithmic precision and recall, real-world enterprise traffic may exhibit novel evasion techniques or encrypted ClientHello (ECH) behaviors.
2. **Simulation Boundaries:** Every action generated in the Block Simulator or Policy Management page is an audit evaluation. PHANTOM AI does not alter host iptables or firewall configurations.
3. **Live Monitoring Claims:** Do not claim Zeek is connected or real enterprise traffic is monitored until explicit authorization and physical sensor configuration have taken place.

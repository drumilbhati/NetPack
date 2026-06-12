# Implementation Plan & GitHub Issues Breakdown

This document breaks down the "Network & Packet Forensics Platform" into manageable phases. Each feature listed below is formatted so you can easily copy and paste it into a GitHub Issue.

---

## Phase 1: Evidence Intake, Case Model & Audit Foundation
**Goal:** Build the forensic foundation before packet analysis: cases, evidence IDs, hashing, secure raw storage, and append-only audit/custody records.

### Issue 1.1: Define Canonical Evidence & Case Schema
*   **Title:** Create PostgreSQL Schema for Cases, Evidence, Custody, Jobs, and Audit
*   **Description:**
    *   **Goal:** Make PostgreSQL the system of record for all forensic evidence and workflows.
    *   **Tasks:**
        *   Create tables for `users`, `roles`, `cases`, `case_members`, `evidence_files`, `custody_events`, `parser_jobs`, `audit_events`, `reports`, and `alerts`.
        *   Use a canonical `case_id` and `evidence_id` across all records and future Elasticsearch documents.
        *   Store SHA-256 hash, file size, original filename, object key, upload actor, parser status, and timestamps for each evidence file.
        *   Add constraints that prevent duplicate active evidence records for the same case and hash.
    *   **Acceptance Criteria:** A migration creates the schema locally and a seed script can create a case, investigator, and evidence placeholder.

### Issue 1.2: Implement Secure PCAP Intake and Raw Storage
*   **Title:** Build Evidence Upload API with Hashing and MinIO Storage
*   **Description:**
    *   **Goal:** Register evidence safely before any parsing occurs.
    *   **Tasks:**
        *   Add FastAPI endpoint `POST /cases/{case_id}/evidence`.
        *   Validate file extension, MIME/type hints, maximum size, and authenticated user permissions.
        *   Stream uploaded PCAP content while calculating SHA-256.
        *   Store the raw file in MinIO using a sanitized object key based on `case_id` and `evidence_id`.
        *   Create the evidence record, first custody event, and audit event in PostgreSQL.
        *   Detect duplicate uploads by hash within the same case.
    *   **Acceptance Criteria:** Uploading a sample PCAP creates one raw object, one evidence record, one custody event, and one audit event; uploading the same file again is handled idempotently.

### Issue 1.3: Local Infrastructure for Foundation Services
*   **Title:** Add Docker Compose for PostgreSQL, MinIO, Elasticsearch, and Worker Runtime
*   **Description:**
    *   **Goal:** Provide a reproducible local environment matching the architecture.
    *   **Tasks:**
        *   Configure PostgreSQL, MinIO, and Elasticsearch in `infra/docker-compose.yml`.
        *   Use environment variables for all credentials and service URLs.
        *   Add health checks for each service.
        *   Document startup and teardown commands.
    *   **Acceptance Criteria:** `docker compose up` starts all services and the backend can connect using local environment settings.

### Issue 1.4: Append-Only Audit and Chain-of-Custody Service
*   **Title:** Implement Audit and Custody Event Recording
*   **Description:**
    *   **Goal:** Make forensic traceability a core platform behavior.
    *   **Tasks:**
        *   Create a shared service for writing `audit_events` and `custody_events`.
        *   Record actor, role, action, target type, target ID, timestamp, request ID, and metadata.
        *   Call the service from evidence upload, evidence view, search, export, and future parser jobs.
        *   Prevent update/delete operations on custody events through application code.
    *   **Acceptance Criteria:** Evidence upload and evidence retrieval both create immutable audit records.

---

## Phase 2: Asynchronous Parsing, DPI & Search
**Goal:** Convert registered PCAP evidence into searchable metadata without compromising raw evidence integrity.

### Issue 2.1: FastAPI Backend and Case Management
*   **Title:** Initialize FastAPI Project with Authenticated Case APIs
*   **Description:**
    *   **Goal:** Set up the backend server framework with case-scoped access controls.
    *   **Tasks:**
        *   Initialize FastAPI application structure.
        *   Add basic authentication stub suitable for local development.
        *   Create endpoints: `POST /cases`, `GET /cases`, `GET /cases/{case_id}`, and `GET /cases/{case_id}/evidence`.
        *   Enforce role and case membership checks at the API layer.
        *   Write audit events for case reads and writes.
    *   **Acceptance Criteria:** API is running, Swagger UI is accessible, and unauthorized users cannot access cases they do not belong to.

### Issue 2.2: Asynchronous PCAP Parser Worker
*   **Title:** Build Retryable Parser Jobs for Registered Evidence
*   **Description:**
    *   **Goal:** Parse PCAPs after intake using a retryable job boundary.
    *   **Tasks:**
        *   Create parser job records when evidence upload succeeds.
        *   Implement a worker that fetches raw PCAPs from MinIO by `evidence_id`.
        *   Extract source IP, destination IP, ports, protocol, packet counts, byte counts, timestamps, and flow direction.
        *   Record parser version and parser status in PostgreSQL.
        *   Make parser jobs idempotent and retryable.
    *   **Acceptance Criteria:** A sample PCAP upload transitions from `registered` to `parsed` and produces flow metadata without duplicate records on retry.

### Issue 2.3: DPI Enrichment for HTTP, DNS, and TLS Metadata
*   **Title:** Enrich Parsed Flows with Protocol-Level Metadata
*   **Description:**
    *   **Goal:** Support meaningful forensic search and detection beyond IP/port tuples.
    *   **Tasks:**
        *   Decode DNS queries, response codes, answer counts, and query entropy.
        *   Decode HTTP methods, hosts, URLs, status codes, and User-Agent where available.
        *   Extract TLS SNI, certificate metadata, and JA3/JA4 fingerprints where supported.
        *   Record parser errors per flow/session without failing the whole evidence file.
    *   **Acceptance Criteria:** Search can filter by DNS domain, HTTP host/User-Agent, and TLS SNI/fingerprint for supported PCAP samples.

### Issue 2.4: Elasticsearch Indexing and Search API
*   **Title:** Index Flow Metadata and Implement Case-Scoped Search
*   **Description:**
    *   **Goal:** Allow investigators to search parsed evidence quickly while PostgreSQL remains authoritative.
    *   **Tasks:**
        *   Create Elasticsearch index mappings for flows, sessions, protocol fields, and alert references.
        *   Include `case_id`, `evidence_id`, parser version, and packet/time bounds on every document.
        *   Create endpoint `GET /cases/{case_id}/search`.
        *   Support filters for source IP, destination IP, protocol, ports, time range, DNS domain, HTTP host, TLS SNI, and anomaly status.
        *   Write audit events for every search.
    *   **Acceptance Criteria:** Searching by IP, protocol, domain, and time range returns only records from cases the user can access.

---

## Phase 3: Investigator Dashboard and Review Workflow
**Goal:** Give investigators usable case, search, graph, timeline, and alert review screens.

### Issue 3.1: React Dashboard and Case Views
*   **Title:** Build Investigator Dashboard Shell
*   **Description:**
    *   **Goal:** Provide the core UI for case-based investigation.
    *   **Tasks:**
        *   Create a React/Vite app with routes for cases, evidence, search, alerts, graph, timeline, and reports.
        *   Display cases and evidence files from the FastAPI backend.
        *   Show evidence processing state: registered, parsing, parsed, failed, retrying.
        *   Surface custody timeline and key evidence hashes.
    *   **Acceptance Criteria:** An investigator can open a case, see evidence files, processing status, and custody events.

### Issue 3.2: Search, Graph, and Timeline Views
*   **Title:** Implement Flow Search, Network Graph, and Timeline UI
*   **Description:**
    *   **Goal:** Make parsed metadata usable for investigation.
    *   **Tasks:**
        *   Build a searchable flow table with filters matching the backend search API.
        *   Build a graph view mapping IPs/domains to nodes and flows to edges.
        *   Build a timeline view showing evidence import, parsed sessions, and alerts over time.
        *   Highlight suspicious or high-severity flows consistently across views.
    *   **Acceptance Criteria:** Search results, graph, and timeline all render from the same case-scoped flow data.

### Issue 3.3: Alert Review Workflow
*   **Title:** Add Alert Triage and Analyst Feedback
*   **Description:**
    *   **Goal:** Let investigators review, classify, and document suspicious traffic.
    *   **Tasks:**
        *   Create alert states: open, investigating, confirmed, false_positive, closed.
        *   Add investigator notes and severity overrides.
        *   Record all alert changes in audit events.
    *   **Acceptance Criteria:** An investigator can mark an alert as confirmed or false positive and the action appears in the audit trail.

---

## Phase 4: Threat Detection and AI Scoring
**Goal:** Add rule-based and model-based detection with measurable outputs and analyst feedback.

### Issue 4.1: Signature-Based Detection
*   **Title:** Integrate Rule-Based Detection for Known Threat Patterns
*   **Description:**
    *   **Goal:** Detect known suspicious behaviors before relying on ML.
    *   **Tasks:**
        *   Add rules for suspicious DNS tunneling indicators, known bad domains/IPs, uncommon ports, beacon-like intervals, and high-volume outbound transfer.
        *   Store rule ID, version, matched fields, severity, and explanation for each alert.
        *   Run rules after parsing and on parser retry without duplicating alerts.
    *   **Acceptance Criteria:** Known synthetic suspicious samples generate explainable alerts tied to evidence and flow IDs.

### Issue 4.2: Anomaly Feature Schema and Baseline
*   **Title:** Build Feature Extraction for Anomaly Detection
*   **Description:**
    *   **Goal:** Define features before training or scoring models.
    *   **Tasks:**
        *   Extract duration, bytes/packets by direction, protocol, port rarity, destination rarity, DNS entropy, periodicity, and TLS fingerprint features.
        *   Define case-level or network-level baseline windows.
        *   Store feature vectors with model version and evidence references.
    *   **Acceptance Criteria:** Feature extraction produces stable, versioned vectors for multiple PCAP samples.

### Issue 4.3: Isolation Forest Anomaly Scoring
*   **Title:** Train and Integrate Initial Anomaly Model
*   **Description:**
    *   **Goal:** Flag unusual flows with explainable context.
    *   **Tasks:**
        *   Train an Isolation Forest model on the agreed feature schema.
        *   Store model version, training data summary, and scoring threshold.
        *   Generate alerts with top contributing features where possible.
        *   Compare against a small labeled/synthetic evaluation set.
    *   **Acceptance Criteria:** The model flags high-volume exfiltration, rare destinations, and DNS tunneling samples with documented false positives.

---

## Phase 5: Forensic Reporting and Evidence Export
**Goal:** Produce legally defensible reports and export packages.

### Issue 5.1: Automated Evidence Reporting
*   **Title:** PDF Report Generation with Chain of Custody
*   **Description:**
    *   **Goal:** Export a court-ready document.
    *   **Tasks:**
        *   Create a backend endpoint `GET /report/{case_id}`.
        *   Generate a PDF that includes case details, investigator name, selected evidence files, custody timeline, summary of anomalies, selected flows, parser version, and the SHA-256 hash of each original PCAP.
        *   Generate an export hash for the final PDF/package.
        *   Record report generation and download as audit events.
    *   **Acceptance Criteria:** Can download a formatted PDF containing accurate data, hashes, custody timeline, and audit-visible export metadata.

### Issue 5.2: Evidence Export Package
*   **Title:** Create Verifiable Evidence Export Bundle
*   **Description:**
    *   **Goal:** Export selected evidence and derived records in a verifiable package.
    *   **Tasks:**
        *   Bundle report PDF, selected CSV/JSON flow records, hash manifest, and custody log.
        *   Include original evidence hashes and generated export package hash.
        *   Store the export bundle in object storage using case/report IDs.
    *   **Acceptance Criteria:** Recomputing hashes from the bundle matches the manifest.

---

## Phase 6: Live Capture, Streaming & Scale
**Goal:** Extend the PCAP-first platform to high-throughput live network capture without changing the evidence model.

### Issue 6.1: Kafka-Based Streaming Ingestion
*   **Title:** Add Kafka Pipeline for Live Capture and Backpressure
*   **Description:**
    *   **Goal:** Support high-throughput capture after the MVP proves the evidence workflow.
    *   **Tasks:**
        *   Add Kafka topics for raw capture chunks, parser jobs, parsed flows, and alerts.
        *   Define partition keys based on case, sensor, and flow/session identity.
        *   Track dropped packets, capture gaps, queue lag, and parser throughput.
    *   **Acceptance Criteria:** A live/simulated capture feed can be processed without changing downstream evidence, search, alert, or report APIs.

### Issue 6.2: SIEM and Deployment Hardening
*   **Title:** Prepare Production Deployment and SIEM Integration
*   **Description:**
    *   **Goal:** Move from prototype to deployable platform.
    *   **Tasks:**
        *   Add Kubernetes manifests or Helm charts.
        *   Add TLS, secrets management, backup/restore, retention policies, and monitoring.
        *   Export selected alerts and audit events to SIEM-compatible formats.
    *   **Acceptance Criteria:** The platform can be deployed with environment-specific secrets and emits health, performance, and security telemetry.

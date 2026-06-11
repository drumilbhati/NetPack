# Implementation Plan & GitHub Issues Breakdown

This document breaks down the "Network & Packet Forensics Platform" into manageable phases. Each feature listed below is formatted so you can easily copy and paste it into a GitHub Issue.

---

## Phase 1: Core Capture & Storage (The Foundation)
**Goal:** Ingest raw packets and store them securely with searchable metadata.

### Issue 1.1: Setup Basic PCAP Ingestion Pipeline
*   **Title:** Build Basic PCAP Ingestion & Parsing Script
*   **Description:**
    *   **Goal:** Create a Python script using `scapy` or `pyshark` that can read a `.pcap` file.
    *   **Tasks:**
        *   Extract Source IP, Destination IP, Source Port, Dest Port, Protocol.
        *   Calculate the SHA-256 hash of the ingested `.pcap` file.
        *   Output the extracted metadata to a JSON file.
    *   **Acceptance Criteria:** Script successfully runs against a sample PCAP file and produces a valid JSON output and hash.

### Issue 1.2: Database Integration (PostgreSQL & Elasticsearch)
*   **Title:** Setup Database Schema and Elasticsearch Indexing
*   **Description:**
    *   **Goal:** Store the extracted metadata securely and make it searchable.
    *   **Tasks:**
        *   Setup a local PostgreSQL database (via Docker).
        *   Create tables for `cases`, `evidence_files` (storing the SHA-256 hash), and `investigators`.
        *   Setup a local Elasticsearch node (via Docker).
        *   Write a script to push the JSON metadata from Issue 1.1 into Elasticsearch.
    *   **Acceptance Criteria:** Can query PostgreSQL for the file hash and Elasticsearch for specific IP addresses.

### Issue 1.3: Secure File Storage (MinIO)
*   **Title:** Implement Raw PCAP Storage in MinIO
*   **Description:**
    *   **Goal:** Securely store the original evidence files.
    *   **Tasks:**
        *   Deploy MinIO using Docker.
        *   Write a Python function to upload the raw `.pcap` file to a MinIO bucket after ingestion.
        *   Link the MinIO object URL to the PostgreSQL `evidence_files` record.
    *   **Acceptance Criteria:** Uploaded PCAP is visible in the MinIO console and linked in the database.

---

## Phase 2: Backend API & Basic Investigation (The Engine)
**Goal:** Expose the stored data via APIs for the frontend to consume.

### Issue 2.1: FastAPI Backend Setup
*   **Title:** Initialize FastAPI Project and Case Management Endpoints
*   **Description:**
    *   **Goal:** Set up the backend server framework.
    *   **Tasks:**
        *   Initialize a FastAPI project.
        *   Create REST endpoints: `POST /cases` (create case), `GET /cases` (list cases).
        *   Create endpoint: `POST /upload` to handle new PCAP uploads (triggering Phase 1 logic).
    *   **Acceptance Criteria:** API is running and Swagger UI is accessible. Can create a case via API.

### Issue 2.2: Search API
*   **Title:** Implement Network Flow Search Endpoint
*   **Description:**
    *   **Goal:** Allow investigators to search packet data.
    *   **Tasks:**
        *   Create endpoint: `GET /search`.
        *   Implement query parameters: `source_ip`, `dest_ip`, `protocol`, `time_range`.
        *   Connect the endpoint to Elasticsearch to fetch results.
    *   **Acceptance Criteria:** Searching for a specific IP via the API returns the correct packet metadata from Elasticsearch.

---

## Phase 3: Deep Packet Inspection & AI (The Intelligence)
**Goal:** Add advanced analysis capabilities.

### Issue 3.1: Protocol Decoding (HTTP/DNS)
*   **Title:** Enhance Parsing with Deep Packet Inspection (DPI)
*   **Description:**
    *   **Goal:** Extract payloads from common protocols.
    *   **Tasks:**
        *   Update the ingest script to decode HTTP requests (URLs, User-Agents).
        *   Update the ingest script to decode DNS queries.
        *   Push this enriched data to Elasticsearch.
    *   **Acceptance Criteria:** Search API can now filter by HTTP User-Agent or requested DNS domain.

### Issue 3.2: Anomaly Detection Model
*   **Title:** Train and Integrate Anomaly Detection Model
*   **Description:**
    *   **Goal:** Flag suspicious traffic automatically.
    *   **Tasks:**
        *   Use `scikit-learn` to build an Isolation Forest model.
        *   Train it on standard flow features (bytes sent/received, duration).
        *   Create an endpoint or background worker that scores new flows and flags anomalies.
    *   **Acceptance Criteria:** The system successfully flags artificially injected high-volume flows as anomalous.

---

## Phase 4: Visualization & UI (The Dashboard)
**Goal:** Build the React interface for investigators.

### Issue 4.1: React Dashboard Setup
*   **Title:** Initialize React App and Dashboard Layout
*   **Description:**
    *   **Goal:** Setup the frontend shell.
    *   **Tasks:**
        *   Create a React/Vite project.
        *   Set up routing (e.g., Dashboard, Case Management, Search).
        *   Implement basic API fetching from the FastAPI backend.
    *   **Acceptance Criteria:** UI displays a list of cases fetched from the backend.

### Issue 4.2: Network Graph Visualization
*   **Title:** Implement D3.js Network Flow Map
*   **Description:**
    *   **Goal:** Visualize "who is talking to whom."
    *   **Tasks:**
        *   Integrate a library like `react-d3-graph` or `vis.js`.
        *   Fetch flow data from the backend and map IPs to nodes, and flows to edges.
        *   Highlight anomalous nodes (from Issue 3.2) in red.
    *   **Acceptance Criteria:** A visual graph renders showing network connections.

---

## Phase 5: Forensics & Reporting (The Final Polish)
**Goal:** Ensure legal admissibility.

### Issue 5.1: Automated Evidence Reporting
*   **Title:** PDF Report Generation with Chain of Custody
*   **Description:**
    *   **Goal:** Export a court-ready document.
    *   **Tasks:**
        *   Create a backend endpoint `GET /report/{case_id}`.
        *   Generate a PDF that includes: Case Details, Investigator Name, Summary of Anomalies, and the **SHA-256 Hash of the original PCAP**.
    *   **Acceptance Criteria:** Can download a formatted PDF containing accurate data and hashes.

# NetPack: Network & Packet Forensics Platform

## Project Overview
A centralized platform for capturing, analyzing, and visualizing network traffic to detect hidden threats and generate legally admissible digital evidence.

## Directory Structure
- `backend/`: FastAPI application for case management, search, and reporting.
- `frontend/`: React application (Vite/TS) for the investigator dashboard and visualizations.
- `data_processing/`: Core ingestion engine and Deep Packet Inspection (DPI) logic.
- `data_processing/index_metadata.py`: Indexes extracted JSON metadata into Elasticsearch.
- `ml_models/`: AI/ML logic for behavioral anomaly detection.
- `infra/`: Docker configurations for Elasticsearch, PostgreSQL, Kafka, and MinIO.
- Root-level Markdown files: problem statement, solution architecture, and implementation plan.

## Getting Started
1. **Infrastructure:** Navigate to `infra/`, copy `.env.example` to `.env`, and run `docker compose up -d postgres minio minio-init elasticsearch`.
2. **Backend:** Navigate to `backend/`, install requirements, and run `uvicorn app.main:app`.
3. **Frontend:** Navigate to `frontend/`, run `npm install` and `npm run dev`.
4. **Live Capture (Optional):** Run `python3 data_processing/live_capture.py --interface eth0 --case-id <UUID>` to start sniffing.

## Documentation
- [Problem Statement](./PROBLEM_STATEMENT.md)
- [Solution Architecture](./SOLUTION_ARCHITECTURE.md)
- [Implementation Plan](./IMPLEMENTATION_PLAN.md)

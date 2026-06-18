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

## GitHub Pages (Frontend)
- Frontend deployment is automated via `.github/workflows/deploy.yml` on pushes to `main`.
- The Vite base path is configured for repository pages (`/NetPack/`) in `frontend/vite.config.ts`.
- In GitHub repository settings, set **Pages source** to **GitHub Actions**.

## GitHub Codespaces (Backend + ML + Infra)
- Codespaces config is in `.devcontainer/devcontainer.json`.
- On first create, dependencies are installed by `.devcontainer/postCreate.sh`.
- On start, infra services (`postgres`, `minio`, `minio-init`, `elasticsearch`) are started by `.devcontainer/postStart.sh`.
- You can manually start app services with:
  - `bash scripts/start-all.sh`
- Service ports forwarded in Codespaces:
  - `5173` frontend
  - `8000` backend
  - `5432` postgres
  - `9000` minio API
  - `9001` minio console
  - `9200` elasticsearch

## Documentation
- [Problem Statement](./PROBLEM_STATEMENT.md)
- [Solution Architecture](./SOLUTION_ARCHITECTURE.md)
- [Implementation Plan](./IMPLEMENTATION_PLAN.md)

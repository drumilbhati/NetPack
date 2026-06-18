#!/usr/bin/env bash
set -euo pipefail

# Start infra
if command -v docker >/dev/null 2>&1; then
  docker compose -f infra/docker-compose.yml up -d postgres minio minio-init elasticsearch
fi

# Start backend
nohup python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 > /tmp/netpack-backend.log 2>&1 &

# Optional: start frontend dev server
nohup npm --prefix frontend run dev -- --host 0.0.0.0 --port 5173 > /tmp/netpack-frontend.log 2>&1 &

echo "NetPack services started"
echo "Backend logs: /tmp/netpack-backend.log"
echo "Frontend logs: /tmp/netpack-frontend.log"

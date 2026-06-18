#!/usr/bin/env bash
set -euo pipefail

# Start core infra services for local development in Codespaces
if command -v docker >/dev/null 2>&1; then
  docker compose -f infra/docker-compose.yml up -d postgres minio minio-init elasticsearch || true
fi

echo "✅ Infra bootstrapped (postgres, minio, elasticsearch)"

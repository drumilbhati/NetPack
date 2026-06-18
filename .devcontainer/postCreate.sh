#!/usr/bin/env bash
set -euo pipefail

# Backend dependencies
python -m pip install --upgrade pip
pip install -r backend/requirements.txt

# Frontend dependencies
npm --prefix frontend ci

# Infra env setup
if [ -f infra/.env.example ] && [ ! -f infra/.env ]; then
  cp infra/.env.example infra/.env
fi

echo "✅ NetPack Codespace dependencies installed"

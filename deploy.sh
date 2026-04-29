#!/usr/bin/env bash
set -euo pipefail

BRANCH="${1:-main}"

echo "==> Pulling latest changes from branch: $BRANCH"
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git pull origin "$BRANCH"

echo "==> Rebuilding and restarting Docker containers"
sudo docker compose down
sudo docker compose up -d --build

echo "==> Done. Container status:"
sudo docker compose ps

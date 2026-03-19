#!/bin/bash
set -euo pipefail

# Ensure required writable files/directories exist
mkdir -p data checker
touch config.yaml 2>/dev/null
chmod 666 config.yaml 2>/dev/null || true

docker compose build
docker compose down
docker compose up -d

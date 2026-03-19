#!/bin/bash
set -euo pipefail

# Bootstrap first-run files with a startup-safe config.
if [ ! -s config.yaml ]; then
  cp config.example.yaml config.yaml
fi

if [ ! -f nodes.txt ]; then
  : > nodes.txt
fi

# Ensure config files are writable for WebUI settings.
chmod 666 config.yaml nodes.txt 2>/dev/null || true

docker compose build
docker compose down
docker compose up -d

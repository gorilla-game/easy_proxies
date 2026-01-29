#!/bin/bash
# Ensure config files are writable for WebUI settings
touch config.yaml nodes.txt 2>/dev/null
chmod 666 config.yaml nodes.txt 2>/dev/null || true
docker compose build && docker compose down && docker compose up -d

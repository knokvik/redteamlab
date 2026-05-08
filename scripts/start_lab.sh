#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/docker/docker-compose.yml"
PROJECT_NAME="devredteam"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running or not reachable."
  exit 1
fi

# pentest_lab pattern: install Loki logging plugin before compose up.
if ! docker plugin ls --format '{{.Name}}' | grep -Eq '^loki(:|$)'; then
  echo "Installing Loki Docker logging plugin..."
  docker plugin install grafana/loki-docker-driver:latest --alias loki --grant-all-permissions
fi

echo "Starting DevRedTeam lab stack..."
docker compose -p "${PROJECT_NAME}" -f "${COMPOSE_FILE}" up -d --build --remove-orphans

# Orchestrator uses Docker SDK to validate attacker reachability to targets.
if python3 -c 'import docker, yaml, rich' >/dev/null 2>&1; then
  python3 "${PROJECT_ROOT}/core/orchestrator.py" \
    --compose-file "${COMPOSE_FILE}" \
    --project-name "${PROJECT_NAME}" \
    --skip-compose-up
else
  echo "Python dependencies missing. Install with: pip install -r ${PROJECT_ROOT}/requirements.txt"
  echo "Skipping orchestrator connectivity check."
fi

echo ""
echo "Lab access URLs:"
echo "  Target app:  http://localhost:9700"
echo "  Grafana:     http://localhost:8000"
echo "  Prometheus:  http://localhost:9090"
echo "  cAdvisor:    http://localhost:8080"
echo "  Loki API:    http://localhost:3100"

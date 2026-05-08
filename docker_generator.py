"""Generate target services and merge them with the existing lab compose."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_BASE_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.yml"
DEFAULT_OUTPUT_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.generated.yml"


def _relative_repo_mount(repo_path: Path, project_root: Path) -> str:
    try:
        rel = repo_path.relative_to(project_root)
        return f"../{rel.as_posix()}"
    except ValueError:
        return str(repo_path)


def _first_network_name(compose_data: Dict) -> str:
    networks = compose_data.get("networks", {})
    if not networks:
        raise ValueError("Compose file has no network definitions.")
    return next(iter(networks))


def _target_services_from_detection(
    detection: Dict,
    network_name: str,
    repo_mount: str,
) -> Tuple[Dict, Dict]:
    services: Dict = {}
    db_metadata: Dict = {"service": None, "type": None}

    frontend_path = detection.get("frontend", {}).get("path")
    backend_path = detection.get("backend", {}).get("path")
    db_type = detection.get("database", {}).get("type")

    if frontend_path:
        services["target-frontend"] = {
            "image": "node:20-alpine",
            "working_dir": "/app",
            "command": "sh -c \"npm install && npm run dev -- --host 0.0.0.0 --port 3000\"",
            "ports": ["3000:3000"],
            "volumes": [f"{repo_mount}:/app"],
            "labels": {"class": "victim", "cluster": "devredteam"},
            "networks": {network_name: {"ipv4_address": "10.50.0.20"}},
        }

    if backend_path:
        backend_kind = detection.get("backend", {}).get("kind")
        backend_service = {
            "labels": {"class": "victim", "cluster": "devredteam"},
            "networks": {network_name: {"ipv4_address": "10.50.0.30"}},
            "volumes": [f"{repo_mount}:/app"],
            "working_dir": "/app",
            "depends_on": [],
        }

        if backend_kind == "fastapi":
            backend_service.update(
                {
                    "image": "python:3.11-slim",
                    "command": "sh -c \"pip install -r requirements.txt && uvicorn main:app --host 0.0.0.0 --port 8000\"",
                    "ports": ["8001:8000"],
                }
            )
        else:
            backend_service.update(
                {
                    "image": "node:20-alpine",
                    "command": "sh -c \"npm install && npm run dev -- --host 0.0.0.0\"",
                    "ports": ["8001:8000"],
                }
            )

        services["target-backend"] = backend_service

    if db_type == "postgres":
        services["target-db"] = {
            "image": "postgres:15",
            "environment": {
                "POSTGRES_DB": "appdb",
                "POSTGRES_USER": "app",
                "POSTGRES_PASSWORD": "app",
            },
            "ports": ["5432:5432"],
            "volumes": ["target-db-data:/var/lib/postgresql/data"],
            "labels": {"class": "victim", "cluster": "devredteam"},
            "networks": {network_name: {"ipv4_address": "10.50.0.40"}},
        }
        db_metadata = {"service": "target-db", "type": "postgres"}
    elif db_type == "mysql":
        services["target-db"] = {
            "image": "mysql:8",
            "environment": {
                "MYSQL_DATABASE": "appdb",
                "MYSQL_USER": "app",
                "MYSQL_PASSWORD": "app",
                "MYSQL_ROOT_PASSWORD": "root",
            },
            "ports": ["3306:3306"],
            "volumes": ["target-db-data:/var/lib/mysql"],
            "labels": {"class": "victim", "cluster": "devredteam"},
            "networks": {network_name: {"ipv4_address": "10.50.0.40"}},
        }
        db_metadata = {"service": "target-db", "type": "mysql"}

    return services, db_metadata


def generate_compose_for_repo(
    repo_path: Path | str,
    detection: Dict,
    base_compose_path: Path | str | None = None,
    output_compose_path: Path | str | None = None,
) -> Dict:
    """Create a merged compose file containing base + generated target services."""
    project_root = PROJECT_ROOT
    repo_dir = Path(repo_path).resolve()
    base_path = Path(base_compose_path) if base_compose_path else DEFAULT_BASE_COMPOSE
    output_path = Path(output_compose_path) if output_compose_path else DEFAULT_OUTPUT_COMPOSE

    base_compose = yaml.safe_load(base_path.read_text(encoding="utf-8"))
    merged = json.loads(json.dumps(base_compose))

    network_name = _first_network_name(merged)
    repo_mount = _relative_repo_mount(repo_dir, project_root)

    generated_services, db_metadata = _target_services_from_detection(detection, network_name, repo_mount)

    # Keep attacker + monitoring intact, replace placeholder victim only when dynamic targets exist.
    if generated_services and "target-web" in merged.get("services", {}):
        merged["services"].pop("target-web", None)

    merged["services"].update(generated_services)

    if "target-db" in generated_services:
        merged.setdefault("volumes", {})["target-db-data"] = None

    output_path.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")

    return {
        "compose_file": str(output_path),
        "db": db_metadata,
        "generated_services": sorted(generated_services.keys()),
    }

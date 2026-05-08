"""Generate target services and merge them with the existing lab compose."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_BASE_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.yml"
DEFAULT_OUTPUT_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.generated.yml"


def _first_network_name(compose_data: Dict) -> str:
    networks = compose_data.get("networks", {})
    if not networks:
        raise ValueError("Compose file has no network definitions.")
    return next(iter(networks))


def _clone_dict(data: Dict) -> Dict:
    return json.loads(json.dumps(data))


def _labels(role: str) -> Dict:
    return {"class": "victim", "cluster": "devredteam", "app.role": role}


def _workdir_for(repo_path: Path, component_path: str | None) -> str:
    if not component_path:
        return "/repo"
    try:
        rel = Path(component_path).resolve().relative_to(repo_path.resolve())
        if not str(rel) or str(rel) == ".":
            return "/repo"
        return f"/repo/{rel.as_posix()}"
    except ValueError:
        return "/repo"


def _target_services_from_detection(
    repo_path: Path,
    detection: Dict,
    network_name: str,
) -> Tuple[Dict, Dict]:
    services: Dict = {}
    db_metadata: Dict = {"service": None, "type": None}

    frontend_kind = detection.get("frontend", {}).get("kind")
    frontend_path = detection.get("frontend", {}).get("path")
    backend_kind = detection.get("backend", {}).get("kind")
    backend_path = detection.get("backend", {}).get("path")
    db_type = detection.get("database", {}).get("type")

    repo_mount = f"{repo_path}:/repo"
    web_workdir = _workdir_for(repo_path, frontend_path or backend_path)
    api_workdir = _workdir_for(repo_path, backend_path)

    # Always create target-web so attacker depends_on remains valid.
    web_service = {
        "labels": _labels("web"),
        "networks": {network_name: {"ipv4_address": "10.50.0.20"}},
    }

    if frontend_kind == "vite-react":
        web_service.update(
            {
                "image": "node:20-alpine",
                "volumes": [repo_mount],
                "working_dir": web_workdir,
                "command": (
                    "sh -c \"npm install && npm run dev -- --host 0.0.0.0 --port 5173\""
                ),
                "ports": ["5173:5173"],
            }
        )
    elif frontend_kind == "nextjs":
        web_service.update(
            {
                "image": "node:20-alpine",
                "volumes": [repo_mount],
                "working_dir": web_workdir,
                "command": (
                    "sh -c \"npm install && npm run dev -- -H 0.0.0.0 -p 5173\""
                ),
                "ports": ["5173:5173"],
            }
        )
    else:
        # Fallback: always expose a reachable victim web service.
        web_service.update(
            {
                "image": "nginx:alpine",
                "ports": ["5173:80"],
                "volumes": [f"{repo_path}:/usr/share/nginx/html:ro"],
            }
        )

    services["target-web"] = web_service

    if backend_kind:
        api_service = {
            "labels": _labels("api"),
            "networks": {network_name: {"ipv4_address": "10.50.0.30"}},
            "volumes": [repo_mount],
            "working_dir": api_workdir,
            "depends_on": [],
        }
        if backend_kind == "fastapi":
            api_service.update(
                {
                    "image": "python:3.11-slim",
                    "command": (
                        "sh -c \"pip install -r requirements.txt && "
                        "uvicorn main:app --host 0.0.0.0 --port 8000\""
                    ),
                    "ports": ["8000:8000"],
                }
            )
        else:
            api_service.update(
                {
                    "image": "node:20-alpine",
                    "command": (
                        "sh -c \"npm install && "
                        "(npm run dev -- --host 0.0.0.0 --port 3000 || npm start)\""
                    ),
                    "ports": ["3000:3000"],
                }
            )
        services["target-api"] = api_service
        services["target-web"].setdefault("depends_on", []).append("target-api")

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
            "labels": _labels("db"),
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
            "labels": _labels("db"),
            "networks": {network_name: {"ipv4_address": "10.50.0.40"}},
        }
        db_metadata = {"service": "target-db", "type": "mysql"}

    if "target-db" in services and "target-api" in services:
        services["target-api"].setdefault("depends_on", []).append("target-db")

    return services, db_metadata


def generate_compose_for_repo(
    repo_path: Path | str,
    detection: Dict,
    base_compose_path: Path | str | None = None,
    output_compose_path: Path | str | None = None,
) -> Dict:
    """Create a merged compose file containing base + generated target services."""
    repo_dir = Path(repo_path).resolve()
    base_path = Path(base_compose_path) if base_compose_path else DEFAULT_BASE_COMPOSE
    output_path = Path(output_compose_path) if output_compose_path else DEFAULT_OUTPUT_COMPOSE

    base_compose = yaml.safe_load(base_path.read_text(encoding="utf-8")) or {}
    merged = _clone_dict(base_compose)

    network_name = _first_network_name(merged)
    generated_services, db_metadata = _target_services_from_detection(
        repo_path=repo_dir,
        detection=detection,
        network_name=network_name,
    )

    # Replace stale placeholder victims but keep attacker + monitoring untouched.
    for service_name in ("target-web", "target-frontend", "target-backend", "target-api", "target-db"):
        if service_name in merged.get("services", {}) and service_name not in generated_services:
            merged["services"].pop(service_name, None)

    merged.setdefault("services", {}).update(generated_services)

    if "target-db" in generated_services:
        merged.setdefault("volumes", {})["target-db-data"] = None

    output_path.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")

    return {
        "compose_file": str(output_path),
        "db": db_metadata,
        "generated_services": sorted(generated_services.keys()),
    }

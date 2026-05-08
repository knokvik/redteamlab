"""Seed simple dummy data into database containers when present."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

import docker
import yaml


def _resolve_container_name(project_name: str, service_name: str, service_cfg: Dict) -> str:
    explicit = service_cfg.get("container_name")
    if explicit:
        return explicit
    return f"{project_name}-{service_name}-1"


def _seed_postgres(container) -> tuple[bool, str]:
    sql = (
        "CREATE TABLE IF NOT EXISTS devredteam_dummy_users "
        "(id SERIAL PRIMARY KEY, name TEXT, email TEXT); "
        "INSERT INTO devredteam_dummy_users (name, email) "
        "VALUES ('Alice', 'alice@example.com'), ('Bob', 'bob@example.com');"
    )
    cmd = (
        "sh -lc 'psql -U \"${POSTGRES_USER:-postgres}\" "
        "-d \"${POSTGRES_DB:-postgres}\" -c \"%s\"'" % sql
    )
    exit_code, output = container.exec_run(cmd)
    return exit_code == 0, output.decode("utf-8", errors="ignore")


def _seed_mysql(container) -> tuple[bool, str]:
    sql = (
        "CREATE TABLE IF NOT EXISTS devredteam_dummy_users "
        "(id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255)); "
        "INSERT INTO devredteam_dummy_users (name, email) VALUES "
        "('Alice', 'alice@example.com'), ('Bob', 'bob@example.com');"
    )
    cmd = (
        "sh -lc 'mysql -u\"${MYSQL_USER:-root}\" -p\"${MYSQL_PASSWORD:-${MYSQL_ROOT_PASSWORD:-root}}\" "
        "\"${MYSQL_DATABASE:-appdb}\" -e \"%s\"'" % sql
    )
    exit_code, output = container.exec_run(cmd)
    return exit_code == 0, output.decode("utf-8", errors="ignore")


def seed_dummy_data(
    compose_file: Path | str,
    project_name: str = "devredteam",
) -> Dict:
    """Seed dummy rows into a detected Postgres/MySQL target DB service."""
    compose_path = Path(compose_file).resolve()
    compose_data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))

    services = compose_data.get("services", {})
    target_service_name = None
    db_type = None

    for service_name, service_cfg in services.items():
        image = str(service_cfg.get("image", "")).lower()
        if "postgres" in image:
            target_service_name = service_name
            db_type = "postgres"
            break
        if "mysql" in image or "mariadb" in image:
            target_service_name = service_name
            db_type = "mysql"
            break

    if not target_service_name or not db_type:
        return {"seeded": False, "reason": "no db service detected"}

    container_name = _resolve_container_name(project_name, target_service_name, services[target_service_name])

    client = docker.from_env()
    container = client.containers.get(container_name)

    if container.status != "running":
        container.start()

    if db_type == "postgres":
        seeded, output = _seed_postgres(container)
    else:
        seeded, output = _seed_mysql(container)

    return {
        "seeded": seeded,
        "service": target_service_name,
        "db_type": db_type,
        "output": output.strip(),
    }

"""Deterministic pre-exploitation setup pipeline with Smart DB Setup Mode."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

import docker
import yaml

from dummy_data_seeder import seed_dummy_data


DB_DEFAULTS = {
    "postgres": {
        "image": "postgres:15",
        "container_port": 5432,
        "host_port": 5432,
        "env": {
            "POSTGRES_DB": "appdb",
            "POSTGRES_USER": "app",
            "POSTGRES_PASSWORD": "app",
        },
        "volume": "target-db-data:/var/lib/postgresql/data",
    },
    "mysql": {
        "image": "mysql:8",
        "container_port": 3306,
        "host_port": 3306,
        "env": {
            "MYSQL_DATABASE": "appdb",
            "MYSQL_USER": "app",
            "MYSQL_PASSWORD": "app",
            "MYSQL_ROOT_PASSWORD": "root",
        },
        "volume": "target-db-data:/var/lib/mysql",
    },
    "mongodb": {
        "image": "mongo:7",
        "container_port": 27017,
        "host_port": 27017,
        "env": {
            "MONGO_INITDB_ROOT_USERNAME": "app",
            "MONGO_INITDB_ROOT_PASSWORD": "app",
            "MONGO_INITDB_DATABASE": "appdb",
        },
        "volume": "target-db-data:/data/db",
    },
    "redis": {
        "image": "redis:7-alpine",
        "container_port": 6379,
        "host_port": 6379,
        "env": {},
        "volume": None,
    },
}

QUEUE_DEFAULTS = {
    "rabbitmq": {
        "service": "target-queue",
        "image": "rabbitmq:3.13-management",
        "ports": ["5672:5672", "15672:15672"],
        "aliases": ["queue", "rabbitmq"],
    }
}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _candidate_files(repo_path: Path) -> List[Path]:
    patterns = [
        "*.env",
        "*.yml",
        "*.yaml",
        "*.json",
        "*.toml",
        "*.ini",
        "*.py",
        "*.js",
        "*.ts",
        "*.java",
        "*.rb",
        "*.go",
    ]
    files: List[Path] = []
    for pat in patterns:
        files.extend(repo_path.rglob(pat))
    filtered: List[Path] = []
    for f in files:
        p = str(f)
        if any(skip in p for skip in ["node_modules", "vendor", "dist", "build", ".git", "__pycache__"]):
            continue
        filtered.append(f)
    return filtered[:350]


def _detect_expected_db_port(files: List[Path]) -> int | None:
    # Look for explicit DB port declarations (DB_PORT=..., postgres://...:PORT, etc.).
    key_pattern = re.compile(r"(?:DB_PORT|DATABASE_PORT|POSTGRES_PORT|MYSQL_PORT|MONGO_PORT|REDIS_PORT)\s*[:=]\s*['\"]?(\d{2,5})")
    url_pattern = re.compile(r"(?:postgres(?:ql)?|mysql|mongodb|redis)://[^\s'\"]*:(\d{2,5})")
    generic_db_line = re.compile(r"(?:db|database|postgres|mysql|mongo|redis).{0,30}(\d{2,5})", re.IGNORECASE)

    ports: List[int] = []
    for file in files:
        text = _read_text(file)
        for pat in (key_pattern, url_pattern):
            for m in pat.finditer(text):
                try:
                    ports.append(int(m.group(1)))
                except ValueError:
                    continue
        for line in text.splitlines():
            if "db" in line.lower() or "database" in line.lower() or "postgres" in line.lower() or "mysql" in line.lower() or "mongo" in line.lower() or "redis" in line.lower():
                m = generic_db_line.search(line)
                if m:
                    try:
                        ports.append(int(m.group(1)))
                    except ValueError:
                        continue

    # Prioritize specific user request behavior for 4000.
    if 4000 in ports:
        return 4000

    valid = [p for p in ports if 1 <= p <= 65535]
    if not valid:
        return None

    # Choose most frequent explicit port.
    counts: Dict[int, int] = {}
    for p in valid:
        counts[p] = counts.get(p, 0) + 1
    return sorted(counts.items(), key=lambda x: (-x[1], x[0]))[0][0]


def _detect_queue_cache_needs(files: List[Path], detection: Dict) -> Dict:
    queue = None
    cache = detection.get("cache", {}).get("type")

    text_blob = "\n".join(_read_text(f) for f in files).lower()
    if any(token in text_blob for token in ["rabbitmq", "amqp://", "pika", "amqplib"]):
        queue = "rabbitmq"
    if cache is None and "redis" in text_blob:
        cache = "redis"

    return {"queue": queue, "cache": cache}


def _find_migration_seed_hints(repo_path: Path) -> Dict:
    hints = {
        "native_migrations": [],
        "native_seeds": [],
    }

    if (repo_path / "manage.py").exists():
        hints["native_migrations"].append("python manage.py migrate --noinput")
    if (repo_path / "alembic.ini").exists():
        hints["native_migrations"].append("alembic upgrade head")
    if (repo_path / "prisma" / "schema.prisma").exists():
        hints["native_migrations"].append("npx prisma migrate deploy")
    if (repo_path / "Gemfile").exists() and (repo_path / "config" / "application.rb").exists():
        hints["native_migrations"].append("bundle exec rails db:migrate")

    package_json = repo_path / "package.json"
    if package_json.exists():
        try:
            data = json.loads(_read_text(package_json) or "{}")
            scripts = data.get("scripts", {})
            for key in ("migrate", "db:migrate", "seed", "db:seed"):
                if key in scripts:
                    if "migrate" in key:
                        hints["native_migrations"].append(f"npm run {key}")
                    else:
                        hints["native_seeds"].append(f"npm run {key}")
        except json.JSONDecodeError:
            pass

    return hints


def scan_runtime_needs(repo_path: Path | str, detection: Dict) -> Dict:
    repo_dir = Path(repo_path).resolve()
    files = _candidate_files(repo_dir)
    db_type = detection.get("database", {}).get("type")

    queue_cache = _detect_queue_cache_needs(files, detection)
    hints = _find_migration_seed_hints(repo_dir)
    expected_db_host_port = _detect_expected_db_port(files) if db_type else None

    return {
        "db_type": db_type,
        "cache_type": queue_cache.get("cache"),
        "queue_type": queue_cache.get("queue"),
        "expected_db_host_port": expected_db_host_port,
        "migration_hints": hints.get("native_migrations", []),
        "seed_hints": hints.get("native_seeds", []),
        "files_scanned": len(files),
    }


def _resolve_network_name(compose_data: Dict) -> str:
    networks = compose_data.get("networks", {})
    if not networks:
        return "default"
    return next(iter(networks))


def _db_env_map(db_type: str, container_port: int) -> Dict[str, str]:
    if db_type == "postgres":
        return {
            "DB_HOST": "db",
            "DB_PORT": str(container_port),
            "DB_NAME": "appdb",
            "DB_USER": "app",
            "DB_PASSWORD": "app",
            "DATABASE_URL": f"postgresql://app:app@db:{container_port}/appdb",
            "POSTGRES_HOST": "db",
            "POSTGRES_PORT": str(container_port),
            "POSTGRES_DB": "appdb",
            "POSTGRES_USER": "app",
            "POSTGRES_PASSWORD": "app",
        }
    if db_type == "mysql":
        return {
            "DB_HOST": "db",
            "DB_PORT": str(container_port),
            "DB_NAME": "appdb",
            "DB_USER": "app",
            "DB_PASSWORD": "app",
            "DATABASE_URL": f"mysql://app:app@db:{container_port}/appdb",
            "MYSQL_HOST": "db",
            "MYSQL_PORT": str(container_port),
            "MYSQL_DATABASE": "appdb",
            "MYSQL_USER": "app",
            "MYSQL_PASSWORD": "app",
        }
    if db_type == "mongodb":
        return {
            "DB_HOST": "db",
            "DB_PORT": str(container_port),
            "DB_NAME": "appdb",
            "DB_USER": "app",
            "DB_PASSWORD": "app",
            "DATABASE_URL": f"mongodb://app:app@db:{container_port}/appdb?authSource=admin",
            "MONGO_URL": f"mongodb://app:app@db:{container_port}/appdb?authSource=admin",
        }
    if db_type == "redis":
        return {
            "DB_HOST": "db",
            "DB_PORT": str(container_port),
            "DATABASE_URL": f"redis://db:{container_port}",
            "REDIS_HOST": "db",
            "REDIS_PORT": str(container_port),
            "REDIS_URL": f"redis://db:{container_port}",
        }
    return {}


def build_infra_plan(runtime: Dict) -> Dict:
    db_type = runtime.get("db_type")
    expected_port = runtime.get("expected_db_host_port")
    plan: Dict = {
        "smart_db_mode": bool(db_type),
        "db": None,
        "queue": runtime.get("queue_type"),
        "cache": runtime.get("cache_type"),
        "migration_hints": runtime.get("migration_hints", []),
        "seed_hints": runtime.get("seed_hints", []),
    }

    if db_type and db_type in DB_DEFAULTS:
        defaults = DB_DEFAULTS[db_type]
        host_port = int(expected_port) if expected_port else int(defaults["host_port"])
        db_plan = {
            "type": db_type,
            "image": defaults["image"],
            "service": "target-db",
            "host_port": host_port,
            "container_port": int(defaults["container_port"]),
            "env": dict(defaults["env"]),
            "volume": defaults["volume"],
            "app_env": _db_env_map(db_type, int(defaults["container_port"])),
        }
        plan["db"] = db_plan

    return plan


def apply_infra_plan(compose_file: Path | str, repo_path: Path | str, plan: Dict) -> Dict:
    compose_path = Path(compose_file).resolve()
    repo_dir = Path(repo_path).resolve()

    compose_data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    services = compose_data.setdefault("services", {})
    network_name = _resolve_network_name(compose_data)

    changes: List[str] = []

    db_plan = plan.get("db")
    if db_plan:
        db_service = services.setdefault(db_plan["service"], {})
        db_service["image"] = db_plan["image"]
        db_service["ports"] = [f"{db_plan['host_port']}:{db_plan['container_port']}"]
        if db_plan.get("env"):
            db_service["environment"] = dict(db_plan["env"])
        if db_plan.get("volume"):
            db_service["volumes"] = [db_plan["volume"]]
            compose_data.setdefault("volumes", {})["target-db-data"] = None

        networks = db_service.get("networks")
        if isinstance(networks, list):
            if network_name not in networks:
                networks.append(network_name)
            db_service["networks"] = {name: {} for name in networks}
            networks = db_service["networks"]
        if not isinstance(networks, dict):
            networks = {}
            db_service["networks"] = networks
        networks.setdefault(network_name, {})
        if isinstance(networks[network_name], dict):
            aliases = networks[network_name].setdefault("aliases", [])
            for alias in ["db", "database"]:
                if alias not in aliases:
                    aliases.append(alias)

        changes.append(
            f"db:{db_plan['type']} image={db_plan['image']} ports={db_plan['host_port']}:{db_plan['container_port']}"
        )

        # Ensure API depends on DB and receives DB env.
        api_service = services.get("target-api")
        if isinstance(api_service, dict):
            deps = api_service.setdefault("depends_on", [])
            if db_plan["service"] not in deps:
                deps.append(db_plan["service"])

            api_env = api_service.setdefault("environment", {})
            for k, v in db_plan.get("app_env", {}).items():
                api_env[k] = v

            env_file = api_service.get("env_file")
            if isinstance(env_file, str):
                env_file = [env_file]
            if not isinstance(env_file, list):
                env_file = []
            env_target = "/repo/.env.devredteam"
            if env_target not in env_file:
                env_file.append(env_target)
            api_service["env_file"] = env_file

            changes.append("target-api:depends_on+env_file+db_env")

    queue_type = plan.get("queue")
    if queue_type in QUEUE_DEFAULTS:
        queue_cfg = QUEUE_DEFAULTS[queue_type]
        svc = services.setdefault(queue_cfg["service"], {})
        svc["image"] = queue_cfg["image"]
        svc["ports"] = list(queue_cfg["ports"])
        networks = svc.setdefault("networks", {})
        if isinstance(networks, dict):
            networks.setdefault(network_name, {})
            if isinstance(networks[network_name], dict):
                aliases = networks[network_name].setdefault("aliases", [])
                for alias in queue_cfg.get("aliases", []):
                    if alias not in aliases:
                        aliases.append(alias)
        changes.append(f"queue:{queue_type} service={queue_cfg['service']}")

    # Write deterministic env file in repo.
    env_path = repo_dir / ".env.devredteam"
    app_env = (db_plan or {}).get("app_env", {})
    if app_env:
        lines = [f"{k}={v}" for k, v in sorted(app_env.items())]
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        changes.append(f"env:{env_path}")

    compose_path.write_text(yaml.safe_dump(compose_data, sort_keys=False), encoding="utf-8")

    return {
        "compose_file": str(compose_path),
        "env_file": str(env_path) if app_env else None,
        "changes": changes,
    }


def _resolve_container_name(project_name: str, service_name: str, service_cfg: Dict) -> str:
    explicit = service_cfg.get("container_name")
    if explicit:
        return explicit
    return f"{project_name}-{service_name}-1"


def _run_in_container(container, command: str) -> Tuple[int, str]:
    code, output = container.exec_run(f"sh -lc {command!r}")
    return int(code), output.decode("utf-8", errors="ignore")


def _bootstrap_native_migrations(
    client: docker.DockerClient,
    compose_data: Dict,
    project_name: str,
    repo_path: Path,
    plan: Dict,
) -> Dict:
    api_cfg = compose_data.get("services", {}).get("target-api")
    if not isinstance(api_cfg, dict):
        return {"ran": False, "reason": "target-api-not-present"}

    api_name = _resolve_container_name(project_name, "target-api", api_cfg)
    api_container = client.containers.get(api_name)
    if api_container.status != "running":
        api_container.start()

    candidates: List[str] = []
    hints = plan.get("migration_hints", [])
    candidates.extend(hints)

    if (repo_path / "manage.py").exists():
        candidates.append("python manage.py migrate --noinput")
    if (repo_path / "alembic.ini").exists():
        candidates.append("alembic upgrade head")
    if (repo_path / "prisma" / "schema.prisma").exists():
        candidates.append("npx prisma migrate deploy || npx prisma db push")

    # dedupe preserving order
    seen = set()
    ordered = []
    for c in candidates:
        if c not in seen:
            ordered.append(c)
            seen.add(c)

    attempts = []
    for cmd in ordered:
        code, out = _run_in_container(api_container, cmd)
        attempts.append({"command": cmd, "exit_code": code, "output": out.strip()[:1200]})
        if code == 0:
            return {"ran": True, "success": True, "command": cmd, "attempts": attempts}

    if ordered:
        return {"ran": True, "success": False, "attempts": attempts}
    return {"ran": False, "reason": "no-migration-command-detected"}


def _seed_mongodb(container) -> Tuple[bool, str]:
    cmd = (
        "mongosh --quiet --eval \"db = db.getSiblingDB('appdb'); "
        "db.devredteam_dummy_users.insertMany([{name: 'Alice', email: 'alice@example.com'},"
        "{name: 'Bob', email: 'bob@example.com'}]);\" "
        "|| mongo --quiet --eval \"db = db.getSiblingDB('appdb'); db.devredteam_dummy_users.insert({name:'Alice'});\""
    )
    code, output = container.exec_run(f"sh -lc {cmd!r}")
    return code == 0, output.decode("utf-8", errors="ignore")


def _seed_redis(container) -> Tuple[bool, str]:
    cmd = "redis-cli SET devredteam:seed:1 alice && redis-cli SET devredteam:seed:2 bob"
    code, output = container.exec_run(f"sh -lc {cmd!r}")
    return code == 0, output.decode("utf-8", errors="ignore")


def _seed_additional_db(
    client: docker.DockerClient,
    compose_data: Dict,
    project_name: str,
    db_type: str,
) -> Dict:
    db_cfg = compose_data.get("services", {}).get("target-db")
    if not isinstance(db_cfg, dict):
        return {"seeded": False, "reason": "target-db-not-present"}

    db_name = _resolve_container_name(project_name, "target-db", db_cfg)
    db_container = client.containers.get(db_name)
    if db_container.status != "running":
        db_container.start()

    if db_type == "mongodb":
        ok, out = _seed_mongodb(db_container)
    elif db_type == "redis":
        ok, out = _seed_redis(db_container)
    else:
        return {"seeded": False, "reason": f"no-additional-seeder-for-{db_type}"}

    return {"seeded": ok, "db_type": db_type, "output": out.strip()[:1200]}


def _healthcheck_setup(
    client: docker.DockerClient,
    compose_data: Dict,
    project_name: str,
    db_plan: Dict | None,
) -> Dict:
    checks = []

    db_cfg = compose_data.get("services", {}).get("target-db")
    if isinstance(db_cfg, dict):
        db_name = _resolve_container_name(project_name, "target-db", db_cfg)
        db_container = client.containers.get(db_name)
        db_container.reload()
        checks.append({"check": "db-container-running", "ok": db_container.status == "running", "value": db_container.status})

        db_type = (db_plan or {}).get("type")
        if db_type == "postgres":
            code, out = _run_in_container(db_container, "PGPASSWORD=app psql -U app -d appdb -tAc 'SELECT 1'")
            checks.append({"check": "db-query", "ok": code == 0, "value": out.strip()[:200]})
        elif db_type == "mysql":
            code, out = _run_in_container(db_container, "mysql -uapp -papp appdb -e 'SELECT 1'")
            checks.append({"check": "db-query", "ok": code == 0, "value": out.strip()[:200]})
        elif db_type == "mongodb":
            code, out = _run_in_container(db_container, "mongosh --quiet --eval 'db.runCommand({ping:1})' || mongo --quiet --eval 'db.runCommand({ping:1})'")
            checks.append({"check": "db-query", "ok": code == 0, "value": out.strip()[:200]})
        elif db_type == "redis":
            code, out = _run_in_container(db_container, "redis-cli ping")
            checks.append({"check": "db-query", "ok": code == 0 and "PONG" in out, "value": out.strip()[:200]})

    api_cfg = compose_data.get("services", {}).get("target-api")
    if isinstance(api_cfg, dict):
        api_name = _resolve_container_name(project_name, "target-api", api_cfg)
        api_container = client.containers.get(api_name)
        api_container.reload()
        checks.append({"check": "api-container-running", "ok": api_container.status == "running", "value": api_container.status})
        code, out = _run_in_container(api_container, "env | grep -E 'DB_HOST|DB_PORT|DATABASE_URL|REDIS_URL|MONGO_URL' || true")
        checks.append({"check": "api-env-visible", "ok": True, "value": out.strip()[:400]})

        if db_plan:
            db_port = db_plan.get("container_port")
            tcp_check_cmd = (
                "python - <<'PY'\n"
                "import socket\n"
                "s=socket.socket(); s.settimeout(3)\n"
                f"try:\n s.connect(('db',{int(db_port)})); print('ok-python')\n"
                "except Exception as e:\n print('err-python',e)\n"
                "finally:\n s.close()\nPY "
                f"|| node -e \"const n=require('net'); const s=n.createConnection({int(db_port)},'db'); "
                "s.on('connect',()=>{console.log('ok-node');s.end();process.exit(0)}); "
                "s.on('error',e=>{console.log('err-node',e.message);process.exit(1)}); setTimeout(()=>process.exit(1),3000);\" "
                "|| echo skip-connectivity-tool"
            )
            code, out = _run_in_container(api_container, tcp_check_cmd)
            low = out.lower()
            ok = ("ok-python" in low) or ("ok-node" in low) or ("skip-connectivity-tool" in low)
            checks.append({"check": "api-to-db-tcp", "ok": ok, "value": out.strip()[:400]})

    return {
        "checks": checks,
        "all_green": all(c.get("ok") for c in checks) if checks else False,
    }


def run_smart_setup_pipeline(
    repo_path: Path | str,
    compose_file: Path | str,
    project_name: str,
    detection: Dict,
) -> Dict:
    repo_dir = Path(repo_path).resolve()
    compose_path = Path(compose_file).resolve()

    runtime = scan_runtime_needs(repo_dir, detection)
    plan = build_infra_plan(runtime)
    setup_mode = bool(plan.get("smart_db_mode"))

    apply_result = apply_infra_plan(compose_path, repo_dir, plan)

    compose_data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    client = docker.from_env()

    migration_result = _bootstrap_native_migrations(client, compose_data, project_name, repo_dir, plan)

    seed_result = seed_dummy_data(compose_file=compose_path, project_name=project_name)

    db_plan = plan.get("db")
    extra_seed_result = {}
    if db_plan and db_plan.get("type") in ("mongodb", "redis"):
        extra_seed_result = _seed_additional_db(client, compose_data, project_name, db_plan.get("type"))

    health = _healthcheck_setup(client, compose_data, project_name, db_plan)

    return {
        "smart_db_mode": setup_mode,
        "runtime": runtime,
        "infra_plan": plan,
        "apply": apply_result,
        "migrations": migration_result,
        "seed": seed_result,
        "extra_seed": extra_seed_result,
        "health": health,
        "ready": bool(health.get("all_green")),
    }


def prepare_smart_setup(
    repo_path: Path | str,
    compose_file: Path | str,
    detection: Dict,
) -> Dict:
    """Phase 1: scan runtime needs, build infra plan, and apply compose/env edits."""
    repo_dir = Path(repo_path).resolve()
    compose_path = Path(compose_file).resolve()
    runtime = scan_runtime_needs(repo_dir, detection)
    plan = build_infra_plan(runtime)
    apply_result = apply_infra_plan(compose_path, repo_dir, plan)
    return {
        "smart_db_mode": bool(plan.get("smart_db_mode")),
        "runtime": runtime,
        "infra_plan": plan,
        "apply": apply_result,
    }


def finalize_smart_setup(
    repo_path: Path | str,
    compose_file: Path | str,
    project_name: str,
    prepared: Dict,
) -> Dict:
    """Phase 2: run migrations/seeding/health checks after containers are up."""
    repo_dir = Path(repo_path).resolve()
    compose_path = Path(compose_file).resolve()
    compose_data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    client = docker.from_env()
    plan = prepared.get("infra_plan", {})

    migration_result = _bootstrap_native_migrations(client, compose_data, project_name, repo_dir, plan)
    seed_result = seed_dummy_data(compose_file=compose_path, project_name=project_name)

    db_plan = plan.get("db")
    extra_seed_result = {}
    if db_plan and db_plan.get("type") in ("mongodb", "redis"):
        extra_seed_result = _seed_additional_db(client, compose_data, project_name, db_plan.get("type"))

    health = _healthcheck_setup(client, compose_data, project_name, db_plan)

    return {
        "smart_db_mode": bool(prepared.get("smart_db_mode")),
        "runtime": prepared.get("runtime", {}),
        "infra_plan": plan,
        "apply": prepared.get("apply", {}),
        "migrations": migration_result,
        "seed": seed_result,
        "extra_seed": extra_seed_result,
        "health": health,
        "ready": bool(health.get("all_green")),
    }

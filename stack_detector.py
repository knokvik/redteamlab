"""Detect high-level application stack details from a cloned repository.

Enhanced with deeper file introspection, auth framework detection, and
support for MongoDB/Redis/SQLite/Elasticsearch in addition to Postgres/MySQL.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_FINGERPRINTS = PROJECT_ROOT / "fingerprints.json"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _package_dependencies(package_json_path: Path) -> set[str]:
    if not package_json_path.exists():
        return set()

    try:
        data = json.loads(_read_text(package_json_path) or "{}")
    except json.JSONDecodeError:
        return set()

    deps = set(data.get("dependencies", {}).keys())
    deps.update(data.get("devDependencies", {}).keys())
    return {item.lower() for item in deps}


def _discover_candidate_dirs(repo_path: Path, max_depth: int = 2) -> List[Path]:
    """Discover candidate directories up to max_depth levels deep."""
    candidates = [repo_path]
    for child in repo_path.iterdir():
        if child.is_dir() and not child.name.startswith(".") and child.name not in ("node_modules", "vendor", "__pycache__", ".git", "dist", "build"):
            candidates.append(child)
            if max_depth > 1:
                for grandchild in child.iterdir():
                    if grandchild.is_dir() and not grandchild.name.startswith(".") and grandchild.name not in ("node_modules", "vendor", "__pycache__"):
                        candidates.append(grandchild)
    return candidates


def _has_file(directory: Path, filename: str) -> bool:
    return (directory / filename).exists()


def _matches_fingerprint(directory: Path, fingerprint: Dict) -> Tuple[bool, List[str]]:
    match_cfg = fingerprint.get("match", {})
    evidence: List[str] = []

    all_files = match_cfg.get("all_files", [])
    for filename in all_files:
        if not _has_file(directory, filename):
            return False, []
        evidence.append(str(directory / filename))

    any_files = match_cfg.get("any_files", [])
    if any_files:
        any_file_hit = False
        for filename in any_files:
            if _has_file(directory, filename):
                any_file_hit = True
                evidence.append(str(directory / filename))
                break
        if not any_file_hit:
            return False, []

    package_deps = _package_dependencies(directory / "package.json")
    any_package_deps = [dep.lower() for dep in match_cfg.get("any_package_deps", [])]
    if any_package_deps:
        if not any(dep in package_deps for dep in any_package_deps):
            return False, []
        evidence.append(f"{directory / 'package.json'}::{','.join(sorted(package_deps))}")

    any_text = [term.lower() for term in match_cfg.get("any_text", [])]
    if any_text:
        haystack = "\n".join(
            [
                _read_text(directory / "requirements.txt"),
                _read_text(directory / "pyproject.toml"),
                _read_text(directory / "docker-compose.yml"),
                _read_text(directory / "docker-compose.yaml"),
                _read_text(directory / ".env"),
                _read_text(directory / ".env.example"),
                _read_text(directory / "package.json"),
                _read_text(directory / "Gemfile"),
                _read_text(directory / "go.mod"),
                _read_text(directory / "pom.xml"),
                _read_text(directory / "build.gradle"),
                _read_text(directory / "composer.json"),
                _read_text(directory / "Cargo.toml"),
            ]
        ).lower()
        if not any(term in haystack for term in any_text):
            return False, []
        evidence.append(f"{directory}::text-match")

    return True, evidence


def _detect_exposed_ports(repo_path: Path) -> List[Dict]:
    """Scan Dockerfiles and compose files for exposed ports."""
    ports = []
    for compose_name in ("docker-compose.yml", "docker-compose.yaml"):
        compose_path = repo_path / compose_name
        if compose_path.exists():
            content = _read_text(compose_path)
            import re
            for match in re.finditer(r"['\"]?(\d+):(\d+)['\"]?", content):
                ports.append({"host": int(match.group(1)), "container": int(match.group(2)), "source": compose_name})

    dockerfile = repo_path / "Dockerfile"
    if dockerfile.exists():
        content = _read_text(dockerfile)
        import re
        for match in re.finditer(r"EXPOSE\s+(\d+)", content):
            ports.append({"container": int(match.group(1)), "source": "Dockerfile"})

    return ports


def _detect_env_variables(repo_path: Path) -> Dict:
    """Scan for environment variable patterns that reveal architecture."""
    env_info = {"has_env": False, "database_urls": [], "api_keys_referenced": False, "secrets_referenced": False}
    for env_file in (".env", ".env.example", ".env.sample", ".env.local"):
        env_path = repo_path / env_file
        if env_path.exists():
            env_info["has_env"] = True
            content = _read_text(env_path).lower()
            if "database_url" in content or "db_host" in content:
                env_info["database_urls"].append(env_file)
            if "api_key" in content or "apikey" in content:
                env_info["api_keys_referenced"] = True
            if "secret" in content or "jwt" in content or "token" in content:
                env_info["secrets_referenced"] = True
    return env_info


def detect_stack(repo_path: Path | str, fingerprints_path: Path | str | None = None) -> Dict:
    """Return a normalized stack detection result for compose generation."""
    repo_dir = Path(repo_path).resolve()
    fp_path = Path(fingerprints_path) if fingerprints_path else DEFAULT_FINGERPRINTS

    fingerprint_data = json.loads(_read_text(fp_path) or "{}")
    fingerprints = fingerprint_data.get("technologies", [])

    candidates = _discover_candidate_dirs(repo_dir)

    detections: List[Dict] = []
    for directory in candidates:
        for fingerprint in fingerprints:
            matched, evidence = _matches_fingerprint(directory, fingerprint)
            if matched:
                detections.append(
                    {
                        "name": fingerprint.get("name"),
                        "role": fingerprint.get("role"),
                        "path": str(directory),
                        "evidence": evidence,
                    }
                )

    frontend = next((d for d in detections if d["role"] == "frontend"), None)
    backend = next((d for d in detections if d["role"] == "backend"), None)

    # Database detection — support full range
    db_type = None
    db_priority = ["postgres", "mysql", "mongodb", "sqlite"]
    for db_name in db_priority:
        if any(d["name"] == db_name for d in detections):
            db_type = db_name
            break

    # Cache/queue detection
    cache_type = None
    if any(d["name"] == "redis" for d in detections):
        cache_type = "redis"

    # Auth detection
    auth_methods = []
    if any(d["name"] == "jwt-auth" for d in detections):
        auth_methods.append("jwt")
    if any(d["name"] == "oauth" for d in detections):
        auth_methods.append("oauth")

    # API style detection
    api_style = "rest"
    if any(d["name"] == "graphql" for d in detections):
        api_style = "graphql"

    # Self-containerized detection
    has_own_docker = any(d["name"] == "docker-self" for d in detections)

    # Port and env analysis
    exposed_ports = _detect_exposed_ports(repo_dir)
    env_info = _detect_env_variables(repo_dir)

    return {
        "repo_path": str(repo_dir),
        "technologies": sorted({d["name"] for d in detections}),
        "detections": detections,
        "frontend": {
            "detected": frontend is not None,
            "kind": frontend["name"] if frontend else None,
            "path": frontend["path"] if frontend else None,
        },
        "backend": {
            "detected": backend is not None,
            "kind": backend["name"] if backend else None,
            "path": backend["path"] if backend else None,
        },
        "database": {
            "detected": db_type is not None,
            "type": db_type,
        },
        "cache": {
            "detected": cache_type is not None,
            "type": cache_type,
        },
        "auth": {
            "methods": auth_methods,
        },
        "api_style": api_style,
        "has_own_docker": has_own_docker,
        "exposed_ports": exposed_ports,
        "env_info": env_info,
    }

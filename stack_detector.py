"""Detect high-level application stack details from a cloned repository."""

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


def _discover_candidate_dirs(repo_path: Path) -> List[Path]:
    candidates = [repo_path]
    for child in repo_path.iterdir():
        if child.is_dir() and not child.name.startswith("."):
            candidates.append(child)
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
                _read_text(directory / ".env"),
                _read_text(directory / "package.json"),
            ]
        ).lower()
        if not any(term in haystack for term in any_text):
            return False, []
        evidence.append(f"{directory}::text-match")

    return True, evidence


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

    db_type = None
    if any(d["name"] == "postgres" for d in detections):
        db_type = "postgres"
    elif any(d["name"] == "mysql" for d in detections):
        db_type = "mysql"

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
    }

"""Clone GitHub repositories into a local temp workspace."""

from __future__ import annotations

import shutil
from pathlib import Path

from git import Repo


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CLONE_DIR = PROJECT_ROOT / "temp_repo"


def clone_repo(github_url: str, destination: Path | str | None = None) -> Path:
    """Clone a repository URL into ./temp_repo and return the local path."""
    if not github_url.startswith(("http://", "https://", "git@")):
        raise ValueError(f"Unsupported Git URL: {github_url}")

    clone_dir = Path(destination) if destination else DEFAULT_CLONE_DIR

    if clone_dir.exists():
        shutil.rmtree(clone_dir)

    Repo.clone_from(github_url, str(clone_dir), depth=1)
    return clone_dir

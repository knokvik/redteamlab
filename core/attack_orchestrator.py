"""Drive localhost-only attack attempts with LLM suggestions and tool fallbacks."""

from __future__ import annotations

import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import docker

from core.remote_llm_client import RemoteLLMClient


def _is_localhost_url(candidate: str) -> bool:
    allowed = ("http://localhost", "http://127.0.0.1", "http://[::1]")
    return any(candidate.startswith(prefix) for prefix in allowed)


def _resolve_attacker_container(project_name: str) -> str:
    client = docker.from_env()
    for container in client.containers.list(all=True):
        labels = container.labels or {}
        if labels.get("com.docker.compose.project") != project_name:
            continue
        if labels.get("com.docker.compose.service") == "attacker":
            return container.name
    raise RuntimeError("attacker container not found")


def _tool_exists(client: docker.DockerClient, attacker_name: str, tool_name: str) -> bool:
    container = client.containers.get(attacker_name)
    code, _ = container.exec_run(f"sh -lc 'command -v {tool_name} >/dev/null 2>&1'")
    return code == 0


def _run_in_attacker(client: docker.DockerClient, attacker_name: str, command: str) -> Dict:
    container = client.containers.get(attacker_name)
    code, output = container.exec_run(f"sh -lc {command!r}")
    return {
        "exit_code": code,
        "output": output.decode("utf-8", errors="ignore").strip(),
    }


def run_attack_loop(
    base_url: str,
    graph_snapshot: Dict,
    observability_collector,
    project_name: str,
    attempts: int = 4,
) -> Dict:
    if not _is_localhost_url(base_url):
        raise ValueError(f"Refusing non-localhost target: {base_url}")

    client = docker.from_env()
    attacker_name = _resolve_attacker_container(project_name)
    llm = RemoteLLMClient()

    results: List[Dict] = []

    for idx in range(1, attempts + 1):
        attempt_id = f"rt-{uuid.uuid4().hex[:10]}"
        snapshot = observability_collector.snapshot()
        suggestion = llm.suggest_attack(
            graph_snapshot=graph_snapshot,
            observability_snapshot=snapshot.get("summary", {}),
            attempt_idx=idx,
            base_url=base_url,
        )

        tool = suggestion.tool.lower().strip()
        command_used = ""
        output = ""
        success = False

        if not _is_localhost_url(base_url):
            results.append(
                {
                    "attempt": idx,
                    "id": attempt_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "success": False,
                    "reason": "non-localhost target blocked",
                }
            )
            continue

        if tool == "nuclei" and _tool_exists(client, attacker_name, "nuclei"):
            command_used = f"nuclei -u {base_url} -H 'X-RedTeam-ID: {attempt_id}' -silent -nc"
            cmd_result = _run_in_attacker(client, attacker_name, command_used)
            output = cmd_result["output"]
            success = cmd_result["exit_code"] == 0
        elif tool == "sqlmap" and _tool_exists(client, attacker_name, "sqlmap"):
            command_used = (
                f"sqlmap -u '{base_url}/?id=1' --batch --level=1 --risk=1 "
                f"--headers='X-RedTeam-ID: {attempt_id}'"
            )
            cmd_result = _run_in_attacker(client, attacker_name, command_used)
            output = cmd_result["output"]
            success = cmd_result["exit_code"] == 0
        else:
            # Fallback probe when tool missing/unavailable.
            command_used = f"curl -sk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/?q={suggestion.payload}'"
            cmd_result = _run_in_attacker(client, attacker_name, command_used)
            output = cmd_result["output"]
            success = cmd_result["exit_code"] == 0

        results.append(
            {
                "attempt": idx,
                "id": attempt_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": tool,
                "source": suggestion.source,
                "plan": suggestion.plan,
                "payload": suggestion.payload,
                "command": command_used,
                "success": success,
                "output": output[:2500],
            }
        )

    return {"attempts": results}

"""Drive localhost-only attack attempts with LLM suggestions and tool execution."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import quote_plus

import docker

from core.remote_llm_client import RemoteLLMClient


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    started = time.perf_counter()
    result = container.exec_run(f"sh -lc {command!r}", demux=True)
    duration_ms = round((time.perf_counter() - started) * 1000.0, 3)

    stdout = ""
    stderr = ""
    if isinstance(result.output, tuple):
        out_b, err_b = result.output
        stdout = (out_b or b"").decode("utf-8", errors="ignore")
        stderr = (err_b or b"").decode("utf-8", errors="ignore")
    else:
        stdout = (result.output or b"").decode("utf-8", errors="ignore")

    return {
        "exit_code": result.exit_code,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "duration_ms": duration_ms,
    }


def _build_command(tool: str, base_url: str, payload: str, attempt_id: str) -> str:
    safe_payload = quote_plus(payload)
    if tool == "nuclei":
        return f"nuclei -u {base_url} -H 'X-RedTeam-ID: {attempt_id}' -silent -nc"
    if tool == "sqlmap":
        return (
            f"sqlmap -u '{base_url}/?id=1' --batch --level=1 --risk=1 "
            f"--headers='X-RedTeam-ID: {attempt_id}'"
        )
    # playwright/curl fallback path uses curl probe to keep execution in attacker container.
    return f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/?q={safe_payload}'"


def run_attack_loop(
    base_url: str,
    graph_snapshot: Dict,
    observability_collector,
    project_name: str,
    attempts: int = 4,
    mode: str = "safe",
    stack_snapshot: Dict | None = None,
    target_urls: List[str] | None = None,
) -> Dict:
    if not _is_localhost_url(base_url):
        raise ValueError(f"Refusing non-localhost target: {base_url}")

    client = docker.from_env()
    attacker_name = _resolve_attacker_container(project_name)
    llm = RemoteLLMClient()

    results: List[Dict] = []
    fallback_used = False

    for idx in range(1, attempts + 1):
        attempt_id = f"rt-{uuid.uuid4().hex[:10]}"
        started_at = _utc_now_iso()
        observability_collector.begin_attempt(
            attempt_id,
            metadata={"attempt": idx, "mode": mode, "target": base_url},
        )

        snapshot = observability_collector.snapshot()
        suggestion = llm.suggest_attack(
            graph_snapshot=graph_snapshot,
            observability_snapshot=snapshot.get("summary", {}),
            attempt_idx=idx,
            base_url=base_url,
            stack_snapshot=stack_snapshot,
            target_urls=target_urls,
            mode=mode,
        )
        if suggestion.source.startswith("fallback:"):
            fallback_used = True

        requested_tool = suggestion.tool.lower().strip()
        command_used = ""
        command_tool = requested_tool
        stderr = ""
        stdout = ""
        exit_code = 1
        duration_ms = 0.0

        if requested_tool in {"nuclei", "sqlmap"} and not _tool_exists(client, attacker_name, requested_tool):
            command_tool = "curl"

        if command_tool not in {"nuclei", "sqlmap", "curl", "playwright"}:
            command_tool = "curl"

        command_used = _build_command(
            tool=command_tool,
            base_url=base_url,
            payload=suggestion.payload,
            attempt_id=attempt_id,
        )
        exec_result = _run_in_attacker(client, attacker_name, command_used)
        exit_code = int(exec_result["exit_code"])
        stdout = exec_result["stdout"]
        stderr = exec_result["stderr"]
        duration_ms = float(exec_result["duration_ms"])

        success = exit_code == 0
        ended_at = _utc_now_iso()
        observability_collector.end_attempt(
            attempt_id,
            metadata={
                "success": success,
                "tool": command_tool,
                "source": suggestion.source,
                "goal_stage": suggestion.goal_stage,
            },
        )

        results.append(
            {
                "attempt": idx,
                "id": attempt_id,
                "started_at": started_at,
                "ended_at": ended_at,
                "timestamp": ended_at,
                "duration_ms": duration_ms,
                "mode": mode,
                "requested_tool": requested_tool,
                "tool": command_tool,
                "source": suggestion.source,
                "fallback_reason": suggestion.fallback_reason,
                "validation_notes": suggestion.validation_notes,
                "goal_stage": suggestion.goal_stage,
                "expected_signal": suggestion.expected_signal,
                "confidence": suggestion.confidence,
                "plan": suggestion.plan,
                "payload": suggestion.payload,
                "command_suggestion": suggestion.command_suggestion,
                "command": command_used,
                "exit_code": exit_code,
                "success": success,
                "stdout": stdout[:12000],
                "stderr": stderr[:8000],
                "output": (stdout + ("\n" + stderr if stderr else ""))[:2500],
            }
        )

    return {"attempts": results, "fallback_used": fallback_used}

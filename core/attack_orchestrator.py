"""Multi-phase kill-chain attack engine.

Implements the full attack lifecycle:
  1. RECON       — Port scans, fingerprinting, WAF detection, directory brute-force
  2. ENUMERATION — Service enumeration, technology mapping, endpoint fuzzing
  3. VULN_SCAN   — Nuclei templates, nikto checks, SSL/TLS weakness detection
  4. EXPLOIT     — SQLi, XSS, SSTI, command injection, LFI/RFI via LLM guidance
  5. POST_EXPLOIT— Data exfiltration probes, privilege escalation checks, lateral movement
  6. STRESS_TEST — Load generation, connection exhaustion, resource saturation
"""

from __future__ import annotations

import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import docker

from core.remote_llm_client import RemoteLLMClient


class AttackPhase(str, Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    STRESS_TEST = "stress_test"


# Attack surface artifacts accumulated across phases.
@dataclass
class AttackContext:
    base_url: str
    target_urls: List[str]
    graph_snapshot: Dict
    stack_snapshot: Dict
    mode: str
    open_ports: List[int] = field(default_factory=list)
    discovered_paths: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    vulnerabilities: List[Dict] = field(default_factory=list)
    credentials_found: List[Dict] = field(default_factory=list)
    phase_results: Dict[str, List[Dict]] = field(default_factory=dict)
    stress_results: Dict = field(default_factory=dict)

    def to_llm_context(self) -> Dict:
        """Serialize accumulated intel for LLM consumption."""
        return {
            "base_url": self.base_url,
            "target_urls": self.target_urls,
            "mode": self.mode,
            "open_ports": self.open_ports,
            "discovered_paths": self.discovered_paths[:50],
            "technologies": self.technologies,
            "waf": self.waf_detected,
            "vulnerabilities_found": len(self.vulnerabilities),
            "vuln_summaries": [
                {"type": v.get("type"), "severity": v.get("severity"), "url": v.get("url")}
                for v in self.vulnerabilities[:10]
            ],
            "credentials_found": len(self.credentials_found),
            "graph": self.graph_snapshot,
            "stack": self.stack_snapshot,
            "prior_phases": {
                phase: len(results) for phase, results in self.phase_results.items()
            },
        }


# Phase configuration: how many attempts per phase, which tools to prioritize.
PHASE_CONFIG = {
    AttackPhase.RECON: {
        "attempts": 2,
        "tools": ["nmap", "whatweb", "wafw00f", "gobuster"],
        "description": "Reconnaissance — port scans, fingerprinting, WAF detection, directory enumeration",
    },
    AttackPhase.ENUMERATION: {
        "attempts": 2,
        "tools": ["ffuf", "gobuster", "dirb", "curl"],
        "description": "Enumeration — endpoint fuzzing, parameter discovery, API mapping",
    },
    AttackPhase.VULN_SCAN: {
        "attempts": 2,
        "tools": ["nuclei", "nikto", "sslscan", "curl"],
        "description": "Vulnerability scanning — CVE checks, misconfigurations, SSL weaknesses",
    },
    AttackPhase.EXPLOIT: {
        "attempts": 4,
        "tools": ["sqlmap", "curl", "nuclei", "metasploit"],
        "description": "Exploitation — SQLi, XSS, SSTI, command injection, LFI/RFI",
    },
    AttackPhase.POST_EXPLOIT: {
        "attempts": 2,
        "tools": ["curl", "sqlmap", "metasploit"],
        "description": "Post-exploitation — data exfiltration, privilege escalation, lateral movement",
    },
    AttackPhase.STRESS_TEST: {
        "attempts": 1,
        "tools": ["siege", "ab", "hping3"],
        "description": "Stress testing — load generation, connection exhaustion, resource saturation",
    },
}

# Total attempts across all phases in order.
KILL_CHAIN_ORDER = [
    AttackPhase.RECON,
    AttackPhase.ENUMERATION,
    AttackPhase.VULN_SCAN,
    AttackPhase.EXPLOIT,
    AttackPhase.POST_EXPLOIT,
    AttackPhase.STRESS_TEST,
]


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


def _run_in_attacker(
    client: docker.DockerClient,
    attacker_name: str,
    command: str,
    timeout_s: int = 120,
) -> Dict:
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


def _build_recon_command(tool: str, base_url: str, attempt_id: str, context: AttackContext) -> str:
    """Build commands for the recon phase."""
    host = base_url.split("://")[-1].split(":")[0].split("/")[0]
    port = "80"
    if ":" in base_url.split("://")[-1]:
        port = base_url.split("://")[-1].split(":")[1].split("/")[0]

    if tool == "nmap":
        return f"nmap -sV -sC -T4 -p 1-10000 --open -oN /tmp/nmap_{attempt_id}.txt {host}"
    if tool == "whatweb":
        return f"whatweb -a 3 '{base_url}'"
    if tool == "wafw00f":
        return f"wafw00f '{base_url}'"
    if tool == "gobuster":
        wordlist = "/opt/wordlists/Discovery/Web-Content/common.txt"
        return (
            f"gobuster dir -u '{base_url}' -w {wordlist} -t 20 -q --no-error "
            f"-H 'X-RedTeam-ID: {attempt_id}'"
        )
    return f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/'"


def _build_enum_command(tool: str, base_url: str, attempt_id: str, context: AttackContext) -> str:
    """Build commands for enumeration phase."""
    if tool == "ffuf":
        wordlist = "/opt/wordlists/Discovery/Web-Content/raft-medium-words.txt"
        return (
            f"ffuf -u '{base_url}/FUZZ' -w {wordlist} -mc 200,301,302,403 -t 30 -s "
            f"-H 'X-RedTeam-ID: {attempt_id}'"
        )
    if tool == "dirb":
        return f"dirb '{base_url}/' -a 'X-RedTeam-ID: {attempt_id}' -S -r"
    if tool == "gobuster":
        wordlist = "/opt/wordlists/Discovery/Web-Content/api-endpoints.txt"
        return (
            f"gobuster dir -u '{base_url}' -w {wordlist} -t 20 -q --no-error "
            f"-H 'X-RedTeam-ID: {attempt_id}'"
        )
    # Probe discovered paths for parameter fuzzing
    paths = context.discovered_paths[:5] or ["/", "/api", "/admin", "/login"]
    path = paths[0]
    return f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}{path}?id=1&q=test&debug=true'"


def _build_vuln_command(tool: str, base_url: str, attempt_id: str, context: AttackContext) -> str:
    """Build commands for vulnerability scanning phase."""
    if tool == "nuclei":
        return (
            f"nuclei -u '{base_url}' -H 'X-RedTeam-ID: {attempt_id}' -silent -nc "
            f"-severity low,medium,high,critical -t /root/nuclei-templates/ 2>/dev/null || "
            f"nuclei -u '{base_url}' -H 'X-RedTeam-ID: {attempt_id}' -silent -nc"
        )
    if tool == "nikto":
        return f"timeout 90 nikto -h '{base_url}' -Tuning 1234567890abc 2>/dev/null"
    if tool == "sslscan":
        host = base_url.split("://")[-1].split("/")[0]
        return f"sslscan {host}"
    return f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/../../../etc/passwd'"


def _build_exploit_command(
    tool: str, base_url: str, payload: str, attempt_id: str, context: AttackContext
) -> str:
    """Build commands for exploitation phase. LLM-guided payloads take priority."""
    safe_payload = quote_plus(payload)

    if tool == "sqlmap":
        # Target discovered paths with parameters if available
        target_url = base_url
        for path in context.discovered_paths:
            if "?" in path or "id" in path.lower() or "user" in path.lower():
                target_url = f"{base_url}{path}"
                break
        return (
            f"sqlmap -u '{target_url}?id=1' --batch --level=3 --risk=2 "
            f"--headers='X-RedTeam-ID: {attempt_id}' --threads=4 "
            f"--technique=BEUSTQ --tamper=space2comment"
        )
    if tool == "nuclei":
        return (
            f"nuclei -u '{base_url}' -H 'X-RedTeam-ID: {attempt_id}' -silent -nc "
            f"-severity high,critical"
        )
    if tool == "metasploit":
        # MSF console one-liner for common web exploits
        host = base_url.split("://")[-1].split(":")[0].split("/")[0]
        port = "80"
        if ":" in base_url.split("://")[-1]:
            port = base_url.split("://")[-1].split(":")[1].split("/")[0]
        return (
            f"msfconsole -q -x 'use auxiliary/scanner/http/dir_scanner;"
            f"set RHOSTS {host};set RPORT {port};run;exit' 2>/dev/null || "
            f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/?q={safe_payload}'"
        )
    # curl-based payload delivery
    return f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/?q={safe_payload}'"


def _build_post_exploit_command(
    tool: str, base_url: str, payload: str, attempt_id: str, context: AttackContext
) -> str:
    """Build commands for post-exploitation phase."""
    safe_payload = quote_plus(payload)

    if tool == "sqlmap" and context.vulnerabilities:
        # Attempt data exfiltration if SQLi was found
        return (
            f"sqlmap -u '{base_url}/?id=1' --batch --level=3 --risk=2 "
            f"--headers='X-RedTeam-ID: {attempt_id}' --dump --threads=4"
        )
    if tool == "curl":
        # Probe for sensitive files and internal endpoints
        return (
            f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' "
            f"'{base_url}/.env' '{base_url}/.git/config' "
            f"'{base_url}/wp-config.php' '{base_url}/config.json' "
            f"'{base_url}/api/users' '{base_url}/admin/config'"
        )
    return f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/?q={safe_payload}'"


def _build_stress_command(base_url: str, attempt_id: str, context: AttackContext) -> str:
    """Build stress test command."""
    return (
        f"/opt/attack-scripts/stress_test.sh '{base_url}' 30 50 "
        f"/home/attacker/results/stress '{attempt_id}'"
    )


def _is_localhost_command(command: str) -> bool:
    for host in re.findall(r"https?://([^\s/'\"]+)", command):
        host = host.strip().lower()
        if host not in {"localhost", "127.0.0.1", "[::1]"}:
            return False
    return True


def _maybe_use_llm_command(command_suggestion: str, base_url: str, attempt_id: str) -> str | None:
    """Return a safe shell command from LLM suggestion when enabled.

    Controlled by DEVREDTEAM_USE_LLM_COMMAND (default: 1).
    """
    enabled = os.getenv("DEVREDTEAM_USE_LLM_COMMAND", "1").strip().lower() not in {"0", "false", "no"}
    if not enabled:
        return None

    raw = (command_suggestion or "").strip()
    if not raw:
        return None

    # Ignore pseudo suggestions like "GET http://...".
    if raw.upper().startswith("GET "):
        return None

    # Strip markdown fences.
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:bash|sh|python|json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)
        raw = raw.strip()

    # Simple hard safety denylists for local runner stability.
    denied = [
        "rm -rf /",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        ":(){:|:&};:",
        "mkfs.",
        "dd if=/dev/zero",
        "docker ",
        "podman ",
        "kubectl ",
        "mount ",
        "umount ",
    ]
    low = raw.lower()
    if any(token in low for token in denied):
        return None

    if not _is_localhost_command(raw):
        return None

    # Normalize base URL placeholder and force correlation header where possible.
    raw = raw.replace("{{BASE_URL}}", base_url).replace("$BASE_URL", base_url)
    if "curl " in raw and "X-RedTeam-ID" not in raw:
        raw = raw.replace("curl ", f"curl -H 'X-RedTeam-ID: {attempt_id}' ", 1)
    if "sqlmap " in raw and "X-RedTeam-ID" not in raw:
        raw = f"{raw} --headers='X-RedTeam-ID: {attempt_id}'"
    if "nuclei " in raw and "X-RedTeam-ID" not in raw:
        raw = raw.replace("nuclei ", f"nuclei -H 'X-RedTeam-ID: {attempt_id}' ", 1)

    return raw


def _build_command_for_phase(
    phase: AttackPhase,
    tool: str,
    base_url: str,
    payload: str,
    attempt_id: str,
    context: AttackContext,
) -> str:
    """Dispatch command building to the appropriate phase handler."""
    if phase == AttackPhase.RECON:
        return _build_recon_command(tool, base_url, attempt_id, context)
    elif phase == AttackPhase.ENUMERATION:
        return _build_enum_command(tool, base_url, attempt_id, context)
    elif phase == AttackPhase.VULN_SCAN:
        return _build_vuln_command(tool, base_url, attempt_id, context)
    elif phase == AttackPhase.EXPLOIT:
        return _build_exploit_command(tool, base_url, payload, attempt_id, context)
    elif phase == AttackPhase.POST_EXPLOIT:
        return _build_post_exploit_command(tool, base_url, payload, attempt_id, context)
    elif phase == AttackPhase.STRESS_TEST:
        return _build_stress_command(base_url, attempt_id, context)
    # Unreachable fallback
    return f"curl -isk -H 'X-RedTeam-ID: {attempt_id}' '{base_url}/'"


def _parse_recon_output(stdout: str, stderr: str, context: AttackContext) -> None:
    """Extract intelligence from recon phase output."""
    combined = f"{stdout}\n{stderr}".lower()

    # Extract open ports from nmap output
    import re
    for match in re.finditer(r"(\d+)/tcp\s+open", combined):
        port = int(match.group(1))
        if port not in context.open_ports:
            context.open_ports.append(port)

    # Extract discovered paths from gobuster/dirb
    for match in re.finditer(r"(/[a-zA-Z0-9_/.-]+)\s+\(Status:\s*(\d+)\)", stdout):
        path = match.group(1)
        if path not in context.discovered_paths:
            context.discovered_paths.append(path)

    # Detect WAF
    if "is behind" in combined and "waf" in combined:
        for line in combined.splitlines():
            if "is behind" in line:
                context.waf_detected = line.strip()
                break

    # Extract technologies from whatweb
    for match in re.finditer(r"\[([A-Za-z0-9./ -]+)\]", stdout):
        tech = match.group(1).strip()
        if len(tech) > 2 and tech not in context.technologies:
            context.technologies.append(tech)


def _parse_vuln_output(stdout: str, stderr: str, context: AttackContext) -> None:
    """Extract vulnerability findings from scan output."""
    import re
    combined = f"{stdout}\n{stderr}"

    # Nuclei findings
    for line in combined.splitlines():
        line_lower = line.lower()
        severity = None
        if "[critical]" in line_lower:
            severity = "critical"
        elif "[high]" in line_lower:
            severity = "high"
        elif "[medium]" in line_lower:
            severity = "medium"
        elif "[low]" in line_lower:
            severity = "low"

        if severity:
            context.vulnerabilities.append({
                "type": "nuclei-finding",
                "severity": severity,
                "detail": line.strip()[:200],
                "url": context.base_url,
            })

    # Nikto findings
    for match in re.finditer(r"OSVDB-\d+.*", combined):
        context.vulnerabilities.append({
            "type": "nikto-finding",
            "severity": "medium",
            "detail": match.group(0).strip()[:200],
            "url": context.base_url,
        })

    # SQLi indicators
    sqli_signals = ["sql syntax", "mysql", "postgresql", "sqlite", "unclosed quotation"]
    for signal in sqli_signals:
        if signal in combined.lower():
            context.vulnerabilities.append({
                "type": "sqli-indicator",
                "severity": "high",
                "detail": f"SQL indicator detected: {signal}",
                "url": context.base_url,
            })
            break


def _parse_enum_output(stdout: str, stderr: str, context: AttackContext) -> None:
    """Extract endpoint data from enumeration output."""
    import re
    # ffuf / gobuster / dirb path results
    for match in re.finditer(r"(/[a-zA-Z0-9_/.-]+)", stdout):
        path = match.group(1)
        if len(path) > 1 and path not in context.discovered_paths:
            context.discovered_paths.append(path)


def _parse_phase_output(
    phase: AttackPhase, stdout: str, stderr: str, context: AttackContext
) -> None:
    """Route output parsing to the correct phase parser."""
    if phase == AttackPhase.RECON:
        _parse_recon_output(stdout, stderr, context)
    elif phase == AttackPhase.ENUMERATION:
        _parse_enum_output(stdout, stderr, context)
    elif phase in (AttackPhase.VULN_SCAN, AttackPhase.EXPLOIT):
        _parse_vuln_output(stdout, stderr, context)


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
    """Execute a full kill-chain attack pipeline across all phases.

    Backwards-compatible with the original flat loop signature, but now
    drives a multi-phase kill chain with accumulated context fed to the LLM.
    """
    if not _is_localhost_url(base_url):
        raise ValueError(f"Refusing non-localhost target: {base_url}")

    client = docker.from_env()
    attacker_name = _resolve_attacker_container(project_name)
    llm = RemoteLLMClient()

    context = AttackContext(
        base_url=base_url,
        target_urls=target_urls or [base_url],
        graph_snapshot=graph_snapshot,
        stack_snapshot=stack_snapshot or {},
        mode=mode,
    )

    all_results: List[Dict] = []
    fallback_used = False
    global_attempt = 0

    for phase in KILL_CHAIN_ORDER:
        config = PHASE_CONFIG[phase]

        # In safe mode, skip stress test and post-exploit
        if mode == "safe" and phase in (AttackPhase.STRESS_TEST, AttackPhase.POST_EXPLOIT):
            continue

        phase_attempts = config["attempts"]
        phase_results: List[Dict] = []

        for phase_idx in range(1, phase_attempts + 1):
            global_attempt += 1
            attempt_id = f"rt-{phase.value[:4]}-{uuid.uuid4().hex[:8]}"
            started_at = _utc_now_iso()

            observability_collector.begin_attempt(
                attempt_id,
                metadata={
                    "attempt": global_attempt,
                    "phase": phase.value,
                    "phase_idx": phase_idx,
                    "mode": mode,
                    "target": base_url,
                },
            )

            # Get observability snapshot for LLM context
            snapshot = observability_collector.snapshot()

            # Ask LLM for attack suggestion with full accumulated context
            suggestion = llm.suggest_attack(
                graph_snapshot=graph_snapshot,
                observability_snapshot=snapshot.get("summary", {}),
                attempt_idx=global_attempt,
                base_url=base_url,
                stack_snapshot=stack_snapshot,
                target_urls=target_urls,
                mode=mode,
                attack_phase=phase.value,
                phase_context=context.to_llm_context(),
            )
            if suggestion.source.startswith("fallback:"):
                fallback_used = True

            # Determine tool — prefer LLM suggestion if it's valid for this phase
            requested_tool = suggestion.tool.lower().strip()
            command_tool = requested_tool

            # Validate tool exists in attacker container
            if command_tool not in {"curl"} and not _tool_exists(client, attacker_name, command_tool):
                # Fall through phase-specific tools, then to curl
                for fallback_tool in config["tools"]:
                    if _tool_exists(client, attacker_name, fallback_tool):
                        command_tool = fallback_tool
                        break
                else:
                    command_tool = "curl"

            # Build and execute the command.
            # Prefer vetted raw LLM shell commands when available; fallback to deterministic builders.
            command_used = _maybe_use_llm_command(suggestion.command_suggestion, base_url, attempt_id)
            if command_used is None:
                command_used = _build_command_for_phase(
                    phase=phase,
                    tool=command_tool,
                    base_url=base_url,
                    payload=suggestion.payload,
                    attempt_id=attempt_id,
                    context=context,
                )

            exec_result = _run_in_attacker(client, attacker_name, command_used)
            exit_code = int(exec_result["exit_code"])
            stdout = exec_result["stdout"]
            stderr = exec_result["stderr"]
            duration_ms = float(exec_result["duration_ms"])

            # Parse output to accumulate attack context intelligence
            _parse_phase_output(phase, stdout, stderr, context)

            success = exit_code == 0
            ended_at = _utc_now_iso()
            observability_collector.end_attempt(
                attempt_id,
                metadata={
                    "success": success,
                    "tool": command_tool,
                    "source": suggestion.source,
                    "phase": phase.value,
                    "goal_stage": suggestion.goal_stage,
                },
            )

            result_entry = {
                "attempt": global_attempt,
                "id": attempt_id,
                "phase": phase.value,
                "phase_idx": phase_idx,
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
            phase_results.append(result_entry)
            all_results.append(result_entry)

        context.phase_results[phase.value] = phase_results

    return {
        "attempts": all_results,
        "fallback_used": fallback_used,
        "attack_context": {
            "open_ports": context.open_ports,
            "discovered_paths": context.discovered_paths,
            "technologies": context.technologies,
            "waf_detected": context.waf_detected,
            "vulnerabilities": context.vulnerabilities,
            "credentials_found": context.credentials_found,
            "stress_results": context.stress_results,
        },
        "phases_executed": [p.value for p in KILL_CHAIN_ORDER if p.value in context.phase_results],
    }

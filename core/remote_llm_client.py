"""Remote LLM client with multi-phase awareness and robust provider support.

Supports:
- Ollama native endpoint: /api/generate
- OpenAI-compatible chat endpoint (LM Studio, proxies): /v1/chat/completions
"""

from __future__ import annotations

import json
import os
import re
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List


DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_LMSTUDIO_MODEL = "local-model"


@dataclass
class LLMSuggestion:
    plan: str
    payload: str
    tool: str
    command_suggestion: str
    source: str
    goal_stage: str
    expected_signal: str
    confidence: float
    validation_notes: List[str]
    fallback_reason: str | None


# Expanded tool registry with categories.
TOOL_REGISTRY = {
    # Recon tools
    "nmap": {"category": "recon", "phases": ["recon"]},
    "whatweb": {"category": "recon", "phases": ["recon"]},
    "wafw00f": {"category": "recon", "phases": ["recon"]},
    # Enumeration tools
    "gobuster": {"category": "enum", "phases": ["recon", "enumeration"]},
    "ffuf": {"category": "enum", "phases": ["enumeration"]},
    "dirb": {"category": "enum", "phases": ["enumeration"]},
    "wfuzz": {"category": "enum", "phases": ["enumeration", "exploit"]},
    # Vulnerability scanners
    "nuclei": {"category": "vuln_scan", "phases": ["vuln_scan", "exploit"]},
    "nikto": {"category": "vuln_scan", "phases": ["vuln_scan"]},
    "sslscan": {"category": "vuln_scan", "phases": ["vuln_scan"]},
    "testssl": {"category": "vuln_scan", "phases": ["vuln_scan"]},
    # Exploitation tools
    "sqlmap": {"category": "exploit", "phases": ["exploit", "post_exploit"]},
    "metasploit": {"category": "exploit", "phases": ["exploit", "post_exploit"]},
    "hydra": {"category": "exploit", "phases": ["exploit"]},
    # General purpose
    "curl": {"category": "general", "phases": ["recon", "enumeration", "vuln_scan", "exploit", "post_exploit"]},
    "playwright": {"category": "general", "phases": ["recon", "enumeration", "exploit"]},
    # Stress testing
    "siege": {"category": "stress", "phases": ["stress_test"]},
    "ab": {"category": "stress", "phases": ["stress_test"]},
    "hping3": {"category": "stress", "phases": ["stress_test"]},
}


class RemoteLLMClient:
    def __init__(self, host: str | None = None, model: str | None = None, timeout_s: int = 30):
        env_host = (
            host
            or os.getenv("LLM_HOST")
            or os.getenv("OLLAMA_HOST")
            or os.getenv("LMSTUDIO_HOST")
            or "http://localhost:11434"
        )
        self.host = env_host.rstrip("/")
        # LLM_API_STYLE: auto | ollama | openai
        self.api_style = (os.getenv("LLM_API_STYLE") or "auto").strip().lower()
        self.model = (
            model
            or os.getenv("OLLAMA_MODEL")
            or os.getenv("LLM_MODEL")
            or os.getenv("LMSTUDIO_MODEL")
            or (DEFAULT_LMSTUDIO_MODEL if self._resolved_api_style() == "openai" else DEFAULT_MODEL)
        )
        self.timeout_s = timeout_s
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.35"))
        self.top_p = float(os.getenv("LLM_TOP_P", "0.9"))
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "1800"))
        self._conversation_history: List[Dict] = []

    def _resolved_api_style(self) -> str:
        if self.api_style in {"ollama", "openai"}:
            return self.api_style
        host = self.host.lower()
        if host.endswith("/v1") or ":1234" in host or "lmstudio" in host:
            return "openai"
        return "ollama"

    @staticmethod
    def _is_localhost_url(candidate: str) -> bool:
        allowed = ("http://localhost", "http://127.0.0.1", "http://[::1]")
        return any(candidate.startswith(prefix) for prefix in allowed)

    @staticmethod
    def _system_prompt(mode: str, phase: str = "exploit") -> str:
        phase_guidance = {
            "recon": (
                "Focus on reconnaissance: port scanning, service identification, technology fingerprinting, "
                "WAF detection, and directory enumeration. Use nmap, whatweb, wafw00f, gobuster. "
                "Extract as much intelligence as possible about the target's attack surface."
            ),
            "enumeration": (
                "Focus on deep enumeration: hidden endpoints, parameter discovery, API route mapping, "
                "backup file discovery, admin panel detection. Use ffuf, gobuster, dirb with targeted wordlists. "
                "Map every possible entry point."
            ),
            "vuln_scan": (
                "Focus on vulnerability scanning: run nuclei templates for known CVEs, check for misconfigurations, "
                "test SSL/TLS weaknesses, probe for OWASP Top 10. Use nuclei, nikto, sslscan. "
                "Identify concrete exploitable vulnerabilities."
            ),
            "exploit": (
                "Focus on active exploitation: SQL injection (union, blind, time-based, error-based), "
                "XSS (reflected, stored, DOM), SSTI, command injection, LFI/RFI, SSRF, IDOR, "
                "authentication bypass, deserialization attacks. Chain vulnerabilities from prior phases. "
                "Use sqlmap with advanced tampering, nuclei exploit templates, custom curl payloads. "
                "Think creatively — combine findings from recon to maximize impact."
            ),
            "post_exploit": (
                "Focus on post-exploitation: data exfiltration from discovered SQL injection points, "
                "sensitive file access (.env, .git/config, config files), privilege escalation, "
                "lateral movement simulation, credential harvesting. "
                "Demonstrate real impact of the vulnerabilities found."
            ),
            "stress_test": (
                "Focus on stress and resilience testing: HTTP flood, slowloris, connection exhaustion, "
                "resource saturation. Measure how the target degrades under load. "
                "Use siege, ab, hping3."
            ),
        }

        base_prompt = phase_guidance.get(phase, phase_guidance["exploit"])

        if mode == "aggressive":
            return (
                "You are an elite red-team operator running authorized local penetration testing. "
                f"Current attack phase: {phase.upper()}. "
                f"{base_prompt} "
                "IMPORTANT: Think step-by-step. Analyze the accumulated context from prior phases. "
                "Chain findings together — if recon found open ports, enumerate them. "
                "If enumeration found endpoints, probe them for vulnerabilities. "
                "If vulnerabilities were found, exploit them. "
                "Return strict JSON: {plan, payload, tool, command_suggestion, goal_stage, expected_signal, confidence, reasoning}. "
                "The 'reasoning' field should explain your chain-of-thought. "
                "All targets must be localhost/127.0.0.1 only."
            )
        return (
            "You are a professional security assessment assistant for authorized local testing. "
            f"Current attack phase: {phase.upper()}. "
            f"{base_prompt} "
            "Think methodically. Analyze prior phase results before suggesting next steps. "
            "Return strict JSON: {plan, payload, tool, command_suggestion, goal_stage, expected_signal, confidence, reasoning}. "
            "Prefer validation probes before destructive tests. Target localhost only."
        )

    @staticmethod
    def _fallback(
        base_url: str,
        reason: str,
        attempt_idx: int,
        mode: str,
        phase: str = "exploit",
    ) -> LLMSuggestion:
        # Phase-specific fallback payloads
        fallback_pools = {
            "recon": [
                ("Nmap service scan", "full-scan", "nmap"),
                ("WhatWeb fingerprint", "fingerprint", "whatweb"),
                ("WAF detection", "waf-detect", "wafw00f"),
                ("Directory enumeration", "dir-enum", "gobuster"),
            ],
            "enumeration": [
                ("API endpoint fuzzing", "FUZZ", "ffuf"),
                ("Hidden directory scan", "dir-scan", "gobuster"),
                ("Parameter discovery", "?id=1&debug=true&admin=1", "curl"),
            ],
            "vuln_scan": [
                ("Nuclei CVE scan", "cve-scan", "nuclei"),
                ("Nikto web scan", "nikto-scan", "nikto"),
                ("Path traversal check", "../../etc/passwd", "curl"),
            ],
            "exploit": [
                ("Union-based SQLi", "' UNION SELECT NULL,NULL,NULL--", "sqlmap"),
                ("Error-based SQLi", "' AND 1=CONVERT(int,(SELECT @@version))--", "curl"),
                ("XSS reflection probe", "<script>alert(document.cookie)</script>", "curl"),
                ("SSTI probe", "{{7*'7'}}", "curl"),
                ("Command injection", "; id; cat /etc/passwd", "curl"),
                ("LFI probe", "....//....//....//etc/passwd", "curl"),
            ],
            "post_exploit": [
                ("Env file exfil", ".env", "curl"),
                ("Git config leak", ".git/config", "curl"),
                ("Database dump", "--dump", "sqlmap"),
            ],
            "stress_test": [
                ("HTTP flood test", "stress", "siege"),
            ],
        }

        pool = fallback_pools.get(phase, fallback_pools["exploit"])
        if mode == "aggressive" and phase == "exploit":
            pool = fallback_pools["exploit"]  # Use full exploit pool

        plan, payload, tool = pool[(attempt_idx - 1) % len(pool)]
        suggestion = f"GET {base_url}/?q={payload}"

        return LLMSuggestion(
            plan=plan,
            payload=payload,
            tool=tool,
            command_suggestion=suggestion,
            source=f"fallback:{reason}",
            goal_stage=phase,
            expected_signal="http_error_or_reflection",
            confidence=0.35 if mode == "safe" else 0.50,
            validation_notes=["deterministic-fallback", f"phase:{phase}"],
            fallback_reason=reason,
        )

    @staticmethod
    def _extract_json(text: str) -> Dict:
        text = text.strip()
        # Strip code fences if model wraps JSON in markdown.
        if text.startswith("```"):
            text = re.sub(r"^```(?:json|bash|python)?\s*", "", text, flags=re.IGNORECASE)
            text = re.sub(r"\s*```$", "", text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise ValueError("No JSON object found in LLM response")
        return json.loads(match.group(0))

    @staticmethod
    def _normalize_tool(tool_name: str, phase: str = "exploit") -> str:
        tool = (tool_name or "").strip().lower()
        if tool in TOOL_REGISTRY:
            # Validate tool is valid for this phase
            if phase in TOOL_REGISTRY[tool]["phases"]:
                return tool
            # Tool exists but not appropriate for phase — still allow it
            return tool
        return "curl"

    @staticmethod
    def _coerce_confidence(value) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            confidence = 0.5
        return max(0.0, min(1.0, confidence))

    @staticmethod
    def _sanitize_command_suggestion(command_suggestion: str) -> str:
        raw = (command_suggestion or "").strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json|bash|python|sh)?\s*", "", raw, flags=re.IGNORECASE)
            raw = re.sub(r"\s*```$", "", raw)
        return raw.strip()

    def _build_context_envelope(
        self,
        attempt_idx: int,
        attack_phase: str,
        mode: str,
        base_url: str,
        target_urls: List[str],
        stack_snapshot: Dict,
        graph_snapshot: Dict,
        accumulated_intel: str,
    ) -> Dict:
        return {
            "attempt": attempt_idx,
            "phase": attack_phase,
            "mode": mode,
            "base_url": base_url,
            "target_urls": target_urls,
            "stack": stack_snapshot,
            "graph": graph_snapshot,
            "accumulated_intelligence": accumulated_intel,
            "available_tools": [
                t for t, info in TOOL_REGISTRY.items() if attack_phase in info["phases"]
            ],
            "schema": {
                "required": ["plan", "payload", "tool", "command_suggestion"],
                "optional": ["goal_stage", "expected_signal", "confidence", "reasoning"],
            },
        }

    def _call_ollama(self, system_prompt: str, context_envelope: Dict) -> Dict:
        payload = {
            "model": self.model,
            "stream": False,
            "system": system_prompt,
            "prompt": json.dumps(context_envelope, indent=2),
            "options": {
                "temperature": self.temperature,
                "top_p": self.top_p,
            },
        }
        if self._conversation_history:
            payload["context"] = self._conversation_history[-3:]

        import requests

        response = requests.post(
            f"{self.host}/api/generate",
            json=payload,
            timeout=self.timeout_s,
        )
        response.raise_for_status()
        body = response.json()
        context_token = body.get("context")
        if context_token:
            self._conversation_history.append(context_token)
        return body

    def _call_openai_chat(self, system_prompt: str, context_envelope: Dict) -> Dict:
        # LM Studio expects /v1/chat/completions with messages.
        host = self.host
        if host.endswith("/v1"):
            endpoint = f"{host}/chat/completions"
        else:
            endpoint = f"{host}/v1/chat/completions"

        headers = {"Content-Type": "application/json"}
        api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LMSTUDIO_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(context_envelope, indent=2)},
            ],
            "temperature": self.temperature,
            "top_p": self.top_p,
            "max_tokens": self.max_tokens,
        }

        # Ask server for JSON output where supported.
        payload["response_format"] = {"type": "json_object"}

        import requests

        response = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=self.timeout_s,
        )
        response.raise_for_status()
        return response.json()

    def _build_conversation_context(
        self,
        phase: str,
        phase_context: Dict | None,
        observability_snapshot: Dict,
    ) -> str:
        """Build rich conversation context including prior phase results and behavioral observations."""
        lines = []

        if phase_context:
            prior = phase_context.get("prior_phases", {})
            if prior:
                lines.append("=== PRIOR PHASE RESULTS ===")
                for p, count in prior.items():
                    lines.append(f"Phase '{p}': {count} attempts executed")

            ports = phase_context.get("open_ports", [])
            if ports:
                lines.append(f"DISCOVERED OPEN PORTS: {ports}")

            paths = phase_context.get("discovered_paths", [])
            if paths:
                lines.append(f"DISCOVERED PATHS ({len(paths)} total): {paths[:20]}")

            techs = phase_context.get("technologies", [])
            if techs:
                lines.append(f"DETECTED TECHNOLOGIES: {techs}")

            waf = phase_context.get("waf")
            if waf:
                lines.append(f"WAF DETECTED: {waf}")

            vuln_count = phase_context.get("vulnerabilities_found", 0)
            vulns = phase_context.get("vuln_summaries", [])
            if vuln_count > 0:
                lines.append(f"VULNERABILITIES FOUND: {vuln_count}")
                for v in vulns:
                    lines.append(f"  - [{v.get('severity', 'unknown')}] {v.get('type', 'unknown')}")

        # Behavioral observations from observability
        if observability_snapshot:
            cpu = observability_snapshot.get("max_cpu_percent", 0)
            mem = observability_snapshot.get("max_memory_bytes", 0)
            errors = observability_snapshot.get("error_log_hits", 0)
            leaks = observability_snapshot.get("sensitive_log_hits", 0)
            db_lat = observability_snapshot.get("db_latency_max_ms")

            lines.append("=== LIVE BEHAVIORAL OBSERVATIONS ===")
            lines.append(f"Peak CPU: {round(float(cpu), 2)}%")
            lines.append(f"Peak Memory: {round(float(mem) / (1024*1024), 2)} MB")
            lines.append(f"Error log hits: {errors}")
            lines.append(f"Sensitive data leak hits: {leaks}")
            if db_lat:
                lines.append(f"DB latency peak: {round(float(db_lat), 2)} ms")
            if float(cpu) > 70:
                lines.append("⚠ HIGH CPU DETECTED — target may be vulnerable to resource exhaustion")
            if errors > 5:
                lines.append("⚠ MANY ERRORS — target is crashing or throwing exceptions, probe harder")
            if leaks > 0:
                lines.append("⚠ SENSITIVE DATA LEAKING in logs — potential information disclosure")
            if db_lat and float(db_lat) > 100:
                lines.append("⚠ HIGH DB LATENCY — possible SQL injection or query abuse vector")

        return "\n".join(lines) if lines else "No prior context available."

    def suggest_attack(
        self,
        graph_snapshot: Dict,
        observability_snapshot: Dict,
        attempt_idx: int,
        base_url: str,
        stack_snapshot: Dict | None = None,
        target_urls: List[str] | None = None,
        mode: str = "safe",
        attack_phase: str = "exploit",
        phase_context: Dict | None = None,
    ) -> LLMSuggestion:
        if not self._is_localhost_url(base_url):
            return self._fallback(
                base_url=base_url,
                reason="NonLocalhostTarget",
                attempt_idx=attempt_idx,
                mode=mode,
                phase=attack_phase,
            )

        system_prompt = self._system_prompt(mode, attack_phase)
        stack_snapshot = stack_snapshot or {}
        target_urls = target_urls or [base_url]

        # Build rich context including behavioral feedback
        accumulated_intel = self._build_conversation_context(
            phase=attack_phase,
            phase_context=phase_context,
            observability_snapshot=observability_snapshot,
        )

        context_envelope = self._build_context_envelope(
            attempt_idx=attempt_idx,
            attack_phase=attack_phase,
            mode=mode,
            base_url=base_url,
            target_urls=target_urls,
            stack_snapshot=stack_snapshot,
            graph_snapshot=graph_snapshot,
            accumulated_intel=accumulated_intel,
        )

        try:
            warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")
            style = self._resolved_api_style()
            if style == "openai":
                body = self._call_openai_chat(system_prompt, context_envelope)
                raw_text = (
                    body.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
                source_name = "remote-openai-compat"
            else:
                body = self._call_ollama(system_prompt, context_envelope)
                raw_text = body.get("response", "")
                source_name = "remote-ollama"

            parsed = self._extract_json(raw_text)
            validation_notes: List[str] = []

            for field in ["plan", "payload", "tool", "command_suggestion"]:
                if field not in parsed or not parsed[field]:
                    raise ValueError(f"Missing field: {field}")

            command_suggestion = self._sanitize_command_suggestion(str(parsed["command_suggestion"]))
            if "http://" in command_suggestion or "https://" in command_suggestion:
                if "localhost" not in command_suggestion and "127.0.0.1" not in command_suggestion:
                    raise ValueError("command_suggestion includes non-localhost URL")

            normalized_tool = self._normalize_tool(str(parsed["tool"]), attack_phase)
            if normalized_tool != str(parsed["tool"]).strip().lower():
                validation_notes.append("tool-normalized")

            # Capture LLM reasoning if provided
            reasoning = str(parsed.get("reasoning", ""))
            if reasoning:
                validation_notes.append(f"llm-reasoning:{reasoning[:200]}")

            return LLMSuggestion(
                plan=str(parsed["plan"]),
                payload=str(parsed["payload"]),
                tool=normalized_tool,
                command_suggestion=command_suggestion,
                source=source_name,
                goal_stage=str(parsed.get("goal_stage") or attack_phase),
                expected_signal=str(parsed.get("expected_signal") or "status_or_error_shift"),
                confidence=self._coerce_confidence(parsed.get("confidence", 0.6)),
                validation_notes=validation_notes,
                fallback_reason=None,
            )
        except Exception as exc:
            return self._fallback(
                base_url=base_url,
                reason=type(exc).__name__,
                attempt_idx=attempt_idx,
                mode=mode,
                phase=attack_phase,
            )

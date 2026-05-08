"""Remote Ollama client with mode-aware prompting and deterministic fallback."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict


DEFAULT_MODEL = "llama3.1:8b"


@dataclass
class LLMSuggestion:
    plan: str
    payload: str
    tool: str
    command_suggestion: str
    source: str


class RemoteLLMClient:
    def __init__(self, host: str | None = None, model: str | None = None, timeout_s: int = 20):
        self.host = (host or os.getenv("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL") or DEFAULT_MODEL
        self.timeout_s = timeout_s

    @staticmethod
    def _is_localhost_url(candidate: str) -> bool:
        allowed = ("http://localhost", "http://127.0.0.1", "http://[::1]")
        return any(candidate.startswith(prefix) for prefix in allowed)

    @staticmethod
    def _system_prompt(mode: str) -> str:
        if mode == "aggressive":
            return (
                "You are an expert red-team assistant for authorized local simulation. "
                "Return only strict JSON with keys: plan,payload,tool,command_suggestion. "
                "Prefer high-signal but controlled probes. Never target non-localhost hosts."
            )
        return (
            "You are an expert security testing assistant for authorized local simulation. "
            "Return only strict JSON with keys: plan,payload,tool,command_suggestion. "
            "Prefer low-risk validation probes first. Never target non-localhost hosts."
        )

    @staticmethod
    def _fallback(base_url: str, reason: str, attempt_idx: int, mode: str) -> LLMSuggestion:
        safe_payloads = [
            ("Header-only probe", "health-check", "curl"),
            ("Basic query fuzz", "' OR '1'='1", "playwright"),
            ("Path traversal probe", "../../etc/passwd", "curl"),
        ]
        aggressive_payloads = [
            ("Union payload probe", "' UNION SELECT NULL--", "sqlmap"),
            ("XSS reflector probe", "<script>alert(1)</script>", "playwright"),
            ("Template injection probe", "{{7*7}}", "nuclei"),
        ]
        pool = aggressive_payloads if mode == "aggressive" else safe_payloads
        plan, payload, tool = pool[(attempt_idx - 1) % len(pool)]
        suggestion = f"GET {base_url}/?q={payload}"
        return LLMSuggestion(
            plan=plan,
            payload=payload,
            tool=tool,
            command_suggestion=suggestion,
            source=f"fallback:{reason}",
        )

    @staticmethod
    def _extract_json(text: str) -> Dict:
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise ValueError("No JSON object found in LLM response")
        return json.loads(match.group(0))

    @staticmethod
    def _normalize_tool(tool_name: str) -> str:
        allowed = {"nuclei", "sqlmap", "playwright", "curl"}
        tool = (tool_name or "").strip().lower()
        if tool in allowed:
            return tool
        return "curl"

    def suggest_attack(
        self,
        graph_snapshot: Dict,
        observability_snapshot: Dict,
        attempt_idx: int,
        base_url: str,
        mode: str = "safe",
    ) -> LLMSuggestion:
        if not self._is_localhost_url(base_url):
            return self._fallback(base_url=base_url, reason="NonLocalhostTarget", attempt_idx=attempt_idx, mode=mode)

        system_prompt = self._system_prompt(mode)
        payload = {
            "model": self.model,
            "stream": False,
            "system": system_prompt,
            "prompt": (
                f"Attempt: {attempt_idx}\n"
                f"Mode: {mode}\n"
                f"Base URL: {base_url}\n"
                f"Graph: {json.dumps(graph_snapshot)}\n"
                f"Observability: {json.dumps(observability_snapshot)}"
            ),
        }

        try:
            import requests

            response = requests.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=self.timeout_s,
            )
            response.raise_for_status()
            body = response.json()
            raw_text = body.get("response", "")
            parsed = self._extract_json(raw_text)

            for field in ["plan", "payload", "tool", "command_suggestion"]:
                if field not in parsed or not parsed[field]:
                    raise ValueError(f"Missing field: {field}")

            command_suggestion = str(parsed["command_suggestion"]).strip()
            if "http://" in command_suggestion or "https://" in command_suggestion:
                if "localhost" not in command_suggestion and "127.0.0.1" not in command_suggestion:
                    raise ValueError("command_suggestion includes non-localhost URL")

            return LLMSuggestion(
                plan=str(parsed["plan"]),
                payload=str(parsed["payload"]),
                tool=self._normalize_tool(str(parsed["tool"])),
                command_suggestion=command_suggestion,
                source="remote-ollama",
            )
        except Exception as exc:
            return self._fallback(
                base_url=base_url,
                reason=type(exc).__name__,
                attempt_idx=attempt_idx,
                mode=mode,
            )

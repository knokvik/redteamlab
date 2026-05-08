"""Remote Ollama client with strict JSON parsing and safe fallback."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict

import requests


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
    def _fallback(base_url: str, reason: str) -> LLMSuggestion:
        return LLMSuggestion(
            plan="Baseline query-parameter fuzz probe against localhost target",
            payload="' OR '1'='1",
            tool="playwright",
            command_suggestion=f"GET {base_url}/?q=%27%20OR%20%271%27=%271",
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

    def suggest_attack(
        self,
        graph_snapshot: Dict,
        observability_snapshot: Dict,
        attempt_idx: int,
        base_url: str,
    ) -> LLMSuggestion:
        payload = {
            "model": self.model,
            "stream": False,
            "prompt": (
                "You are assisting with authorized local security simulation. "
                "Return ONLY JSON with keys plan,payload,tool,command_suggestion. "
                "Target must stay localhost.\n\n"
                f"Attempt: {attempt_idx}\n"
                f"Base URL: {base_url}\n"
                f"Graph: {json.dumps(graph_snapshot)}\n"
                f"Observability: {json.dumps(observability_snapshot)}"
            ),
        }

        try:
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

            return LLMSuggestion(
                plan=str(parsed["plan"]),
                payload=str(parsed["payload"]),
                tool=str(parsed["tool"]).lower(),
                command_suggestion=str(parsed["command_suggestion"]),
                source="remote-ollama",
            )
        except Exception as exc:
            return self._fallback(base_url=base_url, reason=type(exc).__name__)

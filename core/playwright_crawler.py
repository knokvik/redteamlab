"""Playwright-based crawler and graph bootstrap for running targets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import networkx as nx
import yaml


@dataclass
class TargetURL:
    service: str
    url: str
    host_port: int


def _service_host_ports(service_cfg: Dict) -> List[int]:
    ports = service_cfg.get("ports", [])
    host_ports: List[int] = []
    for item in ports:
        if isinstance(item, str) and ":" in item:
            host, _ = item.split(":", 1)
            try:
                host_ports.append(int(host.strip().strip('"').strip("'")))
            except ValueError:
                continue
        elif isinstance(item, dict):
            published = item.get("published")
            try:
                if published is not None:
                    host_ports.append(int(published))
            except ValueError:
                continue
    return host_ports


def discover_target_urls(compose_file: Path | str) -> List[TargetURL]:
    compose_path = Path(compose_file).resolve()
    doc = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    services = doc.get("services", {})

    candidates: List[TargetURL] = []

    for name, cfg in services.items():
        labels = cfg.get("labels", {})
        role = labels.get("app.role", "") if isinstance(labels, dict) else ""
        class_label = labels.get("class", "") if isinstance(labels, dict) else ""

        if class_label != "victim":
            continue

        for host_port in _service_host_ports(cfg):
            url = f"http://localhost:{host_port}"
            candidates.append(TargetURL(service=name, url=url, host_port=host_port))

    # Prioritize expected web-facing service naming + ports.
    score = {
        "target-web": 100,
        "web": 90,
        "frontend": 80,
        "target-api": 60,
        "api": 50,
    }

    def rank_key(item: TargetURL) -> Tuple[int, int]:
        base = 10
        lname = item.service.lower()
        for key, value in score.items():
            if key in lname:
                base = max(base, value)
        if item.host_port in (80, 3000, 5173, 8080, 8000, 9700):
            base += 15
        return (-base, item.host_port)

    return sorted(candidates, key=rank_key)


def select_primary_target_url(compose_file: Path | str) -> str:
    candidates = discover_target_urls(compose_file)
    if not candidates:
        return "http://localhost:9700"
    return candidates[0].url


def _append_flow(flows: List[Dict], name: str, ok: bool, note: str) -> None:
    flows.append({"name": name, "ok": ok, "note": note})


def crawl_and_build_graph(base_url: str, run_id: str, timeout_ms: int = 12000) -> Dict:
    """Crawl target URL and derive endpoint evidence + initial attack graph."""
    now = datetime.now(timezone.utc).isoformat()
    endpoints: set[str] = set()
    flows: List[Dict] = []

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover
        graph = nx.DiGraph()
        graph.add_nodes_from(["attacker", "frontend"])
        graph.add_edge("attacker", "frontend", reason="playwright-not-available")
        return {
            "run_id": run_id,
            "base_url": base_url,
            "timestamp": now,
            "error": f"playwright import failed: {exc}",
            "flows": [{"name": "init", "ok": False, "note": str(exc)}],
            "endpoints": [],
            "graph": {
                "nodes": list(graph.nodes),
                "edges": [{"source": u, "target": v, **d} for u, v, d in graph.edges(data=True)],
            },
        }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(extra_http_headers={"X-RedTeam-ID": run_id})
        context.set_default_timeout(timeout_ms)
        page = context.new_page()

        def capture_request(request) -> None:
            url = request.url
            if url.startswith("http://") or url.startswith("https://"):
                endpoints.add(url)

        page.on("request", capture_request)

        # Flow 1: homepage.
        try:
            page.goto(base_url, wait_until="domcontentloaded")
            _append_flow(flows, "homepage", True, "loaded")
        except Exception as exc:
            _append_flow(flows, "homepage", False, str(exc))

        # Flow 2: login form interaction (best effort selectors).
        try:
            for selector, value in [
                ("input[type='email']", "redteam@example.local"),
                ("input[name*='user']", "redteam"),
                ("input[name*='email']", "redteam@example.local"),
                ("input[type='password']", "RedTeamPass123!"),
            ]:
                loc = page.locator(selector)
                if loc.count() > 0:
                    loc.first.fill(value)
            for button_selector in [
                "button:has-text('Login')",
                "button:has-text('Sign in')",
                "button[type='submit']",
            ]:
                btn = page.locator(button_selector)
                if btn.count() > 0:
                    btn.first.click()
                    break
            _append_flow(flows, "login-flow", True, "attempted selectors")
        except Exception as exc:
            _append_flow(flows, "login-flow", False, str(exc))

        # Flow 3: API call.
        try:
            page.evaluate(
                """
                async () => {
                    const endpoints = ['/api/health', '/api/status', '/health', '/status'];
                    for (const ep of endpoints) {
                        try { await fetch(ep, {headers: {'X-RedTeam-ID': 'crawler'}}); } catch (e) {}
                    }
                }
                """
            )
            _append_flow(flows, "api-flow", True, "fetch probes executed")
        except Exception as exc:
            _append_flow(flows, "api-flow", False, str(exc))

        # Flow 4: logout/navigation.
        try:
            for selector in ["text=Logout", "text=Sign out", "a[href*='logout']", "button:has-text('Logout')"]:
                loc = page.locator(selector)
                if loc.count() > 0:
                    loc.first.click()
                    break
            _append_flow(flows, "logout-flow", True, "best-effort")
        except Exception as exc:
            _append_flow(flows, "logout-flow", False, str(exc))

        context.close()
        browser.close()

    graph = nx.DiGraph()
    graph.add_node("attacker", kind="red_team")
    graph.add_node("frontend", kind="web")
    graph.add_edge("attacker", "frontend", reason="http-entry")

    parsed = [urlparse(endpoint) for endpoint in endpoints]
    has_api = any("/api" in p.path for p in parsed)
    if has_api:
        graph.add_node("backend", kind="api")
        graph.add_edge("frontend", "backend", reason="api-calls-observed")

    # Conservative default edge for data layer possibility.
    graph.add_node("db", kind="data")
    if has_api:
        graph.add_edge("backend", "db", reason="backend-data-path")
    else:
        graph.add_edge("frontend", "db", reason="possible-data-integration")

    return {
        "run_id": run_id,
        "base_url": base_url,
        "timestamp": now,
        "flows": flows,
        "endpoints": sorted(endpoints),
        "graph": {
            "nodes": [{"id": node, **attrs} for node, attrs in graph.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in graph.edges(data=True)],
        },
    }

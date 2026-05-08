"""Generate a production-quality, self-contained HTML report for red-team runs."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import networkx as nx
from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    import plotly.graph_objects as go
    import plotly.io as pio
except Exception:  # pragma: no cover - graceful degradation when plotly is missing
    go = None
    pio = None


TEMPLATE_NAME = "report_template.html"


def _slugify(name: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip().lower())
    normalized = normalized.strip("-")
    return normalized or "repo"


def _behavior_impact_score(observability_summary: Dict, attacks: List[Dict]) -> float:
    max_cpu = float(observability_summary.get("max_cpu_percent", 0.0))
    max_mem = float(observability_summary.get("max_memory_bytes", 0.0))
    success_count = sum(1 for a in attacks if a.get("success"))

    cpu_score = min(10.0, max_cpu / 10.0)
    mem_score = min(10.0, max_mem / (512 * 1024 * 1024))
    success_score = min(10.0, success_count * 2.0)
    return round((cpu_score * 0.45) + (mem_score * 0.25) + (success_score * 0.3), 2)


def _base_cvss_from_attacks(attacks: List[Dict]) -> float:
    if not attacks:
        return 0.0

    high_signal = 0
    for attempt in attacks:
        text = f"{attempt.get('plan', '')} {attempt.get('output', '')}".lower()
        if any(token in text for token in ["vulnerable", "sql", "injection", "xss", "critical", "password"]):
            high_signal += 1

    ratio = high_signal / max(1, len(attacks))
    return round(min(10.0, 3.5 + (ratio * 6.5)), 2)


def _cvss_badge_color(score: float) -> str:
    if score >= 9.0:
        return "#7f1d1d"
    if score >= 7.0:
        return "#b91c1c"
    if score >= 4.0:
        return "#b45309"
    return "#15803d"


def _summarize_logs(samples: List[Dict]) -> str:
    interesting = []
    tokens = ("error", "exception", "failed", "x-redteam-id", "sql", "traceback")

    for sample in samples[-6:]:
        for container in sample.get("containers", []):
            logs = container.get("log_excerpt", "")
            for line in logs.splitlines():
                if any(token in line.lower() for token in tokens):
                    interesting.append(f"[{container.get('container', 'unknown')}] {line}")
                if len(interesting) >= 25:
                    break
            if len(interesting) >= 25:
                break
        if len(interesting) >= 25:
            break

    if interesting:
        return "\n".join(interesting)
    return "No high-signal log lines were captured in this run window."


def _extract_metrics_series(samples: List[Dict]) -> Dict[str, List[float]]:
    timestamps: List[str] = []
    cpu_values: List[float] = []
    mem_values_mb: List[float] = []

    for sample in samples:
        timestamps.append(sample.get("timestamp", ""))
        cpu_max = 0.0
        mem_max = 0.0
        for container in sample.get("containers", []):
            cpu_max = max(cpu_max, float(container.get("cpu_percent", 0.0) or 0.0))
            mem_max = max(mem_max, float(container.get("memory_bytes", 0.0) or 0.0))
        cpu_values.append(round(cpu_max, 3))
        mem_values_mb.append(round(mem_max / (1024 * 1024), 3))

    return {"timestamps": timestamps, "cpu": cpu_values, "memory_mb": mem_values_mb}


def _graph_to_plot_html(
    graph_nodes: List[Dict],
    graph_edges: List[Dict],
    title: str,
    include_plotlyjs: bool,
) -> str:
    if go is None or pio is None:
        return (
            "<div><strong>Graph rendering unavailable:</strong> Plotly is not installed. "
            "Install dependencies with <code>pip install -r requirements.txt</code>.</div>"
        )

    graph = nx.DiGraph()
    for node in graph_nodes:
        if isinstance(node, dict):
            graph.add_node(node.get("id", "unknown"), **{k: v for k, v in node.items() if k != "id"})
        else:
            graph.add_node(str(node))
    for edge in graph_edges:
        graph.add_edge(edge.get("source", "unknown"), edge.get("target", "unknown"), reason=edge.get("reason", ""))

    if not graph.nodes:
        graph.add_node("frontend")

    positions = nx.spring_layout(graph, seed=12)

    edge_x: List[float] = []
    edge_y: List[float] = []
    for source, target in graph.edges():
        x0, y0 = positions[source]
        x1, y1 = positions[target]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line=dict(width=1.6, color="#64748b"),
        hoverinfo="none",
    )

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    for node in graph.nodes(data=True):
        node_id = node[0]
        attrs = node[1]
        x, y = positions[node_id]
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"{node_id} ({attrs.get('kind', 'node')})")
        kind = attrs.get("kind", "node")
        if kind == "red_team":
            node_color.append("#b91c1c")
        elif kind == "api":
            node_color.append("#0369a1")
        elif kind == "data":
            node_color.append("#854d0e")
        else:
            node_color.append("#0f766e")

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=[n[0] for n in graph.nodes(data=True)],
        textposition="top center",
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(size=16, color=node_color, line=dict(width=1, color="#0f172a")),
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title=title,
        template="plotly_white",
        showlegend=False,
        margin=dict(l=10, r=10, t=48, b=10),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=360,
    )

    return pio.to_html(
        fig,
        full_html=False,
        include_plotlyjs=True if include_plotlyjs else False,
        config={"displayModeBar": False},
    )


def _metrics_chart_html(samples: List[Dict], include_plotlyjs: bool) -> str:
    if go is None or pio is None:
        return (
            "<div><strong>Metrics chart unavailable:</strong> Plotly is not installed. "
            "Install dependencies with <code>pip install -r requirements.txt</code>.</div>"
        )

    series = _extract_metrics_series(samples)
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=series["timestamps"],
            y=series["cpu"],
            mode="lines+markers",
            name="CPU % (max/container)",
            line=dict(color="#b91c1c"),
        )
    )
    fig.add_trace(
        go.Scatter(
            x=series["timestamps"],
            y=series["memory_mb"],
            mode="lines+markers",
            name="Memory MB (max/container)",
            yaxis="y2",
            line=dict(color="#0369a1"),
        )
    )
    fig.update_layout(
        template="plotly_white",
        height=360,
        margin=dict(l=10, r=10, t=20, b=10),
        xaxis=dict(title="Timestamp", tickangle=25),
        yaxis=dict(title="CPU %"),
        yaxis2=dict(title="Memory MB", overlaying="y", side="right"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
    )

    return pio.to_html(
        fig,
        full_html=False,
        include_plotlyjs=True if include_plotlyjs else False,
        config={"displayModeBar": False},
    )


def _enrich_after_graph(before_graph: Dict, attacks: List[Dict]) -> Dict:
    nodes = list(before_graph.get("nodes", []))
    edges = list(before_graph.get("edges", []))

    for attack in attacks:
        if not attack.get("success"):
            continue
        tool = str(attack.get("tool", "probe"))
        payload = str(attack.get("payload", "")).strip()
        attack_node = f"attack:{tool}"
        if not any((n.get("id") == attack_node) if isinstance(n, dict) else (n == attack_node) for n in nodes):
            nodes.append({"id": attack_node, "kind": "red_team"})
        edges.append(
            {
                "source": "attacker",
                "target": attack_node,
                "reason": "successful-tool-execution",
            }
        )
        if payload:
            edges.append(
                {
                    "source": attack_node,
                    "target": "frontend",
                    "reason": f"payload:{payload[:40]}",
                }
            )

    return {"nodes": nodes, "edges": edges}


def _prioritized_fixes(attacks: List[Dict], observability_summary: Dict) -> List[str]:
    fixes = [
        "Add strict input validation and output encoding on all user-controlled parameters.",
        "Instrument rate limits and request anomaly detection for repeated probing patterns.",
        "Reduce sensitive log exposure; avoid logging raw payloads, tokens, and stack traces.",
        "Harden DB access: parameterized queries only and least-privileged DB credentials.",
    ]

    if float(observability_summary.get("max_cpu_percent", 0.0)) > 80:
        fixes.insert(0, "Investigate CPU saturation and add circuit breakers for expensive request paths.")
    if any("sql" in str(a.get("output", "")).lower() for a in attacks):
        fixes.insert(0, "Run targeted SQL injection remediation and enforce query parameterization checks.")

    return fixes[:6]


def generate_report(
    output_root: Path | str,
    repo_name: str,
    repo_url: str,
    mode: str,
    run_id: str,
    target_url: str,
    crawl_result: Dict,
    attack_result: Dict,
    observability_result: Dict,
    compose_file: str,
) -> Dict:
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d-%H%M%S")
    slug = _slugify(repo_name)
    report_dir = root / f"{timestamp}-{slug}"
    report_dir.mkdir(parents=True, exist_ok=True)

    attacks = attack_result.get("attempts", [])
    summary = observability_result.get("summary", {})
    samples = observability_result.get("samples", [])

    base_cvss = _base_cvss_from_attacks(attacks)
    behavior_impact = _behavior_impact_score(summary, attacks)
    hybrid_cvss = round((base_cvss * 0.6) + (behavior_impact * 0.4), 2)

    before_graph = crawl_result.get("graph", {"nodes": [], "edges": []})
    after_graph = _enrich_after_graph(before_graph, attacks)

    metrics_html = _metrics_chart_html(samples, include_plotlyjs=True)
    before_html = _graph_to_plot_html(
        graph_nodes=before_graph.get("nodes", []),
        graph_edges=before_graph.get("edges", []),
        title="Before Attacks",
        include_plotlyjs=False,
    )
    after_html = _graph_to_plot_html(
        graph_nodes=after_graph.get("nodes", []),
        graph_edges=after_graph.get("edges", []),
        title="After Attacks",
        include_plotlyjs=False,
    )

    report_index = report_dir / "index.html"
    run_context = {
        "repo_name": repo_name,
        "repo_url": repo_url,
        "mode": mode,
        "run_id": run_id,
        "target_url": target_url,
        "compose_file": compose_file,
        "generated_at": now.isoformat(),
        "report_dir": str(report_dir),
        "self_uri": report_index.as_uri(),
    }

    impact_context = {
        "max_cpu_percent": round(float(summary.get("max_cpu_percent", 0.0)), 3),
        "avg_cpu_percent": round(float(summary.get("avg_cpu_percent", 0.0)), 3),
        "max_memory_mb": round(float(summary.get("max_memory_bytes", 0.0)) / (1024 * 1024), 3),
        "sample_count": int(summary.get("sample_count", 0)),
        "log_excerpt": _summarize_logs(samples),
    }

    cvss_context = {
        "base": base_cvss,
        "behavior": behavior_impact,
        "hybrid": hybrid_cvss,
        "badge_color": _cvss_badge_color(hybrid_cvss),
        "explanation": (
            "Hybrid CVSS combines classic severity evidence from payload outcomes with observed "
            "runtime behavior (resource spikes and correlated logs)."
        ),
    }

    template_dir = Path(__file__).resolve().parents[1] / "templates"
    jinja_env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = jinja_env.get_template(TEMPLATE_NAME)

    html = template.render(
        run=run_context,
        timeline=attacks,
        impact=impact_context,
        cvss=cvss_context,
        fixes=_prioritized_fixes(attacks, summary),
        metrics_chart_html=metrics_html,
        graph_before_html=before_html,
        graph_after_html=after_html,
    )
    report_index.write_text(html, encoding="utf-8")

    # Traceability artifacts.
    (report_dir / "timeline.json").write_text(json.dumps(attacks, indent=2), encoding="utf-8")
    (report_dir / "observability.json").write_text(json.dumps(observability_result, indent=2), encoding="utf-8")
    (report_dir / "graph_before.json").write_text(json.dumps(before_graph, indent=2), encoding="utf-8")
    (report_dir / "graph_after.json").write_text(json.dumps(after_graph, indent=2), encoding="utf-8")

    return {
        "report_path": str(report_index),
        "report_dir": str(report_dir),
        "base_cvss": base_cvss,
        "behavior_impact": behavior_impact,
        "hybrid_cvss": hybrid_cvss,
    }

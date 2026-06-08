"""Generate production-quality HTML report with CVSS v3.1 vectors, CWE mapping, and phase-based timeline."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import networkx as nx
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.cvss_calculator import (
    CVSSVector,
    BehaviorAnalysis,
    auto_detect_vector,
    analyze_behavior,
    compute_base_score,
    compute_ebss,
    finding_score,
    severity_class,
    severity_rating,
    vector_for_cwe,
)

try:
    import plotly.graph_objects as go
    import plotly.io as pio
except Exception:
    go = None
    pio = None

TEMPLATE_NAME = "report_template.html"

# CWE mapping for common attack patterns
CWE_MAP = {
    "sqli": {"id": "CWE-89", "name": "SQL Injection", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "xss": {"id": "CWE-79", "name": "Cross-site Scripting", "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
    "ssti": {"id": "CWE-1336", "name": "Server-Side Template Injection", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "lfi": {"id": "CWE-98", "name": "Local File Inclusion", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "rce": {"id": "CWE-78", "name": "OS Command Injection", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "idor": {"id": "CWE-639", "name": "Insecure Direct Object Reference", "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"},
    "ssrf": {"id": "CWE-918", "name": "Server-Side Request Forgery", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"},
    "path_traversal": {"id": "CWE-22", "name": "Path Traversal", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "info_disclosure": {"id": "CWE-200", "name": "Information Exposure", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    "dos": {"id": "CWE-400", "name": "Resource Exhaustion", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
    "auth_bypass": {"id": "CWE-287", "name": "Authentication Bypass", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "misconfig": {"id": "CWE-16", "name": "Configuration Weakness", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
}


def _slugify(name: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip().lower())
    return normalized.strip("-") or "repo"


def _classify_finding(attack: Dict) -> Dict:
    """Map attack output to CWE and CVSS v3.1 vector."""
    text = f"{attack.get('plan', '')} {attack.get('stdout', '')} {attack.get('payload', '')}".lower()
    for key, cwe in CWE_MAP.items():
        triggers = {
            "sqli": ["sql", "injection", "union select", "sqlmap", "mysql", "postgresql"],
            "xss": ["xss", "script", "alert(", "reflected", "stored xss"],
            "ssti": ["ssti", "template", "{{", "jinja"],
            "lfi": ["lfi", "etc/passwd", "file inclusion", "traversal"],
            "rce": ["rce", "command injection", "exec(", "system(", "; id"],
            "idor": ["idor", "insecure direct"],
            "ssrf": ["ssrf", "server-side request"],
            "path_traversal": ["../", "path traversal", "directory traversal"],
            "info_disclosure": [".env", ".git/config", "information disclosure", "sensitive"],
            "dos": ["dos", "flood", "stress", "exhaustion", "siege"],
            "auth_bypass": ["auth bypass", "authentication", "bypass"],
            "misconfig": ["misconfig", "default credential", "nikto"],
        }
        if any(t in text for t in triggers.get(key, [])):
            return {"cwe": cwe, "type": key}
    return {"cwe": CWE_MAP["misconfig"], "type": "unknown"}


def _base_cvss_from_attacks(attacks: List[Dict]) -> float:
    if not attacks:
        return 0.0
    high_signal = 0
    for attempt in attacks:
        text = f"{attempt.get('plan', '')} {attempt.get('stdout', '')} {attempt.get('stderr', '')}".lower()
        if any(t in text for t in ["vulnerable", "sql", "injection", "xss", "critical", "password", "dump", "rce"]):
            high_signal += 1
    ratio = high_signal / max(1, len(attacks))
    return round(min(10.0, 3.2 + (ratio * 6.8)), 2)


def _behavior_impact_score(observability_summary: Dict, attempt_correlations: Dict[str, Dict], attacks: List[Dict]) -> float:
    max_cpu = float(observability_summary.get("max_cpu_percent", 0.0) or 0.0)
    max_mem = float(observability_summary.get("max_memory_bytes", 0.0) or 0.0)
    db_latency = observability_summary.get("db_latency_max_ms")
    err_hits = float(observability_summary.get("error_log_hits", 0) or 0)
    sensitive_hits = float(observability_summary.get("sensitive_log_hits", 0) or 0)

    cpu_score = min(10.0, max_cpu / 10.0)
    mem_score = min(10.0, max_mem / (512 * 1024 * 1024))
    db_score = min(10.0, float(db_latency or 0.0) / 40.0)
    error_score = min(10.0, err_hits / 3.0)
    leak_score = min(10.0, sensitive_hits / 2.0)
    successes = sum(1 for a in attacks if a.get("success"))
    success_score = min(10.0, successes * 2.0)

    corr_bonus = 0.0
    for corr in attempt_correlations.values():
        window = corr.get("window_summary", {})
        if float(window.get("max_cpu_percent", 0.0) or 0.0) > 60:
            corr_bonus += 0.4
        if float(window.get("error_log_hits", 0.0) or 0.0) > 0:
            corr_bonus += 0.3
        if float(window.get("sensitive_log_hits", 0.0) or 0.0) > 0:
            corr_bonus += 0.4

    score = (cpu_score * 0.25) + (mem_score * 0.15) + (db_score * 0.15) + (error_score * 0.15) + (leak_score * 0.15) + (success_score * 0.15) + corr_bonus
    return round(min(10.0, score), 2)


def _cvss_badge_class(score: float) -> str:
    return severity_class(score)


def _extract_metrics_series(samples: List[Dict]) -> Dict[str, List]:
    timestamps, cpu_values, mem_values_mb, db_latency_values = [], [], [], []
    for sample in samples:
        timestamps.append(sample.get("timestamp", ""))
        cpu_max, mem_max = 0.0, 0.0
        for container in sample.get("containers", []):
            cpu_max = max(cpu_max, float(container.get("cpu_percent", 0.0) or 0.0))
            mem_max = max(mem_max, float(container.get("memory_bytes", 0.0) or 0.0))
        db_info = sample.get("db", {})
        db_latency = db_info.get("db_query_latency_ms")
        cpu_values.append(round(cpu_max, 3))
        mem_values_mb.append(round(mem_max / (1024 * 1024), 3))
        db_latency_values.append(round(float(db_latency), 3) if isinstance(db_latency, (float, int)) else None)
    return {"timestamps": timestamps, "cpu": cpu_values, "memory_mb": mem_values_mb, "db_latency_ms": db_latency_values}


def _graph_to_plot_html(graph_nodes: List[Dict], graph_edges: List[Dict], title: str, include_plotlyjs: bool) -> str:
    if go is None:
        return "<div><strong>Graph unavailable:</strong> Plotly not installed.</div>"
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
    edge_x, edge_y = [], []
    for s, t in graph.edges():
        x0, y0 = positions[s]
        x1, y1 = positions[t]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    edge_trace = go.Scatter(x=edge_x, y=edge_y, mode="lines", line=dict(width=1.6, color="#64748b"), hoverinfo="none")
    node_x, node_y, node_text, node_color = [], [], [], []
    color_map = {"red_team": "#b91c1c", "api": "#0369a1", "data": "#854d0e"}
    for nid, attrs in graph.nodes(data=True):
        x, y = positions[nid]
        node_x.append(x); node_y.append(y)
        node_text.append(f"{nid} ({attrs.get('kind', 'node')})")
        node_color.append(color_map.get(attrs.get("kind"), "#0f766e"))
    node_trace = go.Scatter(x=node_x, y=node_y, mode="markers+text", text=[n for n in graph.nodes()], textposition="top center", hovertext=node_text, hoverinfo="text", marker=dict(size=16, color=node_color, line=dict(width=1, color="#0f172a")))
    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(title=title, template="plotly_white", showlegend=False, margin=dict(l=10, r=10, t=48, b=10), xaxis=dict(showgrid=False, zeroline=False, showticklabels=False), yaxis=dict(showgrid=False, zeroline=False, showticklabels=False), height=360)
    return pio.to_html(fig, full_html=False, include_plotlyjs=True if include_plotlyjs else False, config={"displayModeBar": False})


def _metrics_chart_html(samples: List[Dict], include_plotlyjs: bool) -> str:
    if go is None:
        return "<div><strong>Metrics chart unavailable:</strong> Plotly not installed.</div>"
    series = _extract_metrics_series(samples)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=series["timestamps"], y=series["cpu"], mode="lines+markers", name="CPU % (max)", line=dict(color="#b91c1c")))
    fig.add_trace(go.Scatter(x=series["timestamps"], y=series["memory_mb"], mode="lines+markers", name="Memory MB", yaxis="y2", line=dict(color="#0369a1")))
    fig.add_trace(go.Scatter(x=series["timestamps"], y=series["db_latency_ms"], mode="lines+markers", name="DB Latency ms", yaxis="y3", line=dict(color="#7c3aed")))
    fig.update_layout(template="plotly_white", height=380, margin=dict(l=10, r=10, t=20, b=10), xaxis=dict(title="Timestamp", tickangle=25), yaxis=dict(title="CPU %"), yaxis2=dict(title="Memory MB", overlaying="y", side="right"), yaxis3=dict(title="DB ms", overlaying="y", side="left", anchor="free", position=0.06), legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0))
    return pio.to_html(fig, full_html=False, include_plotlyjs=True if include_plotlyjs else False, config={"displayModeBar": False})


def _enrich_after_graph(before_graph: Dict, attacks: List[Dict]) -> Dict:
    nodes = list(before_graph.get("nodes", []))
    edges = list(before_graph.get("edges", []))
    for attack in attacks:
        if not attack.get("success"):
            continue
        tool = str(attack.get("tool", "probe"))
        payload = str(attack.get("payload", "")).strip()
        attack_node = f"attack:{tool}:{attack.get('attempt')}"
        if not any((n.get("id") == attack_node) if isinstance(n, dict) else (n == attack_node) for n in nodes):
            nodes.append({"id": attack_node, "kind": "red_team"})
        edges.append({"source": "attacker", "target": attack_node, "reason": f"success:{tool}"})
        if payload:
            edges.append({"source": attack_node, "target": "frontend", "reason": f"payload:{payload[:52]}"})
    return {"nodes": nodes, "edges": edges}


def _prioritized_fixes(attacks: List[Dict], observability_summary: Dict) -> List[str]:
    fixes = [
        "Add strict input validation and output encoding for all user-controlled parameters.",
        "Instrument rate limiting and request anomaly detection for repeated attack patterns.",
        "Reduce sensitive log exposure; redact tokens/secrets and avoid raw payload logging.",
        "Harden DB access with parameterized queries and least-privileged credentials.",
        "Implement Content Security Policy (CSP) headers to mitigate XSS attacks.",
        "Deploy Web Application Firewall (WAF) rules for common attack patterns.",
    ]
    if float(observability_summary.get("max_cpu_percent", 0.0) or 0.0) > 80:
        fixes.insert(0, "Investigate CPU saturation and add resource guards for expensive request paths.")
    if observability_summary.get("db_latency_max_ms") and float(observability_summary.get("db_latency_max_ms") or 0.0) > 120:
        fixes.insert(0, "Investigate DB latency spikes and optimize slow query paths under attack load.")
    if float(observability_summary.get("sensitive_log_hits", 0.0) or 0.0) > 0:
        fixes.insert(0, "Add log sanitization controls and disable sensitive-value logging in production paths.")
    if any("sql" in str(a.get("output", "")).lower() for a in attacks):
        fixes.insert(0, "Run targeted SQLi remediation and automated query parameterization checks.")
    return fixes[:10]


def _llm_summary(attacks: List[Dict]) -> Dict:
    source_counts, tool_counts, fallback_count = {}, {}, 0
    for attack in attacks:
        source = str(attack.get("source", "unknown"))
        tool = str(attack.get("tool", "unknown"))
        source_counts[source] = source_counts.get(source, 0) + 1
        tool_counts[tool] = tool_counts.get(tool, 0) + 1
        if source.startswith("fallback:"):
            fallback_count += 1
    lines = [
        f"#{a.get('attempt')} [{a.get('phase', 'n/a')}] [{a.get('source')}] tool={a.get('tool')} conf={a.get('confidence', 'n/a')} plan={str(a.get('plan', ''))[:120]}"
        for a in attacks
    ]
    return {"source_counts": source_counts, "tool_counts": tool_counts, "fallback_count": fallback_count, "suggestion_lines": lines}


def _build_findings(attacks: List[Dict]) -> List[Dict]:
    """Build structured findings with CWE, CVSS vectors, and per-finding scores."""
    findings = []
    for attack in attacks:
        if not attack.get("success"):
            continue
        classification = _classify_finding(attack)
        cwe_id = classification["cwe"]["id"]
        vec = vector_for_cwe(cwe_id)
        score = vec.base_score()
        findings.append({
            "attempt": attack.get("attempt"),
            "phase": attack.get("phase", "exploit"),
            "tool": attack.get("tool"),
            "cwe_id": cwe_id,
            "cwe_name": classification["cwe"]["name"],
            "cvss_vector": vec.vector_string(),
            "cvss_score": score,
            "cvss_severity": severity_rating(score),
            "cvss_badge_class": severity_class(score),
            "finding_type": classification["type"],
            "payload": str(attack.get("payload", ""))[:100],
            "evidence": str(attack.get("output", ""))[:300],
        })
    return findings


def generate_report(
    output_root: Path | str, repo_name: str, repo_url: str, mode: str,
    run_id: str, target_url: str, target_urls: List[str] | None,
    stack_snapshot: Dict | None, crawl_result: Dict, attack_result: Dict,
    observability_result: Dict, compose_file: str,
) -> Dict:
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    slug = _slugify(repo_name)
    report_dir = root / f"{now.strftime('%Y%m%d-%H%M%S')}-{slug}"
    report_dir.mkdir(parents=True, exist_ok=True)

    attacks = attack_result.get("attempts", [])
    summary = observability_result.get("summary", {})
    samples = observability_result.get("samples", [])
    correlations = observability_result.get("attempt_correlations", {})
    attack_context = attack_result.get("attack_context", {})

    # ── CVSS v3.1 auto-detection ──────────────────────────────────────────
    attack_ctx = attack_result.get("attack_context", {})
    cvss_vector = auto_detect_vector(attacks, summary, attack_ctx)
    base_cvss_auto = cvss_vector.base_score()

    # Legacy heuristic scores (kept for comparison)
    base_cvss_heuristic = _base_cvss_from_attacks(attacks)
    behavior_impact_heuristic = _behavior_impact_score(summary, correlations, attacks)
    hybrid_cvss = round((base_cvss_heuristic * 0.6) + (behavior_impact_heuristic * 0.4), 2)

    # ── EBSS calculation ─────────────────────────────────────────────────
    behavior_analysis = analyze_behavior(summary, attack_ctx)
    ebss = compute_ebss(base_cvss_auto, behavior_analysis)

    before_graph = crawl_result.get("graph", {"nodes": [], "edges": []})
    after_graph = _enrich_after_graph(before_graph, attacks)

    metrics_html = _metrics_chart_html(samples, include_plotlyjs=True)
    before_html = _graph_to_plot_html(before_graph.get("nodes", []), before_graph.get("edges", []), "Before Attacks", False)
    after_html = _graph_to_plot_html(after_graph.get("nodes", []), after_graph.get("edges", []), "After Attacks", False)

    findings = _build_findings(attacks)
    phases_executed = attack_result.get("phases_executed", [])

    report_index = report_dir / "index.html"
    run_context = {
        "repo_name": repo_name, "repo_url": repo_url, "mode": mode, "run_id": run_id,
        "target_url": target_url, "target_urls": target_urls or [target_url],
        "compose_file": compose_file, "generated_at": now.isoformat(),
        "report_dir": str(report_dir), "self_uri": report_index.as_uri(),
        "stack_technologies": (stack_snapshot or {}).get("technologies", []),
        "phases_executed": phases_executed,
    }
    impact_context = {
        "max_cpu_percent": round(float(summary.get("max_cpu_percent", 0.0)), 3),
        "avg_cpu_percent": round(float(summary.get("avg_cpu_percent", 0.0)), 3),
        "max_memory_mb": round(float(summary.get("max_memory_bytes", 0.0)) / (1024 * 1024), 3),
        "max_memory_percent": round(float(summary.get("max_memory_percent", 0.0)), 3),
        "sample_count": int(summary.get("sample_count", 0)),
        "db_latency_max_ms": summary.get("db_latency_max_ms"),
        "db_latency_avg_ms": summary.get("db_latency_avg_ms"),
        "db_latency_p95_ms": summary.get("db_latency_p95_ms"),
        "error_log_hits": int(summary.get("error_log_hits", 0) or 0),
        "sensitive_log_hits": int(summary.get("sensitive_log_hits", 0) or 0),
        "disk_read_bytes": summary.get("disk_read_total_bytes", 0),
        "disk_write_bytes": summary.get("disk_write_total_bytes", 0),
        "max_pids": summary.get("max_pids", 0),
        "log_excerpt": summary.get("log_excerpt") or "No correlated error/leak lines found.",
    }

    timeline = []
    for attack in attacks:
        row = dict(attack)
        corr = correlations.get(attack.get("id"), {})
        row["impact_window"] = corr.get("window_summary", {})
        timeline.append(row)

    cvss_context = {
        "base": base_cvss_heuristic,
        "behavior": behavior_impact_heuristic,
        "hybrid": hybrid_cvss,
        "badge_class": _cvss_badge_class(hybrid_cvss),
        "explanation": "Hybrid CVSS combines exploit evidence (base severity) with observed runtime behavior (CPU/memory/DB latency/log impact) using weighted scoring.",
        "weights": {"base": 0.6, "behavior": 0.4},
        # CVSS v3.1 auto-detected vector
        "auto_vector": cvss_vector.vector_string(),
        "auto_score": base_cvss_auto,
        "auto_severity": severity_rating(base_cvss_auto),
        "auto_badge_class": severity_class(base_cvss_auto),
        "vector_breakdown": cvss_vector.breakdown(),
        # EBSS
        "ebss": ebss,
        "ebss_badge_class": severity_class(ebss),
        "ebss_severity": severity_rating(ebss),
        "behavior_severity": behavior_analysis.severity,
        "behavior_severity_label": behavior_analysis.severity_label,
        "behavior_signals": behavior_analysis.signals,
    }

    template_dir = Path(__file__).resolve().parents[1] / "templates"
    jinja_env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html", "xml"]))
    template = jinja_env.get_template(TEMPLATE_NAME)

    html = template.render(
        run=run_context, timeline=timeline, impact=impact_context,
        correlations=correlations, llm=_llm_summary(attacks),
        cvss=cvss_context, fixes=_prioritized_fixes(attacks, summary),
        metrics_chart_html=metrics_html, graph_before_html=before_html,
        graph_after_html=after_html, findings=findings,
        attack_context=attack_context, phases=phases_executed,
    )
    report_index.write_text(html, encoding="utf-8")

    # Traceability artifacts
    (report_dir / "timeline.json").write_text(json.dumps(timeline, indent=2), encoding="utf-8")
    (report_dir / "observability.json").write_text(json.dumps(observability_result, indent=2), encoding="utf-8")
    (report_dir / "graph_before.json").write_text(json.dumps(before_graph, indent=2), encoding="utf-8")
    (report_dir / "graph_after.json").write_text(json.dumps(after_graph, indent=2), encoding="utf-8")
    (report_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

    return {
        "report_path": str(report_index), "report_dir": str(report_dir),
        "base_cvss": base_cvss, "behavior_impact": behavior_impact,
        "hybrid_cvss": hybrid_cvss, "llm_summary": _llm_summary(attacks),
        "findings_count": len(findings),
    }

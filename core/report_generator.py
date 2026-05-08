"""Generate a robust HTML report for red-team simulation runs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from jinja2 import Template


def _behavior_impact_score(observability_summary: Dict, attacks: List[Dict]) -> float:
    max_cpu = float(observability_summary.get("max_cpu_percent", 0.0))
    max_mem = float(observability_summary.get("max_memory_bytes", 0.0))
    successes = sum(1 for a in attacks if a.get("success"))

    cpu_score = min(10.0, max_cpu / 10.0)
    mem_score = min(10.0, max_mem / (500 * 1024 * 1024))
    success_score = min(10.0, successes * 2.0)

    return round((cpu_score * 0.4) + (mem_score * 0.2) + (success_score * 0.4), 2)


def _base_cvss_from_attacks(attacks: List[Dict]) -> float:
    if not attacks:
        return 0.0

    high_signal = 0
    for attempt in attacks:
        out = (attempt.get("output") or "").lower()
        if any(token in out for token in ["vulnerable", "sql injection", "critical", "password"]):
            high_signal += 1

    ratio = high_signal / max(1, len(attacks))
    return round(min(10.0, 4.0 + (ratio * 6.0)), 2)


def generate_report(
    output_dir: Path | str,
    target_url: str,
    crawl_result: Dict,
    attack_result: Dict,
    observability_result: Dict,
    compose_file: str,
) -> Dict:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    attacks = attack_result.get("attempts", [])
    summary = observability_result.get("summary", {})

    base_cvss = _base_cvss_from_attacks(attacks)
    behavior_impact = _behavior_impact_score(summary, attacks)
    hybrid_cvss = round((base_cvss * 0.6) + (behavior_impact * 0.4), 2)

    generated_at = datetime.now(timezone.utc).isoformat()
    graph = crawl_result.get("graph", {})

    template = Template(
        """
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>DevRedTeam Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #f7f8fa; color: #222; }
    .card { background: white; border-radius: 10px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid #e6e6e6; padding: 8px; text-align: left; vertical-align: top; }
    th { background: #fafafa; }
    code { background: #f0f2f5; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>DevRedTeam Simulation Report</h1>
    <p><strong>Generated:</strong> {{ generated_at }}</p>
    <p><strong>Target:</strong> {{ target_url }}</p>
    <p><strong>Compose:</strong> {{ compose_file }}</p>
  </div>

  <div class="card">
    <h2>Hybrid CVSS</h2>
    <p><strong>Base CVSS:</strong> {{ base_cvss }}</p>
    <p><strong>Behavior Impact:</strong> {{ behavior_impact }}</p>
    <p><strong>Hybrid CVSS:</strong> {{ hybrid_cvss }}</p>
  </div>

  <div class="card">
    <h2>Attack Graph</h2>
    <p><strong>Nodes:</strong> {{ graph.nodes|length }} | <strong>Edges:</strong> {{ graph.edges|length }}</p>
    <ul>
      {% for edge in graph.edges %}
      <li><code>{{ edge.source }} -> {{ edge.target }}</code> ({{ edge.reason or 'observed path' }})</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card">
    <h2>Observed Impact</h2>
    <p><strong>Max CPU %:</strong> {{ summary.max_cpu_percent }}</p>
    <p><strong>Avg CPU %:</strong> {{ summary.avg_cpu_percent }}</p>
    <p><strong>Max Memory (bytes):</strong> {{ summary.max_memory_bytes }}</p>
    <p><strong>Samples:</strong> {{ summary.sample_count }}</p>
  </div>

  <div class="card">
    <h2>Attack Attempts</h2>
    <table>
      <tr>
        <th>#</th><th>ID</th><th>Tool</th><th>Source</th><th>Success</th><th>Command</th><th>Output</th>
      </tr>
      {% for attack in attacks %}
      <tr>
        <td>{{ attack.attempt }}</td>
        <td>{{ attack.id }}</td>
        <td>{{ attack.tool }}</td>
        <td>{{ attack.source }}</td>
        <td>{{ attack.success }}</td>
        <td><code>{{ attack.command }}</code></td>
        <td><pre>{{ attack.output }}</pre></td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2>Prioritized Fixes</h2>
    <ol>
      <li>Harden input validation and encoding for API/query parameters.</li>
      <li>Add WAF/rate limits and anomaly alerts for attack-like patterns.</li>
      <li>Review secrets and sensitive logging hygiene in application logs.</li>
      <li>Instrument request tracing with correlation IDs across services.</li>
    </ol>
  </div>
</body>
</html>
        """
    )

    html = template.render(
        generated_at=generated_at,
        target_url=target_url,
        compose_file=compose_file,
        base_cvss=base_cvss,
        behavior_impact=behavior_impact,
        hybrid_cvss=hybrid_cvss,
        graph=graph,
        summary=summary,
        attacks=attacks,
    )

    report_file = out_dir / f"report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.html"
    report_file.write_text(html, encoding="utf-8")

    return {
        "report_path": str(report_file),
        "base_cvss": base_cvss,
        "behavior_impact": behavior_impact,
        "hybrid_cvss": hybrid_cvss,
    }

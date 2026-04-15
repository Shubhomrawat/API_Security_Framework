"""
agents/reporting_agent.py
Enhanced: historical run diffs, confidence scoring display, provider info.
"""
from __future__ import annotations
import json
import uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

from jinja2 import Environment, BaseLoader

from agents.validation_agent import ValidatedResult
from agents.security_agent import SecurityFinding
from core.history import HistoryStore, RunSummary, RunDiff
from core.logger import get_logger

logger = get_logger("reporting_agent")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI API Testing Report — {{ title }}</title>
<style>
  :root {
    --bg:#0d0d0d;--surface:#141414;--surface2:#1e1e1e;
    --accent:#00e5ff;--accent2:#7c3aed;
    --text:#e2e8f0;--muted:#64748b;
    --pass:#10b981;--fail:#f43f5e;--warn:#f59e0b;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem}
  h1{color:var(--accent);font-size:2rem;margin-bottom:.25rem}
  .meta{color:var(--muted);font-size:.9rem;margin-bottom:2rem}
  .grid{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}
  .card{background:var(--surface);border-radius:8px;padding:1.25rem;border-top:3px solid var(--accent)}
  .card h3{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.1em}
  .card p{font-size:2rem;font-weight:700;color:var(--text)}
  table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:8px;overflow:hidden;margin-bottom:2rem}
  th{background:var(--surface2);padding:.75rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;color:var(--muted)}
  td{padding:.75rem 1rem;border-bottom:1px solid var(--surface2);font-size:.85rem}
  tr:last-child td{border-bottom:none}
  .badge{display:inline-block;padding:.2rem .6rem;border-radius:999px;font-size:.7rem;font-weight:700}
  .pass{background:rgba(16,185,129,.2);color:var(--pass)}
  .fail{background:rgba(244,63,94,.2);color:var(--fail)}
  .critical{background:rgba(239,68,68,.2);color:#ef4444}
  .high{background:rgba(244,63,94,.2);color:var(--fail)}
  .medium{background:rgba(245,158,11,.2);color:var(--warn)}
  .low{background:rgba(16,185,129,.2);color:var(--pass)}
  .info{background:rgba(100,116,139,.2);color:var(--muted)}
  h2{margin:1.5rem 0 .75rem;color:var(--accent);font-size:1.2rem}
  .section{margin-bottom:2.5rem}
  .diff-box{background:var(--surface);border-radius:8px;padding:1.25rem;margin-bottom:1.5rem;border-left:4px solid var(--accent)}
  .diff-improved{border-left-color:var(--pass)}
  .diff-regressed{border-left-color:var(--fail)}
  .diff-unchanged{border-left-color:var(--muted)}
  .conf-high{color:var(--pass)}
  .conf-medium{color:var(--warn)}
  .conf-low{color:var(--fail)}
  .tag{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.7rem;background:var(--surface2);color:var(--muted);margin-right:.25rem}
</style>
</head>
<body>
<h1>🔬 AI API Testing Report</h1>
<p class="meta">
  API: <strong>{{ title }}</strong> &nbsp;|&nbsp;
  Generated: {{ generated_at }} &nbsp;|&nbsp;
  Provider: <strong>{{ provider }}</strong> ({{ model }})
  &nbsp;|&nbsp; Run ID: <code>{{ run_id }}</code>
</p>

<div class="grid">
  <div class="card"><h3>Total Tests</h3><p>{{ total }}</p></div>
  <div class="card"><h3>Passed</h3><p style="color:var(--pass)">{{ passed }}</p></div>
  <div class="card"><h3>Failed</h3><p style="color:var(--fail)">{{ failed }}</p></div>
  <div class="card"><h3>Pass Rate</h3><p>{{ "%.1f"|format(pass_rate) }}%</p></div>
  <div class="card"><h3>Security Findings</h3><p style="color:var(--warn)">{{ sec_count }}</p></div>
</div>

{% if diff %}
<div class="section">
<h2>📈 Posture Diff vs Previous Run</h2>
<div class="diff-box diff-{{ diff.overall_trend }}">
  <strong>Overall: {{ diff.overall_trend.upper() }}</strong>
  &nbsp;|&nbsp; Pass rate: {{ "%+.1f"|format(diff.pass_rate_delta) }}%
  &nbsp;|&nbsp; Findings: {{ "%+d"|format(diff.findings_delta) }}
  {% if diff.new_vulnerabilities %}
    &nbsp;|&nbsp; 🆕 New: {{ diff.new_vulnerabilities|join(", ") }}
  {% endif %}
  {% if diff.fixed_vulnerabilities %}
    &nbsp;|&nbsp; ✅ Fixed: {{ diff.fixed_vulnerabilities|join(", ") }}
  {% endif %}
</div>
{% if diff.security_deltas %}
<table>
  <thead><tr><th>OWASP</th><th>Title</th><th>Previous</th><th>Current</th><th>Trend</th></tr></thead>
  <tbody>
  {% for d in diff.security_deltas %}
  <tr>
    <td>{{ d.owasp_id }}</td><td>{{ d.title }}</td>
    <td>{{ d.prev_count }}</td><td>{{ d.curr_count }}</td>
    <td>{% if d.trend == "better" %}<span style="color:var(--pass)">▼ better</span>
        {% elif d.trend == "worse" %}<span style="color:var(--fail)">▲ worse</span>
        {% else %}<span style="color:var(--muted)">→ same</span>{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}
</div>
{% endif %}

<div class="section">
<h2>🔒 Security Findings (OWASP API Top 10)</h2>
{% if findings %}
<table>
  <thead><tr><th>OWASP</th><th>Severity</th><th>Title</th><th>Endpoint</th><th>Confidence</th><th>Source</th><th>Remediation</th></tr></thead>
  <tbody>
  {% for f in findings %}
  <tr>
    <td>{{ f.owasp_id }}</td>
    <td><span class="badge {{ f.severity }}">{{ f.severity.upper() }}</span></td>
    <td>{{ f.title }}</td>
    <td><code>{{ f.method }} {{ f.endpoint }}</code></td>
    <td><span class="conf-{{ f.confidence_label }}" title="{{ f.confidence_reason }}">
      {{ "%.0f"|format(f.confidence * 100) }}% ({{ f.confidence_label }})</span></td>
    <td><span class="tag">{{ f.source }}</span></td>
    <td>{{ f.remediation }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}<p style="color:var(--pass)">✓ No security findings detected.</p>{% endif %}
</div>

<div class="section">
<h2>📋 Test Results</h2>
<table>
  <thead><tr><th>Status</th><th>Test</th><th>Category</th><th>HTTP</th><th>Time (ms)</th><th>Failures</th></tr></thead>
  <tbody>
  {% for r in results %}
  <tr>
    <td><span class="badge {{ 'pass' if r.passed else 'fail' }}">{{ 'PASS' if r.passed else 'FAIL' }}</span></td>
    <td>{{ r.name }}</td>
    <td>{{ r.category }}</td>
    <td>{{ r.status_code or '—' }}</td>
    <td>{{ "%.0f"|format(r.elapsed_ms) }}</td>
    <td>{{ r.failure_summary }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
</div>
</body>
</html>
"""


@dataclass
class ReportRow:
    passed: bool
    name: str
    category: str
    status_code: int | None
    elapsed_ms: float
    failure_summary: str


@dataclass
class Report:
    api_title: str
    total: int
    passed: int
    failed: int
    findings: list
    rows: list
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    generated_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    provider: str = ""
    model: str = ""
    diff: object = None

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100) if self.total else 0


class ReportingAgent:
    def __init__(self, output_dir: str = "reports", track_history: bool = True):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.history = HistoryStore() if track_history else None

    def compile(
        self,
        validated: list[ValidatedResult],
        findings: list[SecurityFinding],
        api_title: str,
        provider: str = "",
        model: str = "",
    ) -> Report:
        rows = []
        for vr in validated:
            failures = "; ".join(c["detail"] for c in vr.validation.failures)
            rows.append(ReportRow(
                passed=vr.passed,
                name=vr.test_name,
                category=vr.execution.test_case.category,
                status_code=vr.execution.log.status_code,
                elapsed_ms=vr.execution.log.elapsed_ms,
                failure_summary=failures[:120] if failures else "",
            ))

        report = Report(
            api_title=api_title,
            total=len(rows),
            passed=sum(1 for r in rows if r.passed),
            failed=sum(1 for r in rows if not r.passed),
            findings=findings,
            rows=rows,
            provider=provider,
            model=model,
        )

        # Save to history and compute diff
        if self.history:
            severity_counts = {s: 0 for s in ("critical", "high", "medium", "low")}
            for f in findings:
                if f.severity in severity_counts:
                    severity_counts[f.severity] += 1

            summary = RunSummary(
                run_id=report.run_id,
                api_title=api_title,
                timestamp=report.generated_at,
                total=report.total,
                passed=report.passed,
                failed=report.failed,
                pass_rate=round(report.pass_rate, 1),
                security_findings=len(findings),
                critical=severity_counts["critical"],
                high=severity_counts["high"],
                medium=severity_counts["medium"],
                low=severity_counts["low"],
                provider=provider,
                model=model,
            )
            self.history.save_run(summary, [f.__dict__ for f in findings])
            report.diff = self.history.compute_diff(api_title)

        return report

    def save_html(self, report: Report) -> Path:
        env = Environment(loader=BaseLoader())
        tmpl = env.from_string(HTML_TEMPLATE)
        html = tmpl.render(
            title=report.api_title,
            generated_at=report.generated_at,
            total=report.total,
            passed=report.passed,
            failed=report.failed,
            pass_rate=report.pass_rate,
            sec_count=len(report.findings),
            findings=report.findings,
            results=report.rows,
            provider=report.provider,
            model=report.model,
            run_id=report.run_id,
            diff=report.diff,
        )
        path = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path.write_text(html, encoding="utf-8")
        logger.info(f"[ReportingAgent] HTML report → {path}")
        return path

    def save_json(self, report: Report) -> Path:
        diff_data = None
        if report.diff:
            diff_data = {
                "overall_trend": report.diff.overall_trend,
                "pass_rate_delta": report.diff.pass_rate_delta,
                "findings_delta": report.diff.findings_delta,
                "new_vulnerabilities": report.diff.new_vulnerabilities,
                "fixed_vulnerabilities": report.diff.fixed_vulnerabilities,
            }

        data = {
            "run_id": report.run_id,
            "api_title": report.api_title,
            "generated_at": report.generated_at,
            "provider": report.provider,
            "model": report.model,
            "summary": {
                "total": report.total,
                "passed": report.passed,
                "failed": report.failed,
                "pass_rate": round(report.pass_rate, 1),
            },
            "diff_vs_previous": diff_data,
            "security_findings": [
                {**f.__dict__, "confidence_label": f.confidence_label}
                for f in report.findings
            ],
            "test_results": [r.__dict__ for r in report.rows],
        }
        path = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info(f"[ReportingAgent] JSON report → {path}")
        return path

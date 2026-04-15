#!/usr/bin/env python3
"""
run.py — Enhanced CLI runner with multi-LLM support, OAuth2 auth, and history diffs

Usage:
  python run.py --spec samples/petstore.yaml
  python run.py --spec api.yaml --provider anthropic
  python run.py --spec api.yaml --auth "Bearer TOKEN"
  python run.py --spec api.yaml --auth-mode oauth2 \
      --oauth2-token-url https://auth.example.com/token \
      --oauth2-client-id myapp --oauth2-client-secret mysecret
  python run.py --spec api.yaml --auth-mode apikey \
      --apikey-header X-Api-Key --auth "my-key-value"
"""
import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from providers.factory import get_provider
from core.auth import AuthManager
from agents.api_understanding_agent import APIUnderstandingAgent
from agents.test_generation_agent import TestGenerationAgent
from agents.execution_agent import ExecutionAgent
from agents.validation_agent import ValidationAgent
from agents.security_agent import SecurityAgent
from agents.reporting_agent import ReportingAgent

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="AI API Testing Framework CLI",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # Core
    parser.add_argument("--spec",      required=True,  help="Path to OpenAPI/Swagger spec")
    parser.add_argument("--base-url",  default="",     help="Override base URL")
    parser.add_argument("--output",    default="reports", help="Output directory for reports")

    # LLM provider
    parser.add_argument("--provider",  default=None,
                        help="LLM provider: openai (default) | anthropic")

    # Auth — static
    parser.add_argument("--auth",      default="",
                        help="Bearer token or raw header value")
    parser.add_argument("--auth-mode", default="bearer",
                        choices=["bearer", "apikey", "oauth2", "none"],
                        help="Auth mode (default: bearer)")

    # Auth — API key
    parser.add_argument("--apikey-header", default="X-Api-Key",
                        help="Header name for API key auth (default: X-Api-Key)")

    # Auth — OAuth2
    parser.add_argument("--oauth2-token-url",    default="", help="OAuth2 token endpoint URL")
    parser.add_argument("--oauth2-client-id",    default="", help="OAuth2 client ID")
    parser.add_argument("--oauth2-client-secret",default="", help="OAuth2 client secret")
    parser.add_argument("--oauth2-scope",        default="", help="OAuth2 scope")

    # Tuning
    parser.add_argument("--no-history", action="store_true", help="Disable historical run tracking")

    args = parser.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        console.print(f"[red]Spec file not found: {spec_path}[/red]")
        sys.exit(1)

    # ── Auth setup ────────────────────────────────────────────────────────────
    auth_mode = args.auth_mode if args.auth else "none"
    auth_manager = AuthManager(
        mode=auth_mode,
        static_header_value=args.auth,
        apikey_header=args.apikey_header,
        token_url=args.oauth2_token_url,
        client_id=args.oauth2_client_id,
        client_secret=args.oauth2_client_secret,
        scope=args.oauth2_scope,
    )
    auth = auth_manager.get_headers()

    # ── Provider info ─────────────────────────────────────────────────────────
    provider = get_provider(args.provider)
    console.print(Panel.fit(
        f"🔬 [bold cyan]AI API Testing Framework[/bold cyan]\n"
        f"Provider: [bold yellow]{provider.name}[/bold yellow] · "
        f"Model: [bold yellow]{getattr(provider, 'model', 'default')}[/bold yellow] · "
        f"Auth: [bold]{auth_mode}[/bold]",
        border_style="cyan",
    ))

    # ── Step 1: Understand ────────────────────────────────────────────────────
    console.print("\n[bold]Step 1/6[/bold] 🧠 API Understanding Agent …")
    agent_u = APIUnderstandingAgent(provider_name=args.provider)
    spec = agent_u.analyze(spec_path, base_url_override=args.base_url or None)
    console.print(f"  ✓ [green]{spec.title}[/green] — {len(spec.endpoints)} endpoints")

    # ── Step 2: Generate ──────────────────────────────────────────────────────
    console.print("\n[bold]Step 2/6[/bold] ⚗️  Test Generation Agent …")
    agent_g = TestGenerationAgent(provider_name=args.provider)
    test_cases = agent_g.generate(spec, auth_header=auth)
    cats = {}
    for tc in test_cases:
        cats[tc.category] = cats.get(tc.category, 0) + 1
    cat_str = " · ".join(f"{v} {k}" for k, v in cats.items())
    console.print(f"  ✓ [green]{len(test_cases)}[/green] test cases ({cat_str})")

    # ── Step 3: Execute ───────────────────────────────────────────────────────
    console.print("\n[bold]Step 3/6[/bold] 🚀 Execution Agent …")
    agent_e = ExecutionAgent()
    exec_results = agent_e.run_all(test_cases)
    errors = sum(1 for r in exec_results if r.log.error)
    console.print(f"  ✓ {len(exec_results)} executed, {errors} network errors")

    # ── Step 4: Validate ──────────────────────────────────────────────────────
    console.print("\n[bold]Step 4/6[/bold] ✅ Validation Agent …")
    agent_v = ValidationAgent()
    validated = agent_v.validate_all(exec_results)
    passed = sum(1 for v in validated if v.passed)
    console.print(f"  ✓ {passed}/{len(validated)} passed")

    # ── Step 5: Security ──────────────────────────────────────────────────────
    console.print("\n[bold]Step 5/6[/bold] 🔒 Security Analysis Agent …")
    agent_s = SecurityAgent(provider_name=args.provider)
    findings = agent_s.analyze(validated)
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    console.print(f"  ✓ {len(findings)} findings ({crit} critical, {high} high)")

    # ── Step 6: Report ────────────────────────────────────────────────────────
    console.print("\n[bold]Step 6/6[/bold] 📊 Reporting Agent …")
    agent_r = ReportingAgent(output_dir=args.output, track_history=not args.no_history)
    report = agent_r.compile(
        validated, findings, spec.title,
        provider=provider.name,
        model=getattr(provider, "model", ""),
    )
    html_path = agent_r.save_html(report)
    json_path = agent_r.save_json(report)
    console.print(f"  ✓ HTML → {html_path}")
    console.print(f"  ✓ JSON → {json_path}")

    # ── Summary ───────────────────────────────────────────────────────────────
    console.print()
    tbl = Table(title="Test Summary", box=box.ROUNDED, border_style="cyan")
    tbl.add_column("Metric", style="bold")
    tbl.add_column("Value", style="cyan")
    tbl.add_row("Run ID",            report.run_id)
    tbl.add_row("Provider",          f"{provider.name} / {getattr(provider, 'model', '')}")
    tbl.add_row("Total Tests",       str(report.total))
    tbl.add_row("Passed",            f"[green]{report.passed}[/green]")
    tbl.add_row("Failed",            f"[red]{report.failed}[/red]")
    tbl.add_row("Pass Rate",         f"[cyan]{report.pass_rate:.1f}%[/cyan]")
    tbl.add_row("Security Findings", f"[yellow]{len(report.findings)}[/yellow]")
    console.print(tbl)

    # History diff
    if report.diff:
        diff = report.diff
        trend_color = {"improved": "green", "regressed": "red", "unchanged": "dim"}.get(diff.overall_trend, "white")
        console.print(f"\n📈 Posture vs previous run: [{trend_color}]{diff.overall_trend.upper()}[/{trend_color}] "
                      f"| Pass rate {diff.pass_rate_delta:+.1f}% "
                      f"| Findings {diff.findings_delta:+d}")
        if diff.new_vulnerabilities:
            console.print(f"   🆕 New findings: [red]{', '.join(diff.new_vulnerabilities)}[/red]")
        if diff.fixed_vulnerabilities:
            console.print(f"   ✅ Fixed: [green]{', '.join(diff.fixed_vulnerabilities)}[/green]")

    # Security findings table
    if findings:
        console.print()
        stbl = Table(title="Security Findings", box=box.SIMPLE, border_style="yellow")
        stbl.add_column("OWASP", style="dim")
        stbl.add_column("Severity")
        stbl.add_column("Title")
        stbl.add_column("Endpoint")
        stbl.add_column("Confidence")
        stbl.add_column("Source", style="dim")
        for f in findings[:15]:
            sev_color = {"critical": "red", "high": "red", "medium": "yellow",
                         "low": "green", "info": "dim"}.get(f.severity, "white")
            conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(f.confidence_label, "dim")
            stbl.add_row(
                f.owasp_id,
                f"[{sev_color}]{f.severity.upper()}[/{sev_color}]",
                f.title,
                f"{f.method} {f.endpoint}",
                f"[{conf_color}]{int(f.confidence*100)}%[/{conf_color}]",
                f.source,
            )
        console.print(stbl)


if __name__ == "__main__":
    main()

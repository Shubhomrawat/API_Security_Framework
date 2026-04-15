"""
app.py — Enhanced FastAPI server with multi-LLM, OAuth2 auth, and history API
Python 3.9 compatible — uses Optional[] instead of X | None syntax
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn
import yaml
import json as _json

load_dotenv()

from providers.factory import get_provider
from core.auth import AuthManager
from core.history import HistoryStore
from agents.api_understanding_agent import APIUnderstandingAgent
from agents.test_generation_agent import TestGenerationAgent
from agents.execution_agent import ExecutionAgent
from agents.validation_agent import ValidationAgent
from agents.security_agent import SecurityAgent
from agents.reporting_agent import ReportingAgent
from core.logger import get_logger

logger = get_logger("app")

app = FastAPI(
    title="AI API Testing Framework",
    description="Multi-agent autonomous API security and functional testing",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_history = HistoryStore()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    ui = Path("static/index.html")
    if ui.exists():
        return ui.read_text(encoding="utf-8")
    return HTMLResponse("<h1>AI API Testing Framework v2</h1><p>POST /run to start a test run.</p>")


@app.post("/run")
async def run_tests(
    spec_file: Optional[UploadFile] = File(None),
    base_url: str = Form(""),
    auth_mode: str = Form("bearer"),
    auth_header_value: str = Form(""),
    auth_header_name: str = Form("Authorization"),
    apikey_header: str = Form("X-Api-Key"),
    oauth2_token_url: str = Form(""),
    oauth2_client_id: str = Form(""),
    oauth2_client_secret: str = Form(""),
    oauth2_scope: str = Form(""),
    provider_name: str = Form(""),
    track_history: bool = Form(True),
):
    if not spec_file and not base_url:
        raise HTTPException(400, "Provide either a spec_file or a base_url")

    effective_mode = auth_mode if (auth_header_value or oauth2_client_id) else "none"
    auth_manager = AuthManager(
        mode=effective_mode,
        static_header_name=auth_header_name,
        static_header_value=auth_header_value,
        apikey_header=apikey_header,
        token_url=oauth2_token_url,
        client_id=oauth2_client_id,
        client_secret=oauth2_client_secret,
        scope=oauth2_scope,
    )
    auth = auth_manager.get_headers()
    provider = get_provider(provider_name or None)

    # 1. Understand
    understanding = APIUnderstandingAgent(provider_name=provider_name or None)
    if spec_file:
        content = await spec_file.read()
        try:
            raw = yaml.safe_load(content)
        except Exception:
            raw = _json.loads(content)
        spec = understanding.analyze(raw, base_url_override=base_url or None)
    else:
        spec = understanding.analyze_raw_text("(no spec provided)", base_url)

    # 2. Generate
    generation = TestGenerationAgent(provider_name=provider_name or None)
    test_cases = generation.generate(spec, auth_header=auth)

    # 3. Execute
    execution = ExecutionAgent()
    exec_results = execution.run_all(test_cases)

    # 4. Validate
    validation = ValidationAgent()
    validated = validation.validate_all(exec_results)

    # 5. Security
    security = SecurityAgent(provider_name=provider_name or None)
    findings = security.analyze(validated)

    # 6. Report
    reporting = ReportingAgent(track_history=track_history)
    report = reporting.compile(
        validated, findings, spec.title,
        provider=provider.name,
        model=getattr(provider, "model", ""),
    )
    html_path = reporting.save_html(report)
    json_path = reporting.save_json(report)

    diff_data = None
    if report.diff:
        diff_data = {
            "overall_trend": report.diff.overall_trend,
            "pass_rate_delta": report.diff.pass_rate_delta,
            "findings_delta": report.diff.findings_delta,
            "new_vulnerabilities": report.diff.new_vulnerabilities,
            "fixed_vulnerabilities": report.diff.fixed_vulnerabilities,
        }

    return JSONResponse({
        "status": "complete",
        "run_id": report.run_id,
        "api_title": report.api_title,
        "provider": provider.name,
        "model": getattr(provider, "model", ""),
        "summary": {
            "total": report.total,
            "passed": report.passed,
            "failed": report.failed,
            "pass_rate": round(report.pass_rate, 1),
            "security_findings": len(report.findings),
        },
        "diff_vs_previous": diff_data,
        "report_html": str(html_path),
        "report_json": str(json_path),
    })


@app.get("/history/{api_title}")
async def get_history(api_title: str, limit: int = 10):
    runs = _history.get_recent_runs(api_title, limit=limit)
    return [r.__dict__ for r in runs]


@app.get("/history/{api_title}/diff")
async def get_diff(api_title: str):
    diff = _history.compute_diff(api_title)
    if not diff:
        raise HTTPException(404, "Not enough runs to compute a diff (need at least 2)")
    return {
        "overall_trend": diff.overall_trend,
        "pass_rate_delta": diff.pass_rate_delta,
        "findings_delta": diff.findings_delta,
        "new_vulnerabilities": diff.new_vulnerabilities,
        "fixed_vulnerabilities": diff.fixed_vulnerabilities,
        "security_deltas": [d.__dict__ for d in diff.security_deltas],
    }


@app.get("/providers")
async def list_providers():
    return {
        "available": [
            {
                "name": "openai",
                "configured": bool(os.getenv("OPENAI_API_KEY")),
                "model": os.getenv("OPENAI_MODEL", "gpt-4o"),
            },
            {
                "name": "anthropic",
                "configured": bool(os.getenv("ANTHROPIC_API_KEY")),
                "model": os.getenv("ANTHROPIC_MODEL", "claude-opus-4-5"),
            },
        ],
        "active": os.getenv("LLM_PROVIDER", "auto-detect"),
    }


@app.get("/reports", response_class=JSONResponse)
async def list_reports():
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    files = sorted(reports_dir.glob("*.json"), reverse=True)
    return [{"name": f.name, "path": str(f), "size": f.stat().st_size} for f in files[:20]]


@app.get("/reports/{filename}")
async def get_report(filename: str):
    path = Path("reports") / filename
    if not path.exists():
        raise HTTPException(404, "Report not found")
    return FileResponse(path)




@app.post("/reset")
async def reset_all():
    """Delete all saved reports and reset history DB."""
    import shutil
    reports_dir = Path("reports")
    if reports_dir.exists():
        for f in reports_dir.glob("*"):
            try:
                f.unlink()
            except Exception:
                pass
    db_path = Path(os.getenv("HISTORY_DB", "aitesting.db"))
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
    logger.info("[Reset] All reports and history cleared")
    return JSONResponse({"status": "reset", "message": "All reports and history cleared"})

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "providers": {
            "openai": bool(os.getenv("OPENAI_API_KEY")),
            "anthropic": bool(os.getenv("ANTHROPIC_API_KEY")),
        },
    }


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("APP_PORT", 8000)),
        reload=os.getenv("DEBUG", "true").lower() == "true",
    )
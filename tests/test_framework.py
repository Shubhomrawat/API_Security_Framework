"""
tests/test_framework.py — Unit tests covering all new features
"""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch


# ── Provider tests ────────────────────────────────────────────────────────────

def test_provider_factory_openai(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from providers.factory import get_provider
    p = get_provider()
    assert p.name == "openai"


def test_provider_factory_anthropic(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    from providers.factory import get_provider
    p = get_provider()
    assert p.name == "anthropic"


def test_provider_factory_invalid():
    from providers.factory import get_provider
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        get_provider("grok")


# ── Auth manager tests ────────────────────────────────────────────────────────

def test_auth_manager_none():
    from core.auth import AuthManager
    am = AuthManager(mode="none")
    assert am.get_headers() == {}


def test_auth_manager_bearer():
    from core.auth import AuthManager
    am = AuthManager(mode="bearer", static_header_value="Bearer tok123")
    hdrs = am.get_headers()
    assert hdrs["Authorization"] == "Bearer tok123"


def test_auth_manager_apikey():
    from core.auth import AuthManager
    am = AuthManager(mode="apikey", static_header_value="my-secret-key",
                     apikey_header="X-Custom-Key")
    hdrs = am.get_headers()
    assert hdrs["X-Custom-Key"] == "my-secret-key"


def test_auth_manager_from_bearer_adds_prefix():
    from core.auth import AuthManager
    am = AuthManager.from_bearer("rawtoken")
    hdrs = am.get_headers()
    assert hdrs["Authorization"] == "Bearer rawtoken"


def test_auth_token_expiry():
    from core.auth import AuthToken
    import time
    t = AuthToken("Authorization", "Bearer x", expires_at=time.time() - 60)
    assert t.is_expired() is True
    t2 = AuthToken("Authorization", "Bearer x", expires_at=0)
    assert t2.is_expired() is False


# ── Security agent rule checks ────────────────────────────────────────────────

def _make_vr(ep="/pets/1", method="GET", code=200, body="{}",
             headers=None, tags=None, payload_body=None, query_params=None):
    from agents.validation_agent import ValidatedResult
    from agents.execution_agent import ExecutionResult
    from agents.test_generation_agent import TestCase
    from core.executor import RequestLog
    from core.validator import ValidationResult

    tc = TestCase(
        endpoint_path=ep, method=method,
        url=f"http://test{ep}",
        tags=tags or [],
        body=payload_body,
        query_params=query_params or {},
    )
    log = RequestLog(
        method=method, url=f"http://test{ep}",
        headers={}, payload=None,
        status_code=code,
        response_body=body,
        response_headers=headers or {},
    )
    er = ExecutionResult(test_case=tc, log=log)
    vr = MagicMock()
    vr.execution = er
    vr.validation = ValidationResult(passed=True, checks=[])
    return vr


def _make_agent():
    mock_provider = MagicMock()
    mock_provider.name = "openai"
    mock_provider.chat_json.return_value = MagicMock(content='{"findings": []}')
    from agents import security_agent as sa
    agent = object.__new__(sa.SecurityAgent)
    agent.provider = mock_provider
    return agent


def test_api1_bola_detected():
    agent = _make_agent()
    vr = _make_vr(ep="/pets/{id}", method="GET", code=200, body='{"id":1,"name":"Fido"}', tags=[])
    findings = agent._check_api1_bola(vr, "/pets/{id}", "GET", 200, '{"id":1,"name":"Fido"}')
    assert any(f.owasp_id == "API1" for f in findings)


def test_api2_broken_auth_detected():
    agent = _make_agent()
    vr = _make_vr(code=200, tags=["auth"])
    findings = agent._check_api2_broken_auth(vr, "/pets", "GET", 200, "{}")
    assert any(f.owasp_id == "API2" for f in findings)


def test_api2_correct_auth_no_finding():
    agent = _make_agent()
    vr = _make_vr(code=401, tags=["auth"])
    findings = agent._check_api2_broken_auth(vr, "/pets", "GET", 401, "{}")
    assert findings == []


def test_api4_rate_limit_missing():
    agent = _make_agent()
    vr = _make_vr(code=200, headers={})
    findings = agent._check_api4_rate_limit(vr, "/pets", "GET", 200, "{}", {})
    assert any(f.owasp_id == "API4" for f in findings)


def test_api5_admin_endpoint():
    agent = _make_agent()
    vr = _make_vr(ep="/admin/users", code=200)
    findings = agent._check_api5_function_auth(vr, "/admin/users", "GET", 200, "{}")
    assert any(f.owasp_id == "API5" for f in findings)


def test_api7_ssrf_detected():
    agent = _make_agent()
    vr = _make_vr(ep="/fetch", method="POST", code=200,
                  body='{"data":"sensitive"}',
                  payload_body={"url": "http://169.254.169.254/latest/meta-data/"})
    findings = agent._check_api7_ssrf(vr, "/fetch", "POST", 200, '{"data":"sensitive"}')
    assert any(f.owasp_id == "API7" for f in findings)


def test_api8_sqli_critical():
    agent = _make_agent()
    vr = _make_vr(code=500, body="You have an error in your SQL syntax near ...")
    findings = agent._check_api8_misconfig(
        vr, "/search", "GET", 500,
        "You have an error in your SQL syntax near ...", {})
    assert any(f.severity == "critical" for f in findings)


def test_api9_beta_endpoint():
    agent = _make_agent()
    vr = _make_vr(ep="/v0/users", code=200)
    findings = agent._check_api9_inventory(vr, "/v0/users", "GET", 200, "{}")
    assert any(f.owasp_id == "API9" for f in findings)


def test_confidence_scores_valid():
    agent = _make_agent()
    vr = _make_vr(ep="/pets/{id}", method="GET", code=200, body='{"id":1}')
    findings = agent._check_api1_bola(vr, "/pets/{id}", "GET", 200, '{"id":1}')
    for f in findings:
        assert 0.0 <= f.confidence <= 1.0
        assert f.confidence_label in ("high", "medium", "low")


def test_deduplication():
    agent = _make_agent()
    from agents.security_agent import SecurityFinding
    f1 = SecurityFinding("API1", "BOLA", "high", "desc", "/a", "GET", "ev", "rem")
    f2 = SecurityFinding("API1", "BOLA", "high", "desc", "/a", "GET", "ev", "rem")
    deduped = agent._deduplicate([f1, f2])
    assert len(deduped) == 1


# ── History store tests ───────────────────────────────────────────────────────

def test_history_save_and_retrieve(tmp_path):
    from core.history import HistoryStore, RunSummary
    store = HistoryStore(db_path=tmp_path / "test.db")
    s = RunSummary(
        run_id="run1", api_title="Test API", timestamp="2024-01-01 00:00:00",
        total=10, passed=8, failed=2, pass_rate=80.0,
        security_findings=3, critical=1, high=1, medium=1, low=0,
        provider="openai", model="gpt-4o",
    )
    store.save_run(s, [{"owasp_id": "API1", "title": "BOLA", "severity": "high",
                        "endpoint": "/a", "method": "GET"}])
    runs = store.get_recent_runs("Test API")
    assert len(runs) == 1
    assert runs[0].run_id == "run1"


def test_history_diff_trend(tmp_path):
    from core.history import HistoryStore, RunSummary
    store = HistoryStore(db_path=tmp_path / "diff.db")
    for i, (n_findings, pass_rate) in enumerate([(5, 60.0), (2, 90.0)]):
        s = RunSummary(
            run_id=f"run{i}", api_title="My API",
            timestamp=f"2024-01-0{i+1} 00:00:00",
            total=10, passed=int(10 * pass_rate / 100),
            failed=10 - int(10 * pass_rate / 100),
            pass_rate=pass_rate, security_findings=n_findings,
            critical=0, high=n_findings, medium=0, low=0,
            provider="openai", model="gpt-4o",
        )
        store.save_run(s, [{"owasp_id": "API1", "title": "BOLA", "severity": "high",
                            "endpoint": "/a", "method": "GET"}] * n_findings)
    diff = store.compute_diff("My API")
    assert diff is not None
    assert diff.overall_trend in ("improved", "regressed", "unchanged")

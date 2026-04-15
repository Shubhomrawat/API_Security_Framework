"""
agents/security_agent.py
Full OWASP API Top 10 coverage — rule-based heuristics + LLM deep scan +
false-positive confidence scoring.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from typing import Any

from providers.factory import get_provider
from agents.validation_agent import ValidatedResult
from core.logger import get_logger

logger = get_logger("security_agent")

OWASP_API_TOP10 = {
    "API1":  "Broken Object Level Authorization",
    "API2":  "Broken Authentication",
    "API3":  "Broken Object Property Level Authorization",
    "API4":  "Unrestricted Resource Consumption",
    "API5":  "Broken Function Level Authorization",
    "API6":  "Unrestricted Access to Sensitive Business Flows",
    "API7":  "Server Side Request Forgery",
    "API8":  "Security Misconfiguration",
    "API9":  "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

SEVERITY_SCORES = {"critical": 9, "high": 7, "medium": 4, "low": 2, "info": 1}


@dataclass
class SecurityFinding:
    owasp_id: str
    title: str
    severity: str        # critical | high | medium | low | info
    description: str
    endpoint: str
    method: str
    evidence: str
    remediation: str
    score: int = 0
    confidence: float = 1.0      # NEW: 0.0–1.0 false-positive confidence
    confidence_reason: str = ""  # NEW: why we rated the confidence this way
    source: str = "rule"         # "rule" | "llm"

    def __post_init__(self):
        self.score = SEVERITY_SCORES.get(self.severity, 1)

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.8:
            return "high"
        if self.confidence >= 0.5:
            return "medium"
        return "low"


class SecurityAgent:
    """
    Detects API vulnerabilities using full OWASP API Top 10 rule checks
    + LLM deep scan + false-positive confidence scoring.
    """

    def __init__(self, provider_name: str | None = None):
        self.provider = get_provider(provider_name)

    def analyze(self, validated_results: list[ValidatedResult]) -> list[SecurityFinding]:
        logger.info(f"[SecurityAgent] Scanning {len(validated_results)} results …")
        findings: list[SecurityFinding] = []

        for vr in validated_results:
            ep   = vr.execution.test_case.endpoint_path
            mth  = vr.execution.test_case.method
            code = vr.execution.log.status_code
            body = vr.execution.log.response_body
            hdrs = vr.execution.log.response_headers

            findings.extend(self._check_api1_bola(vr, ep, mth, code, body))
            findings.extend(self._check_api2_broken_auth(vr, ep, mth, code, body))
            findings.extend(self._check_api3_property_auth(vr, ep, mth, code, body))
            findings.extend(self._check_api4_rate_limit(vr, ep, mth, code, body, hdrs))
            findings.extend(self._check_api5_function_auth(vr, ep, mth, code, body))
            findings.extend(self._check_api6_business_flow(vr, ep, mth, code, body))
            findings.extend(self._check_api7_ssrf(vr, ep, mth, code, body))
            findings.extend(self._check_api8_misconfig(vr, ep, mth, code, body, hdrs))
            findings.extend(self._check_api9_inventory(vr, ep, mth, code, body))
            findings.extend(self._check_api10_unsafe_consumption(vr, ep, mth, code, body))

        # LLM deep scan on a subset
        findings.extend(self._llm_scan(validated_results[:10]))

        # Deduplicate and score
        findings = self._deduplicate(findings)
        findings.sort(key=lambda f: (f.score, f.confidence), reverse=True)

        critical = sum(1 for f in findings if f.severity == "critical")
        high     = sum(1 for f in findings if f.severity == "high")
        logger.info(f"[SecurityAgent] {len(findings)} findings ({critical} critical, {high} high)")
        return findings

    # ── API1 — Broken Object Level Authorization ──────────────────────────────

    def _check_api1_bola(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        findings = []
        if ("{id}" in ep or re.search(r"/\{[^}]+\}", ep)) and code == 200 and len(body) > 20:
            tc = vr.execution.test_case
            confidence = 0.6
            reason = "Object endpoint returned 200; manual verification needed to confirm ownership check."
            # Higher confidence if the test was sent without auth
            if not any(tc.headers.get(h) for h in ("Authorization", "X-Api-Key", "X-Auth-Token")):
                confidence = 0.85
                reason = "Unauthenticated request to object endpoint returned data — likely BOLA."
            findings.append(SecurityFinding(
                owasp_id="API1", title=OWASP_API_TOP10["API1"],
                severity="high",
                description=f"{mth} {ep} returned resource data. Verify object-level authorization is enforced.",
                endpoint=ep, method=mth,
                evidence=f"Status {code}, body length {len(body)}",
                remediation="Validate that the requesting user owns the requested resource on every request.",
                confidence=confidence, confidence_reason=reason, source="rule",
            ))
        return findings

    # ── API2 — Broken Authentication ──────────────────────────────────────────

    def _check_api2_broken_auth(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        tc = vr.execution.test_case
        if "auth" in tc.tags and code not in (401, 403):
            return [SecurityFinding(
                owasp_id="API2", title=OWASP_API_TOP10["API2"],
                severity="high",
                description=f"{mth} {ep} returned {code} on an unauthenticated request (expected 401/403).",
                endpoint=ep, method=mth,
                evidence=f"Status: {code}",
                remediation="Enforce authentication on all protected endpoints. Return 401 when token is absent.",
                confidence=0.9,
                confidence_reason="Rule checked: auth tag present and status code is not 401/403.",
                source="rule",
            )]
        return []

    # ── API3 — Broken Object Property Level Authorization ────────────────────

    def _check_api3_property_auth(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        findings = []
        if code == 200 and mth in ("GET", "PUT", "PATCH"):
            sensitive_fields = ["password", "ssn", "credit_card", "secret", "private_key", "admin"]
            body_lower = body.lower()
            exposed = [f for f in sensitive_fields if f in body_lower]
            if exposed:
                findings.append(SecurityFinding(
                    owasp_id="API3", title=OWASP_API_TOP10["API3"],
                    severity="medium",
                    description=f"{mth} {ep} may expose sensitive properties in response.",
                    endpoint=ep, method=mth,
                    evidence=f"Sensitive field patterns found: {', '.join(exposed)}",
                    remediation="Filter sensitive properties from API responses. Use allowlists, not blocklists.",
                    confidence=0.65,
                    confidence_reason="Pattern match on field names; confirm fields contain real sensitive data.",
                    source="rule",
                ))
        return findings

    # ── API4 — Unrestricted Resource Consumption ──────────────────────────────

    def _check_api4_rate_limit(self, vr, ep, mth, code, body, hdrs) -> list[SecurityFinding]:
        has_rl = any("ratelimit" in k.lower() or "x-rate" in k.lower() or "retry-after" in k.lower()
                     for k in hdrs)
        if not has_rl and mth in ("POST", "GET") and code == 200:
            return [SecurityFinding(
                owasp_id="API4", title=OWASP_API_TOP10["API4"],
                severity="low",
                description=f"No rate-limit headers found on {mth} {ep}.",
                endpoint=ep, method=mth,
                evidence="Missing X-RateLimit-*, RateLimit-*, or Retry-After headers",
                remediation="Implement rate limiting per client/IP and expose limit headers in every response.",
                confidence=0.75,
                confidence_reason="Header absence is reliable; some APIs use WAF-level rate limiting not visible here.",
                source="rule",
            )]
        return []

    # ── API5 — Broken Function Level Authorization ────────────────────────────

    def _check_api5_function_auth(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        admin_patterns = ["/admin", "/internal", "/management", "/debug", "/actuator", "/metrics", "/config"]
        if any(p in ep.lower() for p in admin_patterns):
            if code not in (401, 403, 404):
                return [SecurityFinding(
                    owasp_id="API5", title=OWASP_API_TOP10["API5"],
                    severity="high",
                    description=f"Administrative/internal endpoint {mth} {ep} is accessible (returned {code}).",
                    endpoint=ep, method=mth,
                    evidence=f"Status: {code} on admin-pattern URL",
                    remediation="Restrict admin/internal endpoints to privileged roles. Return 403 for unauthorized access.",
                    confidence=0.8,
                    confidence_reason="Admin URL pattern matched and not returning 401/403/404.",
                    source="rule",
                )]
        return []

    # ── API6 — Unrestricted Access to Sensitive Business Flows ────────────────

    def _check_api6_business_flow(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        sensitive_flows = ["/checkout", "/payment", "/transfer", "/withdraw", "/purchase", "/order", "/coupon", "/promo"]
        if mth == "POST" and any(p in ep.lower() for p in sensitive_flows) and code == 200:
            tc = vr.execution.test_case
            is_fuzz = "fuzz" in tc.tags
            if is_fuzz:
                return [SecurityFinding(
                    owasp_id="API6", title=OWASP_API_TOP10["API6"],
                    severity="medium",
                    description=f"Sensitive business flow {ep} accepted a fuzz payload and returned success.",
                    endpoint=ep, method=mth,
                    evidence=f"Fuzz test returned {code}",
                    remediation="Add business logic validation, CAPTCHA, and anomaly detection on sensitive flows.",
                    confidence=0.7,
                    confidence_reason="Fuzz payload on business flow endpoint succeeded. Confirm manually.",
                    source="rule",
                )]
        return []

    # ── API7 — Server Side Request Forgery ────────────────────────────────────

    def _check_api7_ssrf(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        tc = vr.execution.test_case
        # Check if any fuzz parameter contained an internal URL
        ssrf_indicators = ["169.254.169.254", "localhost", "127.0.0.1", "metadata.google.internal", "::1"]
        payload_str = str(tc.body or "") + str(tc.query_params or "")
        if any(ind in payload_str for ind in ssrf_indicators) and code == 200 and len(body) > 10:
            return [SecurityFinding(
                owasp_id="API7", title=OWASP_API_TOP10["API7"],
                severity="critical",
                description=f"{mth} {ep} may be vulnerable to SSRF — IMDS/localhost payload returned data.",
                endpoint=ep, method=mth,
                evidence=f"Payload contained internal address; status {code}, body {len(body)} bytes",
                remediation="Validate and allowlist URLs. Block requests to internal/cloud metadata addresses.",
                confidence=0.75,
                confidence_reason="SSRF payload succeeded. Verify response content to confirm data leakage.",
                source="rule",
            )]
        return []

    # ── API8 — Security Misconfiguration ─────────────────────────────────────

    def _check_api8_misconfig(self, vr, ep, mth, code, body, hdrs) -> list[SecurityFinding]:
        findings = []
        body_lower = body.lower()

        # Verbose errors / stack traces
        error_patterns = ["traceback", "stack trace", "exception in thread", "at com.", "sql syntax",
                          "ora-", "mysql_", "postgresql", "syntax error"]
        for pattern in error_patterns:
            if pattern in body_lower:
                findings.append(SecurityFinding(
                    owasp_id="API8", title="Verbose Error / Stack Trace Disclosure",
                    severity="medium",
                    description=f"Internal error details leaked in {mth} {ep} response.",
                    endpoint=ep, method=mth,
                    evidence=body[:300],
                    remediation="Suppress stack traces in production. Return generic error messages.",
                    confidence=0.95,
                    confidence_reason="Direct pattern match on known error leak signatures.",
                    source="rule",
                ))
                break

        # SQL injection evidence
        sqli_patterns = ["sql syntax", "ora-", "mysql_", "syntax error.*sql", "unclosed quotation"]
        for pattern in sqli_patterns:
            if re.search(pattern, body_lower):
                findings.append(SecurityFinding(
                    owasp_id="API8", title="SQL Injection Evidence",
                    severity="critical",
                    description=f"SQL error message exposed at {mth} {ep} — possible injection vulnerability.",
                    endpoint=ep, method=mth,
                    evidence=body[:300],
                    remediation="Use parameterised queries. Never surface raw DB errors to clients.",
                    confidence=0.92,
                    confidence_reason="Direct SQL error pattern match.",
                    source="rule",
                ))
                break

        # Missing security headers
        security_headers = ["x-content-type-options", "x-frame-options", "strict-transport-security",
                            "content-security-policy"]
        hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
        missing = [h for h in security_headers if h not in hdrs_lower]
        if len(missing) >= 2 and code == 200:
            findings.append(SecurityFinding(
                owasp_id="API8", title="Missing Security Headers",
                severity="low",
                description=f"{mth} {ep} is missing key security response headers.",
                endpoint=ep, method=mth,
                evidence=f"Missing: {', '.join(missing)}",
                remediation="Add HSTS, X-Content-Type-Options, X-Frame-Options, and CSP headers.",
                confidence=0.85,
                confidence_reason="Header absence is directly observable.",
                source="rule",
            ))

        return findings

    # ── API9 — Improper Inventory Management ─────────────────────────────────

    def _check_api9_inventory(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        beta_patterns = ["/v0/", "/beta/", "/alpha/", "/test/", "/dev/", "/staging/", "/internal/", "/deprecated/"]
        if any(p in ep.lower() for p in beta_patterns) and code not in (404, 410):
            return [SecurityFinding(
                owasp_id="API9", title=OWASP_API_TOP10["API9"],
                severity="low",
                description=f"Non-production/versioned endpoint {ep} is accessible in what may be a production environment.",
                endpoint=ep, method=mth,
                evidence=f"Beta/legacy URL pattern accessible (status {code})",
                remediation="Decommission or restrict old API versions. Maintain an API inventory.",
                confidence=0.7,
                confidence_reason="URL pattern heuristic; confirm whether this is a production environment.",
                source="rule",
            )]
        return []

    # ── API10 — Unsafe Consumption of APIs ───────────────────────────────────

    def _check_api10_unsafe_consumption(self, vr, ep, mth, code, body) -> list[SecurityFinding]:
        # Detect if the API proxies to external services and reflects their errors
        external_indicators = ["third-party", "upstream", "gateway", "proxy", "external service",
                               "bad gateway", "502 bad gateway", "connection refused"]
        body_lower = body.lower()
        if any(ind in body_lower for ind in external_indicators) and code in (502, 503):
            return [SecurityFinding(
                owasp_id="API10", title=OWASP_API_TOP10["API10"],
                severity="info",
                description=f"{mth} {ep} appears to proxy external requests and surfaces upstream errors.",
                endpoint=ep, method=mth,
                evidence=body[:300],
                remediation="Validate and sanitize data from third-party APIs. Handle upstream failures gracefully.",
                confidence=0.5,
                confidence_reason="Heuristic based on response body keywords; low confidence without context.",
                source="rule",
            )]
        return []

    # ── LLM Deep Scan ────────────────────────────────────────────────────────

    def _llm_scan(self, vr_list: list[ValidatedResult]) -> list[SecurityFinding]:
        if not vr_list:
            return []

        samples = []
        for vr in vr_list:
            samples.append({
                "endpoint": vr.execution.test_case.endpoint_path,
                "method": vr.execution.test_case.method,
                "status": vr.execution.log.status_code,
                "body_snippet": vr.execution.log.response_body[:200],
                "response_headers": dict(list(vr.execution.log.response_headers.items())[:10]),
            })

        prompt = f"""You are an expert API penetration tester. Analyse these HTTP response samples
and identify OWASP API Security Top 10 vulnerabilities.

For each finding, also assign a confidence score (0.0–1.0) indicating how likely this is
a TRUE positive vs a false alarm, and a brief confidence_reason.

Return a JSON object with a "findings" array where each item has:
  owasp_id, title, severity (critical|high|medium|low|info),
  description, endpoint, method, evidence, remediation,
  confidence (float 0-1), confidence_reason (string)

Samples:
{json.dumps(samples, indent=2)}

Return ONLY valid JSON."""

        try:
            resp = self.provider.chat_json([{"role": "user", "content": prompt}], max_tokens=2000)
            data = json.loads(resp.content)
            items = data if isinstance(data, list) else data.get("findings", [])
            results = []
            for item in items:
                item.setdefault("confidence", 0.6)
                item.setdefault("confidence_reason", "LLM-generated finding")
                item["source"] = "llm"
                try:
                    results.append(SecurityFinding(**{k: item[k] for k in SecurityFinding.__dataclass_fields__ if k in item}))
                except Exception:
                    pass
            logger.info(f"[SecurityAgent] LLM scan added {len(results)} findings (provider: {self.provider.name})")
            return results
        except Exception as exc:
            logger.warning(f"LLM security scan failed: {exc}")
            return []

    # ── Deduplication ─────────────────────────────────────────────────────────

    def _deduplicate(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        """Remove near-duplicate findings (same OWASP ID + endpoint + method)."""
        seen: set[tuple] = set()
        unique = []
        for f in findings:
            key = (f.owasp_id, f.endpoint, f.method, f.title[:30])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

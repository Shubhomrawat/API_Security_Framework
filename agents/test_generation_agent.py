"""
agents/test_generation_agent.py
Generates functional, negative, edge-case, and security test cases.
Now uses multi-LLM provider abstraction.
"""
from __future__ import annotations
import os
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from providers.factory import get_provider
from core.parser import APISpec, Endpoint
from core.logger import get_logger

logger = get_logger("test_generation_agent")

SQLI_PAYLOADS  = ["' OR '1'='1", "'; DROP TABLE users;--", "1' UNION SELECT null--"]
XSS_PAYLOADS   = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)"]
TRAVERSAL      = ["../../../etc/passwd", "..%2F..%2Fetc%2Fpasswd"]
SSRF_PAYLOADS  = ["http://169.254.169.254/latest/meta-data/", "http://localhost:22", "http://127.0.0.1:6379"]
LARGE_STRING   = "A" * 5000
SPECIAL_CHARS  = "!@#$%^&*(){}[]|;':\",./<>?"

FUZZ_REPLACEMENTS: dict[str, list[Any]] = {
    "string":  [LARGE_STRING, "", None, 0, False, SPECIAL_CHARS] + SQLI_PAYLOADS + XSS_PAYLOADS + SSRF_PAYLOADS,
    "integer": [-1, 0, 99999999, None, "abc", 3.14],
    "number":  [-1.0, 0, float("inf"), None, "abc"],
    "boolean": [None, "yes", 1, "true"],
    "array":   [[], [None], ["A" * 1000]],
    "object":  [{}, {"__proto__": {"admin": True}}],
}


@dataclass
class TestCase:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    description: str = ""
    category: str = "functional"
    endpoint_path: str = ""
    method: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, Any] = field(default_factory=dict)
    body: Any = None
    expected_status: int | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


class TestGenerationAgent:
    def __init__(self, provider_name: str | None = None):
        self.provider = get_provider(provider_name)

    def generate(self, spec: APISpec, auth_header: dict | None = None) -> list[TestCase]:
        logger.info(f"[TestGenerationAgent] Generating tests for {len(spec.endpoints)} endpoints …")
        all_cases: list[TestCase] = []
        auth = auth_header or {}

        for ep in spec.endpoints:
            base_url = f"{spec.base_url.rstrip('/')}{ep.path}"
            all_cases.extend(self._positive_cases(ep, base_url, auth))
            all_cases.extend(self._negative_cases(ep, base_url, auth))
            all_cases.extend(self._fuzz_cases(ep, base_url, auth))
            all_cases.extend(self._auth_bypass_cases(ep, base_url))

        all_cases.extend(self._llm_creative_cases(spec, auth))

        logger.info(f"[TestGenerationAgent] Generated {len(all_cases)} test cases (provider: {self.provider.name})")
        return all_cases

    # ── Positive ───────────────────────────────────────────────────────────────

    def _positive_cases(self, ep: Endpoint, base_url: str, auth: dict) -> list[TestCase]:
        body = self._build_sample_body(ep)
        params = {p.name: self._sample_value(p.schema) for p in ep.parameters if p.location == "query"}
        return [TestCase(
            name=f"[positive] {ep.method} {ep.path}",
            description=f"Happy-path test for {ep.summary or ep.path}",
            category="functional",
            endpoint_path=ep.path,
            method=ep.method,
            url=base_url,
            headers={"Content-Type": "application/json", **auth},
            query_params=params,
            body=body,
            expected_status=200,
            tags=["positive"],
        )]

    # ── Negative ───────────────────────────────────────────────────────────────

    def _negative_cases(self, ep: Endpoint, base_url: str, auth: dict) -> list[TestCase]:
        cases = []
        # Missing required fields
        if ep.request_body:
            cases.append(TestCase(
                name=f"[negative] {ep.method} {ep.path} — empty body",
                category="negative",
                endpoint_path=ep.path,
                method=ep.method,
                url=base_url,
                headers={"Content-Type": "application/json", **auth},
                body={},
                expected_status=400,
                tags=["negative", "validation"],
            ))
        # Wrong content-type
        cases.append(TestCase(
            name=f"[negative] {ep.method} {ep.path} — wrong content-type",
            category="negative",
            endpoint_path=ep.path,
            method=ep.method,
            url=base_url,
            headers={"Content-Type": "text/plain", **auth},
            body="not json",
            expected_status=400,
            tags=["negative"],
        ))
        return cases

    # ── Fuzz / Security ────────────────────────────────────────────────────────

    def _fuzz_cases(self, ep: Endpoint, base_url: str, auth: dict) -> list[TestCase]:
        cases = []
        body_schema = ep.request_body.get("schema", {}) if ep.request_body else {}
        properties = body_schema.get("properties", {})

        for field_name, field_schema in list(properties.items())[:3]:
            field_type = field_schema.get("type", "string")
            for payload in FUZZ_REPLACEMENTS.get(field_type, FUZZ_REPLACEMENTS["string"])[:5]:
                fuzz_body = {field_name: payload}
                cases.append(TestCase(
                    name=f"[fuzz] {ep.method} {ep.path} — {field_name}={str(payload)[:30]}",
                    category="security",
                    endpoint_path=ep.path,
                    method=ep.method,
                    url=base_url,
                    headers={"Content-Type": "application/json", **auth},
                    body=fuzz_body,
                    tags=["fuzz", "security"],
                ))

        # SSRF on URL/uri fields
        for p in ep.parameters:
            if any(kw in p.name.lower() for kw in ("url", "uri", "redirect", "callback", "href")):
                for ssrf in SSRF_PAYLOADS:
                    cases.append(TestCase(
                        name=f"[ssrf] {ep.method} {ep.path} — {p.name}",
                        category="security",
                        endpoint_path=ep.path,
                        method=ep.method,
                        url=base_url,
                        headers={"Content-Type": "application/json", **auth},
                        query_params={p.name: ssrf},
                        tags=["fuzz", "security", "ssrf"],
                    ))

        return cases

    # ── Auth bypass ───────────────────────────────────────────────────────────

    def _auth_bypass_cases(self, ep: Endpoint, base_url: str) -> list[TestCase]:
        """Send requests with no auth, expired token, and mangled token."""
        cases = []
        for label, headers in [
            ("no-auth", {}),
            ("expired-token", {"Authorization": "Bearer expired.token.value"}),
            ("malformed-token", {"Authorization": "Bearer !!invalid!!"}),
        ]:
            cases.append(TestCase(
                name=f"[auth-bypass] {ep.method} {ep.path} — {label}",
                category="security",
                endpoint_path=ep.path,
                method=ep.method,
                url=base_url,
                headers={"Content-Type": "application/json", **headers},
                tags=["auth", "security", label],
            ))
        return cases

    # ── LLM creative ──────────────────────────────────────────────────────────

    def _llm_creative_cases(self, spec: APISpec, auth: dict) -> list[TestCase]:
        if not spec.endpoints:
            return []
        endpoints_str = "\n".join(f"  {e.method} {e.path} — {e.summary}" for e in spec.endpoints[:10])
        prompt = f"""You are an API security tester. Generate 5 creative edge-case or security test cases
for this API. Focus on business logic abuse, privilege escalation, and boundary conditions.

API: {spec.title}
Endpoints:
{endpoints_str}

Return a JSON object with a "tests" array. Each test has:
  name, description, endpoint_path, method, headers (object),
  query_params (object), body (object or null), expected_status (int), tags (array of strings)

Return ONLY valid JSON."""
        try:
            resp = self.provider.chat_json([{"role": "user", "content": prompt}], max_tokens=1500)
            data = json.loads(resp.content)
            items = data.get("tests", [])
            cases = []
            for item in items:
                base = f"{spec.base_url.rstrip('/')}{item.get('endpoint_path', '/')}"
                cases.append(TestCase(
                    name=item.get("name", "LLM test"),
                    description=item.get("description", ""),
                    category="edge",
                    endpoint_path=item.get("endpoint_path", "/"),
                    method=item.get("method", "GET").upper(),
                    url=base,
                    headers={**item.get("headers", {}), **auth},
                    query_params=item.get("query_params", {}),
                    body=item.get("body"),
                    expected_status=item.get("expected_status"),
                    tags=item.get("tags", ["edge", "llm"]),
                ))
            logger.info(f"[TestGenerationAgent] LLM added {len(cases)} creative cases")
            return cases
        except Exception as exc:
            logger.warning(f"LLM creative test generation failed: {exc}")
            return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_sample_body(self, ep: Endpoint) -> Any:
        if not ep.request_body:
            return None
        schema = ep.request_body.get("schema", {})
        return {k: self._sample_value(v) for k, v in schema.get("properties", {}).items()}

    def _sample_value(self, schema: dict) -> Any:
        t = schema.get("type", "string")
        if t == "integer":
            return schema.get("example", 1)
        if t == "number":
            return schema.get("example", 1.0)
        if t == "boolean":
            return True
        if t == "array":
            return []
        if t == "object":
            return {}
        example = schema.get("example") or schema.get("default")
        if example:
            return example
        fmt = schema.get("format", "")
        if fmt == "email":
            return "test@example.com"
        if fmt in ("date-time", "date"):
            return "2024-01-01"
        if fmt == "uri":
            return "https://example.com"
        return "test_value"

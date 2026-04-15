"""
core/validator.py — Validates HTTP responses against expected rules
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from typing import Any

import jsonschema

from core.logger import get_logger

logger = get_logger("validator")

SENSITIVE_PATTERNS = [
    (r"password", "Password field exposed"),
    (r"secret", "Secret field exposed"),
    (r"api_key|apikey", "API key exposed"),
    (r"access_token|accesstoken", "Access token exposed"),
    (r"private_key", "Private key exposed"),
    (r"\b(?:\d[ -]*?){13,16}\b", "Credit card number pattern"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address exposed"),
    (r"ssn|social.security", "SSN pattern detected"),
]

VERBOSE_ERROR_PATTERNS = [
    r"stack trace",
    r"traceback",
    r"exception in thread",
    r"at com\.",
    r"sql syntax",
    r"syntax error.*sql",
    r"ORA-\d+",
    r"mysql_",
    r"postgresql",
]


@dataclass
class ValidationResult:
    passed: bool
    checks: list[dict]

    @property
    def failures(self):
        return [c for c in self.checks if not c["passed"]]


class ResponseValidator:
    """Validates response correctness, schema, and data safety."""

    def validate(
        self,
        status_code: int | None,
        response_body: str,
        expected_status: int | None = None,
        schema: dict | None = None,
    ) -> ValidationResult:
        checks = []

        # 1. Status code check
        if expected_status is not None and status_code is not None:
            passed = status_code == expected_status
            checks.append({
                "name": "Status Code",
                "passed": passed,
                "detail": f"Expected {expected_status}, got {status_code}",
            })

        # 2. Parse body
        parsed = None
        if response_body:
            try:
                parsed = json.loads(response_body)
                checks.append({"name": "JSON Parseable", "passed": True, "detail": "Response is valid JSON"})
            except json.JSONDecodeError:
                checks.append({"name": "JSON Parseable", "passed": False, "detail": "Response is not valid JSON"})

        # 3. Schema validation
        if schema and parsed is not None:
            try:
                jsonschema.validate(instance=parsed, schema=schema)
                checks.append({"name": "Schema Validation", "passed": True, "detail": "Schema matches"})
            except jsonschema.ValidationError as e:
                checks.append({"name": "Schema Validation", "passed": False, "detail": str(e.message)})

        # 4. Sensitive data exposure
        body_lower = response_body.lower()
        for pattern, label in SENSITIVE_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                checks.append({"name": f"Sensitive Data: {label}", "passed": False, "detail": f"Pattern matched: {pattern}"})

        # 5. Verbose error messages
        for pattern in VERBOSE_ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                checks.append({"name": "Verbose Error", "passed": False, "detail": f"Verbose error pattern: {pattern}"})

        # 6. Empty response on 200
        if status_code == 200 and not response_body.strip():
            checks.append({"name": "Non-Empty 200", "passed": False, "detail": "200 OK with empty body"})

        passed = all(c["passed"] for c in checks)
        return ValidationResult(passed=passed, checks=checks)

"""
agents/validation_agent.py
Validates execution results for correctness, schema compliance, and data safety.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from core.validator import ResponseValidator, ValidationResult
from agents.execution_agent import ExecutionResult
from core.logger import get_logger

logger = get_logger("validation_agent")


@dataclass
class ValidatedResult:
    execution: ExecutionResult
    validation: ValidationResult

    @property
    def passed(self) -> bool:
        return self.validation.passed

    @property
    def test_name(self) -> str:
        return self.execution.test_case.name


class ValidationAgent:
    """Validates each execution result and flags failures."""

    def __init__(self):
        self.validator = ResponseValidator()

    def validate_all(self, results: list[ExecutionResult]) -> list[ValidatedResult]:
        logger.info(f"[ValidationAgent] Validating {len(results)} results …")
        validated = []
        for r in results:
            vr = self.validator.validate(
                status_code=r.log.status_code,
                response_body=r.log.response_body,
                expected_status=r.test_case.expected_status,
            )
            validated.append(ValidatedResult(execution=r, validation=vr))

        failures = sum(1 for v in validated if not v.passed)
        logger.info(f"[ValidationAgent] {failures} failures detected")
        return validated

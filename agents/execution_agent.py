"""
agents/execution_agent.py
Runs all test cases concurrently and returns raw execution logs.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass

from core.executor import HTTPExecutor, RequestLog
from agents.test_generation_agent import TestCase
from core.logger import get_logger

logger = get_logger("execution_agent")


@dataclass
class ExecutionResult:
    test_case: TestCase
    log: RequestLog


class ExecutionAgent:
    """Asynchronously executes all test cases and records responses."""

    def __init__(self, timeout: float = 30.0, concurrency: int = 5):
        self.executor = HTTPExecutor(timeout=timeout, concurrency=concurrency)

    def run_all(self, test_cases: list) -> list:
        logger.info(f"[ExecutionAgent] Running {len(test_cases)} test cases ...")
        # Reset semaphore so it binds to the new event loop created by asyncio.run()
        self.executor._semaphore = None
        results = asyncio.run(self._run_async(test_cases))
        passed = sum(1 for r in results if r.log.error is None)
        logger.info(f"[ExecutionAgent] Completed {passed}/{len(results)} without network error")
        return results

    async def _run_async(self, test_cases: list) -> list:
        tasks = [self._execute_one(tc) for tc in test_cases]
        return await asyncio.gather(*tasks)

    async def _execute_one(self, tc: TestCase) -> ExecutionResult:
        log = await self.executor.send(
            method=tc.method,
            url=tc.url,
            headers=tc.headers,
            params=tc.query_params,
            json=tc.body,
        )
        return ExecutionResult(test_case=tc, log=log)
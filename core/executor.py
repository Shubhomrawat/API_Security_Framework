"""
core/executor.py — Async HTTP executor with logging and retry support
"""
from __future__ import annotations
import time
import asyncio
from typing import Any, Optional
from dataclasses import dataclass, field

import httpx

from core.logger import get_logger

logger = get_logger("executor")


@dataclass
class RequestLog:
    method: str
    url: str
    headers: "dict[str, str]"
    payload: Any
    status_code: Optional[int] = None
    response_body: str = ""
    response_headers: "dict[str, str]" = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None


class HTTPExecutor:
    """Async HTTP executor with retry, timeout, and detailed logging."""

    def __init__(self, timeout: float = 30.0, max_retries: int = 3, concurrency: int = 5):
        self.timeout = timeout
        self.max_retries = max_retries
        self._concurrency = concurrency
        self._semaphore: Optional[asyncio.Semaphore] = None  # created lazily inside the loop

    def _get_semaphore(self) -> asyncio.Semaphore:
        """Return (or create) the semaphore bound to the current running loop."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._concurrency)
        return self._semaphore

    async def send(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        json: Any = None,
        data: Any = None,
    ) -> RequestLog:
        headers = headers or {}
        log = RequestLog(method=method, url=url, headers=headers, payload=json or data)

        async with self._get_semaphore():
            for attempt in range(1, self.max_retries + 1):
                try:
                    async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                        t0 = time.perf_counter()
                        resp = await client.request(
                            method=method,
                            url=url,
                            headers=headers,
                            params=params,
                            json=json,
                            data=data,
                        )
                        log.elapsed_ms = (time.perf_counter() - t0) * 1000
                        log.status_code = resp.status_code
                        log.response_headers = dict(resp.headers)
                        try:
                            log.response_body = resp.text[:4096]
                        except Exception:
                            log.response_body = "<binary>"
                        logger.debug(f"{method} {url} → {resp.status_code} ({log.elapsed_ms:.1f}ms)")
                        return log
                except httpx.TimeoutException:
                    log.error = f"Timeout on attempt {attempt}"
                    logger.warning(f"Timeout [{attempt}/{self.max_retries}]: {url}")
                except Exception as exc:
                    log.error = str(exc)
                    logger.error(f"Request error [{attempt}/{self.max_retries}]: {exc}")
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
        return log

    async def send_bulk(self, requests: list[dict]) -> list[RequestLog]:
        tasks = [self.send(**r) for r in requests]
        return await asyncio.gather(*tasks)
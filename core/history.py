"""
core/history.py — Persists test run summaries and computes security posture diffs
"""
from __future__ import annotations
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from core.logger import get_logger

logger = get_logger("history")

DB_PATH = Path(os.environ.get("HISTORY_DB", "aitesting.db"))


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class RunSummary:
    run_id: str
    api_title: str
    timestamp: str
    total: int
    passed: int
    failed: int
    pass_rate: float
    security_findings: int
    critical: int
    high: int
    medium: int
    low: int
    provider: str
    model: str


@dataclass
class SecurityDelta:
    owasp_id: str
    title: str
    prev_count: int
    curr_count: int

    @property
    def delta(self) -> int:
        return self.curr_count - self.prev_count

    @property
    def trend(self) -> str:
        if self.delta > 0:
            return "worse"
        if self.delta < 0:
            return "better"
        return "same"


@dataclass
class RunDiff:
    prev_run_id: str
    curr_run_id: str
    pass_rate_delta: float
    findings_delta: int
    new_vulnerabilities: list
    fixed_vulnerabilities: list
    security_deltas: list
    overall_trend: str


# ── Storage ───────────────────────────────────────────────────────────────────

class HistoryStore:
    """SQLite-backed store for run summaries."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id       TEXT PRIMARY KEY,
                    api_title    TEXT,
                    timestamp    TEXT,
                    total        INTEGER,
                    passed       INTEGER,
                    failed       INTEGER,
                    pass_rate    REAL,
                    security_findings INTEGER,
                    critical     INTEGER,
                    high         INTEGER,
                    medium       INTEGER,
                    low          INTEGER,
                    provider     TEXT,
                    model        TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings_detail (
                    run_id   TEXT,
                    owasp_id TEXT,
                    title    TEXT,
                    severity TEXT,
                    endpoint TEXT,
                    method   TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                )
            """)
            conn.commit()

    def save_run(self, summary: RunSummary, findings_raw: list):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    summary.run_id, summary.api_title, summary.timestamp,
                    summary.total, summary.passed, summary.failed, summary.pass_rate,
                    summary.security_findings,
                    summary.critical, summary.high, summary.medium, summary.low,
                    summary.provider, summary.model,
                ),
            )
            for f in findings_raw:
                conn.execute(
                    "INSERT INTO findings_detail VALUES (?,?,?,?,?,?)",
                    (
                        summary.run_id,
                        f.get("owasp_id", ""),
                        f.get("title", ""),
                        f.get("severity", ""),
                        f.get("endpoint", ""),
                        f.get("method", ""),
                    ),
                )
            conn.commit()
        logger.info(f"[History] Saved run {summary.run_id}")

    def get_recent_runs(self, api_title: str, limit: int = 10) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM runs WHERE api_title=? ORDER BY timestamp DESC LIMIT ?",
                (api_title, limit),
            ).fetchall()
        return [RunSummary(**dict(r)) for r in rows]

    def get_findings_for_run(self, run_id: str) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings_detail WHERE run_id=?",
                (run_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def compute_diff(self, api_title: str) -> RunDiff | None:
        runs = self.get_recent_runs(api_title, limit=2)
        if len(runs) < 2:
            return None

        curr, prev = runs[0], runs[1]
        curr_findings = self.get_findings_for_run(curr.run_id)
        prev_findings = self.get_findings_for_run(prev.run_id)

        def group(findings):
            d = {}
            for f in findings:
                d.setdefault(f["owasp_id"], []).append(f)
            return d

        curr_map = group(curr_findings)
        prev_map = group(prev_findings)
        all_ids = set(curr_map) | set(prev_map)

        deltas = []
        for oid in sorted(all_ids):
            c = len(curr_map.get(oid, []))
            p = len(prev_map.get(oid, []))
            title = (curr_map.get(oid) or prev_map.get(oid) or [{}])[0].get("title", oid)
            deltas.append(SecurityDelta(owasp_id=oid, title=title, prev_count=p, curr_count=c))

        new_vulns = [d.owasp_id for d in deltas if d.prev_count == 0 and d.curr_count > 0]
        fixed = [d.owasp_id for d in deltas if d.prev_count > 0 and d.curr_count == 0]
        pass_delta = curr.pass_rate - prev.pass_rate
        findings_delta = curr.security_findings - prev.security_findings

        if findings_delta < 0 and pass_delta >= 0:
            trend = "improved"
        elif findings_delta > 0 or pass_delta < -5:
            trend = "regressed"
        else:
            trend = "unchanged"

        return RunDiff(
            prev_run_id=prev.run_id,
            curr_run_id=curr.run_id,
            pass_rate_delta=round(pass_delta, 1),
            findings_delta=findings_delta,
            new_vulnerabilities=new_vulns,
            fixed_vulnerabilities=fixed,
            security_deltas=deltas,
            overall_trend=trend,
        )

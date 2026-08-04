"""
CyberScope — database/db.py

SQLite-based persistence layer.
Stores audit sessions, findings, and module results.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class CyberScopeDB:
    """Thread-safe SQLite database for audit history."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS sessions (
        id          TEXT PRIMARY KEY,
        started_at  TEXT NOT NULL,
        mode        TEXT NOT NULL,
        target      TEXT,
        risk_level  TEXT,
        risk_score  REAL,
        modules_run TEXT,
        summary     TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  TEXT NOT NULL,
        module      TEXT NOT NULL,
        type        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence    TEXT,
        recommendation TEXT,
        mitre       TEXT,
        timestamp   TEXT NOT NULL,
        FOREIGN KEY(session_id) REFERENCES sessions(id)
    );

    CREATE TABLE IF NOT EXISTS module_results (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  TEXT NOT NULL,
        module      TEXT NOT NULL,
        status      TEXT NOT NULL,
        duration_ms REAL,
        raw_data    TEXT,
        timestamp   TEXT NOT NULL,
        FOREIGN KEY(session_id) REFERENCES sessions(id)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_sessions_date ON sessions(started_at);
    """

    def __init__(self, db_path: str = "database/cyberscope.db") -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()

    # ── Connection ─────────────────────────────────────────────────────────

    def _connect(self) -> None:
        self._conn = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            isolation_level=None,   # autocommit
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(self.SCHEMA)

    def _db(self) -> sqlite3.Connection:
        if self._conn is None: self._connect()
        return self._conn  # type: ignore

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── Sessions ───────────────────────────────────────────────────────────

    def save_session(
        self,
        session_id:  str,
        mode:        str,
        target:      str  = "",
        risk_level:  str  = "",
        risk_score:  float = 0.0,
        modules_run: List[str] = None,
        summary:     str  = "",
    ) -> None:
        self._db().execute(
            """INSERT OR REPLACE INTO sessions
               (id, started_at, mode, target, risk_level, risk_score, modules_run, summary)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                session_id,
                datetime.now(timezone.utc).isoformat(),
                mode, target, risk_level, risk_score,
                json.dumps(modules_run or []),
                summary,
            ),
        )

    def get_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self._db().execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        r = self._db().execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        return dict(r) if r else None

    # ── Findings ──────────────────────────────────────────────────────────

    def save_findings(
        self,
        session_id: str,
        findings: List[Dict[str, Any]],
    ) -> int:
        rows = [
            (
                session_id,
                f.get("module",""),
                f.get("type",""),
                f.get("severity",""),
                f.get("description",""),
                f.get("evidence",""),
                f.get("recommendation",""),
                f.get("mitre",""),
                f.get("timestamp", datetime.now(timezone.utc).isoformat()),
            )
            for f in findings
        ]
        self._db().executemany(
            """INSERT INTO findings
               (session_id,module,type,severity,description,evidence,recommendation,mitre,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        return len(rows)

    def get_findings(
        self,
        session_id: Optional[str] = None,
        severity:   Optional[str] = None,
        limit:      int = 100,
    ) -> List[Dict[str, Any]]:
        conditions, params = [], []
        if session_id:
            conditions.append("session_id=?"); params.append(session_id)
        if severity:
            conditions.append("severity=?"); params.append(severity.upper())
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        rows = self._db().execute(
            f"SELECT * FROM findings {where} ORDER BY timestamp DESC LIMIT ?", params
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Module results ─────────────────────────────────────────────────────

    def save_module_result(
        self,
        session_id:  str,
        module:      str,
        status:      str,
        duration_ms: float,
        raw_data:    Dict[str, Any],
    ) -> None:
        self._db().execute(
            """INSERT INTO module_results
               (session_id,module,status,duration_ms,raw_data,timestamp)
               VALUES (?,?,?,?,?,?)""",
            (
                session_id, module, status, duration_ms,
                json.dumps(raw_data, default=str),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    # ── Statistics ─────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        db = self._db()
        total_sessions = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_findings = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        by_sev = dict(db.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ).fetchall())
        latest = db.execute(
            "SELECT started_at FROM sessions ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return {
            "total_sessions": total_sessions,
            "total_findings": total_findings,
            "by_severity":    by_sev,
            "latest_scan":    latest[0] if latest else None,
        }

"""SQLite persistence.

Scans are stored so the console opens with results already present. That is a
demo requirement as much as a product one: a live scan must never be the thing
standing between the operator and a populated screen.
"""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any, Optional

from . import config
from .models import Evidence, Finding, ScanResult, ScanTarget

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    target_kind   TEXT NOT NULL,
    target_value  TEXT NOT NULL,
    target_label  TEXT NOT NULL,
    started_at    REAL NOT NULL,
    finished_at   REAL,
    stats         TEXT NOT NULL DEFAULT '{}',
    summary       TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT NOT NULL,
    scan_id     TEXT NOT NULL,
    payload     TEXT NOT NULL,
    risk_score  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, id),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(scan_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_scans_started  ON scans(started_at DESC);
"""


def connect() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init() -> None:
    with connect() as conn:
        conn.executescript(_SCHEMA)


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------

def _finding_to_row(f: Finding) -> str:
    return json.dumps(f.to_dict())


def _row_to_finding(payload: str) -> Finding:
    d = json.loads(payload)
    evidence = [Evidence(**{k: v for k, v in e.items() if k in Evidence.__annotations__})
                for e in d.get("evidence", [])]
    allowed = set(Finding.__annotations__)
    kwargs = {k: v for k, v in d.items() if k in allowed and k != "evidence"}
    kwargs["evidence"] = evidence
    return Finding(**kwargs)


# --------------------------------------------------------------------------
# Writes
# --------------------------------------------------------------------------

def save_scan(result: ScanResult, summary: Optional[dict[str, Any]] = None) -> str:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans "
            "(id, target_kind, target_value, target_label, started_at, finished_at, stats, summary) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (result.id, result.target.kind, result.target.value,
             result.target.label or result.target.value,
             result.started_at, result.finished_at or time.time(),
             json.dumps(result.stats), json.dumps(summary or {})),
        )
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (result.id,))
        conn.executemany(
            "INSERT INTO findings (id, scan_id, payload, risk_score) VALUES (?,?,?,?)",
            [(f.id, result.id, _finding_to_row(f), f.risk_score) for f in result.findings],
        )
    return result.id


def delete_scan(scan_id: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------

def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count "
            "FROM scans s ORDER BY s.started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["stats"] = json.loads(d["stats"])
        d["summary"] = json.loads(d["summary"])
        d["duration"] = (d["finished_at"] or 0) - d["started_at"]
        out.append(d)
    return out


def get_scan(scan_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["stats"] = json.loads(d["stats"])
    d["summary"] = json.loads(d["summary"])
    d["duration"] = (d["finished_at"] or 0) - d["started_at"]
    return d


def get_findings(scan_id: str, limit: int = 5000) -> list[Finding]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT payload FROM findings WHERE scan_id = ? ORDER BY risk_score DESC LIMIT ?",
            (scan_id, limit),
        ).fetchall()
    return [_row_to_finding(r["payload"]) for r in rows]


def load_result(scan_id: str) -> Optional[ScanResult]:
    meta = get_scan(scan_id)
    if not meta:
        return None
    result = ScanResult(
        target=ScanTarget(kind=meta["target_kind"], value=meta["target_value"],
                          label=meta["target_label"]),
        findings=get_findings(scan_id),
        started_at=meta["started_at"],
        finished_at=meta["finished_at"],
        stats=meta["stats"],
    )
    result.id = scan_id
    return result


def latest_scan_id() -> Optional[str]:
    scans = list_scans(limit=1)
    return scans[0]["id"] if scans else None

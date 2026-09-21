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
from .assessment import AssetOverride
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

-- Operator-supplied risk inputs.
--
-- Deliberately NOT keyed on finding id, and deliberately NOT a child of a
-- scan. A finding id contains the line number of its call site, so keying on
-- it would discard a hand-set twenty-five-year lifetime the moment somebody
-- edited the file above it. `asset_key` is the stable identity from
-- app/assessment.py, and the row outlives every scan of that estate.
CREATE TABLE IF NOT EXISTS asset_overrides (
    asset_key        TEXT PRIMARY KEY,
    shelf_life_years REAL,
    migration_years  REAL,
    criticality      REAL,
    sensitivity      TEXT,
    constraints      TEXT NOT NULL DEFAULT '[]',
    note             TEXT NOT NULL DEFAULT '',
    updated_at       REAL NOT NULL
);
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


# --------------------------------------------------------------------------
# Operator overrides
#
# These are the only rows in the database a human typed. Everything else is a
# detection the tool can reproduce by rescanning; an override cannot be, so it
# is kept outside the scan lifecycle and is never touched by one.
# --------------------------------------------------------------------------

def save_override(override: AssetOverride) -> AssetOverride:
    """Persist one asset's operator inputs. An empty override deletes the row."""
    if override.is_empty:
        delete_override(override.asset_key)
        return override
    override.updated_at = time.time()
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO asset_overrides "
            "(asset_key, shelf_life_years, migration_years, criticality, "
            " sensitivity, constraints, note, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (override.asset_key, override.shelf_life_years,
             override.migration_years, override.criticality,
             override.sensitivity, json.dumps(override.constraints),
             override.note, override.updated_at),
        )
    return override


def delete_override(asset_key: str) -> None:
    """Reset one asset to derived and default inputs."""
    with connect() as conn:
        conn.execute("DELETE FROM asset_overrides WHERE asset_key = ?", (asset_key,))


def get_override(asset_key: str) -> Optional[AssetOverride]:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM asset_overrides WHERE asset_key = ?", (asset_key,)
        ).fetchone()
    return _row_to_override(row) if row else None


def list_overrides() -> dict[str, AssetOverride]:
    """Every override, keyed by asset. Loaded once per scoring pass."""
    with connect() as conn:
        rows = conn.execute("SELECT * FROM asset_overrides").fetchall()
    return {r["asset_key"]: _row_to_override(r) for r in rows}


def _row_to_override(row) -> AssetOverride:
    try:
        constraints = json.loads(row["constraints"] or "[]")
    except (json.JSONDecodeError, TypeError):
        constraints = []
    return AssetOverride(
        asset_key=row["asset_key"],
        shelf_life_years=row["shelf_life_years"],
        migration_years=row["migration_years"],
        criticality=row["criticality"],
        sensitivity=row["sensitivity"],
        constraints=constraints,
        note=row["note"] or "",
        updated_at=row["updated_at"] or 0.0,
    )

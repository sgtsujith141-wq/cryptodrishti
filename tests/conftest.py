"""Shared fixtures.

The suite imports the application package directly from the source tree, so
the tests run against exactly the code that ships.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Redirect the scan database before *any* application module is imported.
# `config.DB_PATH` is resolved at import time, so setting this later -- in a
# fixture, say -- would silently let the suite write to the operator's real
# scan history under data/.
os.environ.setdefault(
    "CD_DB", str(Path(tempfile.mkdtemp(prefix="cryptodrishti-tests-")) / "scans.sqlite3")
)

from app.models import Evidence, Finding, ScanResult, ScanTarget  # noqa: E402


def make_finding(algorithm: str = "rsa-2048", *, scanner: str = "source",
                 location: str = "src/auth/keys.py", line: int = 10,
                 rule_id: str = "py.rsa.generate", confidence: float = 0.9,
                 occurrences: int = 1, **kw) -> Finding:
    """Build a Finding with `occurrences` distinct evidence entries."""
    evidence = [
        Evidence(location=location, line=line + i, symbol="generate_private_key",
                 confidence=confidence)
        for i in range(occurrences)
    ]
    return Finding(algorithm=algorithm, scanner=scanner, rule_id=rule_id,
                   evidence=evidence, **kw)


@pytest.fixture
def finding():
    return make_finding


@pytest.fixture
def scan_result():
    def _build(findings, label: str = "fixture") -> ScanResult:
        result = ScanResult(target=ScanTarget(kind="repository", value=".", label=label))
        for f in findings:
            result.add(f)
        result.finished_at = result.started_at + 1.0
        return result
    return _build

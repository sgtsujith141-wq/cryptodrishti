"""Normalisation: turn raw detector hits into cryptographic assets.

A scanner emits one hit per call site. That is the wrong unit for an
inventory. "RSA is used at 145 call sites across 89 files" is one asset with
145 occurrences, not 145 assets -- and a CBOM that lists it 145 times is not
an inventory, it is a log.

Grouping also makes the estate legible: an operator sees ~40 rows they can
reason about instead of 651 they cannot.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..models import Finding

# Paths that are not production code. A private key in a unit-test fixture is
# a real finding -- it should still appear in the inventory -- but it is not
# the same risk as one in a deployed service, and ranking it first makes the
# whole report look naive.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|testing|testdata|test-data|fixtures?|spec|specs|examples?|"
    r"sample|samples|demo|demos|benchmarks?|docs?)(/|$)"
    r"|(^|/)test_[^/]*$"
    r"|_test\.(go|py|java|c|cc|cpp|js|ts)$"
    r"|\.(test|spec)\.(js|ts|jsx|tsx)$",
    re.IGNORECASE,
)

_VENDORED_PATH = re.compile(
    r"(^|/)(vendor|third_party|thirdparty|external|node_modules|deps)(/|$)",
    re.IGNORECASE,
)


def path_class(location: str) -> str:
    """Classify a path as production, test or vendored code."""
    loc = location.replace("\\", "/")
    if _TEST_PATH.search(loc):
        return "test"
    if _VENDORED_PATH.search(loc):
        return "vendored"
    return "production"


# Business criticality multiplier applied to the risk score.
CRITICALITY = {
    "production": 1.0,
    "vendored": 0.75,   # real, but the fix is a dependency bump, not a rewrite
    "test": 0.40,       # inventory it, do not let it head the queue
}


def criticality_for(f: Finding) -> float:
    """Weight a finding by where its evidence actually lives.

    Uses the *best* (most production-like) location, so an algorithm used in
    both production and test code is scored as production.
    """
    if not f.evidence:
        return CRITICALITY["production"]
    classes = {path_class(e.location) for e in f.evidence}
    for kind in ("production", "vendored", "test"):
        if kind in classes:
            return CRITICALITY[kind]
    return CRITICALITY["production"]


def group_key(f: Finding) -> tuple:
    """What makes two hits the same cryptographic asset."""
    return (f.algorithm, f.asset_type, f.mode or "", f.padding or "",
            f.key_size or 0, f.scanner)


def normalize(findings: Iterable[Finding]) -> list[Finding]:
    """Merge detector hits into distinct cryptographic assets."""
    grouped: dict[tuple, Finding] = {}

    for f in findings:
        key = group_key(f)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = f
            continue

        existing.merge(f)
        # Keep the most informative title and detail from whichever hit had one.
        if not existing.detail and f.detail:
            existing.detail = f.detail
        if f.rule_id and f.rule_id not in existing.extra.setdefault("rule_ids", []):
            existing.extra["rule_ids"].append(f.rule_id)

    out = list(grouped.values())

    for f in out:
        # Evidence ordered so production code is what an operator sees first.
        f.evidence.sort(key=lambda e: (
            {"production": 0, "vendored": 1, "test": 2}[path_class(e.location)],
            e.location, e.line or 0,
        ))
        counts: dict[str, int] = {}
        for e in f.evidence:
            k = path_class(e.location)
            counts[k] = counts.get(k, 0) + 1
        f.extra["path_breakdown"] = counts
        f.extra["files"] = len({e.location for e in f.evidence})
        f.extra["context"] = path_class(f.evidence[0].location) if f.evidence else "production"
        # Confidence across many independent sightings is higher than one.
        if f.occurrences >= 5:
            f.confidence = min(0.99, f.confidence + 0.03)

    return out

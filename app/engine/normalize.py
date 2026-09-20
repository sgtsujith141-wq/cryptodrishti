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

from ..models import ASSURANCE_RANK, Finding, strongest_assurance

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
    """What makes two hits the same cryptographic asset.

    ``purpose`` is part of the identity, not a detail. RSA used for signing and
    RSA used for key transport are one algorithm and two migration items with
    two different replacements; merging them would reintroduce the exact defect
    the purpose model exists to prevent, and the merged row could only carry
    one recommendation, which would be wrong for half its evidence.

    ``assurance`` is part of it for the same reason in the other direction: a
    library that *can* do RSA and a call site that *does* must not collapse
    into one row whose evidence no longer says which is which.
    """
    return (f.algorithm, f.asset_type, f.mode or "", f.padding or "",
            f.key_size or 0, f.scanner, f.purpose, f.assurance)


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

        # Assurance is recomputed from the evidence that survived merging, and
        # the breakdown is kept so the UI and the report can say "used at 40
        # sites, and additionally reachable through two libraries" instead of
        # flattening both into one number.
        f.refresh_assurance()
        f.extra["assurance_breakdown"] = f.assurance_breakdown

        # Confidence is the strongest single piece of evidence, and nothing
        # more. An earlier version added 0.03 once a finding had five or more
        # sightings, which manufactured precision from repetition: forty copies
        # of the same regex firing is forty chances for the same rule to be
        # wrong in the same way, not independent corroboration. Blast radius
        # already enters the score through its own named term in the risk
        # engine, so the bump was also double-counting.
        f.confidence = max((e.confidence for e in f.evidence), default=f.confidence)

    return out

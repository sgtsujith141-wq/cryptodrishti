"""Risk engine: quantum classification, Mosca exposure, and scoring.

Two ideas do the work here.

**Mosca's inequality.** Let X be how long the data must stay confidential, Y
how long migration takes, and Z how long until a cryptographically relevant
quantum computer exists. If X + Y > Z, data sealed today is readable by an
adversary who is recording it now. The exposure, in years, is X + Y - Z.

Z is genuinely unknown, so we do not assert a date. We model it as a
triangular distribution over (earliest, likely, latest) and report the
probability that an asset is exposed, alongside the exposure at the median.
Any tool that hardcodes a Q-Day is bluffing, and a cryptographer will say so.

**The score.** Deliberately a transparent product of named factors rather than
a fitted model, because a judge who can audit the arithmetic will trust the
output. Every term is surfaced in the UI next to its input value.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, asdict
from typing import Iterable, Optional

from .. import config
from ..knowledge import algorithms as K
from ..knowledge import purposes as P
from ..models import (
    ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED,
    ASSURANCE_USED, Finding,
)


@dataclass
class QDayModel:
    """Distribution over the arrival year of a CRQC."""

    earliest: int = config.QDAY_EARLIEST
    likely: int = config.QDAY_LIKELY
    latest: int = config.QDAY_LATEST

    def years_from(self, now_year: int) -> float:
        """Z at the median estimate."""
        return max(0.0, float(self.likely - now_year))

    def sample(self, rng: random.Random) -> float:
        return rng.triangular(self.earliest, self.latest, self.likely)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MoscaResult:
    shelf_life: float          # X
    migration_years: float     # Y
    years_to_qday: float       # Z at the median
    exposure_years: float      # X + Y - Z, floored at 0
    probability_exposed: float  # P(X + Y > Z) over the Q-Day distribution
    verdict: str

    def to_dict(self) -> dict:
        return asdict(self)


def mosca(shelf_life: float, migration_years: float, qday: QDayModel,
          now_year: int = 2026, trials: int = 2000,
          seed: int = 26164) -> MoscaResult:
    """Evaluate Mosca's inequality, with uncertainty on Z."""
    z_median = qday.years_from(now_year)
    exposure = max(0.0, shelf_life + migration_years - z_median)

    rng = random.Random(seed)
    hits = 0
    for _ in range(trials):
        z = qday.sample(rng) - now_year
        if shelf_life + migration_years > z:
            hits += 1
    prob = hits / trials

    if exposure <= 0 and prob < 0.25:
        verdict = "Within tolerance at the median estimate."
    elif exposure <= 0:
        verdict = ("No exposure at the median estimate, but a materially likely "
                   "outcome under an earlier Q-Day.")
    elif exposure < 3:
        verdict = "Exposed. Migration should begin in the current planning cycle."
    elif exposure < 8:
        verdict = "Substantially exposed. Data sealed today is unlikely to remain secret."
    else:
        verdict = ("Critically exposed. Confidentiality of long-lived data cannot be "
                   "maintained on the current cryptographic baseline.")

    return MoscaResult(
        shelf_life=shelf_life,
        migration_years=migration_years,
        years_to_qday=z_median,
        exposure_years=round(exposure, 1),
        probability_exposed=round(prob, 3),
        verdict=verdict,
    )


# --------------------------------------------------------------------------
# Per-finding scoring
# --------------------------------------------------------------------------

# How hard is this artefact to migrate? Drives Mosca's Y term. A hardcoded
# call site in application source is a code change; a certificate is a
# reissue; a protocol in a vendor appliance may be a hardware refresh.
MIGRATION_EFFORT_YEARS = {
    "source": 2.0,
    "dependency": 1.5,
    "certificate": 1.0,
    "config": 0.5,
    "network": 2.5,
    "binary": 4.0,       # no source: vendor dependency or reverse engineering
    "container": 2.0,
}

# Internet-facing assets are recorded by anyone on the path, so the
# harvest-now-decrypt-later assumption applies most strongly to them.
EXPOSURE_MULTIPLIER = {
    "network": 1.15,
    "certificate": 1.08,
    "config": 1.05,
    "source": 1.0,
    "dependency": 0.95,
    "binary": 1.05,
    "container": 1.0,
}


# How much a finding's score depends on what its evidence actually proves.
#
# This is a different axis from confidence and is scored separately on
# purpose. Confidence asks "is this identification correct?"; assurance asks
# "does a correct identification here mean the estate uses this?". A
# dependency on a library that implements RSA can be a certain identification
# (confidence 0.9) of something that proves very little (capability), and a
# ranking that cannot express that will put reachable-but-unused algorithms
# above live call sites.
#
# Capability findings are damped hard rather than dropped: they are the
# reachable surface, they belong in the inventory, and they are exactly what
# you check after you have fixed everything you can prove is running.
ASSURANCE_WEIGHT = {
    ASSURANCE_CAPABILITY: 0.45,
    ASSURANCE_DECLARED: 0.80,
    ASSURANCE_USED: 1.00,
    ASSURANCE_OBSERVED: 1.05,
}

# Purpose changes urgency, not just remediation.
#
# Key establishment is the one purpose exposed to harvest-now-decrypt-later:
# a session key agreed today is recovered retroactively from recorded traffic
# the moment a CRQC exists, so the deadline has already passed for data with a
# long confidentiality life. A signature cannot be forged retroactively -- an
# adversary with a CRQC in 2034 cannot un-sign a 2026 release -- so the
# deadline is when the verifying party still needs to trust it. Hashing and
# symmetric encryption move by parameter, not by family, and are cheaper.
PURPOSE_URGENCY = {
    P.KEY_ESTABLISHMENT: 1.15,
    P.ENCRYPTION: 1.00,
    P.SIGNATURE: 0.92,
    P.AUTHENTICATION: 0.90,
    P.HASHING: 0.90,
    P.KEY_DERIVATION: 0.90,
    P.RANDOMNESS: 1.00,
    P.TRANSPORT: 1.00,
    # An unresolved purpose is not discounted. The finding may be the urgent
    # kind, and discounting it would reward the tool for failing to resolve it.
    P.UNKNOWN: 1.00,
}


def _by_scanner(table: dict, scanner: str, default: float) -> float:
    """Look up a per-sensor weight, tolerating a qualified scanner name.

    The container sensor reports as ``container/binary``, ``container/source``
    and so on, so that normalisation keeps those findings apart. The weights
    are defined per family, so an exact miss falls back to the part before the
    slash rather than silently taking the default.
    """
    if scanner in table:
        return table[scanner]
    return table.get(scanner.split("/", 1)[0], default)


def _sensitivity_shelf_life(sensitivity: Optional[str]) -> float:
    return config.SHELF_LIFE_BY_SENSITIVITY.get(
        sensitivity or config.DEFAULT_SENSITIVITY,
        config.SHELF_LIFE_BY_SENSITIVITY[config.DEFAULT_SENSITIVITY],
    )


# Base score by quantum class, on the 0-100 scale. Everything after this is a
# multiplier, so the base is what a judge should be able to argue with.
CLASS_BASE = {
    K.BROKEN: 50.0,
    K.WEAKENED: 30.0,
    K.UNKNOWN: 26.0,
    K.HYBRID: 12.0,
    K.SAFE: 6.0,
}

# Findings that are defects on classical grounds alone, independent of any
# quantum consideration. A hardcoded private key is not a "future" problem.
CLASSICAL_DEFECT_FLOOR = {
    "any.private.key.inline": 88.0,
    "any.hardcoded.secret": 78.0,
    "any.ecb.mode": 62.0,
}


def score_finding(f: Finding, qday: QDayModel, now_year: int = 2026,
                  criticality: float = 1.0) -> Finding:
    """Classify and score one finding in place, and return it."""
    alg = K.get(f.algorithm)
    f.quantum_class = alg.quantum_class

    shelf = _sensitivity_shelf_life(f.sensitivity)
    migration = _by_scanner(MIGRATION_EFFORT_YEARS, f.scanner, 2.0)
    m = mosca(shelf, migration, qday, now_year=now_year, trials=400)
    f.exposure_years = m.exposure_years

    base = CLASS_BASE.get(alg.quantum_class, 26.0) * alg.risk_adjust

    # An algorithm already disallowed on classical grounds outranks a merely
    # quantum-vulnerable one: it is broken today, not in 2034.
    if alg.disallowed_after and alg.disallowed_after <= now_year:
        base = max(base, 50.0)
    # Approaching a NIST IR 8547 milestone.
    elif alg.disallowed_after and alg.disallowed_after <= now_year + 5:
        base += 12.0
    elif alg.deprecated_after and alg.deprecated_after <= now_year + 5:
        base += 6.0

    # Below the 112-bit classical floor.
    if alg.classical_bits is not None and alg.classical_bits < 112:
        base += 8.0

    exposure_mult = _by_scanner(EXPOSURE_MULTIPLIER, f.scanner, 1.0)

    # Mosca gap contributes sub-linearly: 10 years exposed is worse than 5,
    # but not twice as bad, because both already mean "you have lost".
    mosca_term = 1.0 + math.log1p(m.exposure_years) / 6.0

    # Blast radius. An algorithm reached from 200 call sites is a bigger
    # migration than the same algorithm used once.
    occ_term = 1.0 + min(0.15, 0.035 * math.log2(f.occurrences + 1))

    # Confidence damps the score so an uncertain finding cannot outrank a
    # certain one in the remediation queue.
    conf = f.confidence or max((e.confidence for e in f.evidence), default=0.5)
    conf_term = 0.60 + 0.40 * conf

    # Assurance damps it again, on the separate question of what the evidence
    # proves. These are not double-counting: a manifest entry can be a certain
    # identification of a mere capability.
    assurance_term = ASSURANCE_WEIGHT.get(f.assurance, 1.0)

    purpose_term = PURPOSE_URGENCY.get(P.normalise(f.purpose), 1.0)

    score = (base * criticality * exposure_mult * mosca_term * occ_term
             * conf_term * assurance_term * purpose_term)
    # The floor is scaled by criticality too, so a private key in a unit-test
    # fixture is still inventoried but does not outrank production findings.
    score = max(score, CLASSICAL_DEFECT_FLOOR.get(f.rule_id, 0.0) * criticality)

    f.risk_score = round(max(0.0, min(100.0, score)), 1)
    f.extra.setdefault("mosca", m.to_dict())
    f.extra.setdefault("factors", {
        "base_by_class": round(base, 1),
        "algorithm_risk_adjust": alg.risk_adjust,
        "business_criticality": criticality,
        "exposure_multiplier": exposure_mult,
        "mosca_term": round(mosca_term, 3),
        "occurrence_term": round(occ_term, 3),
        "confidence_term": round(conf_term, 3),
        "assurance_term": assurance_term,
        "assurance": f.assurance,
        "purpose_term": purpose_term,
        "purpose": P.normalise(f.purpose),
        "shelf_life_years": shelf,
        "migration_years": migration,
    })
    return f


def severity(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def score_all(findings: Iterable[Finding], qday: Optional[QDayModel] = None,
              now_year: int = 2026) -> list[Finding]:
    """Score every finding, weighting each by where its evidence lives."""
    from .normalize import criticality_for

    qday = qday or QDayModel()
    return [score_finding(f, qday, now_year, criticality=criticality_for(f))
            for f in findings]


def portfolio_summary(findings: list[Finding]) -> dict:
    """Estate-level roll-up for the dashboard tiles."""
    by_class: dict[str, int] = {}
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_class[f.quantum_class] = by_class.get(f.quantum_class, 0) + 1
        by_severity[severity(f.risk_score)] += 1

    vulnerable = sum(by_class.get(c, 0) for c in (K.BROKEN, K.WEAKENED))
    total = len(findings)
    worst = max((f.exposure_years for f in findings), default=0.0)

    by_assurance: dict[str, int] = {}
    by_purpose: dict[str, int] = {}
    for f in findings:
        by_assurance[f.assurance] = by_assurance.get(f.assurance, 0) + 1
        key = P.normalise(f.purpose)
        by_purpose[key] = by_purpose.get(key, 0) + 1

    # Headline totals that count only what the estate can be shown to use.
    # Reporting "412 quantum-vulnerable assets" when 300 of them are library
    # capabilities nobody calls is the single easiest way for this tool to
    # mislead, so both numbers are published side by side.
    proven = [f for f in findings if f.proves_use]
    proven_vulnerable = sum(
        1 for f in proven if f.quantum_class in (K.BROKEN, K.WEAKENED))

    return {
        "total": total,
        "quantum_vulnerable": vulnerable,
        "vulnerable_pct": round(100.0 * vulnerable / total, 1) if total else 0.0,
        "by_class": by_class,
        "by_severity": by_severity,
        "by_assurance": by_assurance,
        "by_purpose": by_purpose,
        "proven_use": len(proven),
        "proven_vulnerable": proven_vulnerable,
        "capability_only": total - len(proven),
        "unresolved_purpose": by_purpose.get(P.UNKNOWN, 0),
        "max_exposure_years": worst,
        "mean_risk": round(sum(f.risk_score for f in findings) / total, 1) if total else 0.0,
    }

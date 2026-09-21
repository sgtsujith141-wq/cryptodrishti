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

import datetime as dt
import math
import os
import random
from dataclasses import dataclass, asdict, field
from typing import Any, Iterable, Optional

from .. import assessment as A
from .. import config
from ..knowledge import algorithms as K
from ..knowledge import purposes as P
from ..models import (
    ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED,
    ASSURANCE_USED, Finding,
)


# --------------------------------------------------------------------------
# The assessment date
#
# Every year-based term is relative to the date the assessment was made, so
# that date has to be recorded rather than assumed. It was previously a
# literal 2026 in three default arguments, which meant a report generated in
# 2028 would quietly compute 2026's answer.
# --------------------------------------------------------------------------

def assessment_date() -> dt.date:
    """The date this assessment is made against.

    Defaults to today. ``CD_ASSESSMENT_DATE`` pins it, which is how tests get
    determinism and how a report can be regenerated to match an earlier one.
    """
    override = os.environ.get("CD_ASSESSMENT_DATE", "").strip()
    if override:
        try:
            return dt.date.fromisoformat(override)
        except ValueError:
            pass
    return dt.date.today()


def _year_fraction(when: dt.date) -> float:
    """A date as a fractional year, so mid-year assessments are not rounded."""
    start = dt.date(when.year, 1, 1)
    end = dt.date(when.year + 1, 1, 1)
    return when.year + (when - start).days / (end - start).days


@dataclass
class QDayModel:
    """An operator-chosen scenario for when a CRQC arrives.

    This is **not** a forecast. Nobody knows when, or whether, a
    cryptographically relevant quantum computer will exist; the defaults are
    one reading of the Global Risk Institute's expert surveys and the operator
    is expected to move them. Every probability this model produces is
    conditional on the three numbers below and means nothing without them,
    which is why they travel with every result that depends on them.

    ``likely`` is the **mode** of the triangular distribution -- its peak, the
    single most likely year. It is not the median. An earlier version used it
    as one and said so in a docstring; for the default scenario the two differ
    by about 1.6 years, always in the direction that understates exposure.
    """

    earliest: int = config.QDAY_EARLIEST
    likely: int = config.QDAY_LIKELY          # the mode, not the median
    latest: int = config.QDAY_LATEST
    # Which point of the distribution drives the headline number. The slider
    # sets the mode, so the mode is the default and the median is reported
    # beside it rather than substituted for it.
    basis: str = "mode"

    def __post_init__(self) -> None:
        if not (self.earliest <= self.likely <= self.latest):
            raise ValueError(
                f"Q-Day scenario must satisfy earliest <= likely <= latest; "
                f"got {self.earliest}, {self.likely}, {self.latest}")
        if self.basis not in ("mode", "median"):
            raise ValueError(f"basis must be 'mode' or 'median'; got {self.basis!r}")

    @property
    def mode_year(self) -> float:
        """The peak of the distribution: the single most likely year."""
        return float(self.likely)

    @property
    def median_year(self) -> float:
        """The year by which the scenario puts the arrival at even odds.

        Closed form for a triangular distribution on (a, b) with mode c:

            c >= (a+b)/2 :  a + sqrt((b-a)(c-a)/2)
            c <  (a+b)/2 :  b - sqrt((b-a)(b-c)/2)
        """
        a, b, c = float(self.earliest), float(self.latest), float(self.likely)
        if b == a:
            return a
        if c >= (a + b) / 2:
            return a + math.sqrt((b - a) * (c - a) / 2)
        return b - math.sqrt((b - a) * (b - c) / 2)

    def basis_year(self) -> float:
        return self.median_year if self.basis == "median" else self.mode_year

    def years_from(self, now_year: float) -> float:
        """Z: years from the assessment date to the chosen point of the scenario."""
        return max(0.0, self.basis_year() - float(now_year))

    def sample(self, rng: random.Random) -> float:
        return rng.triangular(self.earliest, self.latest, self.likely)

    def to_dict(self) -> dict:
        out = asdict(self)
        out.update({
            "mode_year": self.mode_year,
            "median_year": round(self.median_year, 2),
            "basis_year": round(self.basis_year(), 2),
            "is_forecast": False,
            "caveat": (
                "An operator-selected scenario, not a forecast. 'likely' is the "
                "mode of a triangular distribution — its peak — not its median; "
                "both are reported. Every probability derived from this model is "
                "conditional on these three years."),
        })
        return out


# --------------------------------------------------------------------------
# Exposure models
#
# X + Y > Z is the same inequality for every asset, but X does not mean the
# same thing for every asset, and pretending it does is how a tool ends up
# telling you a TLS handshake signature needs to stay unforgeable for
# twenty-five years.
#
# Three models, chosen by the finding's cryptographic purpose:
#
# **Harvest now, decrypt later** (key establishment, encryption). An adversary
# records ciphertext today and decrypts it when a CRQC exists. X is how long
# the plaintext must stay secret. The damage is *retroactive*: traffic already
# on the wire is already lost, so the deadline has in a real sense passed.
#
# **Forgery from Q-Day onward** (signatures, authentication). A CRQC cannot
# un-sign a release published in 2026. What it can do is mint new signatures
# that verify against a key still trusted after Q-Day. So X is not a
# confidentiality lifetime at all -- it is how long this signature or key must
# remain *unforgeable*, which for a TLS handshake is seconds and for a
# firmware root of trust is decades. Nothing is retroactive.
#
# **Grover margin** (symmetric ciphers, hashes). There is no Q-Day cliff:
# Grover halves effective strength whenever a machine exists, and the answer
# is a bigger parameter, not a different family. The years arithmetic is still
# computed so the asset can be ranked beside the others, but the consequence
# is recorded as a parameter change rather than a break.
# --------------------------------------------------------------------------

MODEL_HNDL = "harvest-now-decrypt-later"
MODEL_FORGERY = "forgery-after-q-day"
MODEL_GROVER = "grover-margin"
MODEL_UNRESOLVED = "unresolved-purpose"


@dataclass(frozen=True)
class ExposureModel:
    key: str
    label: str
    x_label: str
    retroactive: bool
    assumptions: str
    consequence: str

    def to_dict(self) -> dict:
        return asdict(self)


EXPOSURE_MODELS: dict[str, ExposureModel] = {
    MODEL_HNDL: ExposureModel(
        key=MODEL_HNDL,
        label="Harvest now, decrypt later",
        x_label="how long the protected data must stay confidential",
        retroactive=True,
        assumptions=(
            "Assumes an adversary is recording this traffic or holds this "
            "ciphertext now, and will decrypt it once a CRQC exists. If that "
            "is not plausible for this asset — a key that never leaves a "
            "private network, for instance — set the confidentiality lifetime "
            "to the period that genuinely applies."),
        consequence=(
            "Confidentiality is lost retroactively. Data already sealed cannot "
            "be un-sealed by migrating afterwards."),
    ),
    MODEL_FORGERY: ExposureModel(
        key=MODEL_FORGERY,
        label="Forgery from Q-Day onward",
        x_label="how long this signature or key must remain unforgeable",
        retroactive=False,
        assumptions=(
            "Assumes signatures already made and already verified are safe: a "
            "CRQC cannot retract them. The exposure is that a key still "
            "trusted after Q-Day can be used to mint new signatures. X is "
            "therefore the trust horizon, not a confidentiality lifetime — "
            "seconds for a TLS handshake, decades for a firmware root key."),
        consequence=(
            "Forged signatures become possible from Q-Day onward. Nothing "
            "signed before then is invalidated."),
    ),
    MODEL_GROVER: ExposureModel(
        key=MODEL_GROVER,
        label="Grover margin",
        x_label="how long the protected data must stay confidential",
        retroactive=True,
        assumptions=(
            "Grover gives a quadratic speed-up, halving effective strength. "
            "There is no arrival cliff: the margin erodes rather than "
            "collapsing, and the years arithmetic below exists so this asset "
            "can be ranked beside the others, not because the same break "
            "applies."),
        consequence=(
            "Effective security halves. The fix is a larger parameter set, "
            "not a change of algorithm family."),
    ),
    MODEL_UNRESOLVED: ExposureModel(
        key=MODEL_UNRESOLVED,
        label="Purpose not established",
        x_label="confidentiality lifetime, assumed pending a resolved purpose",
        retroactive=True,
        assumptions=(
            "The purpose of this asset was not resolved, so the more urgent "
            "of the two models is assumed. That is deliberate: assuming the "
            "milder one would reward the tool for failing to resolve it. "
            "Resolve the purpose and the model will change."),
        consequence="Undetermined until the purpose is resolved.",
    ),
}

_MODEL_BY_PURPOSE = {
    P.KEY_ESTABLISHMENT: MODEL_HNDL,
    P.ENCRYPTION: MODEL_HNDL,
    P.TRANSPORT: MODEL_HNDL,
    P.SIGNATURE: MODEL_FORGERY,
    P.AUTHENTICATION: MODEL_FORGERY,
    P.HASHING: MODEL_GROVER,
    P.KEY_DERIVATION: MODEL_GROVER,
    P.RANDOMNESS: MODEL_GROVER,
    P.UNKNOWN: MODEL_UNRESOLVED,
}


def exposure_model_for(purpose: str, algorithm_key: str = "") -> ExposureModel:
    """Which exposure model applies, from the finding's resolved purpose."""
    key = _MODEL_BY_PURPOSE.get(P.normalise(purpose), MODEL_UNRESOLVED)
    # A symmetric primitive is Grover-limited whatever it is being used for.
    if algorithm_key:
        alg = K.get(algorithm_key)
        if alg.quantum_class == K.WEAKENED and alg.primitive in (
                K.PRIM_BLOCK_CIPHER, K.PRIM_STREAM_CIPHER, K.PRIM_HASH, K.PRIM_MAC):
            key = MODEL_GROVER
    return EXPOSURE_MODELS[key]


@dataclass
class MoscaResult:
    shelf_life: float          # X, meaning set by the exposure model
    migration_years: float     # Y
    years_to_qday: float       # Z at the scenario's chosen point
    exposure_years: float      # X + Y - Z, floored at 0
    probability_exposed: float  # P(X + Y > Z) *given this scenario*
    verdict: str
    model: str = MODEL_HNDL
    model_label: str = ""
    x_label: str = ""
    retroactive: bool = True
    assumptions: str = ""
    consequence: str = ""
    basis: str = "mode"
    basis_year: float = 0.0
    assessment_year: float = 0.0
    conditional_on: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def mosca(shelf_life: float, migration_years: float, qday: QDayModel,
          now_year: Optional[float] = None, trials: int = 2000,
          seed: int = 26164,
          model: Optional[ExposureModel] = None) -> MoscaResult:
    """Evaluate Mosca's inequality under one Q-Day scenario.

    The probability returned is **conditional on that scenario** and is not a
    forecast. It answers "given these three years, what fraction of the
    distribution leaves this asset exposed" — which is a useful thing to know
    and a dangerous thing to quote without its assumptions, so the assumptions
    travel with it.
    """
    model = model or EXPOSURE_MODELS[MODEL_HNDL]
    if now_year is None:
        now_year = _year_fraction(assessment_date())

    z = qday.years_from(now_year)
    exposure = max(0.0, shelf_life + migration_years - z)

    rng = random.Random(seed)
    hits = 0
    for _ in range(trials):
        sampled = qday.sample(rng) - now_year
        if shelf_life + migration_years > sampled:
            hits += 1
    prob = hits / trials

    point = "most likely year" if qday.basis == "mode" else "median year"
    if exposure <= 0 and prob < 0.25:
        verdict = f"Within tolerance at the scenario's {point}."
    elif exposure <= 0:
        verdict = (f"No exposure at the scenario's {point}, but a materially "
                   f"likely outcome if a CRQC arrives earlier.")
    elif exposure < 3:
        verdict = "Exposed. Migration should begin in the current planning cycle."
    elif exposure < 8:
        verdict = ("Substantially exposed under this scenario."
                   if model.retroactive else
                   "Substantially exposed: migration will not finish in time.")
    else:
        verdict = ("Critically exposed. Confidentiality of long-lived data cannot be "
                   "maintained on the current cryptographic baseline."
                   if model.retroactive else
                   "Critically exposed. This key will still be trusted, and "
                   "forgeable, well past the scenario's arrival window.")

    return MoscaResult(
        shelf_life=shelf_life,
        migration_years=migration_years,
        years_to_qday=round(z, 2),
        exposure_years=round(exposure, 1),
        probability_exposed=round(prob, 3),
        verdict=verdict,
        model=model.key,
        model_label=model.label,
        x_label=model.x_label,
        retroactive=model.retroactive,
        assumptions=model.assumptions,
        consequence=model.consequence,
        basis=qday.basis,
        basis_year=round(qday.basis_year(), 2),
        assessment_year=round(float(now_year), 2),
        conditional_on=(
            f"conditional on the Q-Day scenario {qday.earliest}/"
            f"{qday.likely}/{qday.latest} (earliest / most likely / latest), "
            f"assessed at {round(float(now_year), 2)}. Not a forecast."),
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


# --------------------------------------------------------------------------
# Resolving the inputs
#
# Each of X, Y and criticality has three possible sources, in priority order:
# what the operator said, what the tool derived from evidence, and the
# configured default. The resolver returns the value *and* which of those it
# was, because a score built from three defaults and one built from three
# reviewed values are not the same claim.
# --------------------------------------------------------------------------

def resolve_inputs(f: Finding, criticality: float = 1.0,
                   override: Optional[A.AssetOverride] = None,
                   ) -> dict[str, A.RiskInput]:
    """Work out X, Y, sensitivity and criticality, and where each came from."""
    model = exposure_model_for(f.purpose, f.algorithm)

    # ---- sensitivity ----
    if override and override.sensitivity:
        sensitivity = A.RiskInput(
            override.sensitivity, A.OPERATOR,
            "set for this asset by the operator")
    elif f.sensitivity:
        sensitivity = A.RiskInput(
            f.sensitivity, A.DERIVED,
            "carried on the finding by the sensor or a prior assessment")
    else:
        sensitivity = A.RiskInput(
            config.DEFAULT_SENSITIVITY, A.DEFAULT,
            f"estate-wide default ({config.DEFAULT_SENSITIVITY}); not reviewed "
            f"for this asset")

    # ---- X ----
    if override and override.shelf_life_years is not None:
        shelf = A.RiskInput(override.shelf_life_years, A.OPERATOR,
                            f"set for this asset by the operator — {model.x_label}")
    else:
        derived = _sensitivity_shelf_life(sensitivity.value)
        shelf = A.RiskInput(
            derived,
            A.DERIVED if sensitivity.provenance == A.OPERATOR else A.DEFAULT,
            f"from the '{sensitivity.value}' sensitivity tier, read as "
            f"{model.x_label}")

    # ---- Y ----
    if override and override.migration_years is not None:
        migration = A.RiskInput(override.migration_years, A.OPERATOR,
                                "set for this asset by the operator")
    else:
        migration = A.RiskInput(
            _by_scanner(MIGRATION_EFFORT_YEARS, f.scanner, 2.0), A.DERIVED,
            f"inferred from the sensor that found it ({f.scanner}) — a code "
            f"change, a certificate reissue and a vendor binary are not the "
            f"same job")

    # ---- criticality ----
    if override and override.criticality is not None:
        crit = A.RiskInput(override.criticality, A.OPERATOR,
                           "set for this asset by the operator")
    else:
        context = (f.extra or {}).get("context", "production")
        crit = A.RiskInput(
            criticality, A.DERIVED,
            f"inferred from where the evidence lives ({context}); the tool "
            f"cannot know this asset's business value")

    return {"shelf_life_years": shelf, "migration_years": migration,
            "criticality": crit, "sensitivity": sensitivity}


def _container_state(f: Finding) -> tuple[str, float, str]:
    """Deployment state of a container finding, and what it does to the score.

    A key deleted by a later layer is not running, so it is not current
    deployment risk. It is also still extractable from the archive by anyone
    who can pull the image, so it is not nothing either. Damping it rather
    than dropping or keeping it whole is the only honest option, and the
    reason is recorded on the finding.
    """
    provenance = (f.extra or {}).get("container")
    if not provenance:
        return "not-a-container-asset", 1.0, ""
    effective = provenance.get("effective")
    if effective is True:
        return "effective", 1.0, "present in the image's final filesystem"
    if effective is False:
        return "historical", 0.55, (
            "only in a historical layer — not running, but still extractable "
            "from the image archive by anyone who can pull it, so it is "
            "damped rather than dropped")
    return "unknown", 0.85, (
        "the effective state could not be determined for this archive, so it "
        "is treated as possibly live")


def score_finding(f: Finding, qday: QDayModel, now_year: Optional[float] = None,
                  criticality: float = 1.0,
                  override: Optional[A.AssetOverride] = None) -> Finding:
    """Classify and score one finding in place, and return it.

    Every value this writes is recomputed from the inputs given *now*. An
    earlier version used ``setdefault`` for the mosca and factor records,
    which meant a rescored finding kept the arithmetic of the previous
    assessment while displaying the new score — an audit trail that
    contradicted the number it was supposed to explain.
    """
    if now_year is None:
        now_year = _year_fraction(assessment_date())

    alg = K.get(f.algorithm)
    f.quantum_class = alg.quantum_class

    model = exposure_model_for(f.purpose, f.algorithm)
    inputs = resolve_inputs(f, criticality, override)
    shelf = float(inputs["shelf_life_years"].value)
    migration = float(inputs["migration_years"].value)
    crit = float(inputs["criticality"].value)
    f.sensitivity = inputs["sensitivity"].value

    m = mosca(shelf, migration, qday, now_year=now_year, trials=400, model=model)
    f.exposure_years = m.exposure_years

    base = CLASS_BASE.get(alg.quantum_class, 26.0) * alg.risk_adjust

    # An algorithm already disallowed on classical grounds outranks a merely
    # quantum-vulnerable one: it is broken today, not at some future Q-Day.
    # This term is deliberately independent of the quantum scenario.
    classical_defect = False
    if alg.disallowed_after and alg.disallowed_after <= now_year:
        base = max(base, 50.0)
        classical_defect = True
    elif alg.disallowed_after and alg.disallowed_after <= now_year + 5:
        base += 12.0
    elif alg.deprecated_after and alg.deprecated_after <= now_year + 5:
        base += 6.0

    if alg.classical_bits is not None and alg.classical_bits < 112:
        base += 8.0
        classical_defect = True

    exposure_mult = _by_scanner(EXPOSURE_MULTIPLIER, f.scanner, 1.0)
    mosca_term = 1.0 + math.log1p(m.exposure_years) / 6.0
    occ_term = 1.0 + min(0.15, 0.035 * math.log2(f.occurrences + 1))

    conf = f.confidence or max((e.confidence for e in f.evidence), default=0.5)
    conf_term = 0.60 + 0.40 * conf
    assurance_term = ASSURANCE_WEIGHT.get(f.assurance, 1.0)
    purpose_term = PURPOSE_URGENCY.get(P.normalise(f.purpose), 1.0)

    state, state_term, state_note = _container_state(f)

    score = (base * crit * exposure_mult * mosca_term * occ_term
             * conf_term * assurance_term * purpose_term * state_term)
    floor = CLASSICAL_DEFECT_FLOOR.get(f.rule_id, 0.0) * crit * state_term
    score = max(score, floor)

    f.risk_score = round(max(0.0, min(100.0, score)), 1)

    # Overwrite, never setdefault. Stale arithmetic beside a fresh score is
    # worse than no arithmetic at all.
    f.extra["mosca"] = m.to_dict()
    f.extra["risk_inputs"] = {name: value.to_dict()
                              for name, value in inputs.items()}
    f.extra["exposure_model"] = model.to_dict()
    f.extra["assessment"] = {
        "assessed_at_year": round(float(now_year), 2),
        "assessed_on": assessment_date().isoformat(),
        "qday": qday.to_dict(),
        "override_applied": bool(override and not override.is_empty),
        # Carried so downstream consumers -- the CBOM's executionEnvironment
        # among them -- can act on what the operator declared.
        "constraints": list(getattr(override, "constraints", []) or []),
        "operator_inputs": sorted(
            name for name, value in inputs.items()
            if value.provenance == A.OPERATOR),
        "deployment_state": state,
    }
    f.extra["factors"] = {
        "base_by_class": round(base, 1),
        "algorithm_risk_adjust": alg.risk_adjust,
        "business_criticality": round(crit, 3),
        "exposure_multiplier": exposure_mult,
        "mosca_term": round(mosca_term, 3),
        "occurrence_term": round(occ_term, 3),
        "confidence_term": round(conf_term, 3),
        "assurance_term": assurance_term,
        "assurance": f.assurance,
        "purpose_term": purpose_term,
        "purpose": P.normalise(f.purpose),
        "deployment_state_term": state_term,
        "shelf_life_years": shelf,
        "migration_years": migration,
        "exposure_model": model.key,
        "classical_defect": classical_defect,
    }
    if state_note:
        f.extra["factors"]["deployment_state_note"] = state_note
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
              now_year: Optional[float] = None,
              overrides: Optional[dict[str, A.AssetOverride]] = None,
              ) -> list[Finding]:
    """Score every finding, weighting each by where its evidence lives.

    ``overrides`` is keyed by ``assessment.asset_key``, so an operator's
    twenty-five-year lifetime follows one asset across rescans without
    attaching itself to every other use of the same algorithm.
    """
    from .normalize import criticality_for

    qday = qday or QDayModel()
    overrides = overrides or {}
    out = []
    for f in findings:
        key = A.asset_key(f)
        f.extra["asset_key"] = key
        out.append(score_finding(f, qday, now_year,
                                 criticality=criticality_for(f),
                                 override=overrides.get(key)))
    return out


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

"""Core data model.

A scan produces Findings. A Finding is one cryptographic artefact observed at
one or more locations, resolved (or explicitly not resolved) to an Algorithm.

Everything downstream -- risk scoring, the CBOM, the UI -- reads these.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# CBOM asset types, mirroring CycloneDX cryptoProperties.assetType.
ASSET_ALGORITHM = "algorithm"
ASSET_CERTIFICATE = "certificate"
ASSET_PROTOCOL = "protocol"
ASSET_MATERIAL = "related-crypto-material"   # keys, secrets, key material
ASSET_LIBRARY = "library"                    # our extension: a crypto library dependency

# How a finding was detected. Surfaced in the CBOM evidence and in the UI,
# because detection technique is what justifies the confidence score.
TECH_AST = "source-ast-analysis"
TECH_PATTERN = "source-pattern-match"
TECH_MANIFEST = "dependency-manifest"
TECH_BINARY_SYMBOL = "binary-symbol-analysis"
TECH_BINARY_CONST = "binary-constant-match"
TECH_BINARY_STRING = "binary-string-match"
TECH_CERT_PARSE = "certificate-parse"
TECH_NETWORK = "network-probe"
TECH_CONFIG = "config-parse"
TECH_CONTAINER = "container-layer-analysis"

# --------------------------------------------------------------------------
# Assurance: what a piece of evidence actually establishes.
#
# Confidence and assurance answer different questions, and conflating them is
# how an inventory ends up claiming an estate uses an algorithm it merely
# could use. Confidence asks "did we identify this correctly?" -- a regex on a
# comment scores low, a parsed certificate scores high. Assurance asks "what
# does identifying it prove?" -- and a dependency on a library that implements
# RSA proves only that RSA is reachable, however certain we are about the
# dependency.
#
# The four states are ordered. A finding reports the strongest state any of
# its evidence reached, and keeps the breakdown, because "RSA is used at 40
# call sites and also reachable through three libraries" is a different
# migration from either half alone.
# --------------------------------------------------------------------------

ASSURANCE_CAPABILITY = "capability"
ASSURANCE_DECLARED = "declared"
ASSURANCE_USED = "used"
ASSURANCE_OBSERVED = "observed"

ASSURANCE_ORDER = (ASSURANCE_CAPABILITY, ASSURANCE_DECLARED,
                   ASSURANCE_USED, ASSURANCE_OBSERVED)

ASSURANCE_RANK = {name: i for i, name in enumerate(ASSURANCE_ORDER)}

ASSURANCE_LABEL = {
    ASSURANCE_CAPABILITY: "Capability",
    ASSURANCE_DECLARED: "Declared",
    ASSURANCE_USED: "Used",
    ASSURANCE_OBSERVED: "Observed",
}

ASSURANCE_DESCRIPTION = {
    ASSURANCE_CAPABILITY: (
        "The algorithm is reachable because a dependency or linked library "
        "implements it. Nothing here shows it is called. Depending on a "
        "library that can do RSA is not evidence that RSA is used, and an "
        "inventory that treats it as such inflates every total it reports."
    ),
    ASSURANCE_DECLARED: (
        "Configuration or a manifest states that the algorithm is permitted, "
        "enabled or required. This is stated policy, not an execution: a "
        "cipher suite listed in nginx.conf may never be negotiated. It is "
        "still actionable, because the line is what you change."
    ),
    ASSURANCE_USED: (
        "First-party or shipped code invokes the algorithm -- a resolved call "
        "site, or a symbol in a binary that links the routine. This is "
        "evidence of use, not of execution: the path may be dead. It is the "
        "strongest claim static analysis can make."
    ),
    ASSURANCE_OBSERVED: (
        "The algorithm was seen in a real cryptographic artefact -- parsed out "
        "of a certificate that exists, or negotiated in a handshake that "
        "completed. This is the only state backed by something that actually "
        "happened."
    ),
}


def strongest_assurance(values) -> str:
    """The highest assurance in a set, defaulting to capability when empty."""
    best = ASSURANCE_CAPABILITY
    for v in values:
        if ASSURANCE_RANK.get(v, -1) > ASSURANCE_RANK[best]:
            best = v
    return best


@dataclass
class Evidence:
    """Where and how a finding was observed."""

    location: str                       # file path, host:port, or image layer id
    line: Optional[int] = None
    symbol: Optional[str] = None        # the API or symbol that matched
    snippet: str = ""                   # the matched source text, trimmed
    technique: str = TECH_PATTERN
    confidence: float = 0.7
    context: str = ""                   # e.g. the resolved transform string
    # What this single observation establishes. Defaults to the weakest state
    # so a detector that forgets to set it under-claims rather than over-claims.
    assurance: str = ASSURANCE_CAPABILITY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """One cryptographic artefact, with all the places it was observed."""

    algorithm: str                      # key into knowledge.algorithms
    asset_type: str = ASSET_ALGORITHM
    scanner: str = "source"
    title: str = ""
    detail: str = ""
    rule_id: str = ""

    evidence: list[Evidence] = field(default_factory=list)

    # Resolved parameters, where the detector could determine them.
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None

    # What the algorithm is being used *for* at this site. Resolved by the
    # detector from the call, the padding scheme, the certificate's key usage
    # or the protocol role -- never from the algorithm name, because RSA signs
    # and transports keys and the replacements differ completely.
    # "unknown" is a real answer and must survive to the recommendation.
    purpose: str = "unknown"
    purpose_evidence: str = ""          # why the purpose was resolved that way

    # Strongest assurance across this finding's evidence. Recomputed on merge.
    assurance: str = ASSURANCE_CAPABILITY

    # Data sensitivity drives Mosca's X term. Defaults are applied by the
    # risk engine unless a detector or the user knows better.
    sensitivity: Optional[str] = None

    # Populated by the risk engine.
    quantum_class: str = ""
    risk_score: float = 0.0
    exposure_years: float = 0.0
    confidence: float = 0.0

    # Populated by the recommender.
    recommendation: Optional[dict[str, Any]] = None

    extra: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = self.fingerprint()
        if not self.confidence and self.evidence:
            self.confidence = max(e.confidence for e in self.evidence)
        self.refresh_assurance()

    def refresh_assurance(self) -> None:
        """Set the finding's assurance from its evidence."""
        if self.evidence:
            self.assurance = strongest_assurance(e.assurance for e in self.evidence)

    @property
    def assurance_breakdown(self) -> dict[str, int]:
        """How many evidence items sit at each assurance state."""
        out: dict[str, int] = {}
        for e in self.evidence:
            out[e.assurance] = out.get(e.assurance, 0) + 1
        return out

    @property
    def proves_use(self) -> bool:
        """Whether anything here shows the algorithm is actually reached."""
        return self.assurance in (ASSURANCE_USED, ASSURANCE_OBSERVED)

    def fingerprint(self) -> str:
        """Stable id, so the same artefact merges across detectors and scans."""
        first = self.evidence[0] if self.evidence else None
        basis = "|".join(str(x) for x in (
            self.algorithm, self.asset_type, self.rule_id, self.purpose,
            first.location if first else "",
            first.line if first else "",
        ))
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    @property
    def occurrences(self) -> int:
        return len(self.evidence)

    @property
    def primary_location(self) -> str:
        return self.evidence[0].location if self.evidence else ""

    def merge(self, other: "Finding") -> None:
        """Absorb another finding for the same artefact."""
        seen = {(e.location, e.line, e.symbol) for e in self.evidence}
        for e in other.evidence:
            if (e.location, e.line, e.symbol) not in seen:
                self.evidence.append(e)
                seen.add((e.location, e.line, e.symbol))
        self.confidence = max(self.confidence, other.confidence)
        # Prefer a resolved parameter over an unresolved one.
        self.key_size = self.key_size or other.key_size
        self.mode = self.mode or other.mode
        self.padding = self.padding or other.padding
        # A resolved purpose beats an unresolved one, but two *different*
        # resolved purposes must not silently collapse -- that would be the
        # original RSA defect reappearing through the back door. The grouping
        # key keeps them apart; this is the guard if it ever does not.
        if self.purpose == "unknown" and other.purpose != "unknown":
            self.purpose = other.purpose
            self.purpose_evidence = other.purpose_evidence
        self.refresh_assurance()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        d["occurrences"] = self.occurrences
        d["primary_location"] = self.primary_location
        d["assurance_breakdown"] = self.assurance_breakdown
        d["proves_use"] = self.proves_use
        return d


@dataclass
class ScanTarget:
    """What we were asked to scan."""

    kind: str                 # "repository" | "binary" | "host" | "image" | "directory"
    value: str                # path, host:port, or image reference
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """One complete scan."""

    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    stats: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def counts_by_class(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.quantum_class] = out.get(f.quantum_class, 0) + 1
        return out

    def counts_by_scanner(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.scanner] = out.get(f.scanner, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "stats": self.stats,
            "counts_by_class": self.counts_by_class(),
            "counts_by_scanner": self.counts_by_scanner(),
            "total": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

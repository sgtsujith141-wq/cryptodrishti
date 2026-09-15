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

    def fingerprint(self) -> str:
        """Stable id, so the same artefact merges across detectors and scans."""
        first = self.evidence[0] if self.evidence else None
        basis = "|".join(str(x) for x in (
            self.algorithm, self.asset_type, self.rule_id,
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

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        d["occurrences"] = self.occurrences
        d["primary_location"] = self.primary_location
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

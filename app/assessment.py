"""Operator-supplied risk inputs, and where every input came from.

The risk engine has always taken X (confidentiality lifetime), Y (migration
time) and business criticality. Until now it derived all three: X from an
estate-wide sensitivity setting, Y from which sensor found the asset, and
criticality from whether the path looked like test code. Those are reasonable
defaults and they are wrong for any specific asset, because only the operator
knows that the payments key must stay secret for twenty-five years and the
build cache key does not.

This module lets them say so, and — more importantly — makes every number on
screen carry its own origin. A risk score built from four guesses and a score
built from four measured values look identical unless the tool says which is
which, and an operator who cannot tell will trust both equally. So each input
is a ``RiskInput`` with a ``provenance``:

* ``observed``  — read out of the artefact itself (a certificate's expiry).
* ``derived``   — computed by the tool from evidence (migration cost by sensor).
* ``operator``  — supplied by a human, who owns it.
* ``default``   — a configured fallback nobody has looked at yet.

**Override identity.** An override has to survive a rescan, and a rescan
renumbers lines. ``Finding.id`` is a hash that includes the line number, so
keying overrides on it would lose them the moment anyone edited the file above
the call site. ``asset_key`` deliberately excludes line numbers and rule ids,
and deliberately includes location, scanner and purpose, so that two unrelated
AES call sites in different files never share an override.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from . import config

# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------

OBSERVED = "observed"
DERIVED = "derived"
OPERATOR = "operator"
DEFAULT = "default"

PROVENANCE_ORDER = (OBSERVED, OPERATOR, DERIVED, DEFAULT)

PROVENANCE_LABEL = {
    OBSERVED: "Observed",
    DERIVED: "Derived",
    OPERATOR: "Operator-supplied",
    DEFAULT: "Assumed default",
}

PROVENANCE_DESCRIPTION = {
    OBSERVED: ("Read directly from the artefact — a certificate's own expiry "
               "date, a negotiated parameter. A fact about the estate."),
    DERIVED: ("Computed by this tool from evidence it collected, such as "
              "migration cost inferred from which sensor found the asset. A "
              "reasoned estimate, not a measurement."),
    OPERATOR: ("Supplied by a person who knows this system. The tool does not "
               "second-guess it and will not overwrite it on a rescore."),
    DEFAULT: ("A configured fallback that nobody has reviewed for this asset. "
              "Treat any score resting on several of these as provisional."),
}


@dataclass
class RiskInput:
    """One value, and an honest account of where it came from."""

    value: Any
    provenance: str = DEFAULT
    source: str = ""            # a sentence a reader can check

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "provenance": self.provenance,
                "provenance_label": PROVENANCE_LABEL.get(self.provenance,
                                                         self.provenance),
                "source": self.source}


class InvalidOverride(ValueError):
    """An operator-supplied value was out of range or malformed."""


# --------------------------------------------------------------------------
# Bounds
#
# Ranges are wide enough for any real estate and narrow enough that a typo
# cannot silently produce a nonsense score. A rejected value is better than a
# 900-year confidentiality lifetime nobody notices in a report.
# --------------------------------------------------------------------------

LIMITS: dict[str, tuple[float, float, str]] = {
    "shelf_life_years": (0.0, 100.0,
                         "how long this asset's material must stay secret, or "
                         "a signature stay unforgeable, in years"),
    "migration_years": (0.0, 30.0,
                        "how long replacing this asset will take, in years"),
    "criticality": (0.05, 2.0,
                    "business criticality multiplier; 1.0 is an ordinary "
                    "production asset"),
}

VALID_SENSITIVITIES = tuple(config.SHELF_LIFE_BY_SENSITIVITY)

# Deployment constraints an operator can record. These change what the
# recommender may propose, not the risk arithmetic.
VALID_CONSTRAINTS = {
    "constrained-link": "Fixed-size or low-MTU link; large signatures may not fit",
    "fips-required": "FIPS-validated implementation required",
    "hardware-backed": "Key lives in an HSM or secure element",
    "long-lived-signature": "Signature must verify for many years after issue",
    "no-code-change": "Configuration change only; the code cannot be rebuilt",
    "third-party": "Owned by a vendor; migration depends on their timeline",
}


def _check_number(name: str, value: Any) -> float:
    low, high, meaning = LIMITS[name]
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise InvalidOverride(f"{name} must be a number ({meaning}); got {value!r}")
    if number != number or number in (float("inf"), float("-inf")):
        raise InvalidOverride(f"{name} must be a finite number; got {value!r}")
    if not (low <= number <= high):
        raise InvalidOverride(
            f"{name} must be between {low} and {high} — {meaning}. Got {number}.")
    return number


# --------------------------------------------------------------------------
# Asset identity
# --------------------------------------------------------------------------

_LINE_SUFFIX = re.compile(r":\d+$")


def asset_key(finding) -> str:
    """A stable identity for an asset across rescans of the same estate.

    Included: algorithm, asset type, cryptographic purpose, the sensor that
    found it, and the primary location with any line number stripped.

    Excluded: line numbers, rule ids, evidence counts, risk scores.

    **What survives a rescan.** Edits elsewhere in the file, added or removed
    call sites, a changed Q-Day, a re-run with different sensors selected.

    **What does not.** Moving or renaming the file, changing the algorithm at
    that site, or resolving a previously unknown purpose. Each of those makes
    it a genuinely different asset with a different migration, and silently
    carrying a hand-set twenty-five-year lifetime across such a change would
    be worse than losing it.
    """
    location = _LINE_SUFFIX.sub("", finding.primary_location or "")
    basis = "|".join((
        finding.algorithm or "",
        finding.asset_type or "",
        getattr(finding, "purpose", "") or "",
        finding.scanner or "",
        location,
    ))
    return hashlib.sha256(basis.encode()).hexdigest()[:20]


# --------------------------------------------------------------------------
# The override itself
# --------------------------------------------------------------------------

@dataclass
class AssetOverride:
    """Operator-supplied inputs for one asset. Any field may be unset."""

    asset_key: str
    shelf_life_years: Optional[float] = None
    migration_years: Optional[float] = None
    criticality: Optional[float] = None
    sensitivity: Optional[str] = None
    constraints: list[str] = field(default_factory=list)
    note: str = ""
    updated_at: float = 0.0

    @property
    def is_empty(self) -> bool:
        return not any((self.shelf_life_years is not None,
                        self.migration_years is not None,
                        self.criticality is not None,
                        self.sensitivity, self.constraints, self.note))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def parse(cls, key: str, payload: dict[str, Any]) -> "AssetOverride":
        """Build an override from untrusted input, refusing bad values.

        Rejecting is the point. A silently clamped value produces a score the
        operator did not ask for and cannot account for.
        """
        if not isinstance(payload, dict):
            raise InvalidOverride("override payload must be an object")

        unknown = set(payload) - {
            "shelf_life_years", "migration_years", "criticality",
            "sensitivity", "constraints", "note"}
        if unknown:
            raise InvalidOverride(
                f"unknown override field(s): {', '.join(sorted(unknown))}")

        out = cls(asset_key=key)

        for name in ("shelf_life_years", "migration_years", "criticality"):
            value = payload.get(name)
            if value is not None and value != "":
                setattr(out, name, _check_number(name, value))

        sensitivity = payload.get("sensitivity")
        if sensitivity:
            if sensitivity not in VALID_SENSITIVITIES:
                raise InvalidOverride(
                    f"sensitivity must be one of {', '.join(VALID_SENSITIVITIES)}; "
                    f"got {sensitivity!r}")
            out.sensitivity = sensitivity

        constraints = payload.get("constraints") or []
        if constraints:
            if not isinstance(constraints, list):
                raise InvalidOverride("constraints must be a list")
            bad = [c for c in constraints if c not in VALID_CONSTRAINTS]
            if bad:
                raise InvalidOverride(
                    f"unknown constraint(s): {', '.join(map(str, bad))}. "
                    f"Valid: {', '.join(sorted(VALID_CONSTRAINTS))}")
            out.constraints = list(dict.fromkeys(constraints))

        note = payload.get("note") or ""
        if len(str(note)) > 2000:
            raise InvalidOverride("note must be 2000 characters or fewer")
        out.note = str(note)

        return out


def describe_inputs() -> dict[str, Any]:
    """The editable inputs and their bounds, for the console to render."""
    return {
        "limits": {name: {"min": low, "max": high, "meaning": meaning}
                   for name, (low, high, meaning) in LIMITS.items()},
        "sensitivities": {name: config.SHELF_LIFE_BY_SENSITIVITY[name]
                          for name in VALID_SENSITIVITIES},
        "constraints": dict(VALID_CONSTRAINTS),
        "provenance": {name: {"label": PROVENANCE_LABEL[name],
                              "description": PROVENANCE_DESCRIPTION[name]}
                       for name in PROVENANCE_ORDER},
    }

"""Cross-sensor correlation: linking findings that are the same logical asset.

Normalisation already merges hits into assets, and it keeps ``scanner``,
``purpose`` and ``assurance`` in the grouping key on purpose. Those three
dimensions are what stop an RSA signing site from collapsing into an RSA key
transport site, and what stops a library capability from becoming evidence of
use. None of them is removed here.

This is a layer *on top*. It leaves every finding exactly as it was -- same
evidence, same technique, same assurance, same confidence -- and records that
two of them appear to describe one thing in the world. The output is a set of
links, not a merge.

**What counts as evidence of sameness.** Only a shared concrete artefact:

* the same file, cited by two different detectors;
* the same file inside the same container layer;
* the same software component, where a detector actually identified the
  component -- an OpenSSL version banner in a binary, or a named dependency
  in a manifest.

**What does not.** The same algorithm name. An estate uses AES in forty
unrelated places; calling them one asset because they share a string would
produce a migration plan for a component that does not exist. This is the
failure mode the whole module is shaped to avoid, and it is why linking
requires a shared artefact and not merely a shared name.

**What correlation may never do.**

* Turn CAPABILITY into OBSERVED. A dependency that can do RSA, corroborated
  by a call site that does, is still a dependency that can do RSA. The link
  is recorded on both; neither one's assurance changes.
* Raise confidence. Two detectors agreeing is not two independent
  measurements -- they often read the same bytes -- and we have no calibration
  that would justify a number.
* Hide disagreement. Where linked findings contradict each other on key size,
  mode or assurance, the contradiction is recorded and surfaced.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Optional

from ..knowledge import purposes as P
from ..models import (
    ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED, ASSURANCE_RANK,
    ASSURANCE_USED, Finding, strongest_assurance,
)

# Assurance states that describe potential rather than execution.
_POTENTIAL = (ASSURANCE_CAPABILITY, ASSURANCE_DECLARED)
_ACTUAL = (ASSURANCE_USED, ASSURANCE_OBSERVED)


@dataclass
class LogicalAsset:
    """Findings that the evidence says describe one thing."""

    id: str
    algorithm: str
    purpose: str
    members: list[str] = field(default_factory=list)
    basis: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    assurance_states: dict[str, int] = field(default_factory=dict)
    strongest_assurance: str = ASSURANCE_CAPABILITY
    # True when a potential-only finding is linked to one that shows use. The
    # flag lives on the *asset*, never on the member's own assurance.
    corroborated_by_use: bool = False
    conflicts: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detector_of(f: Finding) -> str:
    """Which detector produced this finding.

    Scanner alone is too coarse inside a container scan, where every finding
    carries ``scanner == "container"`` while the work was done by the source,
    binary, config and manifest analysers in turn. The rule namespace is what
    distinguishes them, so the pair is used.
    """
    namespace = (f.rule_id or "").split(".")[0] or "unknown"
    return f"{f.scanner}/{namespace}"


def _norm_location(location: str) -> str:
    """Compare paths by their in-image or in-tree form.

    A container finding is located at ``image:/usr/lib/libcrypto.so`` and a
    directory finding at ``usr/lib/libcrypto.so``. Inside one scan the prefix
    is constant, so stripping it is safe and lets a binary and a manifest in
    the same image meet on the same key.
    """
    text = location.replace("\\", "/")
    if ":/" in text:
        text = text.split(":/", 1)[1]
    return text.strip("./").lower()


def _component_map(findings: Iterable[Finding]) -> dict[str, str]:
    """Which software component each *file* is, where a detector established it.

    A binary carrying an OpenSSL version banner is OpenSSL: one file, one
    component. A ``requirements.txt`` naming six packages is not any of them --
    it is a list. Mapping a manifest's path to whichever library happened to
    be parsed first would link every algorithm any of those six provides to
    every artefact belonging to the one that won the race, which is a false
    link that looks entirely plausible in the output.

    So a path maps to a component only when every library-naming finding at
    that path agrees. A manifest declaring more than one library maps to
    nothing, and its findings still carry their own ``library`` key, which is
    the correct and narrower claim.
    """
    claims: dict[str, set[str]] = {}
    for f in findings:
        library = (f.extra or {}).get("library")
        if not library:
            continue
        for e in f.evidence:
            claims.setdefault(_norm_location(e.location), set()).add(
                str(library).lower())

    return {path: next(iter(names))
            for path, names in claims.items() if len(names) == 1}


def artefact_keys(f: Finding, components: dict[str, str]) -> set[str]:
    """The concrete things this finding is attached to.

    Two findings may only be linked if these intersect. Everything in here is
    something a detector observed, never something derived from the algorithm
    name.
    """
    keys: set[str] = set()
    container = (f.extra or {}).get("container") or {}

    for e in f.evidence:
        location = _norm_location(e.location)
        if not location:
            continue
        layer = container.get("layer_digest")
        if layer:
            # Inside an image, identity is (layer, path): the same path in two
            # layers is two different files, and treating them as one would
            # merge a fixed version with the one it replaced.
            keys.add(f"layer:{layer}:{location}")
        else:
            keys.add(f"file:{location}")

        component = components.get(location)
        if component:
            keys.add(f"component:{component}")

    library = (f.extra or {}).get("library")
    if library:
        keys.add(f"component:{str(library).lower()}")

    return keys


def _conflicts(members: list[Finding]) -> list[str]:
    """Disagreements between linked findings, recorded rather than resolved."""
    out: list[str] = []

    sizes = {f.key_size for f in members if f.key_size}
    if len(sizes) > 1:
        out.append(
            f"linked findings disagree on key size: {sorted(sizes)} — they may be "
            f"different keys in the same component rather than one asset")

    modes = {f.mode for f in members if f.mode}
    if len(modes) > 1:
        out.append(f"linked findings disagree on cipher mode: {sorted(modes)}")

    paddings = {f.padding for f in members if f.padding}
    if len(paddings) > 1:
        out.append(f"linked findings disagree on padding: {sorted(paddings)}")

    states = {f.assurance for f in members}
    if states & set(_POTENTIAL) and states & set(_ACTUAL):
        out.append(
            "this component is both declared as a capability and observed in use; "
            "the capability finding keeps its own assurance and is not promoted")

    return out


def correlate(findings: list[Finding]) -> list[LogicalAsset]:
    """Link findings into logical assets, mutating none of them.

    Each finding gains ``extra["correlation"]`` describing its links. No
    finding's algorithm, purpose, assurance, confidence or evidence is
    touched, which is what makes this safe to run after scoring.
    """
    by_id = {f.id: f for f in findings}
    components = _component_map(findings)

    # Group first by the two dimensions that must always agree. RSA signing and
    # RSA key establishment can never end up in the same bucket, so no amount
    # of shared-artefact evidence can link them.
    buckets: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        buckets.setdefault((f.algorithm, P.normalise(f.purpose)), []).append(f)

    assets: list[LogicalAsset] = []

    for (algorithm, purpose), group in buckets.items():
        if len(group) < 2:
            continue

        keyed = [(f, artefact_keys(f, components)) for f in group]

        # Union-find over shared artefact keys.
        parent: dict[str, str] = {f.id: f.id for f, _ in keyed}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        shared: dict[str, list[str]] = {}
        for f, keys in keyed:
            for key in keys:
                shared.setdefault(key, []).append(f.id)

        linked_by: dict[frozenset[str], set[str]] = {}
        for key, ids in shared.items():
            if len(ids) < 2:
                continue
            # A link is only interesting across detectors. Two hits from the
            # same detector in the same file are already one asset after
            # normalisation, and pairing them again says nothing new.
            detectors = {detector_of(by_id[i]) for i in ids}
            if len(detectors) < 2:
                continue
            for other in ids[1:]:
                union(ids[0], other)
            linked_by.setdefault(frozenset(ids), set()).add(key)

        clusters: dict[str, list[Finding]] = {}
        for f, _ in keyed:
            clusters.setdefault(find(f.id), []).append(f)

        for root, members in clusters.items():
            if len(members) < 2:
                continue
            detectors = sorted({detector_of(m) for m in members})
            if len(detectors) < 2:
                continue

            member_ids = {m.id for m in members}
            basis = sorted({
                key for ids, keys in linked_by.items()
                if ids <= member_ids for key in keys
            })

            states: dict[str, int] = {}
            for m in members:
                states[m.assurance] = states.get(m.assurance, 0) + 1

            present = set(states)
            asset = LogicalAsset(
                id="asset-" + hashlib.sha256(
                    "|".join(sorted(member_ids)).encode()).hexdigest()[:12],
                algorithm=algorithm,
                purpose=purpose,
                members=sorted(member_ids),
                basis=basis,
                detectors=detectors,
                assurance_states=states,
                # The strongest evidence *in the group*. Reported as a property
                # of the asset; no member's own assurance is changed by it.
                strongest_assurance=strongest_assurance(present),
                corroborated_by_use=bool(present & set(_POTENTIAL)
                                         and present & set(_ACTUAL)),
                conflicts=_conflicts(members),
                locations=sorted({e.location for m in members
                                  for e in m.evidence})[:20],
            )
            assets.append(asset)

            for m in members:
                m.extra["correlation"] = {
                    "asset_id": asset.id,
                    "basis": basis,
                    "peers": sorted(member_ids - {m.id}),
                    "peer_detectors": [d for d in detectors
                                       if d != detector_of(m)],
                    "strongest_assurance_in_group": asset.strongest_assurance,
                    # Explicit, so nobody reading the payload has to work out
                    # whether the link changed this finding's standing.
                    "own_assurance_unchanged": m.assurance,
                    "corroborated_by_use": asset.corroborated_by_use,
                    "conflicts": asset.conflicts,
                }

    assets.sort(key=lambda a: (-len(a.members), a.algorithm, a.purpose))
    return assets


def summary(assets: list[LogicalAsset]) -> dict[str, Any]:
    """Estate-level roll-up of what correlation established."""
    return {
        "logical_assets": len(assets),
        "correlated_findings": sum(len(a.members) for a in assets),
        "corroborated_capabilities": sum(1 for a in assets if a.corroborated_by_use),
        "with_conflicts": sum(1 for a in assets if a.conflicts),
        "by_basis": _basis_counts(assets),
    }


def _basis_counts(assets: list[LogicalAsset]) -> dict[str, int]:
    out: dict[str, int] = {}
    for a in assets:
        for key in a.basis:
            kind = key.split(":", 1)[0]
            out[kind] = out.get(kind, 0) + 1
    return out

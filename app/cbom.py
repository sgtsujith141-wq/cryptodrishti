"""CycloneDX 1.6 CBOM emitter.

The problem statement asks for a report "in standardised formats". There is
exactly one standard for a cryptographic inventory: CycloneDX 1.6, published
as ECMA-424, whose CBOM support originated at IBM Research.

We emit components of type ``cryptographic-asset`` carrying a
``cryptoProperties`` object, with detection evidence in ``evidence.occurrences``
and per-finding confidence in ``evidence.identity`` -- the fields CycloneDX 1.6
added specifically so a scanner can say *where* it saw something and *how sure*
it is.

``validate()`` performs structural checks against the specification's required
shapes. It is **not** a full JSON-Schema validation -- we ship no schema file,
to keep the tool dependency-free and offline -- and it says so plainly rather
than overclaiming.

Detection facts and operator assumptions are kept in separate property
namespaces. ``detection:*`` and ``container:*`` are things the tool observed;
``assessment:*`` are inputs a person supplied or a default filled in. A
consumer that cannot tell the two apart will read a score built from four
guesses as though it were measured.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Iterable, Optional

from . import config
from .knowledge import algorithms as K
from .knowledge import purposes as P
from .models import (
    ASSET_ALGORITHM, ASSET_CERTIFICATE, ASSET_MATERIAL, ASSET_PROTOCOL,
    ASSURANCE_LABEL, Finding, ScanResult,
)

SPEC_VERSION = "1.6"
BOM_FORMAT = "CycloneDX"

# Map our internal asset types onto the CycloneDX cryptoProperties.assetType
# enum. CycloneDX has exactly four; our ASSET_LIBRARY is our own grouping and
# is emitted as a plain library component rather than a crypto asset.
_ASSET_TYPE = {
    ASSET_ALGORITHM: "algorithm",
    ASSET_CERTIFICATE: "certificate",
    ASSET_PROTOCOL: "protocol",
    ASSET_MATERIAL: "related-crypto-material",
}

# Our internal primitive names onto the CycloneDX primitive enum.
_PRIMITIVE = {
    K.PRIM_KEM: "kem", K.PRIM_KEY_AGREE: "key-agree",
    K.PRIM_SIGNATURE: "signature", K.PRIM_PKE: "pke",
    K.PRIM_BLOCK_CIPHER: "block-cipher", K.PRIM_STREAM_CIPHER: "stream-cipher",
    K.PRIM_HASH: "hash", K.PRIM_MAC: "mac", K.PRIM_KDF: "key-derive",
    K.PRIM_DRBG: "drbg", K.PRIM_AE: "ae",
}

_TECHNIQUE = {
    "source-ast-analysis": "source-code-analysis",
    "source-pattern-match": "source-code-analysis",
    "dependency-manifest": "manifest-analysis",
    "binary-symbol-analysis": "binary-analysis",
    "binary-constant-match": "binary-analysis",
    "binary-string-match": "binary-analysis",
    "certificate-parse": "other",
    "network-probe": "dynamic-analysis",
    "config-parse": "other",
    # A container layer read is how we reached the bytes, not how the bytes
    # were identified. Findings that came from the source, binary, config or
    # manifest analysers keep *their* technique; only artefacts the container
    # sensor identified itself carry this one.
    "container-layer-analysis": "other",
}


def _bom_ref(f: Finding) -> str:
    return f"crypto/{f.asset_type}/{f.algorithm}/{f.id}"


def _crypto_properties(f: Finding) -> dict[str, Any]:
    alg = K.get(f.algorithm)
    asset_type = _ASSET_TYPE.get(f.asset_type, "algorithm")
    props: dict[str, Any] = {"assetType": asset_type}

    if asset_type == "algorithm":
        ap: dict[str, Any] = {"primitive": _PRIMITIVE.get(alg.primitive, "other")}
        # CycloneDX carries purpose as cryptoFunctions -- the operations the
        # asset performs. Emitting it means the resolved purpose survives
        # export instead of living only in our own model, and an unresolved
        # purpose is emitted as "unknown" rather than omitted, so a consumer
        # can tell "we did not establish this" from "we did not look".
        ap["cryptoFunctions"] = list(
            P.CRYPTO_FUNCTIONS.get(P.normalise(f.purpose), ["unknown"]))
        if f.key_size or alg.classical_bits:
            ap["parameterSetIdentifier"] = str(f.key_size or alg.classical_bits)
        if f.mode:
            ap["mode"] = f.mode
        if f.padding:
            ap["padding"] = f.padding
        if alg.classical_bits is not None:
            ap["classicalSecurityLevel"] = alg.classical_bits
        if alg.nist_level is not None:
            ap["nistQuantumSecurityLevel"] = alg.nist_level
        ap["executionEnvironment"] = "software-plain-ram"
        props["algorithmProperties"] = ap

    elif asset_type == "certificate":
        cp: dict[str, Any] = {}
        for src, dst in (("subject", "subjectName"), ("issuer", "issuerName"),
                         ("not_before", "notValidBefore"), ("not_after", "notValidAfter"),
                         ("signature_algorithm", "signatureAlgorithmRef")):
            if f.extra.get(src):
                cp[dst] = str(f.extra[src])
        cp["certificateFormat"] = f.extra.get("format", "X.509")
        props["certificateProperties"] = cp

    elif asset_type == "related-crypto-material":
        rp: dict[str, Any] = {"type": f.extra.get("material_type", "private-key")}
        if f.key_size:
            rp["size"] = f.key_size
        if f.extra.get("format"):
            rp["format"] = f.extra["format"]
        props["relatedCryptoMaterialProperties"] = rp

    elif asset_type == "protocol":
        pp: dict[str, Any] = {"type": f.extra.get("protocol_type", "tls")}
        if f.extra.get("version"):
            pp["version"] = str(f.extra["version"])
        if f.extra.get("cipher_suites"):
            pp["cipherSuites"] = [{"name": c} for c in f.extra["cipher_suites"]]
        props["protocolProperties"] = pp

    if alg.oid:
        props["oid"] = alg.oid
    return props


def _evidence(f: Finding) -> dict[str, Any]:
    occurrences = []
    for e in f.evidence[:50]:          # cap; the full set stays in our own store
        occ: dict[str, Any] = {"location": e.location}
        if e.line:
            occ["line"] = e.line
        if e.symbol:
            occ["symbol"] = e.symbol
        # Assurance is prefixed onto the context so it survives into the
        # standard field rather than needing an extension a consumer may drop.
        context = (e.context or e.snippet)[:220]
        label = ASSURANCE_LABEL.get(e.assurance, e.assurance)
        occ["additionalContext"] = f"[{label}] {context}".strip()
        occurrences.append(occ)

    techniques = sorted({_TECHNIQUE.get(e.technique, "other") for e in f.evidence})
    identity = {
        "field": "name",
        "confidence": round(f.confidence, 2),
        "methods": [
            {"technique": t, "confidence": round(f.confidence, 2), "value": f.rule_id}
            for t in techniques
        ],
    }
    return {"identity": [identity], "occurrences": occurrences}


def component_for(f: Finding) -> dict[str, Any]:
    alg = K.get(f.algorithm)
    comp: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(f),
        "name": alg.name,
        "cryptoProperties": _crypto_properties(f),
        "evidence": _evidence(f),
    }
    if alg.standard:
        comp["description"] = f"{alg.name} ({alg.standard}). {alg.note}".strip()
    elif alg.note:
        comp["description"] = alg.note

    # Non-standard analysis carried as properties, which is the CycloneDX
    # sanctioned way to add data the spec has no field for.
    comp["properties"] = [
        {"name": "quantum:class", "value": alg.quantum_class},
        {"name": "quantum:riskScore", "value": str(f.risk_score)},
        {"name": "quantum:exposureYears", "value": str(f.exposure_years)},
        {"name": "detection:scanner", "value": f.scanner},
        {"name": "detection:ruleId", "value": f.rule_id},
        {"name": "detection:occurrences", "value": str(f.occurrences)},
        # Assurance travels with every component, because a consumer that
        # cannot tell a library capability from a live call site will add both
        # into the same total and report an estate that does not exist.
        {"name": "detection:assurance", "value": f.assurance},
        {"name": "detection:provesUse", "value": "true" if f.proves_use else "false"},
        {"name": "crypto:purpose", "value": P.normalise(f.purpose)},
    ]
    if f.purpose_evidence:
        comp["properties"].append(
            {"name": "crypto:purposeEvidence", "value": f.purpose_evidence[:400]})
    if f.extra.get("trust_verified") is not None:
        comp["properties"].append(
            {"name": "certificate:trustVerified",
             "value": str(f.extra["trust_verified"]).lower()})

    # Container provenance. Carried as properties, which is the CycloneDX
    # sanctioned place for data the spec has no field for, so a consumer that
    # ignores them still gets a conforming document.
    provenance = f.extra.get("container") or {}
    if provenance:
        comp["properties"].extend([
            {"name": "container:image", "value": str(provenance.get("image", ""))},
            {"name": "container:path", "value": str(provenance.get("path", ""))},
            {"name": "container:layerIndex",
             "value": str(provenance.get("layer_index", ""))},
            {"name": "container:layerDigest",
             "value": str(provenance.get("layer_digest", ""))},
            # The distinction that matters: is this artefact in the image's
            # final filesystem, or only in a layer something later deleted?
            {"name": "container:state", "value": str(provenance.get("state", ""))},
            {"name": "container:effective",
             "value": "true" if provenance.get("effective") else "false"},
        ])
        if provenance.get("image_digest"):
            comp["properties"].append(
                {"name": "container:imageDigest",
                 "value": str(provenance["image_digest"])})
        if provenance.get("platform"):
            comp["properties"].append(
                {"name": "container:platform", "value": str(provenance["platform"])})

    # Assessment. Kept in its own namespace because these are *assumptions*,
    # not detections. A consumer must be able to tell what this tool measured
    # from what a person supplied or a default filled in, and a single flat
    # property list would make the two indistinguishable.
    mosca = f.extra.get("mosca") or {}
    model = f.extra.get("exposure_model") or {}
    inputs = f.extra.get("risk_inputs") or {}
    meta = f.extra.get("assessment") or {}

    if mosca:
        comp["properties"].extend([
            {"name": "assessment:exposureModel", "value": str(model.get("key", ""))},
            {"name": "assessment:exposureModelMeaningOfX",
             "value": str(model.get("x_label", ""))},
            {"name": "assessment:retroactive",
             "value": "true" if model.get("retroactive") else "false"},
            {"name": "assessment:confidentialityLifetimeYears",
             "value": str(mosca.get("shelf_life", ""))},
            {"name": "assessment:migrationYears",
             "value": str(mosca.get("migration_years", ""))},
            {"name": "assessment:yearsToQDay",
             "value": str(mosca.get("years_to_qday", ""))},
            {"name": "assessment:exposureYears",
             "value": str(mosca.get("exposure_years", ""))},
            # Labelled at the point of use, because this number is the most
            # quotable thing in the document and means nothing without it.
            {"name": "assessment:probabilityExposedConditional",
             "value": str(mosca.get("probability_exposed", ""))},
            {"name": "assessment:probabilityConditionalOn",
             "value": str(mosca.get("conditional_on", ""))},
        ])

    for name, value in sorted(inputs.items()):
        comp["properties"].append(
            {"name": f"assessment:input:{name}",
             "value": f"{value.get('value')} ({value.get('provenance')})"})

    if meta.get("operator_inputs"):
        comp["properties"].append(
            {"name": "assessment:operatorSuppliedInputs",
             "value": ", ".join(meta["operator_inputs"])})
    if meta.get("deployment_state") and meta["deployment_state"] != "not-a-container-asset":
        comp["properties"].append(
            {"name": "assessment:deploymentState",
             "value": str(meta["deployment_state"])})

    rec = f.recommendation or {}
    for prop, key in (("assessment:latencyStatus", "latency"),
                      ("assessment:costStatus", "cost")):
        node = rec.get(key) or {}
        if node.get("status"):
            comp["properties"].append({"name": prop, "value": str(node["status"])})
    for unknown in (rec.get("unknowns") or [])[:5]:
        comp["properties"].append(
            {"name": "assessment:unknown", "value": str(unknown)[:400]})
    for warning in (rec.get("constraint_warnings") or [])[:5]:
        comp["properties"].append(
            {"name": "assessment:constraintWarning", "value": str(warning)[:400]})

    # Correlation. A link, never a merge: the component's own assurance is
    # emitted above and is unaffected by anything here.
    link = f.extra.get("correlation") or {}
    if link:
        comp["properties"].extend([
            {"name": "correlation:assetId", "value": str(link.get("asset_id", ""))},
            {"name": "correlation:basis", "value": "; ".join(link.get("basis", []))},
            {"name": "correlation:peerDetectors",
             "value": "; ".join(link.get("peer_detectors", []))},
            {"name": "correlation:corroboratedByUse",
             "value": "true" if link.get("corroborated_by_use") else "false"},
        ])
        for conflict in link.get("conflicts", [])[:3]:
            comp["properties"].append(
                {"name": "correlation:conflict", "value": conflict[:400]})
    if f.recommendation:
        comp["properties"].append(
            {"name": "migration:recommendation",
             "value": str(f.recommendation.get("target_name", "")
                          or "unresolved — purpose not established")})
        if f.recommendation.get("unresolved"):
            comp["properties"].append(
                {"name": "migration:unresolved", "value": "true"})
    return comp


def _metadata_properties(result: ScanResult, findings: list[Finding]
                         ) -> list[dict[str, str]]:
    """Document-level facts, including which image this BOM describes."""
    stats = result.stats or {}
    props = [
        {"name": "sih:problemStatement", "value": config.PS_ID},
        {"name": "sih:organisation", "value": config.PS_ORG},
        {"name": "scan:durationSeconds", "value": str(round(result.duration, 2))},
        {"name": "scan:findings", "value": str(len(findings))},
        {"name": "scan:targetKind", "value": result.target.kind},
        # An incomplete scan that does not say so is the most damaging thing
        # this document could be, so completeness is a first-class field.
        {"name": "scan:complete",
         "value": "true" if stats.get("complete", True) else "false"},
    ]
    for reason in (stats.get("incomplete_reasons") or [])[:10]:
        props.append({"name": "scan:incompleteReason", "value": str(reason)[:400]})

    if stats.get("container_format"):
        props.extend([
            {"name": "container:archiveFormat",
             "value": str(stats["container_format"])},
            {"name": "container:image", "value": str(stats.get("container_image", ""))},
            {"name": "container:layersRead",
             "value": str(stats.get("container_layers", 0))},
            {"name": "container:findingsEffective",
             "value": str(stats.get("container_findings_effective", 0))},
            {"name": "container:findingsHistorical",
             "value": str(stats.get("container_findings_historical", 0))},
        ])
        if stats.get("container_image_digest"):
            props.append({"name": "container:imageDigest",
                          "value": str(stats["container_image_digest"])})

    # Document-level assumptions. Separated from scan facts above by their
    # namespace, and carrying the caveat rather than leaving a reader to
    # supply it.
    from .engine import risk as _risk
    props.extend([
        {"name": "assessment:date", "value": _risk.assessment_date().isoformat()},
        {"name": "assessment:overridesApplied",
         "value": str(stats.get("overrides_applied", 0))},
    ])
    sample = next((f.extra.get("assessment") for f in findings
                   if (f.extra or {}).get("assessment")), None)
    if sample and sample.get("qday"):
        qday = sample["qday"]
        props.extend([
            {"name": "assessment:qdayEarliest", "value": str(qday.get("earliest"))},
            {"name": "assessment:qdayMostLikelyMode", "value": str(qday.get("likely"))},
            {"name": "assessment:qdayLatest", "value": str(qday.get("latest"))},
            {"name": "assessment:qdayMedian", "value": str(qday.get("median_year"))},
            {"name": "assessment:qdayBasis", "value": str(qday.get("basis"))},
            {"name": "assessment:qdayIsForecast", "value": "false"},
            {"name": "assessment:qdayCaveat", "value": str(qday.get("caveat", ""))[:600]},
        ])

    correlation = stats.get("correlation") or {}
    if correlation:
        props.append({"name": "correlation:logicalAssets",
                      "value": str(correlation.get("logical_assets", 0))})
        props.append({"name": "correlation:correlatedFindings",
                      "value": str(correlation.get("correlated_findings", 0))})
    return props


def build(result: ScanResult, findings: Optional[Iterable[Finding]] = None) -> dict[str, Any]:
    """Produce a complete CycloneDX 1.6 CBOM document."""
    findings = list(findings if findings is not None else result.findings)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    serial = "urn:uuid:" + str(uuid.UUID(
        hashlib.sha256(f"{result.id}{result.target.value}".encode()).hexdigest()[:32]))

    doc: dict[str, Any] = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": config.PRODUCT_NAME,
                    "version": config.PRODUCT_VERSION,
                    "description": config.PRODUCT_TAGLINE,
                }]
            },
            "component": {
                "type": "application",
                "bom-ref": f"target/{result.id}",
                "name": result.target.label or result.target.value,
                "description": f"{result.target.kind}: {result.target.value}",
            },
            "properties": _metadata_properties(result, findings),
        },
        "components": [component_for(f) for f in findings],
    }
    return doc


def to_json(result: ScanResult, findings: Optional[Iterable[Finding]] = None,
            indent: int = 2) -> str:
    return json.dumps(build(result, findings), indent=indent)


# --------------------------------------------------------------------------
# Structural validation
# --------------------------------------------------------------------------

_VALID_ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}
_VALID_PRIMITIVES = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
}

# CycloneDX 1.6 cryptoFunctions enum.
_VALID_CRYPTO_FUNCTIONS = {
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
}


def validate(doc: dict[str, Any]) -> tuple[bool, list[str]]:
    """Structural conformance check against the CycloneDX 1.6 CBOM shape.

    Returns (ok, problems). This checks required fields, enum membership and
    reference integrity. It is not a full JSON-Schema validation -- we state
    that explicitly rather than implying more coverage than we have.
    """
    problems: list[str] = []

    if doc.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be 'CycloneDX'")
    if doc.get("specVersion") != SPEC_VERSION:
        problems.append(f"specVersion must be '{SPEC_VERSION}'")
    if not isinstance(doc.get("version"), int):
        problems.append("version must be an integer")
    serial = doc.get("serialNumber", "")
    if not serial.startswith("urn:uuid:"):
        problems.append("serialNumber must be a urn:uuid")
    if "timestamp" not in doc.get("metadata", {}):
        problems.append("metadata.timestamp is required")

    refs: set[str] = set()
    for i, comp in enumerate(doc.get("components", [])):
        where = f"components[{i}]"
        if comp.get("type") != "cryptographic-asset":
            problems.append(f"{where}.type must be 'cryptographic-asset'")
        if not comp.get("name"):
            problems.append(f"{where}.name is required")

        ref = comp.get("bom-ref")
        if not ref:
            problems.append(f"{where}.bom-ref is required")
        elif ref in refs:
            problems.append(f"{where}.bom-ref '{ref}' is not unique")
        else:
            refs.add(ref)

        cp = comp.get("cryptoProperties")
        if not isinstance(cp, dict):
            problems.append(f"{where}.cryptoProperties is required for a cryptographic-asset")
            continue

        at = cp.get("assetType")
        if at not in _VALID_ASSET_TYPES:
            problems.append(f"{where}.cryptoProperties.assetType '{at}' is not a valid enum value")

        if at == "algorithm":
            ap = cp.get("algorithmProperties", {})
            prim = ap.get("primitive")
            if prim and prim not in _VALID_PRIMITIVES:
                problems.append(f"{where}.algorithmProperties.primitive '{prim}' is invalid")
            nl = ap.get("nistQuantumSecurityLevel")
            if nl is not None and not (0 <= nl <= 6):
                problems.append(f"{where}.nistQuantumSecurityLevel {nl} out of range 0-6")
            for fn in ap.get("cryptoFunctions", []) or []:
                if fn not in _VALID_CRYPTO_FUNCTIONS:
                    problems.append(
                        f"{where}.algorithmProperties.cryptoFunctions '{fn}' is invalid")

        ev = comp.get("evidence", {})
        for j, ident in enumerate(ev.get("identity", [])):
            c = ident.get("confidence")
            if c is not None and not (0.0 <= c <= 1.0):
                problems.append(f"{where}.evidence.identity[{j}].confidence {c} out of range 0-1")

    return (not problems), problems

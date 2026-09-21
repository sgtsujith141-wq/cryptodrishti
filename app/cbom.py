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
import re
import time
import uuid
from typing import Any, Iterable, Optional

from . import config
from .knowledge import algorithms as K
from .knowledge import purposes as P
from .models import (
    ASSET_ALGORITHM, ASSET_CERTIFICATE, ASSET_LIBRARY, ASSET_MATERIAL,
    ASSET_PROTOCOL, ASSURANCE_LABEL, Finding, ScanResult,
)

SPEC_VERSION = "1.6"          # the default: the version we rely on
SUPPORTED_SPEC_VERSIONS = ("1.6", "1.7")
BOM_FORMAT = "CycloneDX"

# --------------------------------------------------------------------------
# CycloneDX 1.7
#
# 1.7 is a superset of 1.6 for cryptographic assets: nothing was removed, some
# fields gained replacements and the old ones were deprecated. Emitting 1.7 is
# therefore a real implementation rather than a version-string change, and it
# is only offered because the differences below are actually handled:
#
#   * `curve` is deprecated in favour of `ellipticCurve`, which is a *closed
#     enum* with namespaced names -- `nist/P-256`, not `P-256`.
#   * `algorithmFamily` is new, also a closed enum, and it splits RSA by
#     purpose: RSASSA-PSS, RSASSA-PKCS1 and RSAES-OAEP exist, plain "RSA" does
#     not. An RSA finding whose purpose we never resolved therefore gets no
#     family, which is the correct answer rather than an awkward one.
#   * `signatureAlgorithmRef` is deprecated in favour of
#     `relatedCryptographicAssets`.
#
# Both versions are validated against their own official schema in CI. If that
# ever stops being true, the version comes out of SUPPORTED_SPEC_VERSIONS
# rather than being quietly left to drift.
# --------------------------------------------------------------------------

# Registry key -> the 1.7 `ellipticCurve` enum value.
_CDX17_CURVES = {
    "ecdsa-p-256": "nist/P-256",
    "ecdsa-p-384": "nist/P-384",
    "ecdsa-p-521": "nist/P-521",
    "ecdsa-secp256k1": "secg/secp256k1",
    "ed25519": "other/Ed25519",
    "ed448": "other/Ed448",
    "x25519": "other/Curve25519",
    "x448": "other/Curve448",
}

# Registry family -> the 1.7 `algorithmFamily` enum value. Anything absent is
# omitted rather than approximated.
_CDX17_FAMILIES = {
    "AES": "AES", "3DES": "3DES", "DES": "DES", "RC4": "RC4", "RC2": "RC2",
    "Blowfish": "Blowfish", "CAST": "CAST5", "IDEA": "IDEA", "SEED": "SEED",
    "Camellia": "CAMELLIA", "ChaCha20": "ChaCha20",
    "SHA-1": "SHA-1", "SHA-2": "SHA-2", "SHA-3": "SHA-3",
    "BLAKE2": "BLAKE2", "BLAKE3": "BLAKE3", "MD5": "MD5", "MD2": "MD2",
    "MD4": "MD4",
    "ECDSA": "ECDSA", "ECDH": "ECDH", "EdDSA": "EdDSA", "DSA": "DSA",
    "DH": "FFDH", "ML-KEM": "ML-KEM", "ML-DSA": "ML-DSA", "SLH-DSA": "SLH-DSA",
    "HMAC": "HMAC",
}

# RSA has no single family in 1.7 -- it is split by what the key is doing,
# which is exactly the distinction the purpose model already carries.
_CDX17_RSA_FAMILY = {
    "signature": "RSASSA-PSS",
    "key-establishment": "RSAES-OAEP",
    "encryption": "RSAES-OAEP",
}

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

# The schema constrains `mode` and `padding` to closed enums. Detectors see
# what source code actually writes -- `XTS`, `CFB8`, `PKCS5Padding`,
# `OAEPWithSHA-256AndMGF1Padding` -- and passing those straight through
# produced documents the official validator rejects. Map what maps; send the
# rest to `other`, which is the enum value that exists for exactly this.
_CDX_MODE = {
    "cbc": "cbc", "ecb": "ecb", "ccm": "ccm", "gcm": "gcm",
    "cfb": "cfb", "ofb": "ofb", "ctr": "ctr",
    # Real modes with no enum member of their own.
    "cfb8": "other", "cfb1": "other", "cfb128": "other",
    "xts": "other", "gcm-siv": "other", "siv": "other",
    "ocb": "other", "eax": "other", "cts": "other",
}

_CDX_PADDING = {
    "pkcs5": "pkcs5", "pkcs7": "pkcs7", "pkcs1v15": "pkcs1v15",
    "oaep": "oaep", "raw": "raw",
}


def _cdx_mode(mode: Optional[str]) -> Optional[str]:
    """Map a detected mode onto the CycloneDX enum, or `other`."""
    if not mode:
        return None
    key = str(mode).strip().lower()
    if key in _CDX_MODE:
        return _CDX_MODE[key]
    # `AES/CBC/PKCS5Padding` style values sometimes arrive with suffixes.
    for name, value in _CDX_MODE.items():
        if key.startswith(name):
            return value
    return "other"


def _cdx_padding(padding: Optional[str]) -> Optional[str]:
    """Map a detected padding scheme onto the CycloneDX enum, or `other`."""
    if not padding:
        return None
    key = "".join(ch for ch in str(padding).lower() if ch.isalnum())
    if key.startswith("pkcs1") or "pkcs1v15" in key:
        return "pkcs1v15"
    if key.startswith("oaep") or "oaepwith" in key:
        return "oaep"
    if key.startswith("pkcs5"):
        return "pkcs5"
    if key.startswith("pkcs7"):
        return "pkcs7"
    if key in ("raw", "nopadding", "none"):
        return "raw"
    return _CDX_PADDING.get(key, "other")


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


_CDX_PROTOCOL = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}

_CDX_MATERIAL = {
    "private-key", "public-key", "secret-key", "key", "ciphertext", "signature",
    "digest", "initialization-vector", "nonce", "seed", "salt",
    "shared-secret", "tag", "additional-data", "password", "credential",
    "token", "other", "unknown",
}


def _cdx_protocol(value: Optional[str]) -> str:
    key = (value or "").strip().lower()
    return key if key in _CDX_PROTOCOL else "other"


def _cdx_material(value: Optional[str]) -> str:
    key = (value or "").strip().lower()
    return key if key in _CDX_MATERIAL else "other"


def _as_date_time(value: Any) -> Optional[str]:
    """Coerce a recorded date to an RFC 3339 date-time, or drop it.

    A value we cannot turn into the format the schema asks for is omitted
    rather than emitted in the wrong shape. The date is also available
    verbatim in the properties, so nothing is lost.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z") and "T" in text:
        return text
    if "T" in text:
        return text if text.endswith(("Z", "+00:00")) else text + "Z"
    try:
        import datetime as _dt
        return _dt.datetime.strptime(text, "%Y-%m-%d").replace(
            tzinfo=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def _signature_ref_key(f: Finding) -> str:
    """Index key for the algorithm that signed this certificate."""
    return f"sigalg::{(f.extra or {}).get('signature_algorithm', '')}"


# Curve names as CycloneDX writes them, derived from the registry rather than
# re-parsed from the algorithm key.
_CURVES = {
    "ecdsa-p-256": "P-256", "ecdsa-p-384": "P-384", "ecdsa-p-521": "P-521",
    "ecdsa-secp256k1": "secp256k1",
    "ed25519": "Ed25519", "ed448": "Ed448",
    "x25519": "X25519", "x448": "X448",
}


def _curve_name(alg) -> Optional[str]:
    return _CURVES.get(alg.key)


def _execution_environment(f: Finding) -> str:
    """Where this asset executes, when that was actually established.

    Only an operator saying so counts. The scanners read files; none of them
    observes a runtime, and there is no evidence in a source tree that
    distinguishes a key held in plain RAM from one held in an HSM.
    """
    constraints = ((f.extra or {}).get("assessment") or {}).get("constraints") or []
    if "hardware-backed" in constraints:
        return "hardware"
    return "unknown"


def _bom_ref(f: Finding) -> str:
    return f"crypto/{f.asset_type}/{f.algorithm}/{f.id}"


def _cdx17_family(alg, purpose: str) -> Optional[str]:
    """The 1.7 algorithm family, or None when no enum member is truthful."""
    if alg.family == "RSA":
        # Omitted for an unresolved purpose: 1.7 has no plain "RSA" member,
        # and picking one of the three would assert the purpose we could not
        # establish.
        return _CDX17_RSA_FAMILY.get(P.normalise(purpose))
    return _CDX17_FAMILIES.get(alg.family)


def _crypto_properties(f: Finding,
                       refs: Optional[dict[str, str]] = None,
                       spec_version: str = SPEC_VERSION,
                       ) -> dict[str, Any]:
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
        # The parameter set is the *parameter set* -- a key length, a named
        # parameter set identifier -- and not a security strength. Falling
        # back to `classical_bits` conflated the two: it reported ECDSA P-256
        # as parameter set "128", which is its strength, not its parameters.
        # Strength has its own field below and is emitted there.
        if f.key_size:
            ap["parameterSetIdentifier"] = str(f.key_size)
        elif alg.family in ("ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC"):
            # For the PQC families the parameter set *is* the name's suffix.
            suffix = alg.key.rsplit("-", 1)[-1]
            if suffix.isdigit() or suffix.endswith(("s", "f")):
                ap["parameterSetIdentifier"] = suffix

        # Named curves belong in a curve field, not smuggled into the
        # parameter set. 1.7 deprecated `curve` for `ellipticCurve`, which is
        # a closed enum, so the value differs by version as well as the key.
        if spec_version == "1.7":
            curve = _CDX17_CURVES.get(alg.key)
            if curve:
                ap["ellipticCurve"] = curve
            family = _cdx17_family(alg, f.purpose)
            if family:
                ap["algorithmFamily"] = family
        else:
            curve = _curve_name(alg)
            if curve:
                ap["curve"] = curve
        mode = _cdx_mode(f.mode)
        if mode:
            ap["mode"] = mode
            if mode == "other" and f.mode:
                # The enum lost the detail, so keep it where a reader can see it.
                ap.setdefault("parameterSetIdentifier", str(f.key_size or ""))
        padding = _cdx_padding(f.padding)
        if padding:
            ap["padding"] = padding
        if alg.classical_bits is not None:
            ap["classicalSecurityLevel"] = alg.classical_bits
        if alg.nist_level is not None:
            ap["nistQuantumSecurityLevel"] = alg.nist_level
        # We do not observe the execution environment. Asserting
        # `software-plain-ram` was a guess that happened to be schema-valid,
        # and it is exactly wrong for the assets that matter most -- a key in
        # an HSM is the case you would most want not to mislabel. The enum has
        # `unknown` for this, so `unknown` is what we emit, unless an operator
        # told us otherwise.
        ap["executionEnvironment"] = _execution_environment(f)
        props["algorithmProperties"] = ap

    elif asset_type == "certificate":
        cp: dict[str, Any] = {}
        for src, dst in (("subject", "subjectName"), ("issuer", "issuerName")):
            if f.extra.get(src):
                cp[dst] = str(f.extra[src])
        # The schema declares these `format: date-time`. We were emitting a
        # bare date, which is a different thing and fails a format-checking
        # validator.
        for src, dst in (("not_before", "notValidBefore"),
                         ("not_after", "notValidAfter")):
            stamp = _as_date_time(f.extra.get(src))
            if stamp:
                cp[dst] = stamp
        # `signatureAlgorithmRef` is a refType: a bom-ref pointing at another
        # component in this document. We were putting a human-readable
        # algorithm name in it ("sha256WithRSAEncryption"), which is not a
        # reference to anything. It is now set only when the signing algorithm
        # really is a component here, and omitted otherwise -- an omitted
        # optional field is honest; a dangling reference is not.
        ref = (refs or {}).get(_signature_ref_key(f))
        if ref and ref != _bom_ref(f):
            if spec_version == "1.7":
                # 1.7 deprecated signatureAlgorithmRef for a typed relation.
                cp["relatedCryptographicAssets"] = [
                    {"type": "algorithm", "ref": ref}]
            else:
                cp["signatureAlgorithmRef"] = ref
        cp["certificateFormat"] = f.extra.get("format", "X.509")
        props["certificateProperties"] = cp

    elif asset_type == "related-crypto-material":
        rp: dict[str, Any] = {
            "type": _cdx_material(f.extra.get("material_type"))}
        if f.key_size:
            rp["size"] = f.key_size
        if f.extra.get("format"):
            rp["format"] = f.extra["format"]
        props["relatedCryptoMaterialProperties"] = rp

    elif asset_type == "protocol":
        pp: dict[str, Any] = {
            "type": _cdx_protocol(f.extra.get("protocol_type"))}
        if f.extra.get("version"):
            pp["version"] = str(f.extra["version"])
        if f.extra.get("cipher_suites"):
            pp["cipherSuites"] = [{"name": c} for c in f.extra["cipher_suites"]]
        props["protocolProperties"] = pp

    if alg.oid:
        props["oid"] = alg.oid
    return props


# Rules whose evidence is, by construction, the sensitive thing itself. A CBOM
# is made to be shared -- attached to a ticket, sent to a vendor, committed to
# a repository -- and a tool that finds a hardcoded secret and then publishes
# it has made the problem worse, not better.
_SENSITIVE_RULES = {
    "any.hardcoded.secret", "any.private.key.inline", "cert.privatekey",
}

# A long opaque literal is key material; a short one is usually a cipher
# transform. The threshold is 40 characters because that is comfortably
# longer than every algorithm string a detector legitimately captures
# ("AES/ECB/PKCS5Padding" is 20) and comfortably shorter than a PEM body
# line, a JWT or a base64 key. Redacting by shape alone at a lower
# threshold ate the single most informative field in every Java finding.
_SECRET_LITERAL = re.compile(
    r'''(['"])([A-Za-z0-9+/=_-]{40,})\1''')

# Assignment to an identifier that names a secret. This is the reliable
# signal -- the variable says what it holds -- so it has no length floor
# beyond being long enough to be worth hiding. The identifier list mirrors
# the `any.hardcoded.secret` detector's own list, so a name that triggers a
# finding also triggers redaction when it turns up in another one's snippet.
_SECRET_ASSIGNMENT = re.compile(
    r'''(?i)(\w*(?:secret|password|passphrase|api[_-]?key|private[_-]?key|encryption[_-]?key|aes[_-]?key|signing[_-]?key|token|credential)\w*)\s*[=:]\s*['"]?([^\s'"]{8,})''')


def redact(text: str) -> str:
    """Strip anything that looks like key material from exported evidence.

    Deliberately blunt. A redaction that occasionally masks a harmless
    constant costs a reader one lookup in their own source; a redaction that
    occasionally misses a real key costs them the key.
    """
    if not text:
        return text
    out = _SECRET_ASSIGNMENT.sub(
        lambda m: f"{m.group(1)}=[redacted:{len(m.group(2))} chars]", text)
    out = _SECRET_LITERAL.sub(
        lambda m: f"{m.group(1)}[redacted:{len(m.group(2))} chars]{m.group(1)}",
        out)
    return out


def _safe_symbol(f: Finding, e) -> str:
    """The matched symbol, with sensitive material removed."""
    if f.rule_id in _SENSITIVE_RULES:
        return "[redacted]"
    return redact(str(e.symbol or ""))[:120]


def _safe_context(f: Finding, e) -> str:
    """The evidence context, with sensitive material removed.

    Location and line number are kept -- those are what make the finding
    actionable, and they are not secret. The matched text is not.
    """
    if f.rule_id in _SENSITIVE_RULES:
        return ("[redacted: this finding's evidence is key material or a "
                "secret. See the source location above.]")
    return redact((e.context or e.snippet)[:220])


def _evidence(f: Finding) -> dict[str, Any]:
    occurrences = []
    for e in f.evidence[:50]:          # cap; the full set stays in our own store
        occ: dict[str, Any] = {"location": e.location}
        if e.line:
            occ["line"] = e.line
        if e.symbol:
            # The symbol is the matched text, which for a hardcoded-secret
            # rule *is* the secret. Redacting only additionalContext left the
            # value in plain sight one field over.
            occ["symbol"] = _safe_symbol(f, e)
        # Assurance is prefixed onto the context so it survives into the
        # standard field rather than needing an extension a consumer may drop.
        # The context itself is redacted first.
        context = _safe_context(f, e)
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


def _reference_index(findings: list[Finding]) -> dict[str, str]:
    """bom-refs that other components may legitimately point at.

    Only real components go in. A reference to something this document does
    not contain is worse than an omitted optional field: it looks like
    information and resolves to nothing.
    """
    index: dict[str, str] = {}
    for f in findings:
        if f.rule_id == "cert.sigalg":
            name = (f.extra or {}).get("signature_algorithm") or ""
            if name:
                index.setdefault(f"sigalg::{name}", _bom_ref(f))
        index.setdefault(f"algorithm::{f.algorithm}", _bom_ref(f))
    return index


def _add_container_properties(comp: dict[str, Any], f: Finding) -> None:
    """Image and layer provenance, for whichever component kind carries it."""
    provenance = (f.extra or {}).get("container") or {}
    if not provenance:
        return
    comp.setdefault("properties", []).extend([
        {"name": "container:image", "value": str(provenance.get("image", ""))},
        {"name": "container:path", "value": str(provenance.get("path", ""))},
        {"name": "container:layerIndex",
         "value": str(provenance.get("layer_index", ""))},
        {"name": "container:layerDigest",
         "value": str(provenance.get("layer_digest", ""))},
        # The distinction that matters: is this artefact in the image's final
        # filesystem, or only in a layer something later deleted?
        {"name": "container:state", "value": str(provenance.get("state", ""))},
        {"name": "container:effective",
         "value": "true" if provenance.get("effective") else "false"},
    ])
    if provenance.get("image_digest"):
        comp["properties"].append(
            {"name": "container:imageDigest", "value": str(provenance["image_digest"])})
    if provenance.get("platform"):
        comp["properties"].append(
            {"name": "container:platform", "value": str(provenance["platform"])})


def _is_library_component(f: Finding) -> bool:
    """Whether this finding describes a software library, not a crypto asset.

    A dependency on BouncyCastle is a library. It was being emitted as a
    `cryptographic-asset` with `assetType: algorithm`, which says the
    *package* is an algorithm. The module comment already claimed these were
    emitted as library components; the code did not do it, and a consumer
    counting cryptographic assets would have counted every dependency twice
    over -- once as the library and once per algorithm it provides.
    """
    return f.asset_type == ASSET_LIBRARY and f.rule_id in (
        "dep.library", "bin.version", "container.env")


def _library_component(f: Finding) -> dict[str, Any]:
    """A CycloneDX `library` component, which is what these actually are."""
    extra = f.extra or {}
    name = str(extra.get("library") or f.title or "library")
    comp: dict[str, Any] = {
        "type": "library",
        "bom-ref": _bom_ref(f),
        "name": name,
        "evidence": _evidence(f),
    }
    version = extra.get("version")
    if version:
        comp["version"] = str(version)
    if f.detail:
        comp["description"] = f.detail[:900]
    comp["properties"] = [
        {"name": "detection:scanner", "value": f.scanner},
        {"name": "detection:ruleId", "value": f.rule_id},
        {"name": "detection:assurance", "value": f.assurance},
        {"name": "detection:provesUse", "value": "true" if f.proves_use else "false"},
    ]
    provides = extra.get("provides")
    if provides:
        comp["properties"].append(
            {"name": "crypto:providesAlgorithms", "value": ", ".join(map(str, provides))})
    if extra.get("ecosystem"):
        comp["properties"].append(
            {"name": "detection:ecosystem", "value": str(extra["ecosystem"])})
    _add_container_properties(comp, f)
    return comp


def component_for(f: Finding, refs: Optional[dict[str, str]] = None,
                  spec_version: str = SPEC_VERSION) -> dict[str, Any]:
    if _is_library_component(f):
        return _library_component(f)

    alg = K.get(f.algorithm)
    comp: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(f),
        "name": alg.name,
        "cryptoProperties": _crypto_properties(f, refs, spec_version),
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
    _add_container_properties(comp, f)

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


def build(result: ScanResult, findings: Optional[Iterable[Finding]] = None,
          spec_version: str = SPEC_VERSION) -> dict[str, Any]:
    """Produce a complete CycloneDX CBOM document.

    ``spec_version`` selects 1.6 (the default and the one to rely on) or 1.7.
    Both are emitted as genuine documents and both are validated against their
    own official schema in CI.
    """
    if spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise ValueError(
            f"CycloneDX {spec_version} is not supported by this tool. "
            f"Supported: {', '.join(SUPPORTED_SPEC_VERSIONS)}.")
    findings = list(findings if findings is not None else result.findings)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    serial = "urn:uuid:" + str(uuid.UUID(
        hashlib.sha256(f"{result.id}{result.target.value}".encode()).hexdigest()[:32]))

    # First pass: index the components a reference could legitimately point at.
    # Built before any component is emitted so a certificate can reference the
    # algorithm that signed it *only when that algorithm is really here*.
    refs = _reference_index(findings)

    doc: dict[str, Any] = {
        "bomFormat": BOM_FORMAT,
        "specVersion": spec_version,
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
        "components": [component_for(f, refs, spec_version) for f in findings],
    }
    return doc


def to_json(result: ScanResult, findings: Optional[Iterable[Finding]] = None,
            indent: int = 2, spec_version: str = SPEC_VERSION) -> str:
    return json.dumps(build(result, findings, spec_version), indent=indent)


# --------------------------------------------------------------------------
# Structural validation
# --------------------------------------------------------------------------

_VALID_ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}

# Component types this emitter produces. A library dependency is a library.
_VALID_COMPONENT_TYPES = {"cryptographic-asset", "library"}

_VALID_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}
_VALID_PADDINGS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"}
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
    declared = doc.get("specVersion")
    if declared not in SUPPORTED_SPEC_VERSIONS:
        problems.append(
            f"specVersion '{declared}' is not one this tool emits "
            f"({', '.join(SUPPORTED_SPEC_VERSIONS)})")
    if not isinstance(doc.get("version"), int):
        problems.append("version must be an integer")
    serial = doc.get("serialNumber", "")
    if not serial.startswith("urn:uuid:"):
        problems.append("serialNumber must be a urn:uuid")
    if "timestamp" not in doc.get("metadata", {}):
        problems.append("metadata.timestamp is required")

    refs: set[str] = set()
    pending_refs: list[tuple[str, str]] = []

    for i, comp in enumerate(doc.get("components", [])):
        where = f"components[{i}]"
        kind = comp.get("type")
        if kind not in _VALID_COMPONENT_TYPES:
            problems.append(
                f"{where}.type '{kind}' is not a component type this tool emits "
                f"(expected one of {', '.join(sorted(_VALID_COMPONENT_TYPES))})")
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
        if kind == "library":
            # A library is a package, not a cryptographic asset, and must not
            # carry cryptoProperties claiming otherwise.
            if cp is not None:
                problems.append(
                    f"{where} is a library component and must not carry "
                    f"cryptoProperties")
            continue

        if not isinstance(cp, dict):
            problems.append(f"{where}.cryptoProperties is required for a cryptographic-asset")
            continue

        certificate = cp.get("certificateProperties") or {}
        for field in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
            if certificate.get(field):
                pending_refs.append((f"{where}.certificateProperties.{field}",
                                     certificate[field]))

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

        for field, table in (("mode", _VALID_MODES), ("padding", _VALID_PADDINGS)):
            value = ap.get(field) if at == "algorithm" else None
            if value is not None and value not in table:
                problems.append(
                    f"{where}.algorithmProperties.{field} '{value}' is not a "
                    f"valid enum value")

        ev = comp.get("evidence", {})
        for j, ident in enumerate(ev.get("identity", [])):
            c = ident.get("confidence")
            if c is not None and not (0.0 <= c <= 1.0):
                problems.append(f"{where}.evidence.identity[{j}].confidence {c} out of range 0-1")

    # Reference integrity. A bom-ref that resolves to nothing looks like
    # information and is not; it is worse than an omitted optional field.
    for where, target in pending_refs:
        if target not in refs:
            problems.append(
                f"{where} points at '{target}', which is not a component in "
                f"this document")

    return (not problems), problems

"""Migration recommendation engine.

Clause (iv) of the problem statement asks for alternatives selected "based on
risk profile, latency, cost". That is a constrained choice, not a lookup: the
right answer depends on what the deployment can physically carry.

The constraint that dominates is **size**. An ECDSA P-256 signature is 64
bytes; ML-DSA-65 is 3,309. On a TLS handshake that is invisible. On a
constrained radio link with a 51-byte payload it is impossible, and
recommending it there would be wrong. The engine therefore reasons about the
size delta and says so, including when the honest answer is "no drop-in
replacement exists -- this device needs a hardware refresh".

It also recommends crypto-agility rather than only an algorithm, because a
hardcoded call site will need replacing again at the next transition.

**Purpose, not primitive.** The branch is chosen by what the finding is
*doing*, which the detector resolves from the call site, and not by the
algorithm's name. RSA signs and RSA transports keys; the first is replaced by
ML-DSA and the second by ML-KEM, and no property of the string "RSA" tells you
which. Where the purpose could not be resolved, the engine says so and asks
for the evidence it needs instead of picking the commoner of two answers. An
unresolved finding a human reviews is worth more than a resolved one that is
wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Optional

from ..knowledge import algorithms as K
from ..knowledge import purposes as P
from ..models import Finding

# Deployment profiles. These change the answer, which is the whole point.
PROFILE_GENERAL = "general"
PROFILE_HIGH_ASSURANCE = "high-assurance"
PROFILE_CONSTRAINED = "constrained"
PROFILE_LONG_LIVED = "long-lived"

PROFILES = {
    PROFILE_GENERAL: "General purpose",
    PROFILE_HIGH_ASSURANCE: "High assurance",
    PROFILE_CONSTRAINED: "Constrained / IoT",
    PROFILE_LONG_LIVED: "Firmware signing",
}


@dataclass
class Recommendation:
    target: str                  # algorithm key, or "" when none is suitable
    target_name: str
    rationale: str
    action: str                  # the concrete change to make
    hybrid: bool = False
    size_delta_bytes: Optional[int] = None
    size_note: str = ""
    agility_note: str = ""
    library_support: str = ""
    effort: str = "medium"       # low | medium | high
    confidence: float = 0.9
    # The purpose this recommendation was chosen for, and how that purpose was
    # established. Both are surfaced, so a reader can check the reasoning
    # rather than taking the target on trust.
    purpose: str = P.UNKNOWN
    purpose_evidence: str = ""
    # True when no target could be named because the evidence was insufficient.
    # Distinct from "no migration needed", which is a finished answer.
    unresolved: bool = False
    # What must be established or checked before acting.
    validate_before: str = ""

    # ---- M4: the parts of a recommendation a reader can act on ----------
    #
    # Every one of these is either grounded in something the tool measured or
    # explicitly marked unknown. Latency and cost in particular are left
    # unknown by default and stay that way: this tool has never run a
    # benchmark or priced an engineer, and a plausible-looking number in
    # either field would be the most quotable thing in the report and the
    # least defensible.
    evidence_summary: str = ""
    exposure_explanation: str = ""
    compatibility: list[str] = field(default_factory=list)
    latency: dict[str, Any] = field(default_factory=dict)
    cost: dict[str, Any] = field(default_factory=dict)
    validation_steps: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    constraints_applied: list[str] = field(default_factory=list)
    constraint_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Library support matrix. A recommendation the target codebase cannot execute
# is not a recommendation.
LIBRARY_SUPPORT = {
    "ml-kem": "OpenSSL 3.5+, BoringSSL, liboqs/oqs-provider, BouncyCastle 1.79+, Go 1.24+",
    "ml-dsa": "OpenSSL 3.5+, liboqs/oqs-provider, BouncyCastle 1.79+",
    "slh-dsa": "OpenSSL 3.5+, liboqs, BouncyCastle 1.79+",
    "fn-dsa": "liboqs only; FIPS 206 still draft",
    "hybrid": "OpenSSL 3.5+, Chrome, Firefox, Cloudflare, AWS-LC",
    "aes": "Universal",
}


def _sig_delta(from_key: str, to_key: str) -> Optional[int]:
    a, b = K.get(from_key), K.get(to_key)
    if a.signature_bytes and b.signature_bytes:
        return b.signature_bytes - a.signature_bytes
    if a.public_key_bytes and b.public_key_bytes:
        return b.public_key_bytes - a.public_key_bytes
    return None


def _size_note(delta: Optional[int], profile: str) -> str:
    if delta is None:
        return ""
    if delta <= 0:
        return "No size penalty."
    if profile == PROFILE_CONSTRAINED and delta > 1000:
        return (f"Adds {delta:,} bytes. On a constrained link this is likely "
                f"prohibitive and must be validated against the MTU before adoption.")
    if delta > 3000:
        return (f"Adds {delta:,} bytes per operation. Check any fixed-size protocol "
                f"field, certificate size limit or MTU before rollout.")
    if delta > 500:
        return f"Adds {delta:,} bytes per operation. Negligible over TCP, material over UDP."
    return f"Adds {delta:,} bytes per operation."


def resolve_purpose(f: Finding) -> tuple[str, str]:
    """Work out what this finding is for, and record how we know.

    Three sources, most specific first:

    1. The purpose the detector read off the call site -- an ``RSA_sign``
       call, an OAEP padding object, a certificate's KeyUsage extension.
    2. The purpose the algorithm can only have. ECDH does key agreement and
       nothing else; ECDSA signs and nothing else.
    3. Nothing. The purpose stays unknown.

    RSA reaches step 3 whenever step 1 found nothing, because step 2 cannot
    help: RSA has two purposes with two different replacements. That is the
    entire point of this function, and the reason it returns a reason as well
    as an answer.
    """
    stated = P.normalise(f.purpose)
    if stated != P.UNKNOWN:
        return stated, (f.purpose_evidence
                        or "resolved by the detector from the call site")

    implied = K.default_purpose(f.algorithm)
    if implied != P.UNKNOWN:
        return implied, (f"implied by the algorithm: {K.get(f.algorithm).name} "
                         f"serves only this purpose")

    return P.UNKNOWN, ""


def _unresolved_purpose(f: Finding, alg) -> Recommendation:
    """No target, because naming one would be a coin toss.

    This is the branch that used to be missing. An RSA finding with no
    resolved purpose was sent down the key-establishment path and handed a
    hybrid KEM, which is the right answer for RSA-OAEP and unimplementable
    advice for RSA-PSS. Saying "we do not know yet, here is how to find out"
    is both correct and more useful than a confident wrong answer.
    """
    options = ", ".join(P.LABEL[x].lower() for x in alg.purposes) or "several purposes"
    return Recommendation(
        target="", target_name="Purpose must be resolved first",
        rationale=(
            f"{alg.name} is used for {options}, and the replacement differs "
            f"completely by purpose: a signing key needs ML-DSA, a key-transport "
            f"key needs ML-KEM or a hybrid group. The evidence at this site did "
            f"not establish which, so no target is named. Choosing the more "
            f"common answer would produce advice that cannot be implemented at "
            f"whichever sites it got wrong."
        ),
        action=(
            "Determine what the key does, then re-run the recommendation. The "
            "quickest signals: the padding scheme (PSS signs, OAEP encrypts), "
            "the API called (sign/verify against encrypt/decrypt), or the "
            "KeyUsage extension on any certificate that carries this key."
        ),
        validate_before=(
            "Do not migrate this finding until its purpose is established -- "
            "the two migration paths are not interchangeable."
        ),
        purpose=P.UNKNOWN, unresolved=True,
        effort="medium", confidence=0.4,
    )


def recommend(f: Finding, profile: str = PROFILE_GENERAL) -> Optional[Recommendation]:
    """Choose a migration target for one finding, based on its purpose."""
    alg = K.get(f.algorithm)
    purpose, why = resolve_purpose(f)

    def finish(rec: Recommendation) -> Recommendation:
        rec.purpose = purpose
        rec.purpose_evidence = why
        return rec

    # Already safe: nothing to do, but say why so the UI can show progress.
    if alg.quantum_class == K.SAFE:
        return finish(Recommendation(
            target=alg.key, target_name=alg.name,
            rationale="Already quantum-safe at the detected parameters.",
            action="No migration required. Record in the inventory as compliant.",
            effort="low", confidence=0.95,
        ))

    if alg.quantum_class == K.HYBRID:
        return finish(Recommendation(
            target=alg.key, target_name=alg.name,
            rationale="Hybrid construction: secure if either component holds.",
            action="No migration required. This is the current recommended posture.",
            effort="low", confidence=0.95,
        ))

    # ---- Purpose unresolved on an algorithm that serves more than one -----
    #
    # Checked before every dispatch below, because this is precisely where the
    # old engine guessed.
    if purpose == P.UNKNOWN and len(alg.purposes) > 1 and (
            set(alg.purposes) & P.AMBIGUOUS_WHEN_UNKNOWN):
        return _unresolved_purpose(f, alg)

    # ---- Signatures -------------------------------------------------------
    #
    # Checked before key establishment so that RSA resolved to signing takes
    # this branch. Under the old primitive-based dispatch it could not: RSA
    # carried `pke`, so every RSA finding matched key establishment first.
    if purpose == P.SIGNATURE:
        return finish(_recommend_signature(alg, profile))

    # ---- Key establishment ------------------------------------------------
    #
    # Public-key "encryption" is key transport in all but name -- nobody bulk
    # encrypts with RSA -- so it joins this branch rather than the symmetric one.
    if purpose in (P.KEY_ESTABLISHMENT,) or (
            purpose == P.ENCRYPTION and alg.primitive in (K.PRIM_PKE, K.PRIM_KEM,
                                                          K.PRIM_KEY_AGREE)):
        return finish(_recommend_key_establishment(alg, profile))

    # ---- Symmetric encryption --------------------------------------------
    if purpose == P.ENCRYPTION and alg.primitive in (K.PRIM_BLOCK_CIPHER,
                                                     K.PRIM_STREAM_CIPHER):
        return finish(_recommend_symmetric(alg))

    if purpose == P.HASHING:
        return finish(_recommend_hash(alg, profile))

    if purpose == P.RANDOMNESS:
        return finish(_recommend_rng())

    if purpose == P.TRANSPORT:
        return finish(_recommend_protocol())

    # ---- Fall back to the primitive --------------------------------------
    #
    # Reached when the purpose is unknown but the algorithm is unambiguous, so
    # the primitive is a safe guide rather than a guess -- ECDH does key
    # agreement whatever the call site looks like.
    if alg.primitive in (K.PRIM_KEY_AGREE, K.PRIM_PKE, K.PRIM_KEM):
        return finish(_recommend_key_establishment(alg, profile))
    if alg.primitive == K.PRIM_SIGNATURE:
        return finish(_recommend_signature(alg, profile))
    if alg.primitive in (K.PRIM_BLOCK_CIPHER, K.PRIM_STREAM_CIPHER):
        return finish(_recommend_symmetric(alg))
    if alg.primitive == K.PRIM_HASH:
        return finish(_recommend_hash(alg, profile))
    if alg.key == "weak-rng":
        return finish(_recommend_rng())
    if alg.family in ("TLS", "SSH", "IPsec"):
        return finish(_recommend_protocol())

    # ---- Algorithm itself unresolved -------------------------------------
    return finish(Recommendation(
        target="", target_name="Manual review required",
        rationale=("The algorithm could not be resolved statically, so recommending a "
                   "replacement would be a guess."),
        action=("Review the call site and record the concrete algorithm in the "
                "inventory, then re-run the recommendation."),
        unresolved=True, effort="medium", confidence=0.4,
    ))


# --------------------------------------------------------------------------
# Per-purpose recommendations
#
# The caller has already decided which of these applies, from the finding's
# resolved purpose. None of them re-derives it.
# --------------------------------------------------------------------------

def _recommend_key_establishment(alg, profile: str) -> Recommendation:

        if profile == PROFILE_HIGH_ASSURANCE:
            target = "ml-kem-1024"
            hybrid = False
            rationale = ("Category 5 parameter set for material whose confidentiality "
                         "must survive well past Q-Day.")
        elif profile == PROFILE_CONSTRAINED:
            target = "ml-kem-512"
            hybrid = False
            rationale = ("Smallest standardised ML-KEM parameter set. Still adds over a "
                         "kilobyte per handshake; validate against the link budget.")
        else:
            target = "x25519-ml-kem-768"
            hybrid = True
            rationale = ("Hybrid X25519 + ML-KEM-768 is the current default for transport "
                         "security: secure if either component holds, and already "
                         "negotiated by mainstream browsers and OpenSSL 3.5+.")
        delta = _sig_delta(alg.key, "ml-kem-768")
        return Recommendation(
            target=target, target_name=K.get(target).name,
            rationale=rationale,
            action=("Enable the hybrid group in the TLS configuration and prefer it in "
                    "the group list; no application code change is required."
                    if hybrid else
                    f"Replace the key establishment call with {K.get(target).name}."),
            hybrid=hybrid,
            size_delta_bytes=delta,
            size_note=_size_note(delta, profile),
            agility_note=("Route key establishment through a provider interface so the "
                          "next transition is a configuration change, not a code change."),
            library_support=LIBRARY_SUPPORT["hybrid" if hybrid else "ml-kem"],
            effort="low" if hybrid else "medium",
        )


def _recommend_signature(alg, profile: str) -> Recommendation:
    if profile == PROFILE_LONG_LIVED:
        target = "slh-dsa-128s"
        rationale = ("Hash-based signatures rest only on the security of the hash "
                     "function, which is the most conservative assumption available. "
                     "Correct where the signature must outlive the algorithm's peer "
                     "review -- firmware and root-of-trust keys.")
        effort = "high"
    elif profile == PROFILE_CONSTRAINED:
        target = "fn-dsa-512"
        rationale = ("Falcon has the smallest post-quantum signatures, but constant-time "
                     "implementation is difficult and FIPS 206 is still draft. Adopt "
                     "only where signature size genuinely dominates.")
        effort = "high"
    elif profile == PROFILE_HIGH_ASSURANCE:
        target = "ml-dsa-87"
        rationale = "Category 5 parameter set for high-assurance signing."
        effort = "medium"
    else:
        target = "ml-dsa-65"
        rationale = ("ML-DSA is NIST's primary signature recommendation and the "
                     "general-purpose replacement for RSA and ECDSA signing.")
        effort = "medium"

    delta = _sig_delta(alg.key, target)
    return Recommendation(
        target=target, target_name=K.get(target).name,
        rationale=rationale,
        action=f"Replace signing and verification with {K.get(target).name}, and "
               f"re-issue any certificates that chain to this key.",
        size_delta_bytes=delta,
        size_note=_size_note(delta, profile),
        agility_note=("Signature size changes break fixed-width protocol fields and "
                      "database columns. Audit both before rollout."),
        library_support=LIBRARY_SUPPORT["fn-dsa" if target.startswith("fn") else
                                        ("slh-dsa" if target.startswith("slh") else "ml-dsa")],
        effort=effort,
    )


def _recommend_symmetric(alg) -> Recommendation:
    if alg.key in ("des", "3des", "rc4", "rc2", "blowfish", "cast5", "idea"):
        return Recommendation(
            target="aes-256", target_name="AES-256",
            rationale=(f"{alg.name} is broken on classical grounds and is disallowed "
                       f"independently of any quantum consideration."),
            action="Replace with AES-256-GCM. This is a defect fix, not a migration.",
            size_delta_bytes=0, size_note="No size penalty.",
            library_support=LIBRARY_SUPPORT["aes"], effort="medium", confidence=0.95,
        )
    return Recommendation(
        target="aes-256", target_name="AES-256",
        rationale=("Grover halves effective symmetric strength. Doubling the key "
                   "restores the margin -- no change of algorithm family is needed."),
        action="Move to AES-256-GCM. Usually a configuration or key-length change only.",
        size_delta_bytes=0,
        size_note="No size penalty. The cheapest quantum-risk reduction available.",
        library_support=LIBRARY_SUPPORT["aes"], effort="low", confidence=0.95,
    )


def _recommend_hash(alg, profile: str) -> Recommendation:
    target = "sha384" if profile in (PROFILE_HIGH_ASSURANCE, PROFILE_LONG_LIVED) else "sha256"
    broken = alg.key in ("md2", "md4", "md5", "sha1")
    return Recommendation(
        target=target, target_name=K.get(target).name,
        rationale=("Collision-broken classically; unacceptable for signatures or "
                   "integrity." if broken else
                   "Below the 128-bit post-Grover floor."),
        action=f"Replace with {K.get(target).name}.",
        size_delta_bytes=0, size_note="No size penalty.",
        library_support=LIBRARY_SUPPORT["aes"],
        effort="medium" if broken else "low", confidence=0.95,
    )


def _recommend_rng() -> Recommendation:
    return Recommendation(
        target="", target_name="Cryptographic DRBG",
        rationale=("A predictable generator defeats every algorithm above it. This is "
                   "not a quantum issue -- it is a present-tense break."),
        action=("Replace with the platform CSPRNG: secrets / os.urandom in Python, "
                "SecureRandom in Java, crypto/rand in Go, getrandom(2) on Linux."),
        effort="low", confidence=0.9,
    )


def _recommend_protocol() -> Recommendation:
    return Recommendation(
        target="x25519-ml-kem-768", target_name="Hybrid PQC key exchange",
        rationale=("The protocol version is not the issue -- the negotiated key "
                   "exchange group is. TLS 1.3 with a classical group is still "
                   "Shor-broken."),
        action=("Enable hybrid PQC groups and prefer them in the group list; disable "
                "TLS versions below 1.2."),
        hybrid=True,
        library_support=LIBRARY_SUPPORT["hybrid"], effort="low",
    )



def recommend_all(findings: list[Finding], profile: str = PROFILE_GENERAL,
                  overrides: Optional[dict] = None) -> list[Finding]:
    overrides = overrides or {}
    for f in findings:
        rec = recommend(f, profile)
        if rec:
            override = overrides.get((f.extra or {}).get("asset_key"))
            rec = enrich(f, rec, getattr(override, "constraints", None))
        f.recommendation = rec.to_dict() if rec else None
    return findings


# --------------------------------------------------------------------------
# M4: grounding a recommendation in this specific asset
#
# The target algorithm is only part of an answer. The rest is what supports
# the finding, why it is exposed, what will break, what has to be checked, and
# — the part most tools get wrong — what is simply not known.
# --------------------------------------------------------------------------

UNKNOWN_LATENCY = {
    "status": "not-measured",
    "value": None,
    "note": ("This tool has not benchmarked either algorithm on your hardware, "
             "so it reports no latency figure. Published figures vary by more "
             "than an order of magnitude across platforms and implementations; "
             "measure on the target before planning around a number."),
}

UNKNOWN_COST = {
    "status": "not-estimated",
    "value": None,
    "currency": None,
    "note": ("No cost estimate is produced. Cost depends on engineer day rates, "
             "release cadence, hardware refresh cycles and vendor terms — none "
             "of which this tool has. The migration-effort band and the "
             "occurrence count below are the inputs to your own estimate."),
}


def _evidence_summary(f: Finding) -> str:
    """One sentence a reader can check against the evidence list."""
    if not f.evidence:
        return "No evidence recorded."
    first = f.evidence[0]
    files = (f.extra or {}).get("files") or len({e.location for e in f.evidence})
    where = first.location + (f":{first.line}" if first.line else "")
    techniques = sorted({e.technique for e in f.evidence})
    return (f"{f.occurrences} occurrence(s) across {files} file(s), first at "
            f"{where}, via {', '.join(techniques)}. Assurance: {f.assurance} — "
            f"{'shows the algorithm is reached' if f.proves_use else 'reachable or declared, not shown to be called'}.")


def _exposure_explanation(f: Finding) -> str:
    """Why this asset is exposed, in the terms of its own exposure model."""
    alg = K.get(f.algorithm)
    mosca = (f.extra or {}).get("mosca") or {}
    model = (f.extra or {}).get("exposure_model") or {}

    if alg.quantum_class == K.SAFE:
        return "No quantum exposure at the detected parameters."
    if alg.quantum_class == K.HYBRID:
        return "Hybrid construction: holds if either component holds."

    head = {
        K.BROKEN: (f"{alg.name} rests on factoring or discrete logarithms, "
                   f"both of which Shor's algorithm solves in polynomial time. "
                   f"Key size does not help."),
        K.WEAKENED: (f"{alg.name} is weakened rather than broken: Grover halves "
                     f"effective strength, so a larger parameter set restores "
                     f"the margin."),
    }.get(alg.quantum_class,
          "The algorithm was not resolved, so its exposure is undetermined.")

    if not mosca:
        return head

    tail = (f" Under the selected scenario, X={mosca.get('shelf_life')}y "
            f"({model.get('x_label', 'lifetime')}) plus Y="
            f"{mosca.get('migration_years')}y against Z="
            f"{mosca.get('years_to_qday')}y leaves "
            f"{mosca.get('exposure_years')}y of exposure. "
            f"{model.get('consequence', '')}")
    return head + tail


def _compatibility(alg, target_key: str, f: Finding) -> list[str]:
    """Concrete things that break, drawn from registry data rather than prose."""
    out: list[str] = []
    if not target_key:
        return out
    target = K.get(target_key)

    if target.signature_bytes and alg.signature_bytes:
        if target.signature_bytes > alg.signature_bytes:
            out.append(
                f"Signatures grow from {alg.signature_bytes:,} to "
                f"{target.signature_bytes:,} bytes. Any fixed-width database "
                f"column, protocol field or certificate size limit must be "
                f"widened first.")
    if target.public_key_bytes and alg.public_key_bytes:
        if target.public_key_bytes > alg.public_key_bytes:
            out.append(
                f"Public keys grow from {alg.public_key_bytes:,} to "
                f"{target.public_key_bytes:,} bytes.")
    if target.standard and "draft" in target.standard.lower():
        out.append(
            f"{target.name} rests on {target.standard}. A draft standard can "
            f"still change; adopting it now means accepting a possible "
            f"re-migration.")
    if f.asset_type == "certificate":
        out.append(
            "Certificates must be re-issued, not reconfigured, and every "
            "relying party has to accept the new algorithm before the old one "
            "can be withdrawn.")
    if (f.extra or {}).get("container"):
        out.append(
            "This asset lives in a container image. Replacing it means "
            "rebuilding and re-publishing the image, not patching a host.")
    return out


def _validation_steps(alg, target_key: str, f: Finding) -> list[str]:
    """What to confirm before acting. Deliberately not automated."""
    steps: list[str] = []
    if not f.proves_use:
        steps.append(
            "Confirm this algorithm is actually reached. The evidence shows it "
            "is available or declared, not that any code path calls it.")
    if target_key:
        steps.append(
            f"Confirm the runtime and every peer can negotiate {K.get(target_key).name} "
            f"before removing the current algorithm; run both in parallel first.")
        steps.append(
            "Measure handshake or signing latency on the target hardware. This "
            "tool has not measured it and will not guess.")
    if f.asset_type == "related-crypto-material":
        steps.append(
            "Key material must be regenerated, not re-encoded. Rotate and "
            "revoke the old key; a migrated wrapper around the same secret is "
            "not a migration.")
    steps.append(
        "Apply the change through review and release. This tool does not "
        "rewrite cryptographic code and no unattended rewrite should be "
        "scheduled from its output.")
    return steps


def _unknowns(f: Finding, rec: Recommendation) -> list[str]:
    """What is genuinely not known. Listing it is the point."""
    out: list[str] = []
    inputs = (f.extra or {}).get("risk_inputs") or {}
    defaulted = [name for name, value in inputs.items()
                 if value.get("provenance") == "default"]
    if defaulted:
        out.append(
            f"Risk inputs still at their defaults: {', '.join(sorted(defaulted))}. "
            f"The score is provisional until someone who knows this system "
            f"reviews them.")
    if rec.unresolved:
        out.append("The cryptographic purpose is unresolved, so no target is named.")
    if not f.proves_use:
        out.append("Whether this algorithm is executed at run time.")
    state = ((f.extra or {}).get("container") or {}).get("effective")
    if state is False:
        out.append(
            "Whether this historical layer artefact is still reachable in any "
            "deployed image. It is not in the final filesystem, but it remains "
            "extractable from the archive.")
    out.append("Latency and cost on your hardware and in your organisation.")
    return out


def _apply_constraints(rec: Recommendation, constraints: list[str]) -> None:
    """Warn where an operator-declared constraint fights the recommendation."""
    if not constraints:
        return
    rec.constraints_applied = list(constraints)
    target = K.get(rec.target) if rec.target else None

    if "constrained-link" in constraints and target and target.signature_bytes:
        if target.signature_bytes > 1500:
            rec.constraint_warnings.append(
                f"You marked this a constrained link, and {target.name} "
                f"signatures are {target.signature_bytes:,} bytes. Validate "
                f"against the MTU; this may need a hardware refresh rather "
                f"than an algorithm swap.")
    if "fips-required" in constraints and target:
        if target.standard and "draft" in target.standard.lower():
            rec.constraint_warnings.append(
                f"You require FIPS validation, but {target.name} rests on "
                f"{target.standard}. Choose a finalised standard instead.")
    if "no-code-change" in constraints and rec.effort != "low":
        rec.constraint_warnings.append(
            "You marked this configuration-only, but this change is not a "
            "configuration change. It needs a rebuild or a vendor update.")
    if "third-party" in constraints:
        rec.constraint_warnings.append(
            "You marked this vendor-owned. The migration date is theirs, not "
            "yours; the action here is to obtain their roadmap in writing.")
    if "hardware-backed" in constraints:
        rec.constraint_warnings.append(
            "You marked this key hardware-backed. Confirm the HSM or secure "
            "element supports the target algorithm before planning; many do "
            "not yet, and firmware may not be upgradeable.")


def enrich(f: Finding, rec: Recommendation,
           constraints: Optional[list[str]] = None) -> Recommendation:
    """Ground a chosen target in this asset's own evidence and constraints."""
    alg = K.get(f.algorithm)
    rec.evidence_summary = _evidence_summary(f)
    rec.exposure_explanation = _exposure_explanation(f)
    rec.compatibility = _compatibility(alg, rec.target, f)
    rec.validation_steps = _validation_steps(alg, rec.target, f)
    # Never invented. Both stay unknown unless something actually measured them.
    rec.latency = dict(UNKNOWN_LATENCY)
    rec.cost = dict(UNKNOWN_COST)
    rec.cost["effort_band"] = rec.effort
    rec.cost["occurrences"] = f.occurrences
    rec.cost["files"] = (f.extra or {}).get("files")
    _apply_constraints(rec, constraints or [])
    rec.unknowns = _unknowns(f, rec)
    return rec

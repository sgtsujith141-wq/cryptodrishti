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

from dataclasses import dataclass, asdict
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



def recommend_all(findings: list[Finding], profile: str = PROFILE_GENERAL) -> list[Finding]:
    for f in findings:
        rec = recommend(f, profile)
        f.recommendation = rec.to_dict() if rec else None
    return findings

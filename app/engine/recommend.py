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
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Optional

from ..knowledge import algorithms as K
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


def recommend(f: Finding, profile: str = PROFILE_GENERAL) -> Optional[Recommendation]:
    """Choose a migration target for one finding."""
    alg = K.get(f.algorithm)

    # Already safe: nothing to do, but say why so the UI can show progress.
    if alg.quantum_class == K.SAFE:
        return Recommendation(
            target=alg.key, target_name=alg.name,
            rationale="Already quantum-safe at the detected parameters.",
            action="No migration required. Record in the inventory as compliant.",
            effort="low", confidence=0.95,
        )

    if alg.quantum_class == K.HYBRID:
        return Recommendation(
            target=alg.key, target_name=alg.name,
            rationale="Hybrid construction: secure if either component holds.",
            action="No migration required. This is the current recommended posture.",
            effort="low", confidence=0.95,
        )

    # ---- Key establishment ------------------------------------------------
    if alg.primitive in (K.PRIM_KEY_AGREE, K.PRIM_PKE, K.PRIM_KEM):
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

    # ---- Signatures -------------------------------------------------------
    if alg.primitive == K.PRIM_SIGNATURE:
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

    # ---- Symmetric and hashes --------------------------------------------
    if alg.primitive in (K.PRIM_BLOCK_CIPHER, K.PRIM_STREAM_CIPHER):
        if alg.key in ("des", "3des", "rc4"):
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

    if alg.primitive == K.PRIM_HASH:
        target = "sha384" if profile in (PROFILE_HIGH_ASSURANCE, PROFILE_LONG_LIVED) else "sha256"
        broken = alg.key in ("md5", "sha1")
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

    if alg.key == "weak-rng":
        return Recommendation(
            target="", target_name="Cryptographic DRBG",
            rationale=("A predictable generator defeats every algorithm above it. This is "
                       "not a quantum issue -- it is a present-tense break."),
            action=("Replace with the platform CSPRNG: secrets / os.urandom in Python, "
                    "SecureRandom in Java, crypto/rand in Go, getrandom(2) on Linux."),
            effort="low", confidence=0.9,
        )

    # ---- Protocols --------------------------------------------------------
    if alg.family in ("TLS", "SSH", "IPsec"):
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

    # ---- Unresolved -------------------------------------------------------
    return Recommendation(
        target="", target_name="Manual review required",
        rationale=("The algorithm could not be resolved statically, so recommending a "
                   "replacement would be a guess."),
        action=("Review the call site and record the concrete algorithm in the "
                "inventory, then re-run the recommendation."),
        effort="medium", confidence=0.4,
    )


def recommend_all(findings: list[Finding], profile: str = PROFILE_GENERAL) -> list[Finding]:
    for f in findings:
        rec = recommend(f, profile)
        f.recommendation = rec.to_dict() if rec else None
    return findings

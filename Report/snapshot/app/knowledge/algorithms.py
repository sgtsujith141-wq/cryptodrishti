"""The cryptographic algorithm registry.

This is the tool's ground truth. Every finding resolves to an entry here, and
the entry decides how the finding is classified, scored and remediated.

Classification follows the standard three-way split:

  * Shor-broken     -- public-key schemes whose hardness assumption (integer
                       factorisation or discrete logarithm) collapses under
                       Shor's algorithm. Key size is irrelevant; these are a
                       total break.
  * Grover-weakened -- symmetric primitives and hashes. Grover gives a
                       quadratic speed-up on unstructured search, so effective
                       security halves. Doubling the key size restores it.
  * Quantum-safe    -- schemes with no known quantum advantage beyond Grover,
                       at parameters that leave adequate margin.

NIST quantum security levels (used by the CBOM field of the same name) run
1-5; we use 0 to mean "broken", which is our own extension and is reported as
such rather than as a NIST claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# --------------------------------------------------------------------------
# Quantum vulnerability classes
# --------------------------------------------------------------------------

BROKEN = "shor-broken"
WEAKENED = "grover-weakened"
SAFE = "quantum-safe"
HYBRID = "hybrid"
UNKNOWN = "unknown"

CLASS_ORDER = [BROKEN, WEAKENED, UNKNOWN, HYBRID, SAFE]

CLASS_LABEL = {
    BROKEN: "Broken by Shor",
    WEAKENED: "Weakened by Grover",
    SAFE: "Quantum-safe",
    HYBRID: "Hybrid (classical + PQC)",
    UNKNOWN: "Unknown / unresolved",
}

CLASS_DESCRIPTION = {
    BROKEN: (
        "A cryptographically relevant quantum computer running Shor's algorithm "
        "recovers the private key in polynomial time. Increasing the key size "
        "does not help. Must be replaced."
    ),
    WEAKENED: (
        "Grover's algorithm gives a quadratic speed-up, halving effective "
        "security. Mitigated by moving to a larger parameter set rather than a "
        "different algorithm family."
    ),
    SAFE: (
        "No known quantum attack beyond generic search. Adequate margin at the "
        "parameters detected."
    ),
    HYBRID: (
        "Combines a classical and a post-quantum scheme so the construction "
        "holds if either component holds. Currently the recommended default "
        "for transport security."
    ),
    UNKNOWN: (
        "Detected as cryptographic but not resolved to a specific algorithm. "
        "Reported rather than guessed; needs manual review."
    ),
}

# Weight applied to the risk score. Ordered, not arbitrary.
CLASS_WEIGHT = {
    BROKEN: 1.0,
    WEAKENED: 0.45,
    UNKNOWN: 0.35,
    HYBRID: 0.08,
    SAFE: 0.02,
}

# --------------------------------------------------------------------------
# Primitives -- what the algorithm is *for*. Mirrors the CycloneDX
# cryptoProperties.algorithmProperties.primitive enum.
# --------------------------------------------------------------------------

PRIM_KEM = "kem"
PRIM_KEY_AGREE = "key-agree"
PRIM_SIGNATURE = "signature"
PRIM_PKE = "pke"
PRIM_BLOCK_CIPHER = "block-cipher"
PRIM_STREAM_CIPHER = "stream-cipher"
PRIM_HASH = "hash"
PRIM_MAC = "mac"
PRIM_KDF = "kdf"
PRIM_DRBG = "drbg"
PRIM_AE = "ae"


@dataclass(frozen=True)
class Algorithm:
    """One cryptographic algorithm at a specific parameter set."""

    key: str                          # canonical internal id, e.g. "rsa-2048"
    name: str                         # display name, e.g. "RSA-2048"
    family: str                       # "RSA", "ECDSA", "AES", "ML-KEM", ...
    primitive: str
    quantum_class: str
    classical_bits: Optional[int] = None   # classical security strength, bits
    nist_level: Optional[int] = None       # NIST PQC category, 0 = broken
    oid: Optional[str] = None
    standard: Optional[str] = None         # e.g. "FIPS 203"
    note: str = ""
    # Sizes in bytes, where meaningful. Used by the recommender to reason about
    # protocol impact -- this is the data that makes a recommendation credible.
    public_key_bytes: Optional[int] = None
    signature_bytes: Optional[int] = None
    ciphertext_bytes: Optional[int] = None
    deprecated_after: Optional[int] = None  # NIST IR 8547 deprecation year
    disallowed_after: Optional[int] = None
    # Multiplier on the base risk score. Used where membership of a class is
    # correct but the severity is not uniform across it: a TLS 1.3 endpoint is
    # Shor-broken in its key exchange, yet plainly less urgent than a TLS 1.0
    # one, and scoring them identically would discredit the whole ranking.
    risk_adjust: float = 1.0


def _a(**kw) -> Algorithm:
    return Algorithm(**kw)


# --------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------

ALGORITHMS: dict[str, Algorithm] = {}


def _register(alg: Algorithm) -> Algorithm:
    ALGORITHMS[alg.key] = alg
    return alg


# ---- Public key: broken by Shor -----------------------------------------

for _bits, _sec in ((1024, 80), (2048, 112), (3072, 128), (4096, 152)):
    _register(_a(
        key=f"rsa-{_bits}",
        name=f"RSA-{_bits}",
        family="RSA",
        primitive=PRIM_PKE,
        quantum_class=BROKEN,
        classical_bits=_sec,
        nist_level=0,
        oid="1.2.840.113549.1.1.1",
        standard="PKCS#1 / FIPS 186-5",
        public_key_bytes=_bits // 8,
        signature_bytes=_bits // 8,
        deprecated_after=2030 if _bits >= 2048 else None,
        disallowed_after=2035 if _bits >= 2048 else 2030,
        note=(
            "Factoring an n-bit modulus is polynomial-time under Shor. "
            "RSA-1024 is already below acceptable classical strength."
            if _bits == 1024 else
            "Factoring is polynomial-time under Shor. Key size gives no protection."
        ),
    ))

_register(_a(key="rsa", name="RSA (unspecified size)", family="RSA",
             primitive=PRIM_PKE, quantum_class=BROKEN, nist_level=0,
             oid="1.2.840.113549.1.1.1", standard="PKCS#1",
             note="Key size not resolved from the call site; assume the weakest configured default."))

for _curve, _sec, _pk in (("p-256", 128, 64), ("p-384", 192, 96), ("p-521", 260, 132),
                          ("secp256k1", 128, 64)):
    _register(_a(
        key=f"ecdsa-{_curve}",
        name=f"ECDSA {_curve.upper()}",
        family="ECDSA",
        primitive=PRIM_SIGNATURE,
        quantum_class=BROKEN,
        classical_bits=_sec,
        nist_level=0,
        oid="1.2.840.10045.4.3.2",
        standard="FIPS 186-5",
        public_key_bytes=_pk,
        signature_bytes=_pk,
        deprecated_after=2030,
        disallowed_after=2035,
        note="Elliptic-curve discrete log is polynomial-time under Shor.",
    ))

_register(_a(key="ecdsa", name="ECDSA (unspecified curve)", family="ECDSA",
             primitive=PRIM_SIGNATURE, quantum_class=BROKEN, nist_level=0,
             oid="1.2.840.10045.4.3.2", standard="FIPS 186-5",
             note="Curve not resolved from the call site."))

_register(_a(key="ecdh", name="ECDH", family="ECDH", primitive=PRIM_KEY_AGREE,
             quantum_class=BROKEN, classical_bits=128, nist_level=0,
             oid="1.2.840.10045.2.1", standard="SP 800-56A",
             deprecated_after=2030, disallowed_after=2035,
             note="Elliptic-curve Diffie-Hellman. Broken by Shor."))

_register(_a(key="dh", name="Diffie-Hellman", family="DH", primitive=PRIM_KEY_AGREE,
             quantum_class=BROKEN, classical_bits=112, nist_level=0,
             standard="SP 800-56A", deprecated_after=2030, disallowed_after=2035,
             note="Finite-field discrete log. Broken by Shor."))

_register(_a(key="dsa", name="DSA", family="DSA", primitive=PRIM_SIGNATURE,
             quantum_class=BROKEN, classical_bits=112, nist_level=0,
             oid="1.2.840.10040.4.1", standard="FIPS 186-4",
             disallowed_after=2030,
             note="Already withdrawn for new signatures in FIPS 186-5. Broken by Shor."))

_register(_a(key="ed25519", name="Ed25519", family="EdDSA", primitive=PRIM_SIGNATURE,
             quantum_class=BROKEN, classical_bits=128, nist_level=0,
             oid="1.3.101.112", standard="RFC 8032",
             public_key_bytes=32, signature_bytes=64,
             deprecated_after=2030, disallowed_after=2035,
             note="Excellent classical security, but an elliptic-curve scheme: broken by Shor."))

_register(_a(key="x25519", name="X25519", family="ECDH", primitive=PRIM_KEY_AGREE,
             quantum_class=BROKEN, classical_bits=128, nist_level=0,
             oid="1.3.101.110", standard="RFC 7748", public_key_bytes=32,
             deprecated_after=2030, disallowed_after=2035,
             note="Montgomery-curve key agreement. Broken by Shor; pair with ML-KEM as a hybrid."))

_register(_a(key="elgamal", name="ElGamal", family="ElGamal", primitive=PRIM_PKE,
             quantum_class=BROKEN, nist_level=0,
             note="Discrete-log based. Broken by Shor."))

# ---- Symmetric and hashes ------------------------------------------------

_register(_a(key="aes-128", name="AES-128", family="AES", primitive=PRIM_BLOCK_CIPHER,
             quantum_class=WEAKENED, classical_bits=128, nist_level=1,
             oid="2.16.840.1.101.3.4.1", standard="FIPS 197",
             note="Grover reduces effective strength toward 64 bits. Move to AES-256."))

_register(_a(key="aes-192", name="AES-192", family="AES", primitive=PRIM_BLOCK_CIPHER,
             quantum_class=WEAKENED, classical_bits=192, nist_level=3,
             standard="FIPS 197", note="Acceptable, but AES-256 is the clean target."))

_register(_a(key="aes-256", name="AES-256", family="AES", primitive=PRIM_BLOCK_CIPHER,
             quantum_class=SAFE, classical_bits=256, nist_level=5,
             oid="2.16.840.1.101.3.4.1.46", standard="FIPS 197",
             note="Quantum-safe at current understanding. The migration target for block ciphers."))

_register(_a(key="aes", name="AES (unspecified size)", family="AES",
             primitive=PRIM_BLOCK_CIPHER, quantum_class=WEAKENED,
             standard="FIPS 197", note="Key size not resolved; many libraries default to 128-bit."))

_register(_a(key="3des", name="Triple DES", family="3DES", primitive=PRIM_BLOCK_CIPHER,
             quantum_class=WEAKENED, classical_bits=112, nist_level=0,
             oid="1.2.840.113549.3.7", standard="SP 800-67",
             disallowed_after=2024,
             note="Disallowed by NIST since 2024 on classical grounds alone. Remove."))

_register(_a(key="des", name="DES", family="DES", primitive=PRIM_BLOCK_CIPHER,
             quantum_class=WEAKENED, classical_bits=56, nist_level=0,
             disallowed_after=2005,
             note="Broken classically decades ago. Any occurrence is a defect."))

_register(_a(key="rc4", name="RC4", family="RC4", primitive=PRIM_STREAM_CIPHER,
             quantum_class=WEAKENED, classical_bits=0, nist_level=0,
             disallowed_after=2015,
             note="Prohibited in TLS by RFC 7465. Any occurrence is a defect."))

_register(_a(key="chacha20", name="ChaCha20", family="ChaCha20",
             primitive=PRIM_STREAM_CIPHER, quantum_class=SAFE,
             classical_bits=256, nist_level=5, standard="RFC 8439",
             note="256-bit key; quantum-safe as a symmetric primitive."))

_register(_a(key="md5", name="MD5", family="MD5", primitive=PRIM_HASH,
             quantum_class=WEAKENED, classical_bits=0, nist_level=0,
             oid="1.2.840.113549.2.5", disallowed_after=2010,
             note="Collision-broken classically since 2004. Never acceptable for signatures."))

_register(_a(key="sha1", name="SHA-1", family="SHA-1", primitive=PRIM_HASH,
             quantum_class=WEAKENED, classical_bits=0, nist_level=0,
             oid="1.3.14.3.2.26", disallowed_after=2030,
             note="Practical collisions demonstrated (SHAttered, 2017). Disallowed by NIST after 2030."))

_register(_a(key="sha224", name="SHA-224", family="SHA-2", primitive=PRIM_HASH,
             quantum_class=WEAKENED, classical_bits=112, nist_level=1,
             standard="FIPS 180-4", note="Below the 128-bit floor once Grover is considered."))

_register(_a(key="sha256", name="SHA-256", family="SHA-2", primitive=PRIM_HASH,
             quantum_class=SAFE, classical_bits=256, nist_level=2,
             oid="2.16.840.1.101.3.4.2.1", standard="FIPS 180-4",
             note="Adequate. SHA-384 preferred where a larger margin is wanted."))

_register(_a(key="sha384", name="SHA-384", family="SHA-2", primitive=PRIM_HASH,
             quantum_class=SAFE, classical_bits=384, nist_level=4,
             oid="2.16.840.1.101.3.4.2.2", standard="FIPS 180-4"))

_register(_a(key="sha512", name="SHA-512", family="SHA-2", primitive=PRIM_HASH,
             quantum_class=SAFE, classical_bits=512, nist_level=5,
             oid="2.16.840.1.101.3.4.2.3", standard="FIPS 180-4"))

_register(_a(key="sha3-256", name="SHA3-256", family="SHA-3", primitive=PRIM_HASH,
             quantum_class=SAFE, classical_bits=256, nist_level=2,
             standard="FIPS 202"))

_register(_a(key="hmac", name="HMAC", family="HMAC", primitive=PRIM_MAC,
             quantum_class=SAFE, standard="FIPS 198-1",
             note="Security follows the underlying hash and key length."))

# ---- Post-quantum: the migration targets --------------------------------

_register(_a(key="ml-kem-512", name="ML-KEM-512", family="ML-KEM", primitive=PRIM_KEM,
             quantum_class=SAFE, nist_level=1, standard="FIPS 203",
             public_key_bytes=800, ciphertext_bytes=768,
             note="Lattice KEM from CRYSTALS-Kyber. Category 1 parameter set."))

_register(_a(key="ml-kem-768", name="ML-KEM-768", family="ML-KEM", primitive=PRIM_KEM,
             quantum_class=SAFE, nist_level=3, standard="FIPS 203",
             public_key_bytes=1184, ciphertext_bytes=1088,
             note="The default recommendation for general key establishment."))

_register(_a(key="ml-kem-1024", name="ML-KEM-1024", family="ML-KEM", primitive=PRIM_KEM,
             quantum_class=SAFE, nist_level=5, standard="FIPS 203",
             public_key_bytes=1568, ciphertext_bytes=1568,
             note="Category 5. For long-lived or highly classified material."))

_register(_a(key="ml-dsa-44", name="ML-DSA-44", family="ML-DSA", primitive=PRIM_SIGNATURE,
             quantum_class=SAFE, nist_level=2, standard="FIPS 204",
             public_key_bytes=1312, signature_bytes=2420))

_register(_a(key="ml-dsa-65", name="ML-DSA-65", family="ML-DSA", primitive=PRIM_SIGNATURE,
             quantum_class=SAFE, nist_level=3, standard="FIPS 204",
             public_key_bytes=1952, signature_bytes=3309,
             note="The default recommendation for general-purpose signatures."))

_register(_a(key="ml-dsa-87", name="ML-DSA-87", family="ML-DSA", primitive=PRIM_SIGNATURE,
             quantum_class=SAFE, nist_level=5, standard="FIPS 204",
             public_key_bytes=2592, signature_bytes=4627))

_register(_a(key="slh-dsa-128s", name="SLH-DSA-SHA2-128s", family="SLH-DSA",
             primitive=PRIM_SIGNATURE, quantum_class=SAFE, nist_level=1,
             standard="FIPS 205", public_key_bytes=32, signature_bytes=7856,
             note="Hash-based. Security rests only on the hash function, making it the "
                  "conservative choice for firmware and root-of-trust signing."))

_register(_a(key="slh-dsa-128f", name="SLH-DSA-SHA2-128f", family="SLH-DSA",
             primitive=PRIM_SIGNATURE, quantum_class=SAFE, nist_level=1,
             standard="FIPS 205", public_key_bytes=32, signature_bytes=17088,
             note="Fast-signing variant; much larger signatures."))

_register(_a(key="fn-dsa-512", name="FN-DSA-512 (Falcon)", family="FN-DSA",
             primitive=PRIM_SIGNATURE, quantum_class=SAFE, nist_level=1,
             standard="FIPS 206 (draft)", public_key_bytes=897, signature_bytes=666,
             note="Compact signatures, but constant-time implementation is difficult and "
                  "the standard is still draft."))

_register(_a(key="hqc-128", name="HQC-128", family="HQC", primitive=PRIM_KEM,
             quantum_class=SAFE, nist_level=1, standard="NIST selection, Mar 2025",
             public_key_bytes=2249, ciphertext_bytes=4497,
             note="Code-based KEM. Selected as a structural backup to ML-KEM so a future "
                  "lattice break does not compromise the whole portfolio."))

_register(_a(key="x25519-ml-kem-768", name="X25519MLKEM768", family="Hybrid",
             primitive=PRIM_KEM, quantum_class=HYBRID, nist_level=3,
             standard="IETF TLS hybrid design", public_key_bytes=1216, ciphertext_bytes=1120,
             note="Classical X25519 concatenated with ML-KEM-768. Secure if either "
                  "component holds. Shipping in mainstream browsers and OpenSSL 3.5+."))

_register(_a(key="lms", name="LMS", family="LMS", primitive=PRIM_SIGNATURE,
             quantum_class=SAFE, nist_level=5, standard="RFC 8554 / SP 800-208",
             note="Stateful hash-based signature. Approved for firmware signing only where "
                  "signature state can be guaranteed never to be reused."))

# ---- Protocols -----------------------------------------------------------

_register(_a(key="tls1.0", name="TLS 1.0", family="TLS", primitive=PRIM_AE,
             quantum_class=WEAKENED, nist_level=0, disallowed_after=2020,
             note="Deprecated by RFC 8996. Remove."))

_register(_a(key="tls1.1", name="TLS 1.1", family="TLS", primitive=PRIM_AE,
             quantum_class=WEAKENED, nist_level=0, disallowed_after=2020,
             note="Deprecated by RFC 8996. Remove."))

_register(_a(key="tls1.2", name="TLS 1.2", family="TLS", primitive=PRIM_AE,
             quantum_class=BROKEN, nist_level=0, risk_adjust=0.60,
             note="Key exchange is classical (ECDHE/DHE) and therefore Shor-broken. "
                  "No standardised hybrid PQC key exchange for TLS 1.2."))

_register(_a(key="tls1.3", name="TLS 1.3", family="TLS", primitive=PRIM_AE,
             quantum_class=BROKEN, nist_level=0, risk_adjust=0.45,
             note="Sound protocol design, but classical key exchange by default. "
                  "Supports hybrid PQC groups -- check the negotiated group, not the version."))

_register(_a(key="ssh", name="SSH", family="SSH", primitive=PRIM_AE,
             quantum_class=BROKEN, nist_level=0, risk_adjust=0.75,
             note="Classical key exchange unless a PQC KEX method is explicitly configured."))

_register(_a(key="ikev2", name="IKEv2", family="IPsec", primitive=PRIM_AE,
             quantum_class=BROKEN, nist_level=0,
             note="Classical DH groups unless RFC 8784 pre-shared keys or a PQC KEM are used."))

# ---- Weak randomness -----------------------------------------------------

_register(_a(key="weak-rng", name="Non-cryptographic RNG", family="RNG",
             primitive=PRIM_DRBG, quantum_class=WEAKENED, nist_level=0,
             note="A predictable generator defeats every algorithm above it, quantum or not."))

_register(_a(key="unknown", name="Unresolved cryptographic use", family="Unknown",
             primitive=PRIM_AE, quantum_class=UNKNOWN,
             note="Detected as cryptographic but not resolved to a specific algorithm."))


# --------------------------------------------------------------------------
# Lookup helpers
# --------------------------------------------------------------------------

def get(key: str) -> Algorithm:
    """Resolve an algorithm key, falling back to the family form then unknown.

    ``rsa-2048`` -> exact match. ``rsa-1234`` -> falls back to ``rsa``.
    """
    if key in ALGORITHMS:
        return ALGORITHMS[key]
    family = key.split("-")[0]
    if family in ALGORITHMS:
        return ALGORITHMS[family]
    return ALGORITHMS["unknown"]


def classify(key: str) -> str:
    return get(key).quantum_class


def is_quantum_vulnerable(key: str) -> bool:
    return get(key).quantum_class in (BROKEN, WEAKENED)


def by_class(quantum_class: str) -> list[Algorithm]:
    return [a for a in ALGORITHMS.values() if a.quantum_class == quantum_class]


def summary() -> dict[str, int]:
    counts: dict[str, int] = {c: 0 for c in CLASS_ORDER}
    for a in ALGORITHMS.values():
        counts[a.quantum_class] = counts.get(a.quantum_class, 0) + 1
    return counts

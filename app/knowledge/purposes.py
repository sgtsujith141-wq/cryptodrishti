"""Cryptographic purpose: what an algorithm is being used *for* at a site.

This module exists because of one specific, costly mistake. RSA is not one
thing. RSA-OAEP transports a key; RSA-PSS signs a message. They are the same
mathematics and completely different migration problems: the first is replaced
by a KEM (ML-KEM, or a hybrid), the second by a signature scheme (ML-DSA).
Recommending a KEM for a signing call site is not a rounding error -- it is
advice that cannot be implemented, and a reviewer who notices it stops
trusting every other recommendation in the report.

The earlier model assigned RSA the CycloneDX ``pke`` primitive and routed
every RSA finding down the key-establishment branch. This replaces that with
purpose as a property of the *finding*, resolved from the call site, not of
the algorithm name.

The rule that matters most is the negative one: **an algorithm name never
implies a purpose.** Seeing ``RSA`` tells you nothing about what it is doing.
Where a detector cannot establish purpose from the evidence in front of it,
the purpose stays ``unknown`` and the recommendation says so rather than
picking the more likely of two answers. An unresolved finding a human reviews
is worth more than a resolved one that is wrong.
"""

from __future__ import annotations

from typing import Optional

# --------------------------------------------------------------------------
# The purposes
# --------------------------------------------------------------------------

KEY_ESTABLISHMENT = "key-establishment"
ENCRYPTION = "encryption"
SIGNATURE = "signature"
HASHING = "hashing"
AUTHENTICATION = "authentication"        # MACs: integrity with a shared key
KEY_DERIVATION = "key-derivation"
RANDOMNESS = "randomness"
TRANSPORT = "transport"                  # a protocol, not a bare primitive
UNKNOWN = "unknown"

ALL = (KEY_ESTABLISHMENT, ENCRYPTION, SIGNATURE, HASHING, AUTHENTICATION,
       KEY_DERIVATION, RANDOMNESS, TRANSPORT, UNKNOWN)

LABEL = {
    KEY_ESTABLISHMENT: "Key establishment",
    ENCRYPTION: "Encryption",
    SIGNATURE: "Digital signature",
    HASHING: "Hashing",
    AUTHENTICATION: "Message authentication",
    KEY_DERIVATION: "Key derivation",
    RANDOMNESS: "Random generation",
    TRANSPORT: "Transport security",
    UNKNOWN: "Purpose not established",
}

DESCRIPTION = {
    KEY_ESTABLISHMENT: (
        "Agreeing or transporting a symmetric key. Replaced by a KEM -- ML-KEM, "
        "or a hybrid with the existing classical group. This is the purpose "
        "under the most time pressure, because traffic recorded today is "
        "decrypted retroactively once a CRQC exists."
    ),
    ENCRYPTION: (
        "Encrypting data directly. For a public-key scheme this is usually key "
        "transport in disguise and is treated as such; for a symmetric cipher "
        "it is a parameter change, not a change of family."
    ),
    SIGNATURE: (
        "Signing or verifying. Replaced by a signature scheme -- ML-DSA, or "
        "SLH-DSA where the signature must outlive the algorithm's peer review. "
        "Signatures are not retroactively forgeable, so the deadline is the "
        "lifetime of the verifying relying party, not the recording adversary."
    ),
    HASHING: (
        "Producing a digest. Grover halves the effective preimage strength, so "
        "the fix is a longer output rather than a different family."
    ),
    AUTHENTICATION: (
        "Message authentication with a shared key. Quantum exposure follows the "
        "underlying primitive and the key length."
    ),
    KEY_DERIVATION: "Deriving keys from existing key material or a password.",
    RANDOMNESS: "Generating unpredictable values.",
    TRANSPORT: (
        "A protocol rather than a primitive. Its exposure is determined by the "
        "key exchange it negotiates, not by its version number."
    ),
    UNKNOWN: (
        "The evidence did not establish what this algorithm is being used for. "
        "For an algorithm that can both sign and transport keys -- RSA above "
        "all -- the replacement differs entirely by purpose, so no "
        "recommendation is made until the purpose is resolved."
    ),
}

# Purposes for which a public-key algorithm's replacement differs. When a
# finding carries one of these as UNKNOWN, a recommendation would be a guess.
AMBIGUOUS_WHEN_UNKNOWN = frozenset({KEY_ESTABLISHMENT, ENCRYPTION, SIGNATURE})


def normalise(value: Optional[str]) -> str:
    """Coerce anything to a known purpose, defaulting to unknown."""
    if not value:
        return UNKNOWN
    v = str(value).strip().lower()
    return v if v in ALL else UNKNOWN


# --------------------------------------------------------------------------
# CycloneDX mapping
# --------------------------------------------------------------------------
#
# CycloneDX 1.6 carries this as ``cryptoFunctions``, a list of the operations
# an asset performs. Mapping onto it means the purpose survives export rather
# than living only in our own model.

CRYPTO_FUNCTIONS = {
    KEY_ESTABLISHMENT: ["encapsulate", "decapsulate"],
    ENCRYPTION: ["encrypt", "decrypt"],
    SIGNATURE: ["sign", "verify"],
    HASHING: ["digest"],
    AUTHENTICATION: ["tag"],
    KEY_DERIVATION: ["keyderive"],
    RANDOMNESS: ["generate"],
    TRANSPORT: ["other"],
    UNKNOWN: ["unknown"],
}

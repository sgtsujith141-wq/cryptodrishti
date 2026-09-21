"""Cache key derivation.

Demonstration 4: real source evidence at a real line, and a hash identity that
Milestone 2 corrected — SHA3-512 must stay SHA3-512, and BLAKE2b must not
become SHA-512.
"""

import hashlib


def cache_key(blob: bytes) -> str:
    return hashlib.md5(blob).hexdigest()          # legacy, still in the estate


def content_digest(blob: bytes) -> bytes:
    return hashlib.sha3_512(blob).digest()


def fast_digest(blob: bytes) -> bytes:
    return hashlib.blake2b(blob).digest()

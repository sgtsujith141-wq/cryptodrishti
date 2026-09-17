"""The algorithm registry is the tool's ground truth.

If a classification here is wrong, every score and every recommendation
downstream is wrong, so these assertions pin the claims the README makes.
"""

from __future__ import annotations

import pytest

from app.knowledge import algorithms as K


@pytest.mark.parametrize("key", [
    "rsa-2048", "rsa-4096", "dsa", "dh", "ecdh", "ecdsa-p-256", "ecdsa-p-521",
    "ed25519", "x25519", "elgamal", "ecdsa-secp256k1",
])
def test_public_key_schemes_are_shor_broken(key):
    """Shor breaks factoring and discrete log outright -- key size is irrelevant."""
    assert K.classify(key) == K.BROKEN


@pytest.mark.parametrize("key", ["aes-128", "aes-192", "3des", "des", "rc4",
                                 "md5", "sha1", "sha224"])
def test_small_symmetric_and_legacy_hashes_are_grover_weakened(key):
    assert K.classify(key) == K.WEAKENED


@pytest.mark.parametrize("key", ["ml-kem-512", "ml-kem-768", "ml-kem-1024",
                                 "ml-dsa-44", "ml-dsa-87", "slh-dsa-128s",
                                 "aes-256", "sha384", "sha512", "sha3-256"])
def test_pqc_and_large_symmetric_are_quantum_safe(key):
    assert K.classify(key) == K.SAFE


def test_rsa_key_size_does_not_change_the_verdict():
    """A bigger modulus buys classical margin, not quantum margin."""
    classes = {K.classify(f"rsa-{bits}") for bits in (1024, 2048, 3072, 4096)}
    assert classes == {K.BROKEN}


def test_aes_128_is_weakened_but_aes_256_is_safe():
    """Grover halves symmetric security, so doubling the key restores it.

    This is the single distinction that justifies recommending a parameter
    change for symmetric crypto instead of an algorithm change.
    """
    assert K.classify("aes-128") == K.WEAKENED
    assert K.classify("aes-256") == K.SAFE


def test_unknown_key_resolves_to_the_family_then_to_unknown():
    """`get` degrades gracefully rather than raising mid-scan."""
    assert K.get("rsa-1234").key == "rsa"        # unlisted size -> family
    assert K.get("nonexistent-cipher").key == "unknown"


def test_unknown_is_reported_not_guessed():
    """An unresolved artefact must never be silently treated as safe."""
    assert K.classify("nonexistent-cipher") == K.UNKNOWN
    assert K.classify("nonexistent-cipher") != K.SAFE


def test_hybrid_construction_is_its_own_class():
    assert K.classify("x25519-ml-kem-768") == K.HYBRID


def test_every_registry_entry_has_a_valid_class_and_primitive():
    for key, alg in K.ALGORITHMS.items():
        assert alg.quantum_class in K.CLASS_ORDER, key
        assert alg.key == key, "registry key must match the algorithm's own key"
        assert alg.name, key


def test_class_weights_are_strictly_ordered_by_severity():
    """Ordering is what makes the remediation queue defensible."""
    order = [K.CLASS_WEIGHT[c] for c in K.CLASS_ORDER]
    assert order == sorted(order, reverse=True)


def test_is_quantum_vulnerable_covers_broken_and_weakened_only():
    assert K.is_quantum_vulnerable("rsa-2048")
    assert K.is_quantum_vulnerable("aes-128")
    assert not K.is_quantum_vulnerable("ml-kem-768")
    assert not K.is_quantum_vulnerable("x25519-ml-kem-768")


def test_summary_accounts_for_every_registered_algorithm():
    assert sum(K.summary().values()) == len(K.ALGORITHMS)

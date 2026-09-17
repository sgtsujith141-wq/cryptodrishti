"""Migration recommendations.

A recommendation is only useful if it names a target the codebase can actually
execute, and if it changes with the deployment profile -- a firmware signing
key and a web session key do not get the same answer.
"""

from __future__ import annotations

import pytest

from app.engine.recommend import (
    PROFILE_CONSTRAINED, PROFILE_GENERAL, PROFILE_HIGH_ASSURANCE,
    PROFILE_LONG_LIVED, recommend, recommend_all,
)
from app.knowledge import algorithms as K

from conftest import make_finding


# --------------------------------------------------------------------------
# Key establishment
# --------------------------------------------------------------------------

def test_classical_key_exchange_gets_a_hybrid_target_by_default():
    """Hybrid is the deployable answer today: safe if either half holds."""
    rec = recommend(make_finding("ecdh"), PROFILE_GENERAL)
    assert rec.target == "x25519-ml-kem-768"
    assert rec.hybrid is True


def test_high_assurance_prefers_pure_pqc_over_hybrid():
    rec = recommend(make_finding("ecdh"), PROFILE_HIGH_ASSURANCE)
    assert rec.target == "ml-kem-1024"
    assert rec.hybrid is False


def test_constrained_profile_picks_the_smallest_standardised_parameter_set():
    rec = recommend(make_finding("ecdh"), PROFILE_CONSTRAINED)
    assert rec.target == "ml-kem-512"


def test_rsa_key_transport_is_routed_to_a_kem():
    rec = recommend(make_finding("rsa-2048"), PROFILE_GENERAL)
    assert K.get(rec.target).quantum_class in (K.SAFE, K.HYBRID)


# --------------------------------------------------------------------------
# Signatures
# --------------------------------------------------------------------------

def test_signatures_default_to_ml_dsa():
    rec = recommend(make_finding("ecdsa-p-256"), PROFILE_GENERAL)
    assert rec.target == "ml-dsa-65"


def test_firmware_signing_gets_hash_based_signatures():
    """SLH-DSA rests only on the hash function -- the conservative choice for
    a key that must outlive the algorithm's peer review."""
    rec = recommend(make_finding("ecdsa-p-256"), PROFILE_LONG_LIVED)
    assert rec.target == "slh-dsa-128s"


def test_constrained_signing_gets_the_smallest_signature_with_a_caveat():
    rec = recommend(make_finding("ecdsa-p-256"), PROFILE_CONSTRAINED)
    assert rec.target == "fn-dsa-512"
    assert "draft" in rec.rationale.lower()


def test_signature_size_growth_is_quantified_not_hidden():
    """Post-quantum signatures are much larger; a migration plan that omits
    this detail breaks fixed-width protocol fields in production."""
    rec = recommend(make_finding("ecdsa-p-256"), PROFILE_GENERAL)
    assert rec.size_delta_bytes is not None and rec.size_delta_bytes > 0
    assert rec.size_note


def test_constrained_profile_warns_when_the_size_delta_is_prohibitive():
    rec = recommend(make_finding("ecdsa-p-256"), PROFILE_CONSTRAINED)
    assert rec.size_note


# --------------------------------------------------------------------------
# Symmetric, hashes and RNG
# --------------------------------------------------------------------------

def test_weak_symmetric_ciphers_move_to_aes_256_without_changing_family():
    rec = recommend(make_finding("aes-128"), PROFILE_GENERAL)
    assert rec.target == "aes-256"
    assert rec.size_delta_bytes == 0


def test_classically_broken_ciphers_are_called_defects_not_migrations():
    for key in ("des", "3des", "rc4"):
        rec = recommend(make_finding(key), PROFILE_GENERAL)
        assert rec.target == "aes-256"
        assert "defect" in rec.action.lower() or "classical" in rec.rationale.lower()


def test_broken_hashes_are_flagged_on_collision_grounds():
    for key in ("md5", "sha1"):
        rec = recommend(make_finding(key), PROFILE_GENERAL)
        assert "collision" in rec.rationale.lower()


def test_high_assurance_hashing_moves_to_sha384():
    assert recommend(make_finding("sha1"), PROFILE_HIGH_ASSURANCE).target == "sha384"
    assert recommend(make_finding("sha1"), PROFILE_GENERAL).target == "sha256"


def test_weak_rng_is_reported_as_a_present_tense_break():
    rec = recommend(make_finding("weak-rng"), PROFILE_GENERAL)
    assert "not a quantum issue" in rec.rationale.lower()
    assert "urandom" in rec.action or "CSPRNG" in rec.action


# --------------------------------------------------------------------------
# Honesty about what cannot be recommended
# --------------------------------------------------------------------------

def test_already_safe_algorithms_are_marked_compliant_not_migrated():
    rec = recommend(make_finding("ml-kem-768"), PROFILE_GENERAL)
    assert rec.target == "ml-kem-768"
    assert "no migration" in rec.action.lower()
    assert rec.effort == "low"


def test_hybrid_findings_need_no_migration():
    rec = recommend(make_finding("x25519-ml-kem-768"), PROFILE_GENERAL)
    assert "no migration" in rec.action.lower()


def test_unresolved_algorithms_get_manual_review_not_a_guess():
    """Recommending a replacement for something we could not identify would
    be a guess presented as advice."""
    rec = recommend(make_finding("nonexistent-cipher"), PROFILE_GENERAL)
    assert rec.target == ""
    assert "manual review" in rec.target_name.lower()
    assert rec.confidence < 0.5


def test_protocol_findings_point_at_the_group_not_the_version():
    """TLS 1.3 with a classical group is still Shor-broken."""
    rec = recommend(make_finding("tls1.3"), PROFILE_GENERAL)
    assert rec.hybrid is True
    assert "group" in rec.rationale.lower()


# --------------------------------------------------------------------------
# Every recommendation must be actionable
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key", sorted(K.ALGORITHMS))
def test_every_algorithm_yields_an_actionable_recommendation(key):
    rec = recommend(make_finding(key), PROFILE_GENERAL)
    assert rec is not None, key
    assert rec.action, key
    assert rec.rationale, key
    assert rec.effort in ("low", "medium", "high"), key


@pytest.mark.parametrize("key", ["rsa-2048", "ecdh", "ecdsa-p-256", "aes-128", "md5"])
def test_vulnerable_algorithms_are_never_sent_to_another_vulnerable_target(key):
    rec = recommend(make_finding(key), PROFILE_GENERAL)
    if rec.target:
        assert K.get(rec.target).quantum_class in (K.SAFE, K.HYBRID), key


def test_recommend_all_attaches_a_recommendation_to_every_finding():
    findings = recommend_all([make_finding("rsa-2048"), make_finding("aes-128")])
    assert all(f.recommendation is not None for f in findings)
    assert all("action" in f.recommendation for f in findings)


def test_rsa_is_modelled_as_key_transport_not_signing():
    """A documented limitation, pinned so it cannot change silently.

    The registry assigns RSA the `pke` primitive, so an RSA *signing* call site
    is routed to the key-establishment branch and recommended a KEM rather than
    ML-DSA. Correct for RSA key transport, wrong for RSA signatures -- see the
    README's Known limitations.
    """
    assert K.get("rsa-2048").primitive == K.PRIM_PKE
    rec = recommend(make_finding("rsa-2048"), PROFILE_GENERAL)
    assert rec.target == "x25519-ml-kem-768"

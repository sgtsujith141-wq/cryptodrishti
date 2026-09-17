"""Mosca's inequality and the scoring model.

The README claims the score is a transparent product of named factors and that
Q-Day is modelled as a distribution rather than asserted. These tests hold the
implementation to both claims.
"""

from __future__ import annotations

import pytest

from app.engine.risk import (
    QDayModel, mosca, portfolio_summary, score_all, score_finding, severity,
)
from app.knowledge import algorithms as K

from conftest import make_finding

QDAY = QDayModel(earliest=2030, likely=2034, latest=2044)
NOW = 2026


# --------------------------------------------------------------------------
# Mosca's inequality: X + Y > Z
# --------------------------------------------------------------------------

def test_exposure_is_x_plus_y_minus_z():
    """Z at the median is 2034 - 2026 = 8 years, so 10 + 3 - 8 = 5."""
    m = mosca(shelf_life=10, migration_years=3, qday=QDAY, now_year=NOW)
    assert m.years_to_qday == 8.0
    assert m.exposure_years == pytest.approx(5.0)


def test_exposure_floors_at_zero_rather_than_going_negative():
    """Negative exposure is not 'safety margin' the score should reward."""
    m = mosca(shelf_life=1, migration_years=1, qday=QDAY, now_year=NOW)
    assert m.exposure_years == 0.0


def test_longer_confidentiality_lifetime_never_reduces_exposure():
    previous = -1.0
    for shelf in (1, 5, 10, 25, 50):
        m = mosca(shelf, 2, QDAY, now_year=NOW)
        assert m.exposure_years >= previous
        previous = m.exposure_years


def test_probability_is_reported_not_a_hardcoded_qday():
    """A 25-year shelf life is certainly exposed; a 1-year one is not certain."""
    certain = mosca(shelf_life=25, migration_years=2, qday=QDAY, now_year=NOW)
    marginal = mosca(shelf_life=1, migration_years=1, qday=QDAY, now_year=NOW)
    assert certain.probability_exposed == 1.0
    assert 0.0 <= marginal.probability_exposed < 1.0


def test_probability_is_monotonic_in_shelf_life():
    probs = [mosca(s, 2, QDAY, now_year=NOW).probability_exposed
             for s in (1, 4, 8, 16, 32)]
    assert probs == sorted(probs)


def test_mosca_is_deterministic_for_a_fixed_seed():
    """A score that changes between runs is not auditable."""
    a = mosca(10, 3, QDAY, now_year=NOW)
    b = mosca(10, 3, QDAY, now_year=NOW)
    assert a.to_dict() == b.to_dict()


def test_every_mosca_result_carries_a_verdict():
    for shelf in (1, 5, 10, 25):
        assert mosca(shelf, 2, QDAY, now_year=NOW).verdict


def test_an_earlier_qday_increases_exposure():
    pessimistic = QDayModel(earliest=2027, likely=2029, latest=2035)
    assert (mosca(10, 3, pessimistic, now_year=NOW).exposure_years
            > mosca(10, 3, QDAY, now_year=NOW).exposure_years)


# --------------------------------------------------------------------------
# Per-finding scoring
# --------------------------------------------------------------------------

def test_shor_broken_outranks_grover_weakened():
    """The core ordering claim: a total break beats a halved key."""
    rsa = score_finding(make_finding("rsa-2048"), QDAY, NOW)
    aes = score_finding(make_finding("aes-128"), QDAY, NOW)
    assert rsa.risk_score > aes.risk_score


def test_quantum_safe_algorithms_score_lowest():
    safe = score_finding(make_finding("ml-kem-768"), QDAY, NOW)
    weak = score_finding(make_finding("aes-128"), QDAY, NOW)
    broken = score_finding(make_finding("rsa-2048"), QDAY, NOW)
    assert safe.risk_score < weak.risk_score < broken.risk_score


def test_unresolved_findings_outrank_quantum_safe_ones():
    """'We could not identify this' must not be filed as good news."""
    unknown = score_finding(make_finding("nonexistent-cipher"), QDAY, NOW)
    safe = score_finding(make_finding("ml-kem-768"), QDAY, NOW)
    assert unknown.risk_score > safe.risk_score


def test_score_is_bounded_to_the_published_scale():
    for key in K.ALGORITHMS:
        f = score_finding(make_finding(key, occurrences=50, confidence=1.0), QDAY, NOW)
        assert 0.0 <= f.risk_score <= 100.0, key


def test_scoring_records_every_factor_it_used():
    """The UI shows the arithmetic; the arithmetic has to be there."""
    f = score_finding(make_finding("rsa-2048"), QDAY, NOW)
    factors = f.extra["factors"]
    for key in ("base_by_class", "algorithm_risk_adjust", "business_criticality",
                "exposure_multiplier", "mosca_term", "occurrence_term",
                "confidence_term", "shelf_life_years", "migration_years"):
        assert key in factors, key
    assert "mosca" in f.extra


def test_more_call_sites_raise_the_score_sub_linearly():
    once = score_finding(make_finding("rsa-2048", occurrences=1), QDAY, NOW)
    many = score_finding(make_finding("rsa-2048", occurrences=64), QDAY, NOW)
    assert many.risk_score > once.risk_score
    # Blast radius is a modifier, not the dominant term.
    assert many.risk_score < once.risk_score * 1.3


def test_low_confidence_findings_cannot_outrank_certain_ones():
    certain = score_finding(make_finding("rsa-2048", confidence=1.0), QDAY, NOW)
    unsure = score_finding(make_finding("rsa-2048", confidence=0.3), QDAY, NOW)
    assert unsure.risk_score < certain.risk_score


def test_binary_findings_carry_a_longer_migration_cost_than_config():
    """No source means a vendor dependency, which takes longer to fix."""
    binary = score_finding(make_finding("rsa-2048", scanner="binary"), QDAY, NOW)
    config = score_finding(make_finding("rsa-2048", scanner="config"), QDAY, NOW)
    assert binary.extra["factors"]["migration_years"] > config.extra["factors"]["migration_years"]


def test_hardcoded_private_key_is_critical_on_classical_grounds_alone():
    """Not a 2034 problem -- a today problem, so it gets a floor."""
    f = score_finding(
        make_finding("unknown", rule_id="any.private.key.inline",
                     location="src/config/settings.py"),
        QDAY, NOW,
    )
    assert f.risk_score >= 85.0
    assert severity(f.risk_score) == "critical"


def test_scoring_the_same_finding_twice_gives_the_same_score():
    a = score_finding(make_finding("ecdsa-p-256"), QDAY, NOW).risk_score
    b = score_finding(make_finding("ecdsa-p-256"), QDAY, NOW).risk_score
    assert a == b


# --------------------------------------------------------------------------
# Path weighting: production code outranks test fixtures
# --------------------------------------------------------------------------

def test_production_findings_outrank_identical_test_findings():
    prod = score_all([make_finding("rsa-2048", location="src/auth/keys.py")],
                     QDAY, NOW)[0]
    test = score_all([make_finding("rsa-2048", location="tests/test_auth.py")],
                     QDAY, NOW)[0]
    assert prod.risk_score > test.risk_score


def test_a_private_key_in_a_test_fixture_is_inventoried_but_not_first():
    """The floor is scaled by criticality, so fixtures do not head the queue."""
    prod = score_all([make_finding("unknown", rule_id="any.private.key.inline",
                                   location="src/settings.py")], QDAY, NOW)[0]
    fixture = score_all([make_finding("unknown", rule_id="any.private.key.inline",
                                      location="tests/fixtures/key.py")], QDAY, NOW)[0]
    assert fixture.risk_score > 0, "still inventoried"
    assert fixture.risk_score < prod.risk_score


# --------------------------------------------------------------------------
# Severity bands and roll-up
# --------------------------------------------------------------------------

@pytest.mark.parametrize("score,band", [
    (0, "low"), (24.9, "low"), (25, "medium"), (44.9, "medium"),
    (45, "high"), (69.9, "high"), (70, "critical"), (100, "critical"),
])
def test_severity_bands_are_contiguous(score, band):
    assert severity(score) == band


def test_portfolio_summary_counts_agree_with_the_findings():
    findings = score_all([
        make_finding("rsa-2048"), make_finding("ecdsa-p-256"),
        make_finding("aes-128"), make_finding("ml-kem-768"),
    ], QDAY, NOW)
    s = portfolio_summary(findings)
    assert s["total"] == 4
    assert s["quantum_vulnerable"] == 3          # two broken, one weakened
    assert s["vulnerable_pct"] == 75.0
    assert sum(s["by_severity"].values()) == 4
    assert sum(s["by_class"].values()) == 4


def test_portfolio_summary_handles_an_empty_scan():
    s = portfolio_summary([])
    assert s["total"] == 0 and s["vulnerable_pct"] == 0.0 and s["mean_risk"] == 0.0

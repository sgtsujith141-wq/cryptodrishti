"""Detector hits become distinct cryptographic assets.

Six sensors run over the same tree, so the same artefact is seen repeatedly.
Reporting raw hits would inflate the inventory; these tests pin the merge.
"""

from __future__ import annotations

import pytest

from app.engine.normalize import CRITICALITY, criticality_for, group_key, normalize
from app.models import Evidence, Finding

from conftest import make_finding


@pytest.mark.parametrize("path", [
    "tests/test_auth.py", "src/spec/crypto_spec.rb", "app/__tests__/keys.test.ts",
    "pkg/crypto_test.go", "testdata/sample.pem", "examples/demo.py",
    "src/fixtures/key.pem",
])
def test_test_and_example_paths_are_recognised(path):
    from app.engine.normalize import path_class
    assert path_class(path) == "test"


@pytest.mark.parametrize("path", [
    "vendor/openssl/crypto.c", "third_party/boringssl/aes.c",
    "node_modules/jsrsasign/rsa.js", "deps/libsodium/core.c",
])
def test_vendored_paths_are_recognised(path):
    from app.engine.normalize import path_class
    assert path_class(path) == "vendored"


@pytest.mark.parametrize("path", [
    "src/auth/keys.py", "lib/crypto.go", "internal/tls/handshake.c",
    "app/services/signing.java",
])
def test_first_party_source_is_production(path):
    from app.engine.normalize import path_class
    assert path_class(path) == "production"


def test_windows_separators_are_handled():
    from app.engine.normalize import path_class
    assert path_class(r"tests\test_auth.py") == "test"


def test_criticality_uses_the_most_production_like_location():
    """An algorithm used in both production and tests is a production problem."""
    f = Finding(algorithm="rsa-2048", evidence=[
        Evidence(location="tests/test_auth.py", line=1),
        Evidence(location="src/auth/keys.py", line=2),
    ])
    assert criticality_for(f) == CRITICALITY["production"]


def test_criticality_of_a_test_only_finding_is_discounted():
    f = Finding(algorithm="rsa-2048",
                evidence=[Evidence(location="tests/test_auth.py", line=1)])
    assert criticality_for(f) == CRITICALITY["test"]
    assert CRITICALITY["test"] < CRITICALITY["vendored"] < CRITICALITY["production"]


def test_identical_artefacts_from_different_locations_merge():
    merged = normalize([
        make_finding("aes-128", location="src/a.py", line=1),
        make_finding("aes-128", location="src/b.py", line=2),
    ])
    assert len(merged) == 1
    assert merged[0].occurrences == 2
    assert merged[0].extra["files"] == 2


def test_different_key_sizes_stay_separate_assets():
    """RSA-2048 and RSA-4096 are different migration items."""
    out = normalize([
        make_finding("rsa", key_size=2048, location="src/a.py"),
        make_finding("rsa", key_size=4096, location="src/b.py"),
    ])
    assert len(out) == 2


def test_different_modes_stay_separate_assets():
    """AES-CBC and AES-ECB are not the same finding -- one is a defect."""
    out = normalize([
        make_finding("aes", mode="CBC", location="src/a.py"),
        make_finding("aes", mode="ECB", location="src/b.py"),
    ])
    assert len(out) == 2


def test_findings_from_different_sensors_are_not_collapsed():
    """Source and binary evidence corroborate each other; merging loses that."""
    out = normalize([
        make_finding("rsa-2048", scanner="source", location="src/a.py"),
        make_finding("rsa-2048", scanner="binary", location="bin/app"),
    ])
    assert len(out) == 2


def test_duplicate_evidence_at_the_same_site_is_not_double_counted():
    out = normalize([
        make_finding("aes-128", location="src/a.py", line=5),
        make_finding("aes-128", location="src/a.py", line=5),
    ])
    assert len(out) == 1
    assert out[0].occurrences == 1


def test_production_evidence_is_listed_before_test_evidence():
    """Operators read the first line; it should be the one that matters."""
    out = normalize([
        make_finding("aes-128", location="tests/test_a.py", line=1),
        make_finding("aes-128", location="src/a.py", line=2),
    ])
    assert out[0].evidence[0].location == "src/a.py"


def test_path_breakdown_is_recorded_for_the_ui():
    out = normalize([
        make_finding("aes-128", location="src/a.py"),
        make_finding("aes-128", location="tests/test_a.py"),
        make_finding("aes-128", location="vendor/lib.c"),
    ])
    assert out[0].extra["path_breakdown"] == {"production": 1, "vendored": 1, "test": 1}


def test_repetition_does_not_manufacture_confidence():
    """Forty sightings from one rule are not forty independent confirmations.

    An earlier version added 0.03 to any finding with five or more occurrences.
    That turned repetition into precision: the same regex firing forty times is
    forty chances for one rule to be wrong in the same way. Blast radius is a
    real signal and it has its own named term in the risk engine; it does not
    belong in the confidence that the identification is correct.
    """
    single = normalize([make_finding("aes-128", location="src/a.py", confidence=0.7)])
    many = normalize([make_finding("aes-128", location=f"src/f{i}.py", confidence=0.7)
                      for i in range(40)])
    assert many[0].confidence == single[0].confidence == 0.7
    assert many[0].occurrences == 40      # the count is kept, just not laundered


def test_confidence_is_the_strongest_single_piece_of_evidence():
    out = normalize([
        make_finding("aes-128", location="src/a.py", confidence=0.55),
        make_finding("aes-128", location="src/b.py", confidence=0.92),
        make_finding("aes-128", location="src/c.py", confidence=0.61),
    ])
    assert out[0].confidence == 0.92


def test_group_key_is_stable_for_the_same_artefact():
    a = make_finding("aes-128", location="src/a.py")
    b = make_finding("aes-128", location="src/b.py")
    assert group_key(a) == group_key(b)


def test_normalising_nothing_yields_nothing():
    assert normalize([]) == []

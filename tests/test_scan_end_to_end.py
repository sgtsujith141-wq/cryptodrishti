"""End-to-end: real source files in, scored findings and a valid CBOM out.

These tests write a small fixture tree containing genuine cryptographic defects
and assert the pipeline finds them. They are the ones that would catch a
regression a unit test of any single stage would miss.
"""

from __future__ import annotations

import json

import pytest

from app import cbom
from app.engine.risk import severity
from app.knowledge import algorithms as K
from app.orchestrator import scan_target
from app.scanners import source

VULNERABLE_PY = '''
"""A module with deliberate cryptographic defects, used as a scan fixture."""
import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def make_rsa_key():
    # 1024-bit RSA: below the classical floor and Shor-broken.
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def make_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def weak_digest(data):
    return hashlib.md5(data).hexdigest()


def legacy_digest(data):
    return hashlib.sha1(data).hexdigest()


def ecb_cipher(key):
    # ECB leaks plaintext structure -- a classical defect, not a quantum one.
    return Cipher(algorithms.AES(key), modes.ECB())


def guessable_token():
    # Not a CSPRNG.
    return random.randint(0, 2 ** 32)
'''

SAFE_PY = '''
"""A module using modern primitives, used to check for false positives."""
import hashlib
import secrets


def strong_digest(data):
    return hashlib.sha384(data).hexdigest()


def good_token():
    return secrets.token_bytes(32)
'''


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "legacy_crypto.py").write_text(VULNERABLE_PY)
    (tmp_path / "src" / "modern_crypto.py").write_text(SAFE_PY)
    (tmp_path / "tests" / "test_legacy.py").write_text(VULNERABLE_PY)
    return tmp_path


@pytest.fixture
def scanned(tree):
    return scan_target(tree, label="fixture", sensors=["source"])


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def test_the_scan_completes_and_reports_what_it_read(scanned):
    assert scanned.stats["files_scanned"] >= 3
    assert scanned.findings, "a tree full of defects must not scan clean"


def test_ast_analysis_finds_the_rsa_key_generation(scanned):
    rsa = [f for f in scanned.findings if f.algorithm.startswith("rsa")]
    assert rsa, "RSA key generation should be detected"
    assert any(e.line for f in rsa for e in f.evidence), "findings must carry line numbers"


def test_the_undersized_rsa_key_size_is_resolved_from_the_call(scanned):
    """The AST pass reads key_size=1024 out of the keyword argument -- that is
    the difference between 'RSA is present' and 'RSA-1024 is present'."""
    sizes = {f.key_size for f in scanned.findings if f.algorithm.startswith("rsa")}
    assert 1024 in sizes


def test_elliptic_curve_selection_is_detected(scanned):
    assert any("ecdsa" in f.algorithm or "ec" in f.algorithm.lower()
               for f in scanned.findings)


@pytest.mark.parametrize("algorithm", ["md5", "sha1"])
def test_broken_hashes_are_detected(scanned, algorithm):
    assert any(f.algorithm == algorithm for f in scanned.findings)


def test_ecb_mode_is_detected_as_a_classical_defect(scanned):
    ecb = [f for f in scanned.findings
           if f.mode == "ECB" or "ecb" in f.rule_id.lower()
           or "ECB" in (f.detail or "")]
    assert ecb, "ECB mode should be reported"


def test_non_cryptographic_randomness_is_detected(scanned):
    assert any(f.algorithm == "weak-rng" for f in scanned.findings)


def test_modern_primitives_are_not_reported_as_vulnerable(scanned):
    """sha384 and secrets are correct usage; flagging them would train the
    operator to ignore the tool."""
    modern = [f for f in scanned.findings
              if "modern_crypto.py" in f.primary_location]
    assert all(not K.is_quantum_vulnerable(f.algorithm) for f in modern)


# --------------------------------------------------------------------------
# Scoring and ranking
# --------------------------------------------------------------------------

def test_every_finding_is_classified_and_scored(scanned):
    for f in scanned.findings:
        assert f.quantum_class in K.CLASS_ORDER
        assert 0.0 <= f.risk_score <= 100.0
        assert f.extra.get("factors"), "the score must show its arithmetic"


def test_every_finding_carries_a_recommendation(scanned):
    for f in scanned.findings:
        assert f.recommendation is not None
        assert f.recommendation["action"]


def test_the_highest_ranked_finding_is_genuinely_severe(scanned):
    top = max(scanned.findings, key=lambda f: f.risk_score)
    assert severity(top.risk_score) in ("critical", "high")


def test_production_code_outranks_the_identical_test_file(scanned):
    """The same defects exist in src/ and tests/; src must rank higher."""
    prod = [f for f in scanned.findings if f.primary_location.startswith("src/")]
    assert prod, "production findings expected"
    top_prod = max(f.risk_score for f in prod)
    test_only = [f for f in scanned.findings
                 if all(e.location.startswith("tests/") for e in f.evidence)]
    for f in test_only:
        assert f.risk_score <= top_prod


def test_scanning_the_same_tree_twice_gives_the_same_scores(tree):
    a = scan_target(tree, sensors=["source"])
    b = scan_target(tree, sensors=["source"])
    assert ({(f.algorithm, f.risk_score) for f in a.findings}
            == {(f.algorithm, f.risk_score) for f in b.findings})


# --------------------------------------------------------------------------
# CBOM output
# --------------------------------------------------------------------------

def test_the_scan_emits_a_structurally_valid_cbom(scanned):
    doc = cbom.build(scanned)
    valid, problems = cbom.validate(doc)
    assert valid, problems


def test_the_cbom_contains_one_component_per_finding(scanned):
    doc = cbom.build(scanned)
    assert len(doc["components"]) == len(scanned.findings)


def test_the_cbom_is_serialisable(scanned):
    assert json.loads(cbom.to_json(scanned))["bomFormat"] == "CycloneDX"


# --------------------------------------------------------------------------
# Robustness -- a scanner that crashes on bad input is not deployable
# --------------------------------------------------------------------------

def test_an_empty_directory_scans_clean_without_error(tmp_path):
    result = scan_target(tmp_path, sensors=["source"])
    assert result.findings == []


def test_a_file_with_a_syntax_error_does_not_abort_the_scan(tmp_path):
    """Real repositories contain files that do not parse."""
    (tmp_path / "broken.py").write_text("def f(:\n    this is not python\n")
    (tmp_path / "good.py").write_text(VULNERABLE_PY)
    result = scan_target(tmp_path, sensors=["source"])
    assert result.findings, "the parseable file must still be scanned"


def test_a_binary_file_with_a_source_extension_is_survived(tmp_path):
    (tmp_path / "data.py").write_bytes(bytes(range(256)) * 32)
    (tmp_path / "good.py").write_text(VULNERABLE_PY)
    result = scan_target(tmp_path, sensors=["source"])
    assert result.findings


def test_skip_directories_are_not_scanned(tmp_path):
    """node_modules and .git would swamp the inventory with third-party noise."""
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.py").write_text(VULNERABLE_PY)
    files = list(source.iter_source_files(tmp_path))
    assert not any("node_modules" in str(f) for f in files)

"""The benchmark itself, and a floor it must not fall below.

A benchmark nobody runs is a document. This keeps it executable, keeps the
matching honest, and fails when a detector change makes the measured numbers
worse — which is the only way a regression in precision or recall becomes
visible before somebody ships it.

The TLS probe is skipped here: it binds a loopback port, and a test suite that
needs a listener is a test suite that fails in the wrong places.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
sys.path.insert(0, str(BENCH))

runner = pytest.importorskip("run", reason="benchmark runner not importable")


@pytest.fixture(scope="module")
def result():
    return runner.run(detail=True, tls=False)


# ==========================================================================
# The measurement itself
# ==========================================================================

def test_the_benchmark_runs_and_covers_every_supported_scanner(result):
    measured = set(result["per_scanner"])
    assert measured == {"source", "dependency", "config",
                        "binary", "certificate", "container"}, measured


def test_no_false_negatives_against_the_current_corpus(result):
    """Each of these was a detector defect when the corpus first found it."""
    assert result["false_negatives"] == [], result["false_negatives"]


def test_no_false_positives_against_the_current_corpus(result):
    assert result["false_positives"] == [], result["false_positives"]


def test_nothing_fires_in_the_negative_files(result):
    """Comments, prose, crypto-shaped identifiers, a disable list and a
    symbol-free binary. A hit in any of them is precision traded for nothing."""
    assert result["negative_file_hits"] == [], result["negative_file_hits"]


def test_the_measured_floor_is_not_crossed(result):
    """A floor, not a target. Dropping below it means a detector regressed."""
    overall = result["overall"]
    assert overall["precision"] >= 0.95, overall
    assert overall["recall"] >= 0.95, overall
    assert overall["f1"] >= 0.95, overall


def test_purpose_and_assurance_are_measured_separately(result):
    """Getting the purpose of something you never found is not an achievement,
    so both are scored over true positives only."""
    assert result["purpose_accuracy"]["scored"] > 0
    assert result["assurance_accuracy"]["scored"] > 0
    assert result["purpose_accuracy"]["accuracy"] >= 0.95
    assert result["assurance_accuracy"]["accuracy"] >= 0.95


def test_genuinely_ambiguous_cases_are_excluded_rather_than_guessed(result):
    """A bare elliptic-curve object serves ECDSA or ECDH. Scoring it either
    way would be marking our own guess correct."""
    assert result["purpose_ambiguous_excluded"] >= 1


# ==========================================================================
# The honesty properties of the harness
# ==========================================================================

def test_duplicates_cannot_inflate_true_positives():
    """One artefact reported by two rules must count once."""
    expected = [{"file": "a.py", "line": 3, "algorithm": "md5",
                 "purpose": "hashing", "assurance": "used", "scanner": "source"}]
    actual = [
        {"file": "a.py", "line": 3, "algorithm": "md5", "purpose": "hashing",
         "assurance": "used", "scanner": "source", "rule_id": "r1"},
        {"file": "a.py", "line": 3, "algorithm": "md5", "purpose": "hashing",
         "assurance": "used", "scanner": "source", "rule_id": "r2"},
    ]
    scored = runner.score(expected, actual, set())
    assert scored["per_scanner"]["source"]["tp"] == 1
    assert scored["per_scanner"]["source"]["fp"] == 0


def test_an_exact_algorithm_match_is_required():
    """sha3-512 must not satisfy an expectation of sha3-256. This is the
    whole reason the algorithm-identity work in M2 happened."""
    expected = [{"file": "a.py", "line": 1, "algorithm": "sha3-256",
                 "purpose": "hashing", "assurance": "used", "scanner": "source"}]
    actual = [{"file": "a.py", "line": 1, "algorithm": "sha3-512",
               "purpose": "hashing", "assurance": "used", "scanner": "source",
               "rule_id": "r"}]
    scored = runner.score(expected, actual, set())
    assert scored["per_scanner"]["source"]["tp"] == 0
    assert scored["per_scanner"]["source"]["fn"] == 1
    assert scored["per_scanner"]["source"]["fp"] == 1


def test_findings_outside_the_labelled_corpus_are_out_of_scope():
    """A finding in a file the manifest does not label is not a false
    positive — the corpus simply says nothing about it."""
    expected = [{"file": "a.py", "line": 1, "algorithm": "md5",
                 "purpose": "hashing", "assurance": "used", "scanner": "source"}]
    actual = [{"file": "unlabelled.py", "line": 9, "algorithm": "rsa",
               "purpose": "unknown", "assurance": "used", "scanner": "source",
               "rule_id": "r"}]
    scored = runner.score(expected, actual, set())
    assert scored["per_scanner"]["source"]["fp"] == 0


def test_any_finding_in_a_negative_file_is_a_false_positive():
    actual = [{"file": "neg.py", "line": 4, "algorithm": "md5",
               "purpose": "hashing", "assurance": "used", "scanner": "source",
               "rule_id": "r"}]
    scored = runner.score([], actual, {"neg.py"})
    assert scored["per_scanner"]["source"]["fp"] == 1


# ==========================================================================
# The corpus and its labelling
# ==========================================================================

def test_the_manifest_is_versioned_and_carries_a_changelog():
    manifest = runner.load_manifest()
    assert manifest["manifest_version"]
    assert manifest["changelog"], "label changes must be auditable"
    for entry in manifest["changelog"]:
        assert entry["justification"], "a label change needs a reason"
        assert entry["effect_on_score"], "and a stated effect"


def test_the_manifest_states_that_it_measures_only_this_corpus():
    manifest = runner.load_manifest()
    note = manifest["scope_note"].lower()
    assert "not" in note and "real-world" in note


def test_the_corpus_contains_no_real_key_material():
    """Nothing here is, or resembles, a usable private key."""
    import tempfile

    work = Path(tempfile.mkdtemp())
    try:
        import generate
        generate.build(work)
        for path in work.rglob("*"):
            if not path.is_file():
                continue
            blob = path.read_bytes()
            if b"PRIVATE KEY" not in blob:
                continue
            # The only private-key marker in the corpus is the synthetic one,
            # whose body decodes to the word SYNTHETIC.
            assert b"U1lOVEhFVElD" in blob, path
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def test_committed_fixtures_contain_no_private_keys():
    for path in (ROOT / "benchmark" / "corpus").rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes(), path


def test_the_recorded_baseline_is_preserved_for_comparison():
    """The pre-fix numbers are kept so the improvement can be checked."""
    baseline = json.loads(
        (BENCH / "results" / "baseline-382e7d1.json").read_text())
    assert baseline["overall"]["fp"] > 0 or baseline["overall"]["fn"] > 0, (
        "a baseline with nothing wrong in it would not be worth keeping")

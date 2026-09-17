"""CycloneDX 1.6 CBOM emission and structural validation.

`validate()` deliberately checks structure rather than performing full
JSON-Schema validation. These tests cover both directions: that a real scan
emits a conforming document, and that the validator actually rejects
non-conforming ones instead of always returning True.
"""

from __future__ import annotations

import json

import pytest

from app import cbom
from app.engine.risk import QDayModel, score_all
from app.models import ASSET_CERTIFICATE, ScanResult, ScanTarget

from conftest import make_finding

QDAY = QDayModel()


@pytest.fixture
def document():
    findings = score_all([
        make_finding("rsa-2048", location="src/auth.py"),
        make_finding("ecdsa-p-256", location="src/token.py", rule_id="py.ec.curve"),
        make_finding("aes-128", location="src/store.py", rule_id="py.cipher.algorithm"),
        make_finding("ml-kem-768", location="src/kex.py", rule_id="py.kem"),
    ], QDAY, 2026)
    result = ScanResult(target=ScanTarget(kind="repository", value=".", label="fixture"))
    for f in findings:
        result.add(f)
    result.finished_at = result.started_at + 1.0
    return cbom.build(result)


# --------------------------------------------------------------------------
# Emission
# --------------------------------------------------------------------------

def test_emitted_document_declares_cyclonedx_1_6(document):
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["version"] == 1
    assert document["serialNumber"].startswith("urn:uuid:")


def test_a_real_scan_emits_a_conforming_document(document):
    valid, problems = cbom.validate(document)
    assert valid, problems
    assert problems == []


def test_every_finding_becomes_a_cryptographic_asset_component(document):
    components = document["components"]
    assert len(components) == 4
    assert {c["type"] for c in components} == {"cryptographic-asset"}


def test_components_carry_crypto_properties_with_an_asset_type(document):
    valid_types = {"algorithm", "certificate", "protocol", "related-crypto-material"}
    for c in document["components"]:
        assert c["cryptoProperties"]["assetType"] in valid_types


def test_bom_refs_are_unique(document):
    refs = [c["bom-ref"] for c in document["components"]]
    assert len(refs) == len(set(refs))


def test_detection_evidence_is_carried_into_the_bom(document):
    """CycloneDX 1.6 added occurrences/identity so a scanner can show its work."""
    for c in document["components"]:
        assert c["evidence"]["occurrences"], c["bom-ref"]
        assert "identity" in c["evidence"]


def test_metadata_names_the_tool_that_produced_the_bom(document):
    tools = document["metadata"]["tools"]
    components = tools["components"] if isinstance(tools, dict) else tools
    assert any("CryptoDrishti" in (t.get("name") or "") for t in components)


def test_document_round_trips_through_json(document):
    reparsed = json.loads(json.dumps(document))
    valid, problems = cbom.validate(reparsed)
    assert valid, problems


def test_certificate_findings_emit_certificate_asset_type():
    f = make_finding("rsa-2048", scanner="certificate", location="pki/server.pem",
                     asset_type=ASSET_CERTIFICATE)
    component = cbom.component_for(score_all([f], QDAY, 2026)[0])
    assert component["cryptoProperties"]["assetType"] == "certificate"


def test_empty_scan_still_emits_a_valid_document():
    result = ScanResult(target=ScanTarget(kind="repository", value=".", label="empty"))
    result.finished_at = result.started_at
    doc = cbom.build(result)
    valid, problems = cbom.validate(doc)
    assert valid, problems
    assert doc["components"] == []


def test_to_json_produces_parseable_output():
    result = ScanResult(target=ScanTarget(kind="repository", value=".", label="fixture"))
    result.add(score_all([make_finding("rsa-2048")], QDAY, 2026)[0])
    result.finished_at = result.started_at + 1.0
    assert json.loads(cbom.to_json(result))["specVersion"] == "1.6"


# --------------------------------------------------------------------------
# The validator has to be able to say no
# --------------------------------------------------------------------------

def test_validator_rejects_a_missing_bom_format(document):
    del document["bomFormat"]
    valid, problems = cbom.validate(document)
    assert not valid and problems


def test_validator_rejects_the_wrong_spec_version(document):
    document["specVersion"] = "1.4"
    valid, problems = cbom.validate(document)
    assert not valid and problems


def test_validator_rejects_an_asset_type_outside_the_enum(document):
    document["components"][0]["cryptoProperties"]["assetType"] = "not-a-real-type"
    valid, problems = cbom.validate(document)
    assert not valid and problems


def test_validator_rejects_duplicate_bom_refs(document):
    document["components"][1]["bom-ref"] = document["components"][0]["bom-ref"]
    valid, problems = cbom.validate(document)
    assert not valid
    assert any("bom-ref" in p.lower() or "duplicate" in p.lower() for p in problems)


def test_validator_reports_what_is_wrong_not_just_that_it_is_wrong(document):
    del document["bomFormat"]
    document["specVersion"] = "1.4"
    _, problems = cbom.validate(document)
    assert len(problems) >= 2, "each distinct defect should be reported"


def test_validator_rejects_a_crypto_asset_with_no_crypto_properties(document):
    """A `cryptographic-asset` without cryptoProperties is the defect most
    likely to slip through, because the component itself still looks well
    formed."""
    del document["components"][0]["cryptoProperties"]
    valid, problems = cbom.validate(document)
    assert not valid and problems

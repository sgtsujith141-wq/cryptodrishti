"""Official schema conformance, CBOM semantics and report completeness.

The structural validator in ``cbom.validate`` was never conformance and never
claimed to be. This suite is the difference: it validates against the schema
the CycloneDX project publishes, vendored at a pinned commit, and it covers
the semantic mismatches a schema cannot catch — a library emitted as an
algorithm, a reference that resolves to nothing, an execution environment
asserted rather than observed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app import cbom, report, schema_validation as SV
from app.engine import recommend, risk
from app.knowledge import algorithms as K
from app.knowledge import purposes as P
from app.models import (
    ASSET_CERTIFICATE, ASSET_LIBRARY, ASSET_MATERIAL, ASSET_PROTOCOL,
    ScanResult, ScanTarget,
)

from conftest import make_finding

pytestmark = pytest.mark.skipif(
    not SV.available(), reason=SV.unavailable_reason())


def scored(findings, **kw) -> ScanResult:
    risk.score_all(findings, risk.QDayModel())
    recommend.recommend_all(findings)
    result = ScanResult(target=ScanTarget(kind="repository", value="/estate",
                                          label="estate"))
    result.findings = findings
    result.stats = dict(kw)
    return result


@pytest.fixture
def exercised() -> ScanResult:
    """One finding per shape the emitter has a branch for."""
    fs = []

    lib = make_finding("rsa", rule_id="dep.library", location="requirements.txt")
    lib.asset_type = ASSET_LIBRARY
    lib.extra.update({"library": "pycryptodome", "version": "3.19.0",
                      "ecosystem": "pip", "provides": ["rsa", "aes"]})
    fs.append(lib)

    for mode in ("xts", "cfb8", "gcm"):
        f = make_finding("aes-256", rule_id=f"py.{mode}", location=f"{mode}.py")
        f.mode = mode
        fs.append(f)

    for pad in ("pkcs5padding", "OAEPWithSHA-256AndMGF1Padding", "NoPadding"):
        f = make_finding("rsa", rule_id=f"java.{pad[:6]}", location=f"{pad[:6]}.java")
        f.padding = pad
        fs.append(f)

    fs.append(make_finding("ecdsa-p-256", rule_id="py.ec", location="ec.py"))
    fs.append(make_finding("ml-kem-768", rule_id="c.pqc", location="pqc.c"))

    cert = make_finding("rsa-2048", rule_id="cert.x509", location="server.pem")
    cert.asset_type = ASSET_CERTIFICATE
    cert.extra.update({"subject": "CN=example", "issuer": "CN=ca",
                       "not_before": "2024-01-01", "not_after": "2027-01-01",
                       "signature_algorithm": "sha256WithRSAEncryption",
                       "format": "X.509", "trust_verified": False})
    fs.append(cert)

    sigalg = make_finding("rsa", rule_id="cert.sigalg", location="server.pem")
    sigalg.asset_type = ASSET_CERTIFICATE
    sigalg.extra.update({"signature_algorithm": "sha256WithRSAEncryption",
                         "format": "X.509"})
    fs.append(sigalg)

    proto = make_finding("tls1.2", rule_id="net.tlsversion", location="host:443")
    proto.asset_type = ASSET_PROTOCOL
    proto.extra.update({"protocol_type": "tls", "version": "TLSv1.2",
                        "cipher_suites": ["ECDHE-RSA-AES256-GCM-SHA384"]})
    fs.append(proto)

    key = make_finding("unknown", rule_id="cert.privatekey", location="server.key")
    key.asset_type = ASSET_MATERIAL
    key.extra.update({"material_type": "private-key", "format": "PEM"})
    fs.append(key)

    return scored(fs)


# ==========================================================================
# 1 & 2. Official schema validation, positive and negative
# ==========================================================================

@pytest.mark.parametrize("version", cbom.SUPPORTED_SPEC_VERSIONS)
def test_an_exercised_document_passes_the_official_schema(exercised, version):
    doc = cbom.build(exercised, spec_version=version)
    valid, problems = SV.validate(doc, version)
    assert valid, problems


@pytest.mark.parametrize("version", cbom.SUPPORTED_SPEC_VERSIONS)
def test_the_structural_check_also_passes(exercised, version):
    doc = cbom.build(exercised, spec_version=version)
    valid, problems = cbom.validate(doc)
    assert valid, problems


@pytest.mark.parametrize("mutate,fragment", [
    (lambda d: d.update(bomFormat="NotCycloneDX"), "NotCycloneDX"),
    (lambda d: d.update(serialNumber="not-a-urn"), "serialNumber"),
    (lambda d: d["components"][1]["cryptoProperties"]["algorithmProperties"]
        .update(primitive="teleport"), "teleport"),
    (lambda d: d["components"][1]["cryptoProperties"]["algorithmProperties"]
        .update(mode="quantum"), "quantum"),
    (lambda d: d["components"][1]["cryptoProperties"]["algorithmProperties"]
        .update(executionEnvironment="the-cloud"), "the-cloud"),
    (lambda d: d["components"][1]["cryptoProperties"]
        .update(assetType="vibes"), "vibes"),
    (lambda d: d["components"][1].update(type="sandwich"), "sandwich"),
    (lambda d: d["components"][1].pop("name"), "name"),
])
def test_deliberately_malformed_documents_are_rejected(exercised, mutate, fragment):
    """A validator that passes anything is not a validator."""
    doc = cbom.build(exercised)
    mutate(doc)
    valid, problems = SV.validate(doc, "1.6")
    assert not valid, f"the official schema accepted {fragment!r}"
    assert any(fragment in p for p in problems), problems


def test_an_unexpected_spec_version_is_caught_by_the_structural_check(exercised):
    """The official 1.6 schema does not enum-constrain `specVersion`.

    That is upstream's choice, not a gap we can close in the schema, so the
    structural validator carries this one. Worth a test precisely because the
    obvious assumption -- that the official schema catches everything -- is
    wrong here.
    """
    doc = cbom.build(exercised)
    doc["specVersion"] = "9.9"
    assert SV.validate(doc, "1.6")[0] is True, "upstream does not constrain this"
    valid, problems = cbom.validate(doc)
    assert not valid
    assert any("9.9" in p for p in problems)


def test_validation_that_cannot_run_is_never_reported_as_a_pass(monkeypatch):
    """`checked` is a field in its own right for exactly this reason."""
    monkeypatch.setattr(SV, "available", lambda: False)
    monkeypatch.setattr(SV, "unavailable_reason", lambda: "pretend it is missing")
    out = SV.report({"bomFormat": "CycloneDX", "specVersion": "1.6"})
    assert out["checked"] is False
    assert out["valid"] is None
    assert out["reason_unavailable"] == "pretend it is missing"


def test_a_modified_schema_is_refused_rather_than_trusted(monkeypatch, tmp_path):
    """A validator you can quietly edit is not a validator."""
    monkeypatch.setattr(SV, "verify_checksums",
                        lambda: ["bom-1.6.schema.json does not match"])
    with pytest.raises(SV.SchemaUnavailable, match="does not match"):
        SV.validate({"bomFormat": "CycloneDX", "specVersion": "1.6"}, "1.6")


def test_the_vendored_schemas_match_their_recorded_checksums():
    assert SV.verify_checksums() == []


def test_schema_provenance_is_recorded_and_pinned():
    p = SV.provenance()
    assert p["source"].startswith("https://github.com/CycloneDX/specification")
    assert re.fullmatch(r"[0-9a-f]{40}", p["pinned_commit"])
    assert set(p["versions"]) == set(cbom.SUPPORTED_SPEC_VERSIONS)


def test_validation_is_offline():
    """No network call at validation time: the schemas are on disk."""
    import socket

    def refuse(*a, **kw):
        raise AssertionError("schema validation attempted a network connection")

    original = socket.socket.connect
    socket.socket.connect = refuse
    try:
        doc = cbom.build(scored([make_finding("rsa-2048")]))
        valid, problems = SV.validate(doc, "1.6")
        assert valid, problems
    finally:
        socket.socket.connect = original


# ==========================================================================
# 3-6. CBOM semantics a schema cannot catch
# ==========================================================================

def test_a_library_dependency_is_a_library_component_not_an_algorithm(exercised):
    """The defect: the module comment said this already happened. It did not."""
    doc = cbom.build(exercised)
    libraries = [c for c in doc["components"] if c["type"] == "library"]
    assert len(libraries) == 1

    lib = libraries[0]
    assert lib["name"] == "pycryptodome"
    assert lib["version"] == "3.19.0"
    assert "cryptoProperties" not in lib, (
        "a package is not a cryptographic asset and must not claim to be one")


@pytest.mark.parametrize("mode,expected", [
    ("xts", "other"), ("cfb8", "other"), ("gcm", "gcm"), ("cbc", "cbc"),
])
def test_modes_outside_the_enum_become_other_rather_than_failing(mode, expected):
    f = make_finding("aes-256", location="a.py")
    f.mode = mode
    doc = cbom.build(scored([f]))
    ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap["mode"] == expected
    assert SV.validate(doc, "1.6")[0]


@pytest.mark.parametrize("padding,expected", [
    ("pkcs5padding", "pkcs5"), ("OAEPWithSHA-256AndMGF1Padding", "oaep"),
    ("PKCS1Padding", "pkcs1v15"), ("NoPadding", "raw"),
])
def test_java_padding_strings_map_onto_the_enum(padding, expected):
    f = make_finding("rsa", location="A.java")
    f.padding = padding
    doc = cbom.build(scored([f]))
    ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap["padding"] == expected


def test_execution_environment_is_unknown_unless_it_was_established():
    """It was hardcoded to software-plain-ram, which is a guess.

    Schema-valid and exactly wrong for the asset you would least want to
    mislabel: a key in an HSM.
    """
    doc = cbom.build(scored([make_finding("rsa-2048")]))
    ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap["executionEnvironment"] == "unknown"


def test_a_hardware_backed_constraint_is_honoured_when_an_operator_sets_it():
    """The one case where the environment is known: a person said so."""
    from app.assessment import AssetOverride, asset_key

    f = make_finding("rsa-2048")
    key = asset_key(f)
    risk.score_all([f], risk.QDayModel(), overrides={
        key: AssetOverride(asset_key=key, constraints=["hardware-backed"])})
    recommend.recommend_all([f])

    result = ScanResult(target=ScanTarget(kind="repository", value="/e"))
    result.findings = [f]
    ap = cbom.build(result)["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap["executionEnvironment"] == "hardware"


def test_parameter_set_is_a_parameter_set_not_a_security_strength():
    """ECDSA P-256 was reported with parameterSetIdentifier 128 — its strength."""
    doc = cbom.build(scored([make_finding("ecdsa-p-256", location="ec.py")]))
    ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap.get("curve") == "P-256"
    assert ap.get("parameterSetIdentifier") != "128"
    # Strength has its own field and keeps its own value.
    assert ap["classicalSecurityLevel"] == 128


def test_key_size_drives_the_parameter_set_when_it_is_known():
    f = make_finding("rsa-2048", location="k.py")
    f.key_size = 2048
    doc = cbom.build(scored([f]))
    ap = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap["parameterSetIdentifier"] == "2048"
    assert ap["classicalSecurityLevel"] == 112      # strength, not key size


def test_certificate_dates_are_emitted_as_date_times(exercised):
    doc = cbom.build(exercised)
    cert = next(c for c in doc["components"]
                if c.get("cryptoProperties", {}).get("assetType") == "certificate"
                and "certificateProperties" in c["cryptoProperties"]
                and c["cryptoProperties"]["certificateProperties"].get("notValidAfter"))
    cp = cert["cryptoProperties"]["certificateProperties"]
    assert cp["notValidAfter"].endswith("Z")
    assert "T" in cp["notValidAfter"]


def test_signature_algorithm_ref_resolves_to_a_real_component(exercised):
    """It held a human-readable name, which is not a reference to anything."""
    doc = cbom.build(exercised)
    refs = {c["bom-ref"] for c in doc["components"]}
    found = False
    for c in doc["components"]:
        ref = (c.get("cryptoProperties", {})
                .get("certificateProperties", {})
                .get("signatureAlgorithmRef"))
        if ref:
            found = True
            assert ref in refs, f"{ref} does not resolve to a component"
    assert found, "the fixture should produce at least one signature reference"


def test_a_dangling_reference_is_caught_by_the_structural_validator(exercised):
    doc = cbom.build(exercised)
    for c in doc["components"]:
        cp = c.get("cryptoProperties", {}).get("certificateProperties")
        if cp and cp.get("signatureAlgorithmRef"):
            cp["signatureAlgorithmRef"] = "crypto/nowhere/does-not-exist"
            break
    valid, problems = cbom.validate(doc)
    assert not valid
    assert any("not a component in this document" in p for p in problems)


def test_unknown_stays_unknown_through_the_export():
    f = make_finding("unknown", rule_id="java.getinstance.dynamic", location="D.java")
    doc = cbom.build(scored([f]))
    comp = doc["components"][0]
    ap = comp["cryptoProperties"]["algorithmProperties"]
    assert ap["cryptoFunctions"] == ["unknown"]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["crypto:purpose"] == "unknown"
    assert SV.validate(doc, "1.6")[0]


def test_bom_refs_are_unique_across_an_exercised_document(exercised):
    doc = cbom.build(exercised)
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))


# ==========================================================================
# CycloneDX 1.7
# ==========================================================================

def test_both_supported_versions_are_genuinely_emitted_and_validated(exercised):
    assert cbom.SUPPORTED_SPEC_VERSIONS == ("1.6", "1.7")
    for version in cbom.SUPPORTED_SPEC_VERSIONS:
        doc = cbom.build(exercised, spec_version=version)
        assert doc["specVersion"] == version
        valid, problems = SV.validate(doc, version)
        assert valid, (version, problems)


def test_an_unsupported_version_is_refused_rather_than_relabelled(exercised):
    """Changing specVersion without changing the document would be a lie."""
    with pytest.raises(ValueError, match="not supported"):
        cbom.build(exercised, spec_version="1.5")


def test_17_uses_the_new_curve_field_and_16_uses_the_deprecated_one():
    f = make_finding("ecdsa-p-256", location="ec.py")
    ap16 = cbom.build(scored([f]), spec_version="1.6")[
        "components"][0]["cryptoProperties"]["algorithmProperties"]
    ap17 = cbom.build(scored([f]), spec_version="1.7")[
        "components"][0]["cryptoProperties"]["algorithmProperties"]

    assert ap16["curve"] == "P-256"
    assert "ellipticCurve" not in ap16
    # 1.7 deprecated `curve` and its replacement is a namespaced closed enum.
    assert ap17["ellipticCurve"] == "nist/P-256"
    assert "curve" not in ap17


@pytest.mark.parametrize("purpose,family", [
    (P.SIGNATURE, "RSASSA-PSS"),
    (P.KEY_ESTABLISHMENT, "RSAES-OAEP"),
])
def test_17_algorithm_family_follows_the_resolved_rsa_purpose(purpose, family):
    """1.7 has no plain "RSA" family; it splits by what the key does."""
    f = make_finding("rsa-2048", purpose=purpose, location="k.py")
    ap = cbom.build(scored([f]), spec_version="1.7")[
        "components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap["algorithmFamily"] == family


def test_17_omits_the_family_when_the_rsa_purpose_is_unresolved():
    """Picking one of the three would assert a purpose we did not establish."""
    f = make_finding("rsa-2048", location="k.py")
    ap = cbom.build(scored([f]), spec_version="1.7")[
        "components"][0]["cryptoProperties"]["algorithmProperties"]
    assert "algorithmFamily" not in ap


def test_17_replaces_the_deprecated_signature_reference(exercised):
    doc = cbom.build(exercised, spec_version="1.7")
    related = [c["cryptoProperties"]["certificateProperties"]
               for c in doc["components"]
               if c.get("cryptoProperties", {}).get("certificateProperties", {})
               .get("relatedCryptographicAssets")]
    assert related, "1.7 should use relatedCryptographicAssets"
    assert related[0]["relatedCryptographicAssets"][0]["type"] == "algorithm"
    assert "signatureAlgorithmRef" not in related[0]


# ==========================================================================
# 9. No leaked secret material
# ==========================================================================

def test_a_hardcoded_secret_is_never_exported_into_the_cbom(tmp_path):
    """A CBOM is made to be shared. Publishing the secret it found is worse
    than not finding it."""
    from app.scanners import source

    (tmp_path / "conf.py").write_text(
        'SECRET_KEY = "hunter2hunter2hunter2hunter2AAAA"\n'
        'API_TOKEN = "tok_abcdefghijklmnopqrstuvwxyz"\n')
    findings, _ = source.scan(tmp_path)
    assert findings, "the fixture should trip the hardcoded-secret rule"

    body = json.dumps(cbom.build(scored(findings)))
    assert "hunter2" not in body
    assert "tok_abcdefghijklmnop" not in body
    assert "redacted" in body


def test_private_key_evidence_is_redacted_but_the_location_is_kept(tmp_path):
    f = make_finding("unknown", rule_id="any.private.key.inline",
                     location="deploy/id_rsa")
    f.evidence[0].snippet = "-----BEGIN RSA PRIVATE KEY-----MIIEow..."
    doc = cbom.build(scored([f]))
    occ = doc["components"][0]["evidence"]["occurrences"][0]
    assert "MIIEow" not in json.dumps(doc)
    assert occ["location"] == "deploy/id_rsa", "the location is what makes it actionable"


def test_redaction_does_not_eat_ordinary_algorithm_evidence():
    """Over-redaction destroys the most informative field in a Java finding."""
    assert cbom.redact('Cipher.getInstance("AES/ECB/PKCS5Padding")') == \
        'Cipher.getInstance("AES/ECB/PKCS5Padding")'
    assert cbom.redact('MessageDigest.getInstance("SHA3-512")') == \
        'MessageDigest.getInstance("SHA3-512")'


# ==========================================================================
# 7, 8, 10-12. The report
# ==========================================================================

def test_the_full_report_contains_every_finding_not_only_the_top_fifteen():
    """A summary passed off as an inventory is the failure mode here."""
    findings = [make_finding("rsa-2048", location=f"svc/m{i}/keys.py")
                for i in range(40)]
    result = scored(findings)
    html = report.build(result, risk.portfolio_summary(findings))

    assert html.count('<article class="chain">') == 40
    for i in (0, 17, 39):
        assert f"svc/m{i}/keys.py" in html


def test_every_chain_block_carries_the_whole_traceable_chain():
    result = scored([make_finding("rsa-2048", purpose=P.SIGNATURE)])
    html = report.build(result, risk.portfolio_summary(result.findings))
    for step in ("1 · Detection evidence", "2 · Purpose and assurance",
                 "3 · Quantum classification", "4 · Risk inputs and assumptions",
                 "5 · Recommended alternative", "6 · Action and validation"):
        assert step in html, step


def test_a_complete_scan_says_so_and_a_partial_scan_says_why():
    complete = scored([make_finding("rsa-2048")], complete=True)
    html = report.build(complete, risk.portfolio_summary(complete.findings))
    assert "Complete." in html

    partial = scored([make_finding("rsa-2048")], complete=False,
                     incomplete_reasons=["1 sensor(s) failed"],
                     sensor_errors={"binary": "RuntimeError: disk vanished"})
    html = report.build(partial, risk.portfolio_summary(partial.findings))
    assert "PARTIAL — this inventory is incomplete" in html
    assert "disk vanished" in html
    assert "Absence of a finding below is not evidence of absence" in html


def test_policy_refusals_appear_in_the_report():
    result = scored(
        [make_finding("rsa-2048")], complete=False,
        incomplete_reasons=["1 endpoint(s) refused by network policy"],
        endpoints_refused=[{"destination": "169.254.169.254",
                            "reason": "cloud instance metadata service"}],
        filesystem_policy={"skipped": {"symlink escaping the scan root": 3}},
    )
    html = report.build(result, risk.portfolio_summary(result.findings))
    assert "169.254.169.254" in html
    assert "cloud instance metadata service" in html
    assert "symlink escaping the scan root" in html


def test_unknown_latency_and_cost_stay_unknown_in_the_report():
    result = scored([make_finding("rsa-2048", purpose=P.SIGNATURE)])
    html = report.build(result, risk.portfolio_summary(result.findings))
    assert "not-measured" in html
    assert "not-estimated" in html
    assert "Neither is estimated by this tool" in html


def test_a_historical_container_asset_is_labelled_in_the_report():
    f = make_finding("unknown", rule_id="cert.privatekey",
                     scanner="container/certificate", location="img:/etc/k.key")
    f.extra["container"] = {"image": "app:1", "path": "etc/k.key",
                            "layer_index": 0, "effective": False,
                            "state": "historical", "superseded_by_layer": 1}
    result = scored([f])
    html = report.build(result, risk.portfolio_summary(result.findings))
    assert "historical layer only" in html
    assert "still" in html and "extractable" in html


def test_operator_inputs_are_distinguished_from_derived_ones_in_the_report():
    from app.assessment import AssetOverride

    f = make_finding("rsa-2048")
    key = __import__("app.assessment", fromlist=["asset_key"]).asset_key(f)
    risk.score_all([f], risk.QDayModel(),
                   overrides={key: AssetOverride(asset_key=key,
                                                 shelf_life_years=30.0)})
    recommend.recommend_all([f])
    result = ScanResult(target=ScanTarget(kind="repository", value="/e"))
    result.findings = [f]
    html = report.build(result, risk.portfolio_summary([f]))

    assert "prov-operator" in html
    assert "prov-derived" in html or "prov-default" in html


def test_the_report_prints_without_a_service():
    result = scored([make_finding("rsa-2048")])
    html = report.build(result, risk.portfolio_summary(result.findings))
    assert "@media print" in html
    assert "page-break-inside" in html
    # Self-contained: no external fetches, so it works offline and in print.
    assert "http://" not in html.replace("http://www.w3.org", "")
    assert "<script" not in html.lower()


# ==========================================================================
# 10. HTML escaping against hostile input
# ==========================================================================

HOSTILE = '<script>alert("xss")</script>'


def test_hostile_values_cannot_inject_markup_into_the_report():
    """Every untrusted value reaches the report through html.escape."""
    f = make_finding("rsa-2048", location=f"src/{HOSTILE}/keys.py")
    f.title = HOSTILE
    f.detail = HOSTILE
    f.purpose_evidence = HOSTILE
    f.evidence[0].snippet = HOSTILE
    f.evidence[0].technique = HOSTILE

    result = scored([f])
    result.target.label = HOSTILE
    result.target.value = HOSTILE
    html = report.build(result, risk.portfolio_summary(result.findings))

    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_hostile_stats_cannot_inject_markup():
    result = scored([make_finding("rsa-2048")], complete=False,
                    incomplete_reasons=[HOSTILE],
                    sensor_errors={HOSTILE: HOSTILE},
                    endpoints_refused=[{"destination": HOSTILE, "reason": HOSTILE}],
                    filesystem_policy={"skipped": {HOSTILE: 1}})
    html = report.build(result, risk.portfolio_summary(result.findings))
    assert "<script>alert" not in html
    assert html.count("&lt;script&gt;") >= 4


def test_hostile_correlation_data_cannot_inject_markup():
    result = scored([make_finding("rsa-2048")], logical_assets=[{
        "algorithm": HOSTILE, "purpose": HOSTILE, "basis": [HOSTILE],
        "detectors": [HOSTILE], "assurance_states": {HOSTILE: 1},
        "conflicts": [HOSTILE], "corroborated_by_use": True,
    }])
    html = report.build(result, risk.portfolio_summary(result.findings))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_a_hostile_recommendation_cannot_inject_markup():
    f = make_finding("rsa-2048", purpose=P.SIGNATURE)
    risk.score_all([f], risk.QDayModel())
    recommend.recommend_all([f])
    f.recommendation["action"] = HOSTILE
    f.recommendation["rationale"] = HOSTILE
    f.recommendation["unknowns"] = [HOSTILE]
    f.recommendation["validation_steps"] = [HOSTILE]
    f.recommendation["compatibility"] = [HOSTILE]

    result = ScanResult(target=ScanTarget(kind="repository", value="/e"))
    result.findings = [f]
    html = report.build(result, risk.portfolio_summary([f]))
    assert "<script>alert" not in html


# ==========================================================================
# 12/13. Saved assessment consistency, and no regressions
# ==========================================================================

def test_the_report_uses_the_assessment_recorded_on_the_findings(monkeypatch):
    """A report generated later must not silently restate today's scenario."""
    monkeypatch.setenv("CD_ASSESSMENT_DATE", "2026-03-01")
    f = make_finding("rsa-2048")
    risk.score_all([f], risk.QDayModel(earliest=2029, likely=2031, latest=2040))
    recommend.recommend_all([f])
    result = ScanResult(target=ScanTarget(kind="repository", value="/e"))
    result.findings = [f]

    # Time moves on; the saved assessment must not.
    monkeypatch.setenv("CD_ASSESSMENT_DATE", "2029-12-25")
    html = report.build(result, risk.portfolio_summary([f]))

    assert "2031" in html, "the saved Q-Day scenario must be the one reported"
    assert "2029-12-25" not in html.split("Assessment date")[1][:200], \
        "the report must not substitute a later assessment date"


def test_directory_and_container_exports_still_validate(tmp_path):
    """The regression that would matter most."""
    import sys
    sys.path.insert(0, "tests")
    import imagelab as L
    from app import orchestrator

    (tmp_path / "a.py").write_text("import hashlib\nhashlib.sha3_512(b'x')\n")
    directory = orchestrator.scan_target(tmp_path, sensors=["source"])

    builder = L.OCIBuilder()
    builder.add_image([L.tar_bytes([("app/main.py", L.CRYPTO_APP_PY),
                                    ("app/requirements.txt", L.REQUIREMENTS)],
                                   gzipped=True)], tag="reg:1")
    image = orchestrator.scan_image(builder.write_tar(tmp_path / "reg.tar"))

    for result in (directory, image):
        for version in cbom.SUPPORTED_SPEC_VERSIONS:
            doc = cbom.build(result, spec_version=version)
            valid, problems = SV.validate(doc, version)
            assert valid, (result.target.kind, version, problems)
            structural, sproblems = cbom.validate(doc)
            assert structural, (result.target.kind, version, sproblems)

"""Milestone 2: detection correctness, end to end over labelled fixtures.

Every test here runs the real scanner over a real file in ``tests/fixtures``
and asserts on what comes out the far end of the pipeline -- after
normalisation, scoring, recommendation and CBOM export -- rather than on an
intermediate structure. A defect that is corrected in the scanner and lost in
normalisation is not corrected.

Each defect recorded in ``docs/sih/BASELINE.md`` has a test here that fails
against the code as it stood at 267448e.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import cbom
from app.engine import normalize, recommend, risk
from app.knowledge import algorithms as K
from app.knowledge import purposes as P
from app.models import (
    ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED, ASSURANCE_USED,
    ScanResult, ScanTarget,
)
from app.scanners import source

FIXTURES = Path(__file__).parent / "fixtures"


def scan_fixture(*parts: str):
    """Scan one fixture file or directory and return normalised assets."""
    target = FIXTURES.joinpath(*parts)
    root = target if target.is_dir() else target.parent
    raw, _ = source.scan(root)
    if target.is_file():
        raw = [f for f in raw
               if any(e.location.endswith(target.name) for e in f.evidence)]
    return normalize.normalize(raw)


def algorithms_in(findings) -> set[str]:
    return {f.algorithm for f in findings}


def pipeline(findings, profile=recommend.PROFILE_GENERAL):
    """Run the full downstream pipeline, as a real scan does."""
    risk.score_all(findings, risk.QDayModel())
    recommend.recommend_all(findings, profile)
    return findings


# ==========================================================================
# 1-3. RSA purpose
# ==========================================================================

def test_rsa_signing_fixture_gets_a_signature_recommendation():
    """End-to-end case 1: a signing call site must not receive a KEM."""
    findings = pipeline(scan_fixture("rsa_purpose", "signing.go"))
    rsa = [f for f in findings if f.algorithm.startswith("rsa")]
    assert rsa, "the signing fixture produced no RSA finding"

    for f in rsa:
        assert f.purpose == P.SIGNATURE, f"{f.rule_id} resolved {f.purpose}"
        target = K.get(f.recommendation["target"])
        assert target.primitive == K.PRIM_SIGNATURE, (
            f"{f.rule_id} was recommended {target.name}, which is not a "
            f"signature scheme")
        assert target.primitive != K.PRIM_KEM


def test_rsa_key_transport_fixture_gets_a_kem_recommendation():
    """End-to-end case 2: key transport must receive a KEM or a hybrid."""
    findings = pipeline(scan_fixture("rsa_purpose", "transport.go"))
    rsa = [f for f in findings if f.algorithm.startswith("rsa")]
    assert rsa

    for f in rsa:
        assert f.purpose == P.KEY_ESTABLISHMENT
        target = K.get(f.recommendation["target"])
        assert target.primitive in (K.PRIM_KEM, K.PRIM_KEY_AGREE)


def test_ambiguous_rsa_fixture_stays_unresolved():
    """End-to-end case 3: generation reveals nothing, so nothing is invented."""
    findings = pipeline(scan_fixture("rsa_purpose", "ambiguous.go"))
    rsa = [f for f in findings if f.algorithm.startswith("rsa")]
    assert rsa

    for f in rsa:
        assert f.purpose == P.UNKNOWN
        assert f.recommendation["unresolved"] is True
        assert f.recommendation["target"] == ""


def test_the_three_rsa_purposes_are_separate_assets_after_normalisation():
    """They must not merge: one row can carry only one recommendation."""
    findings = pipeline(scan_fixture("rsa_purpose"))
    purposes = {f.purpose for f in findings if f.algorithm.startswith("rsa")}
    assert {P.SIGNATURE, P.KEY_ESTABLISHMENT, P.UNKNOWN} <= purposes


def test_java_apis_resolve_purpose_from_the_call_not_the_algorithm():
    findings = pipeline(scan_fixture("rsa_purpose", "Purposes.java"))
    by_rule = {f.rule_id: f for f in findings if f.algorithm.startswith("rsa")}

    assert by_rule["java.signature"].purpose == P.SIGNATURE
    assert by_rule["java.cipher.getinstance"].purpose == P.KEY_ESTABLISHMENT
    assert by_rule["java.keypairgen"].purpose == P.UNKNOWN


def test_padding_scheme_resolves_python_rsa_purpose():
    """PSS signs, OAEP encrypts, PKCS#1 v1.5 does both and so resolves nothing."""
    findings = pipeline(scan_fixture("rsa_purpose", "padding.py"))
    purposes = {f.purpose for f in findings if f.algorithm.startswith("rsa")}
    assert P.SIGNATURE in purposes
    assert P.KEY_ESTABLISHMENT in purposes
    assert P.UNKNOWN in purposes, "PKCS#1 v1.5 must not resolve a purpose"


def test_purpose_survives_into_the_cbom_as_crypto_functions():
    findings = pipeline(scan_fixture("rsa_purpose", "signing.go"))
    result = ScanResult(target=ScanTarget(kind="repository", value="fixture"))
    result.findings = findings
    doc = cbom.build(result)

    ok, problems = cbom.validate(doc)
    assert ok, problems

    rsa_components = [
        c for c in doc["components"]
        if c["cryptoProperties"].get("algorithmProperties", {}).get("cryptoFunctions")
        and "RSA" in c["name"]
    ]
    assert rsa_components
    for c in rsa_components:
        fns = c["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"]
        assert "sign" in fns and "verify" in fns
        assert "encapsulate" not in fns


def test_unresolved_purpose_is_exported_as_unknown_not_omitted():
    """A consumer must tell "we did not establish it" from "we did not look"."""
    findings = pipeline(scan_fixture("rsa_purpose", "ambiguous.go"))
    result = ScanResult(target=ScanTarget(kind="repository", value="fixture"))
    result.findings = findings
    doc = cbom.build(result)

    rsa = [c for c in doc["components"] if "RSA" in c["name"]]
    assert rsa
    for c in rsa:
        fns = c["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"]
        assert fns == ["unknown"]
        props = {p["name"]: p["value"] for p in c["properties"]}
        assert props["crypto:purpose"] == "unknown"
        assert props["migration:unresolved"] == "true"


# ==========================================================================
# 4-5. Hash identity
# ==========================================================================

EXPECTED_PYTHON_HASHES = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3-224", "sha3-256", "sha3-384", "sha3-512",
    "shake128", "shake256", "blake2b", "blake2s",
    "sha512-224", "sha512-256",
}


@pytest.mark.parametrize("expected", sorted(EXPECTED_PYTHON_HASHES))
def test_every_python_hash_variant_keeps_its_own_identity(expected):
    found = algorithms_in(scan_fixture("hashes", "digests.py"))
    assert expected in found, (
        f"{expected} was not reported at its own identity; got {sorted(found)}")


def test_sha3_512_is_not_reported_as_sha3_256():
    """The defect, inverted. Both appear in the fixture and must stay distinct."""
    found = algorithms_in(scan_fixture("hashes", "digests.py"))
    assert "sha3-512" in found
    assert "sha3-256" in found
    assert K.get("sha3-512").classical_bits == 512
    assert K.get("sha3-256").classical_bits == 256


def test_blake2b_and_blake2s_keep_their_own_identities():
    """They are not SHA-512 and SHA-256, which is what they used to become."""
    found = algorithms_in(scan_fixture("hashes", "digests.py"))
    assert "blake2b" in found
    assert "blake2s" in found
    assert K.get("blake2b").family == "BLAKE2"
    assert K.get("blake2s").family == "BLAKE2"
    assert K.get("blake2b").key != K.get("sha512").key
    assert K.get("blake2s").key != K.get("sha256").key


@pytest.mark.parametrize("expected", ["sha3-224", "sha3-256", "sha3-384", "sha3-512"])
def test_java_sha3_variants_keep_their_identity(expected):
    found = algorithms_in(scan_fixture("hashes", "Digests.java"))
    assert expected in found


@pytest.mark.parametrize("expected", ["sha3-256", "sha3-512", "blake2b", "blake2s"])
def test_node_modern_digests_keep_their_identity(expected):
    found = algorithms_in(scan_fixture("hashes", "digests.js"))
    assert expected in found


def test_hash_identity_survives_the_whole_pipeline():
    """Case 4 and 5, stated as the pipeline requirement rather than a lookup.

    Source -> Finding -> normalise -> risk -> recommend -> CBOM. A correction
    lost at any stage is not a correction.
    """
    findings = pipeline(scan_fixture("hashes", "digests.py"))
    result = ScanResult(target=ScanTarget(kind="repository", value="fixture"))
    result.findings = findings
    doc = cbom.build(result)

    names = {c["name"] for c in doc["components"]}
    assert "SHA3-512" in names
    assert "BLAKE2b" in names
    assert "BLAKE2s" in names

    # And the parameters travelled with them.
    by_name = {c["name"]: c for c in doc["components"]}
    sha3_512 = by_name["SHA3-512"]["cryptoProperties"]["algorithmProperties"]
    assert sha3_512["classicalSecurityLevel"] == 512
    assert sha3_512["cryptoFunctions"] == ["digest"]


def test_hash_fixtures_do_not_fire_on_prose_or_variable_names():
    """Labelled negatives. Precision matters as much as recall."""
    findings = scan_fixture("hashes", "negative.py")
    assert findings == [], (
        "false positives on crypto-adjacent code: "
        + str([(f.algorithm, f.rule_id, f.evidence[0].snippet) for f in findings]))


def test_md2_is_not_reported_as_md5():
    """A smaller instance of the same class of error, fixed alongside."""
    from app.knowledge.rules_source import _norm_alg
    assert _norm_alg("MD2") == "md2"
    assert K.get("md2").name == "MD2"
    assert K.get("md2").oid != K.get("md5").oid


@pytest.mark.parametrize("cipher", ["blowfish", "cast5", "idea", "seed", "camellia"])
def test_named_ciphers_are_no_longer_collapsed_to_unknown(cipher):
    """Five identifiable ciphers used to be reported as unresolved."""
    assert K.get(cipher).key == cipher
    assert K.get(cipher).quantum_class != K.UNKNOWN


# ==========================================================================
# 6. Assurance — capability is not use
# ==========================================================================

def test_dependency_capability_is_not_reported_as_use():
    """Case 6. A manifest proves the library is linked, not that RSA is called."""
    from app.scanners import deps

    raw, _ = deps.scan(FIXTURES / "rsa_purpose")
    findings = normalize.normalize(raw)
    assert findings, "the manifest fixture produced no dependency findings"

    provides = [f for f in findings if f.rule_id == "dep.provides"]
    assert provides, "no capability findings were produced"
    for f in provides:
        assert f.assurance == ASSURANCE_CAPABILITY
        assert f.proves_use is False

    library = [f for f in findings if f.rule_id == "dep.library"]
    for f in library:
        assert f.assurance == ASSURANCE_DECLARED


def test_source_call_sites_are_marked_as_used():
    findings = scan_fixture("rsa_purpose", "signing.go")
    assert findings
    for f in findings:
        assert f.assurance == ASSURANCE_USED
        assert f.proves_use is True


def test_capability_and_use_do_not_merge_into_one_asset():
    """Merging them would produce a row whose evidence no longer says which."""
    from app.scanners import deps

    dep_raw, _ = deps.scan(FIXTURES / "rsa_purpose")
    src_raw, _ = source.scan(FIXTURES / "rsa_purpose")
    merged = normalize.normalize(dep_raw + src_raw)

    rsa = [f for f in merged if f.algorithm.startswith("rsa")]
    assurances = {f.assurance for f in rsa}
    assert ASSURANCE_CAPABILITY in assurances
    assert ASSURANCE_USED in assurances
    for f in rsa:
        # No single asset may mix the two, because one row carries one verdict.
        assert len(f.assurance_breakdown) == 1, f.assurance_breakdown


def test_capability_findings_rank_below_equivalent_call_sites():
    from conftest import make_finding

    capability = make_finding("rsa-2048", assurance=ASSURANCE_CAPABILITY,
                              purpose=P.KEY_ESTABLISHMENT)
    used = make_finding("rsa-2048", assurance=ASSURANCE_USED,
                        purpose=P.KEY_ESTABLISHMENT)
    risk.score_all([capability, used], risk.QDayModel())
    assert capability.risk_score < used.risk_score


def test_the_portfolio_publishes_proven_use_alongside_the_raw_total():
    """Reporting one number that mixes both is the easiest way to mislead."""
    from conftest import make_finding

    findings = [
        make_finding("rsa-2048", assurance=ASSURANCE_CAPABILITY),
        make_finding("rsa-2048", location="b.py", assurance=ASSURANCE_USED),
        make_finding("ecdh", location="c.py", assurance=ASSURANCE_OBSERVED),
    ]
    risk.score_all(findings, risk.QDayModel())
    summary = risk.portfolio_summary(findings)

    assert summary["total"] == 3
    assert summary["proven_use"] == 2
    assert summary["capability_only"] == 1
    assert summary["by_assurance"][ASSURANCE_CAPABILITY] == 1


def test_assurance_reaches_the_cbom():
    findings = pipeline(scan_fixture("rsa_purpose", "signing.go"))
    result = ScanResult(target=ScanTarget(kind="repository", value="fixture"))
    result.findings = findings
    doc = cbom.build(result)

    for c in doc["components"]:
        props = {p["name"]: p["value"] for p in c["properties"]}
        assert props["detection:assurance"] in (
            ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_USED,
            ASSURANCE_OBSERVED)
        assert props["detection:provesUse"] in ("true", "false")
        for occ in c["evidence"]["occurrences"]:
            assert occ["additionalContext"].startswith("[")


# ==========================================================================
# 7. TLS: a failed probe is not an observation
# ==========================================================================

def test_a_failed_hybrid_probe_does_not_invent_a_negotiated_group(monkeypatch):
    """Case 7, and the sharpest of the TLS defects.

    Offering a hybrid group and being refused tells you that group was not
    accepted. It does not tell you ECDH was negotiated. The old code named
    ECDH anyway, which recorded an inference as a measurement.
    """
    from app.scanners import network
    from app.netpolicy import Destination

    dest = Destination(host="fixture.test", port=443, addresses=("203.0.113.9",))

    monkeypatch.setattr(network, "_probe_version", lambda d, v, t: (
        {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
         "bits": 256, "peercert_der": b""}
        if v == network.ssl.TLSVersion.TLSv1_3 else None))
    monkeypatch.setattr(network, "_probe_pq_group",
                        lambda d, t: (False, "no hybrid group accepted"))
    monkeypatch.setattr(network, "_observe_negotiated_group",
                        lambda d, t: (None, "no OpenSSL 3.5+ available locally"))

    findings = network.scan_endpoint(dest)
    kex = [f for f in findings if f.rule_id == "net.pqgroup"]
    assert len(kex) == 1

    assert kex[0].algorithm == "unknown", (
        "a refused hybrid probe must not name a specific classical mechanism")
    assert kex[0].extra["mechanism_observed"] is False
    assert "not observed" in kex[0].detail


def test_an_observed_group_is_named_because_it_was_actually_read(monkeypatch):
    """The other half: when the group really was read, name it."""
    from app.scanners import network
    from app.netpolicy import Destination

    dest = Destination(host="fixture.test", port=443, addresses=("203.0.113.9",))
    monkeypatch.setattr(network, "_probe_version", lambda d, v, t: (
        {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
         "bits": 256, "peercert_der": b""}
        if v == network.ssl.TLSVersion.TLSv1_3 else None))
    monkeypatch.setattr(network, "_probe_pq_group",
                        lambda d, t: (False, "no hybrid group accepted"))
    monkeypatch.setattr(network, "_observe_negotiated_group",
                        lambda d, t: ("X25519", "read from the completed handshake"))

    findings = network.scan_endpoint(dest)
    kex = [f for f in findings if f.rule_id == "net.pqgroup"][0]
    assert kex.algorithm == "x25519"
    assert kex.extra["mechanism_observed"] is True


def test_an_untestable_hybrid_probe_stays_undetermined(monkeypatch):
    from app.scanners import network
    from app.netpolicy import Destination

    dest = Destination(host="fixture.test", port=443, addresses=("203.0.113.9",))
    monkeypatch.setattr(network, "_probe_version", lambda d, v, t: (
        {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
         "bits": 256, "peercert_der": b""}
        if v == network.ssl.TLSVersion.TLSv1_3 else None))
    monkeypatch.setattr(network, "_probe_pq_group",
                        lambda d, t: (None, "not tested: no OpenSSL 3.5+"))
    monkeypatch.setattr(network, "_observe_negotiated_group",
                        lambda d, t: (None, "unavailable"))

    findings = network.scan_endpoint(dest)
    kex = [f for f in findings if f.rule_id == "net.pqgroup"][0]
    assert kex.algorithm == "unknown"
    assert kex.extra["pq_supported"] is None
    assert "undetermined" in kex.detail


def test_tls13_cipher_suite_does_not_encode_key_exchange():
    """Never infer post-quantum safety, or any key exchange, from TLS 1.3."""
    parsed = network_parse("TLS_AES_256_GCM_SHA384", "TLSv1.3")
    assert parsed["encodes_kex"] is False
    assert parsed["kex"] is None
    assert parsed["auth"] is None
    assert "negotiated independently" in parsed["note"]


def test_tls12_cipher_suite_decomposes_into_its_real_parts():
    parsed = network_parse("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2")
    assert parsed["encodes_kex"] is True
    assert parsed["kex"] == "ecdh"
    assert parsed["auth"] == "rsa"


def test_an_undecomposable_suite_is_reported_as_such_not_guessed():
    parsed = network_parse("AES256-SHA", "TLSv1.2")
    assert parsed["encodes_kex"] is False
    assert parsed["kex"] is None


def network_parse(suite: str, version: str) -> dict:
    from app.scanners import network
    return network.parse_cipher_suite(suite, version)


def test_protocol_version_is_recorded_separately_from_key_exchange(monkeypatch):
    from app.scanners import network
    from app.netpolicy import Destination

    dest = Destination(host="fixture.test", port=443, addresses=("203.0.113.9",))
    monkeypatch.setattr(network, "_probe_version", lambda d, v, t: (
        {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
         "bits": 256, "peercert_der": b""}
        if v == network.ssl.TLSVersion.TLSv1_3 else None))
    monkeypatch.setattr(network, "_probe_pq_group", lambda d, t: (False, "none"))
    monkeypatch.setattr(network, "_observe_negotiated_group",
                        lambda d, t: (None, "unavailable"))

    findings = network.scan_endpoint(dest)
    rules = {f.rule_id for f in findings}
    assert "net.tlsversion" in rules
    assert "net.ciphersuite" in rules
    assert "net.pqgroup" in rules

    version = [f for f in findings if f.rule_id == "net.tlsversion"][0]
    assert version.extra["determines_quantum_exposure"] is False


def test_obsolete_draft_groups_are_not_offered_by_default():
    from app.scanners import network
    assert "X25519Kyber768Draft00" not in network.PQ_GROUPS
    assert "X25519Kyber768Draft00" in network.OBSOLETE_PQ_GROUPS


def test_certificates_record_that_trust_was_not_verified():
    """Parsing a certificate establishes contents, never trust."""
    from app.scanners import certs

    mods = certs._import_x509()
    if mods is None:
        pytest.skip("cryptography not installed")

    pem = _self_signed_pem()
    findings = certs._parse_certificate(pem, "fixture.pem", mods)
    assert findings
    assert findings[0].extra["trust_verified"] is False
    assert "not attempted" in findings[0].extra["trust_note"]


def test_certificate_key_usage_resolves_purpose():
    from app.scanners import certs

    mods = certs._import_x509()
    if mods is None:
        pytest.skip("cryptography not installed")

    signing = certs._parse_certificate(
        _self_signed_pem(key_cert_sign=True), "ca.pem", mods)
    assert signing[0].purpose == P.SIGNATURE
    assert "KeyUsage" in signing[0].purpose_evidence

    transport = certs._parse_certificate(
        _self_signed_pem(key_encipherment=True), "tls.pem", mods)
    assert transport[0].purpose == P.KEY_ESTABLISHMENT


def test_a_certificate_without_key_usage_leaves_purpose_unresolved():
    from app.scanners import certs

    mods = certs._import_x509()
    if mods is None:
        pytest.skip("cryptography not installed")

    findings = certs._parse_certificate(_self_signed_pem(no_key_usage=True),
                                        "plain.pem", mods)
    assert findings[0].purpose == P.UNKNOWN
    assert "no KeyUsage" in findings[0].purpose_evidence


def test_a_dual_use_certificate_is_unresolved_rather_than_guessed():
    from app.scanners import certs

    mods = certs._import_x509()
    if mods is None:
        pytest.skip("cryptography not installed")

    findings = certs._parse_certificate(
        _self_signed_pem(key_cert_sign=True, key_encipherment=True),
        "dual.pem", mods)
    assert findings[0].purpose == P.UNKNOWN
    assert "dual-use" in findings[0].purpose_evidence


def _self_signed_pem(key_cert_sign: bool = False, key_encipherment: bool = False,
                     no_key_usage: bool = False) -> bytes:
    """Build a throwaway self-signed certificate in memory.

    Generated per call rather than committed, so the suite never ships key
    material and never depends on a fixture expiring.
    """
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as H
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
    )
    if not no_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=key_encipherment, data_encipherment=False,
                key_agreement=False, key_cert_sign=key_cert_sign,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
    cert = builder.sign(key, H.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


# ==========================================================================
# 8. Nothing from Milestone 1 regressed
# ==========================================================================

def test_scan_to_cbom_still_completes_with_the_security_controls_in_place(tmp_path):
    """Case 8: a full scan -> inventory -> recommendation -> CBOM flow."""
    from app import orchestrator

    (tmp_path / "a.py").write_text(
        "import hashlib\nhashlib.sha3_512(b'x')\nhashlib.md5(b'y')\n")
    result = orchestrator.scan_target(tmp_path, sensors=["source"],
                                      endpoints=["169.254.169.254"])

    # M1 controls still hold.
    assert result.stats["complete"] is False
    assert any("refused" in r for r in result.stats["incomplete_reasons"])
    assert "filesystem_policy" in result.stats

    # M2 corrections hold through the same run.
    assert "sha3-512" in {f.algorithm for f in result.findings}

    doc = cbom.build(result)
    ok, problems = cbom.validate(doc)
    assert ok, problems
    assert json.loads(json.dumps(doc))["specVersion"] == "1.6"

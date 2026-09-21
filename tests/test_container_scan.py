"""Container image scanning and cross-sensor correlation, end to end.

Images are generated per test rather than committed: a committed image is a
binary nobody reviews, and generating one lets a malformed case exist without
a malformed file ever being checked in. Nothing built here contains real key
material -- the PEM bodies are the word SYNTHETIC in base64.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import cbom, container as C, orchestrator
from app.engine import correlate, normalize
from app.knowledge import purposes as P
from app.models import (
    ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED, ASSURANCE_USED,
)
from app.scanners import container as sensor

import imagelab as L


# --------------------------------------------------------------------------
# Image builders used across the module
# --------------------------------------------------------------------------

def rich_image(tmp_path: Path, name: str = "rich.tar") -> Path:
    """An image with something for every analyser, plus a deleted key."""
    # RSA_new alongside RSA_sign on purpose: one symbol states the operation
    # and one does not, so the image carries both a purpose-resolved RSA asset
    # and a purpose-unresolved one. Correlation must treat them differently.
    libcrypto = (L.fake_elf([b"RSA_sign", b"RSA_new", b"SHA256_Init", b"MD5_Init"])
                 + b"OpenSSL 3.0.2 15 Mar 2022\x00")
    layer0 = L.tar_bytes([
        ("etc/nginx.conf", L.NGINX_CONF),
        ("etc/ssl/private/server.key", L.SYNTHETIC_PEM_KEY),
    ], gzipped=True)
    layer1 = L.tar_bytes([
        ("app/main.py", L.CRYPTO_APP_PY),
        ("app/requirements.txt", b"openssl==3.0.2\npycryptodome==3.19.0\n"),
        ("usr/lib/libcrypto.so.3", libcrypto),
        ("etc/ssl/private/.wh.server.key", b""),
    ], gzipped=True)
    builder = L.OCIBuilder()
    builder.add_image([layer0, layer1], tag="rich:latest",
                      env=["PATH=/usr/bin", "SSL_CERT_FILE=/etc/ssl/certs/ca.pem"])
    return builder.write_tar(tmp_path / name)


# ==========================================================================
# Formats
# ==========================================================================

def test_an_oci_archive_is_recognised_and_scanned(tmp_path):
    archive = rich_image(tmp_path)
    findings, stats = sensor.scan(archive)
    assert stats["container_format"] == "oci-archive"
    assert stats["container_image"] == "rich:latest"
    assert stats["container_layers"] == 2
    assert findings


def test_an_unpacked_oci_layout_directory_is_scanned(tmp_path):
    builder = L.OCIBuilder()
    layer = L.tar_bytes([("app/main.py", L.CRYPTO_APP_PY)], gzipped=True)
    builder.add_image([layer], tag="dir:1")
    layout = builder.write_dir(tmp_path / "layout")

    findings, stats = sensor.scan(layout)
    assert stats["container_format"] == "oci-layout-dir"
    assert "sha3-512" in {f.algorithm for f in findings}


def test_a_docker_save_archive_is_scanned(tmp_path):
    layer = L.tar_bytes([("app/main.py", L.CRYPTO_APP_PY),
                         ("etc/nginx.conf", L.NGINX_CONF)])
    archive = L.write_docker_archive(
        tmp_path / "docker.tar",
        [{"tag": "svc:1.0", "layers": [layer]}])

    findings, stats = sensor.scan(archive)
    assert stats["container_format"] == "docker-archive"
    assert stats["container_image"] == "svc:1.0"
    assert "sha3-512" in {f.algorithm for f in findings}


def test_every_supported_format_is_documented():
    """Coverage is claimed in exactly one place and the API serves that place."""
    assert set(C.SUPPORTED_FORMATS) == {
        "oci-layout-dir", "oci-archive", "docker-archive"}
    for description in C.SUPPORTED_FORMATS.values():
        assert description


def test_inspect_describes_an_archive_without_reading_layers(tmp_path):
    archive = rich_image(tmp_path)
    info = C.inspect(archive)
    assert info["format"] == "oci-archive"
    assert [i["name"] for i in info["images"]] == ["rich:latest"]
    assert info["archive"]["layers_read"] == 0


# ==========================================================================
# What is actually detected, and by which analyser
# ==========================================================================

def test_each_analyser_contributes_and_records_the_technique_that_ran(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    techniques = {f.extra.get("inner_technique") for f in findings}
    assert "source-analysis" in techniques
    assert "dependency-manifest" in techniques
    assert "config-parse" in techniques
    assert any(t and t.startswith("binary-analysis") for t in techniques)


def test_hash_identity_is_preserved_inside_an_image(tmp_path):
    """The M2 correction must survive the container path too."""
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    algorithms = {f.algorithm for f in findings}
    assert "sha3-512" in algorithms
    assert "md5" in algorithms


def test_rsa_purpose_is_preserved_inside_an_image(tmp_path):
    """padding.PSS in a layer resolves to signing, exactly as on disk."""
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    rsa = [f for f in findings if f.algorithm.startswith("rsa")
           and f.rule_id.startswith("py.")]
    assert rsa
    assert all(f.purpose == P.SIGNATURE for f in rsa)


def test_manifest_capability_inside_an_image_is_still_capability(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    provides = [f for f in findings if f.rule_id == "dep.provides"]
    assert provides
    assert all(f.evidence[0].assurance == ASSURANCE_CAPABILITY for f in provides)
    assert all(not f.proves_use for f in provides)


def test_image_config_environment_is_declared_not_observed(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    env = [f for f in findings if f.rule_id == "container.env"]
    assert env, "the image config set SSL_CERT_FILE and should be reported"
    assert env[0].evidence[0].assurance == ASSURANCE_DECLARED


def test_an_image_with_no_cryptography_produces_no_findings(tmp_path):
    builder = L.OCIBuilder()
    layer = L.tar_bytes([("README", L.PLAIN_README),
                         ("data/values.csv", b"a,b,c\n1,2,3\n")], gzipped=True)
    builder.add_image([layer], tag="plain:1")
    archive = builder.write_tar(tmp_path / "plain.tar")

    findings, stats = sensor.scan(archive)
    assert findings == []
    assert stats["container_layers"] == 1
    assert stats["container_files_analysed"] == 2


# ==========================================================================
# Layers, whiteouts and provenance
# ==========================================================================

def test_a_deleted_file_is_reported_as_historical_not_active(tmp_path):
    """The distinction the whole layer replay exists for."""
    archive = rich_image(tmp_path)
    findings, stats = sensor.scan(archive)

    key = [f for f in findings if f.rule_id == "cert.privatekey"]
    assert key, "the private key in layer 0 should still be inventoried"
    provenance = key[0].extra["container"]
    assert provenance["effective"] is False
    assert provenance["state"] == "historical"
    assert provenance["superseded_by_layer"] == 1
    assert "historical layer" in key[0].title
    assert "NOT in the image's final filesystem" in key[0].detail
    assert stats["container_findings_historical"] >= 1


def test_a_file_replaced_by_a_later_layer_is_historical(tmp_path):
    builder = L.OCIBuilder()
    old = L.tar_bytes([("app/x.py", b"import hashlib\nhashlib.md5(b'x')\n")],
                      gzipped=True)
    new = L.tar_bytes([("app/x.py", b"import hashlib\nhashlib.sha256(b'x')\n")],
                      gzipped=True)
    builder.add_image([old, new], tag="replaced:1")
    archive = builder.write_tar(tmp_path / "replaced.tar")

    findings, _ = sensor.scan(archive)
    by_algorithm = {f.algorithm: f.extra["container"] for f in findings}
    assert by_algorithm["md5"]["effective"] is False
    assert by_algorithm["sha256"]["effective"] is True


def test_an_opaque_whiteout_removes_a_whole_directory(tmp_path):
    builder = L.OCIBuilder()
    first = L.tar_bytes([("secrets/a.key", L.SYNTHETIC_PEM_KEY),
                         ("secrets/b.key", L.SYNTHETIC_PEM_KEY),
                         ("app/keep.py", L.CRYPTO_APP_PY)], gzipped=True)
    second = L.tar_bytes([("secrets/.wh..wh..opq", b"")], gzipped=True)
    builder.add_image([first, second], tag="opaque:1")
    archive = builder.write_tar(tmp_path / "opaque.tar")

    findings, _ = sensor.scan(archive)
    keys = [f for f in findings if f.rule_id == "cert.privatekey"]
    assert len(keys) == 2
    assert all(f.extra["container"]["effective"] is False for f in keys)

    kept = [f for f in findings if "keep.py" in f.evidence[0].location]
    assert kept and all(f.extra["container"]["effective"] for f in kept)


def test_every_finding_carries_image_layer_and_path_provenance(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    for f in findings:
        provenance = f.extra.get("container")
        assert provenance, f"{f.rule_id} carries no container provenance"
        assert provenance["image"] == "rich:latest"
        assert provenance["path"]
        assert "layer_index" in provenance
        assert provenance["state"] in ("effective", "historical")
        # Layer files are located at image:/path. The image config blob is not
        # a file in any layer, so it names itself instead of inventing a path.
        assert f.evidence[0].location.startswith("rich:latest:")

    from_layers = [f for f in findings if f.extra["container"]["layer_index"] >= 0]
    assert from_layers
    assert all(f.evidence[0].location.startswith("rich:latest:/")
               for f in from_layers)
    assert all(f.extra["container"]["layer_digest"].startswith("sha256:")
               for f in from_layers)


def test_whiteout_markers_are_not_themselves_reported_as_files(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    assert not any(".wh." in f.extra["container"]["path"] for f in findings)


# ==========================================================================
# Correlation
# ==========================================================================

def correlated(findings):
    assets = normalize.normalize(findings)
    return assets, correlate.correlate(assets)


def test_a_declared_capability_links_to_observed_use_in_the_same_component(tmp_path):
    """The case the directive names: capability corroborated by use."""
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    assets, links = correlated(findings)

    rsa_links = [a for a in links if a.algorithm == "rsa"]
    assert rsa_links, "RSA in the OpenSSL binary and in the openssl dependency"
    asset = rsa_links[0]
    assert asset.basis == ["component:openssl"]
    assert {d.split("/")[1] for d in asset.detectors} == {"binary", "dependency"}
    assert asset.corroborated_by_use is True
    # It is the purpose-unresolved RSA that links. The dependency declares a
    # capability and says nothing about what it is for; the binary's RSA_new
    # says the same. Neither claims more than the other.
    assert asset.purpose == P.UNKNOWN


def test_a_resolved_purpose_does_not_correlate_with_an_unresolved_one(tmp_path):
    """RSA_sign is signing. A dependency's RSA capability is not established
    as signing, so linking them would assert a purpose nobody observed.

    This is the M2 purpose guarantee reaching the correlation layer: it was
    found by the M6 benchmark, which showed the binary sensor throwing away
    the operation that the symbol name was stating outright.
    """
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    assets, links = correlated(findings)

    signing = [f for f in assets
               if f.algorithm == "rsa" and f.purpose == P.SIGNATURE]
    assert signing, "RSA_sign should resolve to a signing asset"
    for f in signing:
        assert "correlation" not in f.extra, (
            "a signing asset must not be linked to an unresolved capability")


def test_a_manifest_declaring_several_libraries_maps_to_none_of_them(tmp_path):
    """A requirements.txt is a list, not a component.

    Mapping its path to whichever library parsed first would link every
    algorithm any of them provides to every artefact of the winner -- a false
    link that reads as entirely plausible. MD5 here comes from pycryptodome,
    and there is no pycryptodome artefact in the image, so it links to nothing
    even though an OpenSSL binary in the same image also implements MD5.
    """
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    _, links = correlated(findings)

    md5_links = [a for a in links if a.algorithm == "md5"]
    assert md5_links == [], (
        "MD5 capability from pycryptodome must not attach to the OpenSSL binary")

    assert all(a.basis == ["component:openssl"] for a in links)


def test_the_inner_analyser_stays_visible_in_the_scanner_name(tmp_path):
    """Normalisation groups by scanner, so a flat name would merge analysers.

    A directory scan keeps an MD5 call site in source apart from an MD5 symbol
    in a shipped library. An image scan must too, or the inventory silently
    loses the distinction between what an application does and what a vendored
    binary can do.
    """
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    assets = normalize.normalize(findings)

    md5 = [f for f in assets if f.algorithm == "md5"]
    scanners = {f.scanner for f in md5}
    assert {"container/source", "container/binary", "container/dependency"} <= scanners
    for f in md5:
        assert len({e.location for e in f.evidence}) == 1


def test_correlation_never_promotes_capability_to_observed(tmp_path):
    """The hard rule. A link records agreement, it does not upgrade evidence."""
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    assets, links = correlated(findings)

    linked = [f for f in assets if f.extra.get("correlation")]
    assert linked
    for f in linked:
        link = f.extra["correlation"]
        assert link["own_assurance_unchanged"] == f.assurance
        if f.rule_id == "dep.provides":
            assert f.assurance == ASSURANCE_CAPABILITY
            assert f.proves_use is False


def test_correlation_does_not_change_confidence(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    assets = normalize.normalize(findings)
    before = {f.id: f.confidence for f in assets}
    correlate.correlate(assets)
    assert {f.id: f.confidence for f in assets} == before


def test_the_same_algorithm_in_unrelated_components_is_not_linked(tmp_path):
    """A shared name is not a shared asset."""
    builder = L.OCIBuilder()
    layer = L.tar_bytes([
        ("service_a/hash.py", b"import hashlib\nhashlib.md5(b'a')\n"),
        ("service_b/hash.py", b"import hashlib\nhashlib.md5(b'b')\n"),
    ], gzipped=True)
    builder.add_image([layer], tag="unrelated:1")
    archive = builder.write_tar(tmp_path / "unrelated.tar")

    findings, _ = sensor.scan(archive)
    _, links = correlated(findings)
    assert links == [], "two unrelated MD5 call sites must not become one asset"


def test_rsa_signing_and_rsa_key_establishment_never_correlate():
    """The M2 guarantee, restated against the correlation layer."""
    from conftest import make_finding

    signing = make_finding("rsa-2048", scanner="source", rule_id="py.ast.pss",
                           location="lib/crypto.py", purpose=P.SIGNATURE)
    transport = make_finding("rsa-2048", scanner="binary", rule_id="bin.symbol",
                             location="lib/crypto.py",
                             purpose=P.KEY_ESTABLISHMENT)
    links = correlate.correlate([signing, transport])
    assert links == [], (
        "same algorithm, same file, different purpose — these are two "
        "migration items and must never merge")


def test_findings_from_one_detector_are_not_linked_to_each_other():
    from conftest import make_finding

    a = make_finding("aes-128", scanner="source", rule_id="py.ast.x",
                     location="lib/a.py", purpose=P.ENCRYPTION)
    b = make_finding("aes-128", scanner="source", rule_id="py.ast.y",
                     location="lib/a.py", purpose=P.ENCRYPTION)
    assert correlate.correlate([a, b]) == []


def test_conflicting_key_sizes_are_recorded_not_resolved():
    from conftest import make_finding

    small = make_finding("rsa", scanner="source", rule_id="py.gen",
                         location="lib/x.py", purpose=P.SIGNATURE, key_size=2048)
    large = make_finding("rsa", scanner="binary", rule_id="bin.symbol",
                         location="lib/x.py", purpose=P.SIGNATURE, key_size=4096)
    links = correlate.correlate([small, large])
    assert len(links) == 1
    assert any("disagree on key size" in c for c in links[0].conflicts)


def test_correlation_leaves_unlinkable_findings_alone(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    assets, links = correlated(findings)
    linked_ids = {i for a in links for i in a.members}
    unlinked = [f for f in assets if f.id not in linked_ids]
    assert unlinked, "most findings have no corroborating peer, which is normal"
    assert all("correlation" not in f.extra for f in unlinked)


def test_correlation_summary_counts_what_it_established(tmp_path):
    archive = rich_image(tmp_path)
    findings, _ = sensor.scan(archive)
    _, links = correlated(findings)
    summary = correlate.summary(links)
    assert summary["logical_assets"] == len(links)
    assert summary["correlated_findings"] == sum(len(a.members) for a in links)
    assert summary["by_basis"].get("component")


# ==========================================================================
# The full pipeline and the CBOM
# ==========================================================================

def test_an_image_scan_runs_the_same_pipeline_as_a_directory_scan(tmp_path):
    archive = rich_image(tmp_path)
    result = orchestrator.scan_image(archive)

    assert result.target.kind == "image"
    assert result.stats["sensors_run"] == ["container"]
    assert result.findings
    assert all(f.quantum_class for f in result.findings)
    assert all(f.recommendation for f in result.findings)
    assert result.stats["correlation"]["logical_assets"] >= 1


def test_container_findings_reach_a_conforming_cbom(tmp_path):
    archive = rich_image(tmp_path)
    result = orchestrator.scan_image(archive)
    doc = cbom.build(result)

    valid, problems = cbom.validate(doc)
    assert valid, problems
    assert doc["specVersion"] == "1.6"
    assert json.loads(json.dumps(doc))         # round-trips


def test_the_cbom_preserves_image_and_layer_provenance(tmp_path):
    archive = rich_image(tmp_path)
    result = orchestrator.scan_image(archive)
    doc = cbom.build(result)

    for component in doc["components"]:
        props = {p["name"]: p["value"] for p in component["properties"]}
        assert props["container:image"] == "rich:latest"
        assert props["container:path"]
        assert props["container:state"] in ("effective", "historical")

    metadata = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert metadata["scan:targetKind"] == "image"
    assert metadata["container:archiveFormat"] == "oci-archive"
    assert int(metadata["container:findingsHistorical"]) >= 1


def test_the_cbom_marks_historical_components_as_such(tmp_path):
    archive = rich_image(tmp_path)
    result = orchestrator.scan_image(archive)
    doc = cbom.build(result)

    historical = [c for c in doc["components"]
                  if any(p["name"] == "container:effective" and p["value"] == "false"
                         for p in c["properties"])]
    assert historical, "the deleted private key must be marked, not dropped"


def test_the_cbom_carries_correlation_without_changing_assurance(tmp_path):
    archive = rich_image(tmp_path)
    result = orchestrator.scan_image(archive)
    doc = cbom.build(result)

    correlated_components = [
        c for c in doc["components"]
        if any(p["name"] == "correlation:assetId" for p in c["properties"])]
    assert correlated_components

    for component in correlated_components:
        props = {p["name"]: p["value"] for p in component["properties"]}
        assert props["correlation:basis"]
        # The component still reports its own assurance, not the group's.
        assert props["detection:assurance"] in (
            ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_USED,
            ASSURANCE_OBSERVED)


def test_directory_scanning_still_works_unchanged(tmp_path):
    """The regression that would matter most."""
    (tmp_path / "a.py").write_text(
        "import hashlib\nhashlib.sha3_512(b'x')\nhashlib.md5(b'y')\n")
    result = orchestrator.scan_target(tmp_path, sensors=["source"])

    assert result.target.kind == "repository"
    assert "sha3-512" in {f.algorithm for f in result.findings}
    assert result.stats["complete"] is True
    assert "container_format" not in result.stats
    assert not any(f.extra.get("container") for f in result.findings)


# ==========================================================================
# The HTTP surface
# ==========================================================================

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CD_DB", str(tmp_path / "scans.sqlite3"))
    monkeypatch.delenv("CD_TOKEN", raising=False)
    from fastapi.testclient import TestClient
    from app.api import app as fastapi_app
    with TestClient(fastapi_app) as c:
        yield c


def run_scan(client, **body) -> dict:
    import time as _time
    response = client.post("/api/scan", json=body)
    assert response.status_code == 200, response.text
    scan_id = response.json()["scan_id"]
    for _ in range(400):
        status = client.get(f"/api/scan/{scan_id}/status").json()
        if status["state"] in ("done", "error", "refused"):
            break
        _time.sleep(0.02)
    return {"id": scan_id, "status": status}


def test_the_api_advertises_only_formats_it_can_read(client):
    meta = client.get("/api/meta").json()
    assert set(meta["container_formats"]) == set(C.SUPPORTED_FORMATS)
    assert ".tar" in meta["container_suffixes"]


def test_inspect_endpoint_lists_the_images_in_an_archive(client, tmp_path):
    archive = rich_image(tmp_path)
    info = client.get("/api/container/inspect",
                      params={"path": str(archive)}).json()
    assert info["format"] == "oci-archive"
    assert info["images"][0]["name"] == "rich:latest"


def test_inspect_endpoint_refuses_a_non_image_with_a_reason(client, tmp_path):
    plain = tmp_path / "plain.tar"
    plain.write_bytes(L.tar_bytes([("hello.txt", b"world")]))
    response = client.get("/api/container/inspect", params={"path": str(plain)})
    assert response.status_code == 400
    assert "manifest.json" in response.json()["detail"]


def test_an_ambiguous_archive_is_rejected_at_the_request(client, tmp_path):
    """The operator finds out immediately, not from an empty result later."""
    builder = L.OCIBuilder()
    layer = L.tar_bytes([("a.py", b"import hashlib\nhashlib.md5(b'x')\n")],
                        gzipped=True)
    builder.add_image([layer], tag="svc:amd64", platform=("linux", "amd64"))
    builder.add_image([layer], tag="svc:arm64", platform=("linux", "arm64"))
    archive = builder.write_tar(tmp_path / "multi.tar")

    response = client.post("/api/scan", json={"path": str(archive),
                                              "target_kind": "image"})
    assert response.status_code == 400
    assert "none was selected" in response.json()["detail"]


def test_an_image_scan_completes_through_the_api(client, tmp_path):
    archive = rich_image(tmp_path)
    run = run_scan(client, path=str(archive), target_kind="image")
    assert run["status"]["state"] == "done"

    payload = client.get(f"/api/scan/{run['id']}").json()
    assert payload["container"]["format"] == "oci-archive"
    assert payload["container"]["image"] == "rich:latest"
    assert payload["container"]["layers"] == 2
    assert payload["container"]["findings_historical"] >= 1
    assert payload["correlation"]["logical_assets"] >= 1
    assert payload["logical_assets"]


def test_an_image_scan_exports_a_valid_cbom_through_the_api(client, tmp_path):
    archive = rich_image(tmp_path)
    run = run_scan(client, path=str(archive), target_kind="image")

    doc = client.get(f"/api/scan/{run['id']}/cbom").json()
    assert doc["specVersion"] == "1.6"

    validation = client.get(f"/api/scan/{run['id']}/cbom/validate").json()
    assert validation["valid"] is True, validation["problems"]
    # The structural check must keep saying what it actually checks...
    assert "NOT full schema conformance" in validation["structural"]["note"]
    # ...and a container CBOM must pass the official schema too.
    assert validation["official"]["checked"] is True
    assert validation["official"]["valid"] is True, validation["official"]["problems"]


def test_a_directory_scan_through_the_api_is_unaffected(client, tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.sha3_512(b'x')\n")
    run = run_scan(client, path=str(tmp_path), target_kind="directory")
    assert run["status"]["state"] == "done"

    payload = client.get(f"/api/scan/{run['id']}").json()
    assert payload["container"] == {}
    assert "sha3-512" in {f["algorithm"] for f in payload["findings"]}


def test_a_directory_passed_as_an_image_is_refused(client, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    response = client.post("/api/scan", json={"path": str(tmp_path),
                                              "target_kind": "image"})
    assert response.status_code == 400
    assert "OCI image layout" in response.json()["detail"]


def test_an_unknown_target_kind_is_rejected_by_the_schema(client, tmp_path):
    response = client.post("/api/scan", json={"path": str(tmp_path),
                                              "target_kind": "kubernetes"})
    assert response.status_code == 422

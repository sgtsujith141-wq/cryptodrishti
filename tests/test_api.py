"""HTTP surface.

The console is the demo, so these exercise the routes it actually calls,
against a temporary database so a test run never touches real scan history.
"""

from __future__ import annotations

import time

import pytest


@pytest.fixture(scope="module")
def client():
    # conftest already redirected CD_DB to a temporary database at import time.
    from fastapi.testclient import TestClient
    from app.api import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    d = tmp_path_factory.mktemp("target")
    (d / "crypto.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def k(): return rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        "def h(d): return hashlib.md5(d).hexdigest()\n"
    )
    return str(d)


@pytest.fixture(scope="module")
def completed_scan(client, target):
    scan_id = client.post("/api/scan", json={"path": target}).json()["scan_id"]
    for _ in range(100):
        status = client.get(f"/api/scan/{scan_id}/status").json()
        if status["state"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert status["state"] == "done", status
    return scan_id


# --------------------------------------------------------------------------
# Static surfaces
# --------------------------------------------------------------------------

def test_index_serves_the_console(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "CryptoDrishti" in r.text


def test_meta_exposes_the_profiles_and_qday_defaults(client):
    m = client.get("/api/meta").json()
    assert m["product"] == "CryptoDrishti"
    assert set(m["profiles"]) >= {"general", "high-assurance", "constrained", "long-lived"}
    q = m["qday_default"]
    assert q["earliest"] <= q["likely"] <= q["latest"]


def test_the_algorithm_registry_is_served_to_the_console(client):
    algorithms = client.get("/api/knowledge/algorithms").json()["algorithms"]
    assert len(algorithms) > 40
    keys = {a["key"] for a in algorithms}
    assert {"rsa-2048", "ml-kem-768", "aes-256"} <= keys


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def test_a_scan_runs_to_completion_and_finds_the_defects(client, completed_scan):
    payload = client.get(f"/api/scan/{completed_scan}").json()
    assert payload["findings"], "the fixture contains RSA-1024 and MD5"
    algorithms = {f["algorithm"] for f in payload["findings"]}
    assert any(a.startswith("rsa") for a in algorithms)
    assert "md5" in algorithms


def test_status_of_an_unknown_scan_is_404(client):
    assert client.get("/api/scan/does-not-exist/status").status_code == 404


def test_a_completed_scan_appears_in_the_history(client, completed_scan):
    scans = client.get("/api/scans").json()["scans"]
    assert any(s["id"] == completed_scan for s in scans)


def test_scanning_a_nonexistent_path_is_refused_before_a_job_is_started(client):
    """A bad target fails at the request, not a second later in a background job.

    The root is vetted synchronously so the operator gets the reason straight
    away instead of watching a progress bar that was never going to finish.
    """
    response = client.post("/api/scan", json={"path": "/no/such/path/xyz"})
    assert response.status_code == 400
    assert "resolve" in response.json()["detail"].lower()


# --------------------------------------------------------------------------
# CBOM export
# --------------------------------------------------------------------------

def test_cbom_export_is_cyclonedx_1_6(client, completed_scan):
    doc = client.get(f"/api/scan/{completed_scan}/cbom").json()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"


def test_cbom_validation_endpoint_passes_and_states_its_scope(client, completed_scan):
    v = client.get(f"/api/scan/{completed_scan}/cbom/validate").json()
    assert v["valid"] is True
    assert v["problems"] == []
    # The endpoint must not imply a full JSON-Schema validation it does not do.
    assert "not a full" in v["note"].lower()


def test_cbom_for_an_unknown_scan_is_404(client):
    assert client.get("/api/scan/nope/cbom").status_code == 404


# --------------------------------------------------------------------------
# Q-Day re-scoring: the interaction that makes Mosca tangible
# --------------------------------------------------------------------------

def test_an_earlier_qday_raises_the_estate_risk(client, completed_scan):
    late = client.post("/api/qday", json={
        "scan_id": completed_scan, "earliest": 2040, "likely": 2050,
        "latest": 2060, "sensitivity": "internal", "persist": False,
    }).json()
    early = client.post("/api/qday", json={
        "scan_id": completed_scan, "earliest": 2027, "likely": 2029,
        "latest": 2032, "sensitivity": "restricted", "persist": False,
    }).json()
    assert early["summary"]["mean_risk"] > late["summary"]["mean_risk"]


def test_qday_rejects_an_incoherent_distribution(client, completed_scan):
    r = client.post("/api/qday", json={
        "scan_id": completed_scan, "earliest": 2050, "likely": 2030,
        "latest": 2040, "sensitivity": "internal", "persist": False,
    })
    assert r.status_code == 400


def test_qday_for_an_unknown_scan_is_404(client):
    r = client.post("/api/qday", json={
        "scan_id": "nope", "earliest": 2030, "likely": 2034,
        "latest": 2044, "sensitivity": "internal", "persist": False,
    })
    assert r.status_code == 404


# --------------------------------------------------------------------------
# Folder picker
# --------------------------------------------------------------------------

def test_browse_lists_directories(client, tmp_path):
    (tmp_path / "child").mkdir()
    r = client.get("/api/browse", params={"path": str(tmp_path)}).json()
    assert "child" in {e["name"] for e in r["entries"]}


def test_browse_of_a_missing_path_is_404(client):
    assert client.get("/api/browse", params={"path": "/no/such/dir/xyz"}).status_code == 404

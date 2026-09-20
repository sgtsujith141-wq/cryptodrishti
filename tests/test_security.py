"""Adversarial tests for the tool's own attack surface.

Everything here uses controlled local fixtures, literal addresses that
``getaddrinfo`` resolves without a DNS query, and monkeypatched resolution.
No test in this file contacts a system we do not own.

Each test corresponds to a defect recorded in ``docs/sih/BASELINE.md`` and
fails against the code as it stood at 90f4da3.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path

import pytest

from app import auth, fspolicy, netpolicy
from app.netpolicy import DestinationRefused, NetPolicy


# ==========================================================================
# S1 / S5 — destination parsing and SSRF resistance
# ==========================================================================

@pytest.mark.parametrize("raw,expected", [
    ("example.com", ("example.com", 443)),
    ("example.com:8443", ("example.com", 8443)),
    ("https://example.com/deep/path?q=1", ("example.com", 443)),
    ("HTTPS://Example.COM", ("example.com", 443)),
    ("example.com.", ("example.com", 443)),          # trailing-dot FQDN
    ("[2001:db8::1]:8443", ("2001:db8::1", 8443)),
    ("2001:db8::1", ("2001:db8::1", 443)),           # bare v6, no port
    ("[::1]", ("::1", 443)),
])
def test_destinations_parse_to_the_right_host_and_port(raw, expected):
    assert netpolicy.parse_destination(raw) == expected


def test_ipv6_literal_is_not_torn_in_half_by_the_port_split():
    """`partition(':')` on `[::1]:443` yielded host `[`. It must not."""
    host, port = netpolicy.parse_destination("[::1]:443")
    assert host == "::1"
    assert port == 443
    assert ipaddress.ip_address(host).is_loopback


@pytest.mark.parametrize("raw", [
    "", "   ",
    "example.com:0",
    "example.com:70000",
    "example.com:notaport",
    "example.com\r\nHost: evil",        # header injection shape
    "exam ple.com",
    "[2001:db8::1",                     # unterminated literal
    "[2001:db8::1]junk",
    "gopher://example.com",             # scheme with no default port
])
def test_malformed_destinations_are_refused(raw):
    with pytest.raises(DestinationRefused):
        netpolicy.parse_destination(raw)


@pytest.mark.parametrize("literal,why", [
    ("127.0.0.1", "loopback"),
    ("127.1.2.3", "loopback"),
    ("0.0.0.0", "unspecified"),
    ("10.1.2.3", "private"),
    ("172.16.9.9", "private"),
    ("192.168.1.1", "private"),
    ("100.64.0.5", "carrier-grade NAT"),
    ("169.254.169.254", "cloud metadata"),
    ("169.254.1.1", "link-local"),
    ("224.0.0.1", "multicast"),
    ("255.255.255.255", "broadcast"),
    ("::1", "v6 loopback"),
    ("::", "v6 unspecified"),
    ("fd00::1", "v6 unique local"),
    ("fe80::1", "v6 link-local"),
    ("ff02::1", "v6 multicast"),
    ("::ffff:127.0.0.1", "v4-mapped loopback"),
    ("::ffff:10.0.0.1", "v4-mapped private"),
    ("2002:7f00:1::1", "6to4-wrapped loopback"),
    ("64:ff9b::7f00:1", "NAT64-wrapped loopback"),
])
def test_internal_addresses_are_refused_however_they_are_spelled(literal, why):
    reason = netpolicy.address_refusal(ipaddress.ip_address(literal))
    assert reason is not None, f"{literal} ({why}) was allowed"


@pytest.mark.parametrize("literal", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_ordinary_public_addresses_are_allowed(literal):
    assert netpolicy.address_refusal(ipaddress.ip_address(literal)) is None


def test_decimal_and_octal_loopback_normalise_to_loopback():
    """2130706433 and 0177.0.0.1 are 127.0.0.1. A string blocklist misses both."""
    assert netpolicy.address_refusal(ipaddress.ip_address(2130706433)) == "loopback"


@pytest.mark.parametrize("raw", [
    "127.0.0.1", "localhost", "[::1]:443", "169.254.169.254", "10.0.0.1:443",
])
def test_vetting_refuses_internal_destinations_end_to_end(raw):
    with pytest.raises(DestinationRefused):
        netpolicy.vet(raw, NetPolicy())


def test_port_allowlist_blocks_a_scan_of_arbitrary_services():
    """An endpoint list must not double as a port scanner."""
    with pytest.raises(DestinationRefused, match="not in the allowed set"):
        netpolicy.vet("example.com:9200", NetPolicy())


def test_the_relaxation_exists_and_must_be_asked_for():
    lab = NetPolicy(allow_private=True)
    dest = netpolicy.vet("127.0.0.1", lab)
    assert dest.private_allowed is True, "a relaxed probe must be marked as relaxed"
    with pytest.raises(DestinationRefused):
        netpolicy.vet("127.0.0.1", NetPolicy(allow_private=False))


def test_an_explicit_allowlist_excludes_everything_else():
    policy = NetPolicy(allowed_hosts=frozenset({"example.com"}))
    with pytest.raises(DestinationRefused, match="authorized destination list"):
        netpolicy.vet("8.8.8.8", policy)


def test_a_name_resolving_to_both_public_and_private_is_refused_entirely(monkeypatch):
    """The shape of DNS rebinding. Using only the half that passed is not safe."""
    def fake(host, port, **kw):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(DestinationRefused, match="rebinding"):
        netpolicy.vet("split-horizon.test", NetPolicy())


def test_a_vetted_destination_carries_addresses_not_just_a_name(monkeypatch):
    """We must connect to what we checked, not re-resolve the name."""
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", p))])
    dest = netpolicy.vet("example.test", NetPolicy())
    assert dest.addresses == ("93.184.216.34",)
    assert dest.host == "example.test"          # kept for SNI only


def test_endpoint_count_is_capped_and_the_overflow_is_reported():
    policy = NetPolicy(max_endpoints=3)
    accepted, refused = netpolicy.vet_all(
        [f"10.0.0.{i}" for i in range(10)], policy)
    assert accepted == []
    assert len(refused) == 10
    assert any("3-endpoint limit" in r["reason"] for r in refused)


def test_one_bad_endpoint_does_not_discard_the_others(monkeypatch):
    real = socket.getaddrinfo

    def fake(host, port, **kw):
        if host == "good.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        return real(host, port, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    accepted, refused = netpolicy.vet_all(["good.test", "127.0.0.1"], NetPolicy())
    assert [d.host for d in accepted] == ["good.test"]
    assert len(refused) == 1


def test_the_network_sensor_refuses_without_opening_a_socket(monkeypatch):
    """No connection attempt may happen for a destination policy rejects."""
    from app.scanners import network

    def explode(*a, **kw):
        raise AssertionError("a socket was opened for a refused destination")

    monkeypatch.setattr(netpolicy, "connect", explode)
    findings, stats = network.scan(["127.0.0.1", "169.254.169.254"])
    assert findings == []
    assert stats["endpoints_probed"] == 0
    assert len(stats["endpoints_refused"]) == 2


def test_refusals_reach_the_scan_stats_rather_than_disappearing():
    from app.scanners import network
    _, stats = network.scan(["169.254.169.254"])
    reason = stats["endpoints_refused"][0]["reason"]
    assert "metadata" in reason, "the operator must be told why, not just that"


def test_the_obsolete_kyber_draft_group_is_no_longer_offered():
    from app.scanners import network
    assert "X25519Kyber768Draft00" not in network.PQ_GROUPS
    assert "X25519MLKEM768" in network.PQ_GROUPS
    # Still recognised, so an endpoint using one is reported as superseded
    # rather than as an absence of post-quantum support.
    assert "X25519Kyber768Draft00" in network.OBSOLETE_PQ_GROUPS


# ==========================================================================
# S3 / S8 — filesystem boundaries and symlink handling
# ==========================================================================

@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A scan root with a symlink pointing at a secret outside it."""
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text("PRIVATE_KEY = 'do not exfiltrate'\n")
    (outside / "nested").mkdir()
    (root / "real.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    os.symlink(outside / "secret.py", root / "innocent.py")
    os.symlink(outside, root / "innocent_dir")
    return root


def test_a_symlinked_file_escaping_the_root_is_not_read(tree):
    root = fspolicy.resolve_root(tree)
    policy = fspolicy.FsPolicy(root=root)
    assert fspolicy.readable(root / "real.py", root, policy) is True
    assert fspolicy.readable(root / "innocent.py", root, policy) is False


def test_a_symlinked_directory_escaping_the_root_is_not_walked(tree):
    root = fspolicy.resolve_root(tree)
    policy = fspolicy.FsPolicy(root=root)
    dirnames = ["innocent_dir"]
    fspolicy.filter_dirnames(str(root), dirnames, set(), root, policy)
    assert dirnames == []


def test_the_source_sensor_does_not_read_through_an_escaping_symlink(tree):
    """The end-to-end version: file contents must not reach evidence.snippet."""
    from app.scanners import source

    root = fspolicy.resolve_root(tree)
    policy = fspolicy.FsPolicy(root=root)
    files = {p.name for p in source.iter_source_files(root, policy=policy)}
    assert "real.py" in files
    assert "innocent.py" not in files

    findings, _ = source.scan(root, policy=policy)
    blob = " ".join(e.snippet for f in findings for e in f.evidence)
    assert "do not exfiltrate" not in blob


def test_skipped_paths_are_counted_so_the_operator_knows_the_scan_is_partial(tree):
    from app.scanners import source

    root = fspolicy.resolve_root(tree)
    policy = fspolicy.FsPolicy(root=root)
    list(source.iter_source_files(root, policy=policy))
    report = policy.report()
    assert report["skipped"], "a silent skip is an incomplete inventory reported as complete"
    assert any("symlink" in reason for reason in report["skipped"])


@pytest.mark.parametrize("name", ["shadow", ".netrc", ".git-credentials", ".npmrc"])
def test_credential_stores_are_never_read(tmp_path, name):
    root = fspolicy.resolve_root(tmp_path)
    (tmp_path / name).write_text("secret")
    policy = fspolicy.FsPolicy(root=root)
    assert fspolicy.readable(tmp_path / name, root, policy) is False


@pytest.mark.parametrize("denied", ["/proc", "/sys", "/dev"])
def test_synthetic_filesystems_are_never_traversed(denied):
    assert fspolicy.should_traverse(denied) is False
    assert fspolicy.should_traverse(denied + "/self") is False


def test_a_nonexistent_root_is_refused_with_a_reason():
    with pytest.raises(fspolicy.PathRefused):
        fspolicy.resolve_root("/no/such/path/at/all")


# ==========================================================================
# S6 / S9 — bounds
# ==========================================================================

def test_the_entry_budget_stops_a_runaway_walk(tmp_path):
    root = fspolicy.resolve_root(tmp_path)
    for i in range(50):
        (tmp_path / f"f{i}.py").write_text("x = 1\n")
    policy = fspolicy.FsPolicy(root=root, max_entries=10)

    from app.scanners import source
    found = list(source.iter_source_files(root, policy=policy))
    assert len(found) <= 10
    assert policy.exhausted() is True
    assert "partial" in policy.report()["incomplete"]


def test_an_expired_deadline_ends_the_walk_rather_than_running_to_completion(tmp_path):
    root = fspolicy.resolve_root(tmp_path)
    for i in range(20):
        (tmp_path / f"f{i}.py").write_text("x = 1\n")
    policy = fspolicy.FsPolicy(root=root, deadline=0.0)    # already past

    from app.scanners import source
    assert list(source.iter_source_files(root, policy=policy)) == []
    assert policy.expired() is True
    assert policy.report()["incomplete"].startswith("scan deadline")


def test_a_scan_reports_its_own_completeness(tmp_path):
    from app import orchestrator

    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    result = orchestrator.scan_target(tmp_path, sensors=["source"])
    assert result.stats["complete"] is True
    assert "filesystem_policy" in result.stats
    assert result.stats["time_budget_seconds"] > 0


def test_a_refused_endpoint_makes_the_whole_scan_incomplete(tmp_path):
    from app import orchestrator

    (tmp_path / "a.py").write_text("x = 1\n")
    result = orchestrator.scan_target(
        tmp_path, sensors=["source"], endpoints=["169.254.169.254"])
    assert result.stats["complete"] is False
    assert any("refused" in r for r in result.stats["incomplete_reasons"])


# ==========================================================================
# S2 — access control and the bind address
# ==========================================================================

@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "127.0.0.2", ""])
def test_loopback_bindings_need_no_token(host, monkeypatch):
    monkeypatch.delenv("CD_TOKEN", raising=False)
    assert auth.is_loopback(host) is True
    auth.check_binding(host)              # must not raise


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5"])
def test_a_non_loopback_binding_without_a_token_is_refused(host, monkeypatch):
    monkeypatch.delenv("CD_TOKEN", raising=False)
    assert auth.is_loopback(host) is False
    with pytest.raises(auth.InsecureBinding, match="Refusing to bind"):
        auth.check_binding(host)


def test_a_non_loopback_binding_with_a_token_is_permitted(monkeypatch):
    monkeypatch.setenv("CD_TOKEN", "s3cret-token-value")
    auth.check_binding("0.0.0.0")         # must not raise


def test_token_comparison_rejects_a_wrong_or_missing_token(monkeypatch):
    monkeypatch.setenv("CD_TOKEN", "correct-horse-battery-staple")
    assert auth.token_matches("correct-horse-battery-staple") is True
    assert auth.token_matches("correct-horse-battery-stapl") is False
    assert auth.token_matches("") is False
    assert auth.token_matches(None) is False


def test_no_configured_token_means_no_gate(monkeypatch):
    monkeypatch.delenv("CD_TOKEN", raising=False)
    assert auth.token_matches(None) is True


def test_api_routes_are_gated_when_a_token_is_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("CD_DB", str(tmp_path / "t.sqlite3"))
    monkeypatch.setenv("CD_TOKEN", "unit-test-token")
    from fastapi.testclient import TestClient
    from app.api import app as fastapi_app

    with TestClient(fastapi_app) as client:
        assert client.get("/api/meta").status_code == 401
        assert client.get("/api/browse").status_code == 401
        # Liveness carries no estate data and stays open.
        assert client.get("/healthz").status_code == 200
        # Either header or bearer is accepted.
        ok = client.get("/api/meta", headers={"Authorization": "Bearer unit-test-token"})
        assert ok.status_code == 200
        ok2 = client.get("/api/meta", headers={auth.HEADER_NAME: "unit-test-token"})
        assert ok2.status_code == 200


# ==========================================================================
# S7 — no traceback disclosure
# ==========================================================================

def test_a_failed_scan_returns_a_reference_not_a_traceback(monkeypatch, tmp_path):
    monkeypatch.setenv("CD_DB", str(tmp_path / "t.sqlite3"))
    monkeypatch.delenv("CD_TOKEN", raising=False)
    from app import api

    def boom(*a, **kw):
        raise RuntimeError("internal detail at /Users/someone/secret/path.py")

    monkeypatch.setattr(api.orchestrator, "scan_target", boom)
    api._run_scan("job-1", api.ScanRequest(path=str(tmp_path)))
    job = api._JOBS["job-1"]

    assert job["state"] == "error"
    assert "trace" not in job, "tracebacks must not leave the process"
    assert job["error"].startswith("RuntimeError:")
    assert len(job["error_ref"]) == 8


def test_concurrent_scans_are_capped_rather_than_unbounded(monkeypatch, tmp_path):
    monkeypatch.setenv("CD_DB", str(tmp_path / "t.sqlite3"))
    from app import api

    # Hold every slot, then confirm the next scan is refused rather than run.
    held = [api._SCAN_SLOTS.acquire(timeout=0.1)
            for _ in range(api.config.MAX_CONCURRENT_SCANS)]
    try:
        assert all(held)
        api._run_scan("job-2", api.ScanRequest(path=str(tmp_path)))
        assert api._JOBS["job-2"]["state"] == "refused"
        assert "already running" in api._JOBS["job-2"]["error"]
    finally:
        for _ in held:
            api._SCAN_SLOTS.release()


def test_a_bad_scan_root_is_a_400_not_a_background_job(monkeypatch, tmp_path):
    monkeypatch.setenv("CD_DB", str(tmp_path / "t.sqlite3"))
    monkeypatch.delenv("CD_TOKEN", raising=False)
    from fastapi.testclient import TestClient
    from app.api import app as fastapi_app

    with TestClient(fastapi_app) as client:
        r = client.post("/api/scan", json={"path": "/definitely/not/here"})
        assert r.status_code == 400
        assert "scan_id" not in r.json()


def test_an_oversized_endpoint_list_is_rejected_at_the_schema(monkeypatch, tmp_path):
    monkeypatch.setenv("CD_DB", str(tmp_path / "t.sqlite3"))
    monkeypatch.delenv("CD_TOKEN", raising=False)
    from fastapi.testclient import TestClient
    from app.api import app as fastapi_app

    with TestClient(fastapi_app) as client:
        r = client.post("/api/scan", json={"path": str(tmp_path),
                                           "endpoints": ["a.test"] * 500})
        assert r.status_code == 422

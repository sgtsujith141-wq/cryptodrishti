"""Adversarial tests for container archive handling.

An image is an archive that came from somewhere else, and the classic way to
lose a machine to one is to call ``extractall``. Every test here builds a
hostile archive in a temporary directory, feeds it to the reader, and asserts
that the hostile member was refused *and counted* -- a silent skip would mean
reporting an incomplete image as complete.

Nothing here writes outside ``tmp_path``, contacts a network, or requires a
container runtime.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
from pathlib import Path

import pytest

from app import container as C
from app.container import ArchiveLimits, ArchiveStats, ContainerError

import imagelab as L


def read_members(blob: bytes, limits: ArchiveLimits | None = None):
    """Run the reader over one tar and return (members, stats)."""
    limits = limits or ArchiveLimits()
    stats = ArchiveStats()
    members = list(C.iter_tar_members(io.BytesIO(blob), limits, stats))
    return members, stats


# ==========================================================================
# Path traversal and absolute paths
# ==========================================================================

def test_upward_traversal_members_are_refused():
    blob = L.tar_bytes([("../../etc/passwd", b"root:x:0:0"),
                        ("safe.txt", b"fine")])
    members, stats = read_members(blob)
    assert [m.path for m in members] == ["safe.txt"]
    assert "member path traverses upward" in stats.refused


def test_absolute_member_paths_are_refused():
    blob = L.tar_bytes([("etc/shadow", b"secret")], absolute=True)
    members, stats = read_members(blob)
    assert members == []
    assert "absolute member path" in stats.refused


def test_a_windows_drive_letter_is_refused():
    blob = L.tar_bytes([("C:\\Windows\\System32\\config", b"x")])
    _, stats = read_members(blob)
    assert "absolute member path with a drive letter" in stats.refused


def test_control_characters_in_a_name_are_refused():
    blob = L.tar_bytes([("evil\nname.txt", b"x")])
    _, stats = read_members(blob)
    assert "member name contains control characters" in stats.refused


def test_an_over_long_path_is_refused():
    limits = ArchiveLimits(max_path_length=64)
    blob = L.tar_bytes([("a/" * 80 + "f.txt", b"x")])
    _, stats = read_members(blob, limits)
    assert "member path exceeds the length limit" in stats.refused


# ==========================================================================
# Link escapes
# ==========================================================================

def test_a_symlink_to_an_absolute_path_is_refused():
    blob = L.tar_bytes([("keep.txt", b"x")],
                       links=[("link", "/etc/passwd", "sym")])
    _, stats = read_members(blob)
    assert "link to an absolute path" in stats.refused


def test_a_symlink_escaping_the_archive_root_is_refused():
    """`a/b -> ../../etc/passwd` escapes though neither name looks wrong."""
    blob = L.tar_bytes([("a/keep.txt", b"x")],
                       links=[("a/b", "../../etc/passwd", "sym")])
    _, stats = read_members(blob)
    assert "link escaping the archive root" in stats.refused


def test_a_hard_link_escaping_the_archive_root_is_refused():
    blob = L.tar_bytes([("a/keep.txt", b"x")],
                       links=[("a/h", "../../../root/.ssh/id_rsa", "hard")])
    _, stats = read_members(blob)
    assert "link escaping the archive root" in stats.refused


def test_a_link_that_stays_inside_is_allowed_but_carries_no_content():
    blob = L.tar_bytes([("a/real.txt", b"payload")],
                       links=[("a/alias.txt", "real.txt", "sym")])
    members, stats = read_members(blob)
    paths = {m.path for m in members}
    assert "a/real.txt" in paths
    assert "a/alias.txt" in paths
    alias = next(m for m in members if m.path == "a/alias.txt")
    assert alias.data == b"", "a link must never be read as though it had content"


def test_a_link_with_no_target_is_refused():
    blob = L.tar_bytes([("keep.txt", b"x")], links=[("dangling", "", "sym")])
    _, stats = read_members(blob)
    assert "link with no target" in stats.refused


# ==========================================================================
# Special files
# ==========================================================================

@pytest.mark.parametrize("kind,reason", [
    (tarfile.CHRTYPE, "device node"),
    (tarfile.BLKTYPE, "device node"),
    (tarfile.FIFOTYPE, "FIFO"),
])
def test_special_files_are_refused(kind, reason):
    blob = L.tar_bytes([("keep.txt", b"x")], specials=[("dev/thing", kind)])
    members, stats = read_members(blob)
    assert reason in stats.refused
    assert [m.path for m in members] == ["keep.txt"]


# ==========================================================================
# Resource exhaustion
# ==========================================================================

def test_an_oversized_member_is_refused_before_it_is_read():
    limits = ArchiveLimits(max_member_bytes=1024)
    blob = L.tar_bytes([("big.bin", b"A" * 5000), ("small.txt", b"ok")])
    members, stats = read_members(blob, limits)
    assert [m.path for m in members] == ["small.txt"]
    assert "member exceeds the per-file size limit" in stats.refused


def test_the_total_byte_budget_stops_a_decompression_bomb():
    """A bomb is bounded by the budget, not by the disk -- we never write."""
    limits = ArchiveLimits(max_total_bytes=4096, max_member_bytes=4096)
    blob = L.tar_bytes([(f"f{i}.bin", b"A" * 2000) for i in range(20)])
    members, stats = read_members(blob, limits)
    assert stats.bytes_read <= 4096
    assert len(members) < 20
    assert stats.truncated is True
    assert "total uncompressed size budget exhausted" in stats.refused


def test_the_member_count_budget_is_enforced():
    limits = ArchiveLimits(max_members=5)
    blob = L.tar_bytes([(f"f{i}.txt", b"x") for i in range(50)])
    members, stats = read_members(blob, limits)
    assert len(members) <= 5
    assert stats.truncated is True
    assert "member budget exhausted" in stats.refused


def test_nesting_deeper_than_the_limit_is_refused():
    limits = ArchiveLimits(max_depth=1)
    stats = ArchiveStats()
    blob = L.tar_bytes([("inner.txt", b"x")])
    members = list(C.iter_tar_members(io.BytesIO(blob), limits, stats, depth=2))
    assert members == []
    assert "archive nesting deeper than the limit" in stats.refused


def test_an_expired_deadline_stops_the_read_and_says_so():
    limits = ArchiveLimits(deadline=time.monotonic() - 1)
    blob = L.tar_bytes([(f"f{i}.txt", b"x") for i in range(10)])
    members, stats = read_members(blob, limits)
    assert members == []
    assert stats.truncated is True
    assert any("time budget" in n for n in stats.notes)


# ==========================================================================
# Malformed and unsupported input
# ==========================================================================

def test_a_corrupt_tar_fails_with_a_clear_message(tmp_path):
    bad = tmp_path / "broken.tar"
    bad.write_bytes(b"this is definitely not a tar archive" * 40)
    with pytest.raises(ContainerError) as excinfo:
        C.open_archive(bad)
    assert "not a readable tar archive" in str(excinfo.value)


def test_an_unsupported_extension_is_named_not_guessed(tmp_path):
    bad = tmp_path / "image.rar"
    bad.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 100)
    with pytest.raises(ContainerError) as excinfo:
        C.open_archive(bad)
    assert "supported image archive" in str(excinfo.value)


def test_a_tar_that_is_not_an_image_is_refused_with_a_reason(tmp_path):
    plain = tmp_path / "notanimage.tar"
    plain.write_bytes(L.tar_bytes([("hello.txt", b"world")]))
    with pytest.raises(ContainerError) as excinfo:
        C.open_archive(plain)
    message = str(excinfo.value)
    assert "neither an OCI index.json nor a Docker manifest.json" in message
    assert "Supported formats" in message


def test_malformed_image_metadata_fails_clearly(tmp_path):
    archive = tmp_path / "badmeta.tar"
    archive.write_bytes(L.tar_bytes([
        ("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'),
        ("index.json", b"{ this is not json"),
    ]))
    with pytest.raises(ContainerError) as excinfo:
        C.open_archive(archive)
    assert "not valid JSON" in str(excinfo.value)


def test_an_index_with_no_manifests_is_refused(tmp_path):
    archive = tmp_path / "empty.tar"
    archive.write_bytes(L.tar_bytes([
        ("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'),
        ("index.json", json.dumps({"schemaVersion": 2, "manifests": []}).encode()),
    ]))
    with pytest.raises(ContainerError, match="no manifests"):
        C.open_archive(archive)


def test_a_manifest_entry_with_a_malformed_digest_is_skipped(tmp_path):
    builder = L.OCIBuilder()
    builder.add_image([L.tar_bytes([("a.txt", b"x")])], tag="good:1")
    index = builder.index()
    index["manifests"].append({"mediaType": index["manifests"][0]["mediaType"],
                               "digest": "notadigest", "size": 1})
    archive = builder.write_tar(tmp_path / "mixed.tar", index_override=index)

    info = C.inspect(archive)
    assert len(info["images"]) == 1
    assert "manifest entry with a malformed digest" in info["archive"]["refused"]


def test_a_missing_layer_blob_is_reported_not_silently_empty(tmp_path):
    builder = L.OCIBuilder()
    layer = L.tar_bytes([("app/x.py", L.CRYPTO_APP_PY)], gzipped=True)
    builder.add_image([layer], tag="holey:1")
    # Drop the layer blob, keeping the manifest that references it.
    del builder.blobs[L.digest_of(layer)]
    archive = builder.write_tar(tmp_path / "holey.tar")

    from app.scanners import container as sensor
    findings, stats = sensor.scan(archive)
    assert findings == []
    refused = stats["container_archive_stats"]["refused"]
    assert "layer blob missing from the archive" in refused


def test_a_zstd_layer_is_named_rather_than_reported_empty(tmp_path):
    """The standard library cannot decompress zstd. Say so, do not pretend."""
    builder = L.OCIBuilder()
    builder.add_image(
        [b"not really zstd"], tag="zstd:1",
        layer_media="application/vnd.oci.image.layer.v1.tar+zstd")
    archive = builder.write_tar(tmp_path / "zstd.tar")

    from app.scanners import container as sensor
    findings, stats = sensor.scan(archive)
    assert findings == []
    refused = stats["container_archive_stats"]["refused"]
    assert any("zstd" in reason for reason in refused)


# ==========================================================================
# Multiple images must never be resolved silently
# ==========================================================================

def test_a_multi_image_archive_without_a_selector_is_refused(tmp_path):
    builder = L.OCIBuilder()
    layer = L.tar_bytes([("a.py", b"import hashlib\nhashlib.md5(b'x')\n")], gzipped=True)
    builder.add_image([layer], tag="app:amd64", platform=("linux", "amd64"))
    builder.add_image([layer], tag="app:arm64", platform=("linux", "arm64"))
    archive = builder.write_tar(tmp_path / "multi.tar")

    from app.scanners import container as sensor
    with pytest.raises(ContainerError) as excinfo:
        sensor.scan(archive)
    message = str(excinfo.value)
    assert "2 images and none was selected" in message
    assert "app:amd64" in message and "app:arm64" in message


def test_a_multi_image_archive_scans_the_named_image(tmp_path):
    builder = L.OCIBuilder()
    amd = L.tar_bytes([("amd.py", b"import hashlib\nhashlib.md5(b'x')\n")], gzipped=True)
    arm = L.tar_bytes([("arm.py", b"import hashlib\nhashlib.sha1(b'x')\n")], gzipped=True)
    builder.add_image([amd], tag="app:amd64", platform=("linux", "amd64"))
    builder.add_image([arm], tag="app:arm64", platform=("linux", "arm64"))
    archive = builder.write_tar(tmp_path / "multi.tar")

    from app.scanners import container as sensor
    findings, stats = sensor.scan(archive, image="app:arm64")
    assert stats["container_image"] == "app:arm64"
    assert {f.algorithm for f in findings} == {"sha1"}
    assert len(stats["container_images_available"]) == 2


def test_an_unknown_selector_names_the_available_images(tmp_path):
    builder = L.OCIBuilder()
    builder.add_image([L.tar_bytes([("a.txt", b"x")])], tag="real:1")
    archive = builder.write_tar(tmp_path / "one.tar")

    from app.scanners import container as sensor
    with pytest.raises(ContainerError) as excinfo:
        sensor.scan(archive, image="nosuch:9")
    assert "Available: real:1" in str(excinfo.value)


# ==========================================================================
# Nothing is ever written outside the caller's own space
# ==========================================================================

def test_scanning_an_image_writes_nothing_to_disk(tmp_path, monkeypatch):
    """The reader streams into memory. Any file creation is a bug."""
    builder = L.OCIBuilder()
    layer = L.tar_bytes([("app/main.py", L.CRYPTO_APP_PY),
                         ("etc/nginx.conf", L.NGINX_CONF)], gzipped=True)
    builder.add_image([layer], tag="nowrite:1")
    archive = builder.write_tar(tmp_path / "nowrite.tar")

    before = {p for p in tmp_path.rglob("*")}

    opened: list[str] = []
    real_open = io.open

    def watched_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
            opened.append(f"{file}:{mode}")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(io, "open", watched_open)

    from app.scanners import container as sensor
    findings, _ = sensor.scan(archive)
    assert findings

    assert opened == [], f"the scan opened files for writing: {opened}"
    assert {p for p in tmp_path.rglob("*")} == before


def test_a_hostile_layer_does_not_stop_the_rest_of_the_image(tmp_path):
    """One bad member is a normal condition, not a dead scan."""
    hostile = L.tar_bytes(
        [("../../escape.py", b"import hashlib\nhashlib.md5(b'x')\n"),
         ("app/good.py", L.CRYPTO_APP_PY)],
        links=[("app/bad", "/etc/passwd", "sym")],
        specials=[("dev/null", tarfile.CHRTYPE)],
        gzipped=True,
    )
    builder = L.OCIBuilder()
    builder.add_image([hostile], tag="hostile:1")
    archive = builder.write_tar(tmp_path / "hostile.tar")

    from app.scanners import container as sensor
    findings, stats = sensor.scan(archive)

    assert findings, "the safe member should still have been analysed"
    assert any("good.py" in e.location for f in findings for e in f.evidence)
    assert not any("escape" in e.location for f in findings for e in f.evidence)

    refused = stats["container_archive_stats"]["refused"]
    assert "member path traverses upward" in refused
    assert "link to an absolute path" in refused
    assert "device node" in refused


def test_archive_refusals_reach_the_operator_as_scan_warnings(tmp_path):
    from app import api, orchestrator

    hostile = L.tar_bytes([("../../escape.py", b"x"), ("app/main.py", L.CRYPTO_APP_PY)],
                          gzipped=True)
    builder = L.OCIBuilder()
    builder.add_image([hostile], tag="warned:1")
    archive = builder.write_tar(tmp_path / "warned.tar")

    result = orchestrator.scan_image(archive)
    assert result.stats["complete"] is False
    warnings = api._scan_warnings(result.stats)
    assert any("refused" in w for w in warnings), warnings

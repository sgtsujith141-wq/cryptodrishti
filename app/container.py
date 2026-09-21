"""Safe, read-only reading of local container image archives.

A container image is an untrusted archive that arrived from somewhere else,
and the classic way to lose a machine to one is to call ``tarfile.extractall``
on it. This module never extracts anything. It streams members, checks each
one against a policy before a single byte of content is read, and hands the
bytes to an analyser in memory. Nothing from an image is ever written to the
project directory, or to anywhere else.

Three layers of defence, in the order they apply:

**Name.** Absolute paths, drive letters, ``..`` components, control characters
and over-long names are rejected before the member is opened. Link members are
checked the same way *and* their targets are resolved against the archive root,
because a symlink is a path traversal that happens at read time rather than at
write time.

**Shape.** Only regular files carry content we will read. Devices, FIFOs and
sockets are recorded and skipped -- there is nothing in a character device we
want, and a scanner that tries to read one deserves what it gets.

**Budget.** Member count, per-member size, total uncompressed bytes, nesting
depth and wall clock are all bounded. The total-bytes bound is the one that
stops a decompression bomb: a 1 MB archive that expands to 40 GB fails on the
budget, not on the disk, because we were never writing to disk.

Supported formats are enumerated in ``SUPPORTED_FORMATS`` and nowhere else.
Anything not on that list fails with a message naming what it found, because
"unsupported" without a reason is indistinguishable from a bug.
"""

from __future__ import annotations

import io
import json
import posixpath
import re
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

# --------------------------------------------------------------------------
# What we claim to support
# --------------------------------------------------------------------------

SUPPORTED_FORMATS = {
    "oci-layout-dir": "OCI image layout, unpacked directory (oci-layout + index.json)",
    "oci-archive": "OCI image layout packed as a tar archive",
    "docker-archive": "Docker `docker save` tar archive (manifest.json)",
}

# Compression the standard library handles without an external tool. Anything
# else is named and refused rather than half-attempted.
SUPPORTED_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
                      ".tar.xz", ".txz", ".oci", ".oci.tar")

_MEDIA_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
_MEDIA_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_MEDIA_DOCKER_MANIFEST_LIST = (
    "application/vnd.docker.distribution.manifest.list.v2+json")
_MEDIA_DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"

# Layer media types whose blobs are tar archives we can walk.
_LAYER_MEDIA = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
}

# zstd is a legitimate OCI layer compression that the standard library cannot
# decompress. We name it rather than reporting an empty layer.
_UNREADABLE_LAYER_MEDIA = {
    "application/vnd.oci.image.layer.v1.tar+zstd":
        "zstd-compressed layers need the optional `zstandard` package",
}

_DIGEST_RE = re.compile(r"^sha(?:256|512):[0-9a-f]{32,128}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._@:+\-/]+$")


class ContainerError(Exception):
    """An image archive could not be read. The message is operator-facing."""


class ArchiveRefused(ContainerError):
    """An archive member violated policy. Never raised for the whole archive."""


# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

@dataclass
class ArchiveLimits:
    """Bounds for reading one image. Every one of these has stopped something."""

    max_members: int = 200_000          # entries across all layers
    max_member_bytes: int = 256 << 20   # 256 MB for any single file
    max_total_bytes: int = 4 << 30      # 4 GB uncompressed, the bomb bound
    max_layers: int = 256
    max_depth: int = 3                  # archive -> layer -> nested archive
    max_path_length: int = 4096
    max_blob_bytes: int = 2 << 30       # a single layer blob
    deadline: Optional[float] = None    # monotonic clock

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline


@dataclass
class ArchiveStats:
    """What the reader did and what it refused. Reported, never discarded."""

    members_seen: int = 0
    members_read: int = 0
    bytes_read: int = 0
    layers_read: int = 0
    refused: dict[str, int] = field(default_factory=dict)
    examples: list[str] = field(default_factory=list)
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def refuse(self, reason: str, name: str = "") -> None:
        self.refused[reason] = self.refused.get(reason, 0) + 1
        if name and len(self.examples) < 25:
            self.examples.append(f"{reason}: {name[:180]}")

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "members_seen": self.members_seen,
            "members_read": self.members_read,
            "bytes_read": self.bytes_read,
            "layers_read": self.layers_read,
        }
        if self.refused:
            out["refused"] = dict(self.refused)
            out["refused_examples"] = list(self.examples)
        if self.truncated:
            out["truncated"] = ("a limit was reached; the image was not read in "
                                "full and this inventory is partial")
        if self.notes:
            out["notes"] = list(self.notes)
        return out


# --------------------------------------------------------------------------
# Member vetting
# --------------------------------------------------------------------------

def member_refusal(member: tarfile.TarInfo, limits: ArchiveLimits) -> Optional[str]:
    """Why this member must not be read, or None if it may be.

    Applied before the member is opened, so a hostile name never reaches a
    filesystem call. We are not extracting, but a name is also used for
    reporting and for the whiteout logic, and a ``..`` that reaches either is
    a bug waiting to be found by someone else.
    """
    name = member.name or ""

    if not name or name in (".", "./"):
        return "empty member name"
    if len(name) > limits.max_path_length:
        return "member path exceeds the length limit"
    if "\x00" in name or any(ord(c) < 32 for c in name):
        return "member name contains control characters"
    if name.startswith("/") or name.startswith("\\"):
        return "absolute member path"
    if re.match(r"^[A-Za-z]:[\\/]", name):
        return "absolute member path with a drive letter"

    parts = name.replace("\\", "/").split("/")
    if ".." in parts:
        return "member path traverses upward"

    # Order matters: tarfile's isdev() is true for FIFOs as well as character
    # and block devices, so the specific checks come first. All three are
    # refused either way; this is so the refusal names what it actually found.
    if member.isfifo():
        return "FIFO"
    if member.ischr() or member.isblk() or member.isdev():
        return "device node"
    if getattr(member, "issock", lambda: False)():
        return "socket"

    if member.issym() or member.islnk():
        target = member.linkname or ""
        if not target:
            return "link with no target"
        if target.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", target):
            return "link to an absolute path"
        # Resolve the link relative to its own directory and confirm it stays
        # inside the archive. `a/b -> ../../etc/passwd` escapes even though
        # neither name on its own looks wrong.
        base = posixpath.dirname(name.replace("\\", "/"))
        resolved = posixpath.normpath(posixpath.join(base, target.replace("\\", "/")))
        if resolved.startswith("../") or resolved == "..":
            return "link escaping the archive root"
        return None            # a safe link: recorded, but carries no content

    if member.isreg() and member.size > limits.max_member_bytes:
        return "member exceeds the per-file size limit"

    return None


@dataclass
class ArchiveMember:
    """One vetted regular file from inside an image."""

    path: str                  # normalised, archive-relative
    size: int
    data: bytes
    layer_digest: str = ""
    layer_index: int = -1


def _normalise(name: str) -> str:
    return posixpath.normpath(name.replace("\\", "/")).lstrip("./")


def iter_tar_members(
    fileobj, limits: ArchiveLimits, stats: ArchiveStats,
    layer_digest: str = "", layer_index: int = -1, depth: int = 0,
) -> Iterator[ArchiveMember]:
    """Stream regular files out of a tar, applying policy to every member.

    Yields bytes, never paths on disk. The caller analyses in memory and the
    content is dropped; at no point does image content exist as a file we
    created.
    """
    if depth > limits.max_depth:
        stats.refuse("archive nesting deeper than the limit")
        return

    try:
        # Stream mode: no seeking, no index, bounded memory. It is also the
        # mode that refuses to be tricked into re-reading members.
        tar = tarfile.open(fileobj=fileobj, mode="r|*")
    except tarfile.TarError as exc:
        raise ContainerError(f"archive could not be opened: {exc}")

    try:
        for member in tar:
            if limits.expired():
                stats.truncated = True
                stats.note("time budget reached while reading the image")
                return
            stats.members_seen += 1
            if stats.members_seen > limits.max_members:
                stats.truncated = True
                stats.refuse("member budget exhausted")
                return

            reason = member_refusal(member, limits)
            if reason:
                stats.refuse(reason, member.name)
                continue

            if not member.isreg():
                # Directories and safe links pass policy but carry no content.
                # Whiteout markers are directory-level and handled by the
                # caller from the member name, which it still sees below.
                if member.issym() or member.islnk():
                    yield ArchiveMember(path=_normalise(member.name), size=0,
                                        data=b"", layer_digest=layer_digest,
                                        layer_index=layer_index)
                continue

            if stats.bytes_read + member.size > limits.max_total_bytes:
                stats.truncated = True
                stats.refuse("total uncompressed size budget exhausted",
                             member.name)
                return

            try:
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                # Read one byte past the declared size: a member whose real
                # content exceeds its header is malformed, and trusting the
                # header is how a size check gets bypassed.
                data = handle.read(limits.max_member_bytes + 1)
            except (tarfile.TarError, OSError, EOFError) as exc:
                stats.refuse(f"member could not be read ({type(exc).__name__})",
                             member.name)
                continue

            if len(data) > limits.max_member_bytes:
                stats.refuse("member exceeded the per-file size limit while "
                             "being read", member.name)
                continue

            stats.members_read += 1
            stats.bytes_read += len(data)
            yield ArchiveMember(path=_normalise(member.name), size=len(data),
                                data=data, layer_digest=layer_digest,
                                layer_index=layer_index)
    finally:
        try:
            tar.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Blob access
#
# An OCI directory keeps blobs as files; an archive keeps them as tar members.
# Both are reduced to "give me a stream for this digest" so the layer walker
# does not care which it was handed.
# --------------------------------------------------------------------------

class BlobSource:
    """Read-only access to an image's blobs. Never writes anything."""

    def __init__(self, limits: ArchiveLimits, stats: ArchiveStats):
        self.limits = limits
        self.stats = stats

    def open(self, digest: str):                       # pragma: no cover - iface
        raise NotImplementedError

    def read_small(self, digest: str, cap: int = 32 << 20) -> bytes:
        """Read a metadata blob. Capped, because a manifest is never large."""
        handle = self.open(digest)
        if handle is None:
            raise ContainerError(f"blob {digest} is not present in this archive")
        with handle:
            data = handle.read(cap + 1)
        if len(data) > cap:
            raise ContainerError(f"metadata blob {digest} exceeds {cap} bytes")
        return data

    def read_json(self, digest: str) -> dict:
        try:
            return json.loads(self.read_small(digest))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ContainerError(f"blob {digest} is not valid JSON: {exc}")

    def close(self) -> None:
        pass


def _blob_relpath(digest: str) -> str:
    algorithm, _, hexdigest = digest.partition(":")
    return f"blobs/{algorithm}/{hexdigest}"


class DirectoryBlobSource(BlobSource):
    """Blobs as files under an unpacked OCI layout."""

    def __init__(self, root: Path, limits: ArchiveLimits, stats: ArchiveStats):
        super().__init__(limits, stats)
        self.root = root

    def open(self, digest: str):
        if not _DIGEST_RE.match(digest):
            raise ContainerError(f"malformed digest {digest!r}")
        path = self.root / _blob_relpath(digest)
        try:
            # Confirm the blob really is inside the layout: a layout directory
            # can contain symlinks like any other directory.
            real = path.resolve()
            real.relative_to(self.root.resolve())
        except (OSError, ValueError):
            self.stats.refuse("blob path escapes the image layout", digest)
            return None
        if not real.is_file():
            return None
        if real.stat().st_size > self.limits.max_blob_bytes:
            self.stats.refuse("blob exceeds the size limit", digest)
            return None
        return real.open("rb")


class TarBlobSource(BlobSource):
    """Blobs as members of a tar archive, addressed by name.

    Opened seekable so members can be fetched in the order the manifest lists
    them rather than the order the archive happens to store them. Layer replay
    has to be ordered or whiteouts cannot be applied, and only the member
    index is held in memory -- names, not content.
    """

    def __init__(self, path: Path, limits: ArchiveLimits, stats: ArchiveStats):
        super().__init__(limits, stats)
        try:
            self.tar = tarfile.open(path, mode="r:*")
        except tarfile.TarError as exc:
            raise ContainerError(f"archive could not be opened: {exc}")
        self.index: dict[str, tarfile.TarInfo] = {}
        try:
            for member in self.tar:
                if len(self.index) > limits.max_members:
                    stats.truncated = True
                    stats.refuse("member budget exhausted while indexing")
                    break
                if member_refusal(member, limits):
                    continue
                if member.isreg():
                    self.index[_normalise(member.name)] = member
        except tarfile.TarError as exc:
            raise ContainerError(f"archive index is corrupt: {exc}")

    def has(self, name: str) -> bool:
        return _normalise(name) in self.index

    def open_name(self, name: str):
        member = self.index.get(_normalise(name))
        if member is None:
            return None
        if member.size > self.limits.max_blob_bytes:
            self.stats.refuse("blob exceeds the size limit", name)
            return None
        try:
            return self.tar.extractfile(member)
        except tarfile.TarError as exc:
            self.stats.refuse(f"blob unreadable ({exc})", name)
            return None

    def open(self, digest: str):
        if not _DIGEST_RE.match(digest):
            raise ContainerError(f"malformed digest {digest!r}")
        for candidate in (_blob_relpath(digest), digest.replace(":", "/")):
            handle = self.open_name(candidate)
            if handle is not None:
                return handle
        return None

    def close(self) -> None:
        try:
            self.tar.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Image discovery
# --------------------------------------------------------------------------

@dataclass
class ImageRef:
    """One image inside an archive that could be scanned."""

    index: int
    digest: str                 # manifest digest, or "" for a docker archive
    tags: list[str] = field(default_factory=list)
    platform: str = ""
    media_type: str = ""
    # Docker archives address layers by member name rather than by digest.
    docker_config: str = ""
    docker_layers: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        """A stable selector the operator can pass back in."""
        if self.tags:
            return self.tags[0]
        if self.digest:
            return self.digest
        return f"image[{self.index}]"

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "digest": self.digest, "tags": self.tags,
                "platform": self.platform, "media_type": self.media_type,
                "name": self.name}


@dataclass
class ImageArchive:
    """A validated, openable image archive. Nothing has been read yet."""

    path: Path
    kind: str                   # a key of SUPPORTED_FORMATS
    images: list[ImageRef]
    stats: ArchiveStats
    _source: Optional[BlobSource] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path), "format": self.kind,
            "format_description": SUPPORTED_FORMATS[self.kind],
            "images": [i.to_dict() for i in self.images],
            "archive": self.stats.to_dict(),
        }

    def close(self) -> None:
        if self._source is not None:
            self._source.close()
            self._source = None


def _platform_string(node: dict) -> str:
    platform = node.get("platform") or {}
    parts = [platform.get("os", ""), platform.get("architecture", "")]
    variant = platform.get("variant")
    if variant:
        parts.append(variant)
    return "/".join(p for p in parts if p)


def detect_format(path: Path) -> str:
    """Name the archive format, or refuse with what was actually found."""
    if path.is_dir():
        if (path / "oci-layout").is_file() and (path / "index.json").is_file():
            return "oci-layout-dir"
        raise ContainerError(
            f"{path} is a directory but not an OCI image layout (no oci-layout "
            f"and index.json). Supported formats: "
            + "; ".join(SUPPORTED_FORMATS.values()))

    if not path.is_file():
        raise ContainerError(f"{path} is neither a file nor a directory")

    lowered = path.name.lower()
    if not lowered.endswith(SUPPORTED_SUFFIXES):
        raise ContainerError(
            f"{path.name} does not look like a supported image archive. "
            f"Expected one of {', '.join(SUPPORTED_SUFFIXES)}.")

    if not tarfile.is_tarfile(path):
        raise ContainerError(
            f"{path.name} is not a readable tar archive. Compressed formats "
            f"other than gzip, bzip2 and xz are not supported.")
    return "archive"            # refined once the members are indexed


def open_archive(path: str | Path, limits: Optional[ArchiveLimits] = None
                 ) -> ImageArchive:
    """Validate an archive and enumerate the images inside it.

    Reads metadata only. No layer is touched, so this is cheap enough to drive
    a picker in the console, and it is the call that makes multi-image
    archives explicit instead of silently resolving to the first entry.
    """
    limits = limits or ArchiveLimits()
    stats = ArchiveStats()
    path = Path(path).expanduser().resolve()

    kind = detect_format(path)
    if kind == "oci-layout-dir":
        source: BlobSource = DirectoryBlobSource(path, limits, stats)
        index = json.loads((path / "index.json").read_text(encoding="utf-8"))
        images = _images_from_oci_index(index, source, stats)
        archive = ImageArchive(path=path, kind=kind, images=images, stats=stats)
        archive._source = source
        return archive

    tar_source = TarBlobSource(path, limits, stats)
    try:
        if tar_source.has("index.json") and tar_source.has("oci-layout"):
            handle = tar_source.open_name("index.json")
            index = json.loads(handle.read(32 << 20))
            images = _images_from_oci_index(index, tar_source, stats)
            archive = ImageArchive(path=path, kind="oci-archive", images=images,
                                   stats=stats)
        elif tar_source.has("manifest.json"):
            handle = tar_source.open_name("manifest.json")
            manifest = json.loads(handle.read(32 << 20))
            images = _images_from_docker_manifest(manifest, stats)
            archive = ImageArchive(path=path, kind="docker-archive",
                                   images=images, stats=stats)
        else:
            raise ContainerError(
                f"{path.name} is a tar archive but contains neither an OCI "
                f"index.json nor a Docker manifest.json, so it is not a "
                f"container image. Supported formats: "
                + "; ".join(SUPPORTED_FORMATS.values()))
    except json.JSONDecodeError as exc:
        tar_source.close()
        raise ContainerError(f"image metadata is not valid JSON: {exc}")
    except Exception:
        tar_source.close()
        raise

    archive._source = tar_source
    return archive


def _images_from_oci_index(index: dict, source: BlobSource,
                           stats: ArchiveStats) -> list[ImageRef]:
    """Flatten an OCI index, descending one level into nested indexes."""
    if not isinstance(index, dict):
        raise ContainerError("index.json is not a JSON object")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ContainerError("index.json lists no manifests")

    out: list[ImageRef] = []
    for node in manifests:
        if not isinstance(node, dict):
            stats.refuse("malformed manifest entry in index.json")
            continue
        digest = node.get("digest", "")
        if not _DIGEST_RE.match(str(digest)):
            stats.refuse("manifest entry with a malformed digest", str(digest))
            continue
        media = node.get("mediaType", "")
        annotations = node.get("annotations") or {}
        tag = annotations.get("org.opencontainers.image.ref.name")

        if media in (_MEDIA_OCI_INDEX, _MEDIA_DOCKER_MANIFEST_LIST):
            # A multi-architecture index. Each child is its own image and is
            # listed as one, rather than being collapsed into the parent.
            try:
                child = source.read_json(digest)
            except ContainerError as exc:
                stats.refuse(f"nested index unreadable ({exc})", digest)
                continue
            for sub in child.get("manifests", []) or []:
                sub_digest = sub.get("digest", "")
                if not _DIGEST_RE.match(str(sub_digest)):
                    continue
                out.append(ImageRef(
                    index=len(out), digest=sub_digest,
                    tags=[tag] if tag else [],
                    platform=_platform_string(sub),
                    media_type=sub.get("mediaType", ""),
                ))
            continue

        out.append(ImageRef(index=len(out), digest=digest,
                            tags=[tag] if tag else [],
                            platform=_platform_string(node), media_type=media))

    if not out:
        raise ContainerError("index.json contained no usable image manifests")
    return out


def _images_from_docker_manifest(manifest: Any,
                                 stats: ArchiveStats) -> list[ImageRef]:
    if not isinstance(manifest, list) or not manifest:
        raise ContainerError("manifest.json is not a non-empty JSON array")
    out: list[ImageRef] = []
    for node in manifest:
        if not isinstance(node, dict):
            stats.refuse("malformed entry in manifest.json")
            continue
        config = node.get("Config") or ""
        layers = [str(x) for x in (node.get("Layers") or [])]
        if not config or not layers:
            stats.refuse("manifest.json entry names no config or no layers")
            continue
        tags = [str(t) for t in (node.get("RepoTags") or [])]
        out.append(ImageRef(index=len(out), digest="", tags=tags,
                            media_type=_MEDIA_DOCKER_MANIFEST,
                            docker_config=config, docker_layers=layers))
    if not out:
        raise ContainerError("manifest.json contained no usable image entries")
    return out


def select_image(archive: ImageArchive, selector: str = "") -> ImageRef:
    """Choose which image to scan, refusing to guess when it is ambiguous.

    An archive holding a linux/amd64 and a linux/arm64 build holds two
    different estates. Picking the first would produce an inventory of
    something the operator did not ask about and could not tell apart from the
    one they wanted, so an unselected multi-image archive is an error that
    names the choices.
    """
    if not archive.images:
        raise ContainerError("the archive contains no images")

    if selector:
        wanted = selector.strip()
        for image in archive.images:
            if wanted in (image.name, image.digest, str(image.index)) or \
                    wanted in image.tags or wanted == image.platform:
                return image
        available = ", ".join(
            f"{i.name}" + (f" ({i.platform})" if i.platform else "")
            for i in archive.images)
        raise ContainerError(
            f"no image in this archive matches {selector!r}. Available: {available}")

    if len(archive.images) == 1:
        return archive.images[0]

    available = "; ".join(
        f"[{i.index}] {i.name}" + (f" — {i.platform}" if i.platform else "")
        for i in archive.images)
    raise ContainerError(
        f"this archive contains {len(archive.images)} images and none was "
        f"selected. Naming one is required, because each is a different estate: "
        f"{available}")


# --------------------------------------------------------------------------
# Layer replay
#
# A container filesystem is a stack of tar layers applied in order, where
# deletions are encoded as marker files rather than as absences:
#
#   .wh.<name>      removes <name> from the accumulated filesystem
#   .wh..wh..opq    removes everything previously under this directory
#
# A scanner that reads layers without replaying whiteouts reports files the
# running container does not have. That is not a small error: the commonest
# reason a private key is in a layer at all is that someone noticed and
# deleted it in the next one. The key is still extractable from the archive,
# so it is still a finding -- but it is a *historical* finding, and calling it
# a live one would be wrong in the opposite direction.
# --------------------------------------------------------------------------

WHITEOUT_PREFIX = ".wh."
WHITEOUT_OPAQUE = ".wh..wh..opq"


@dataclass
class LayerFile:
    """One file read out of one layer, with its final visibility resolved."""

    path: str
    data: bytes
    layer_index: int
    layer_digest: str
    effective: bool                 # present in the final filesystem
    superseded_by: int = -1         # layer that replaced or removed it

    @property
    def state(self) -> str:
        if self.effective:
            return "effective"
        return "historical"


def _whiteout_target(path: str) -> tuple[str, bool]:
    """Return (target path, is_opaque) for a whiteout marker, else ("", False)."""
    directory, _, base = path.rpartition("/")
    if base == WHITEOUT_OPAQUE:
        return directory, True
    if base.startswith(WHITEOUT_PREFIX):
        real = base[len(WHITEOUT_PREFIX):]
        return (f"{directory}/{real}" if directory else real), False
    return "", False


def layer_digests(archive: ImageArchive, image: ImageRef,
                  source: BlobSource) -> list[tuple[str, str]]:
    """Ordered (layer id, media type) pairs for one image."""
    if archive.kind == "docker-archive":
        return [(name, "application/vnd.docker.image.rootfs.diff.tar") 
                for name in image.docker_layers]

    manifest = source.read_json(image.digest)
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        raise ContainerError(f"manifest {image.digest} lists no layers")
    out: list[tuple[str, str]] = []
    for node in layers:
        digest = str(node.get("digest", ""))
        if not _DIGEST_RE.match(digest):
            continue
        out.append((digest, str(node.get("mediaType", ""))))
    return out


def image_config(archive: ImageArchive, image: ImageRef,
                 source: BlobSource) -> dict:
    """The image config blob: entrypoint, env, history, labels."""
    try:
        if archive.kind == "docker-archive":
            handle = source.open_name(image.docker_config)   # type: ignore[attr-defined]
            if handle is None:
                return {}
            return json.loads(handle.read(32 << 20))
        manifest = source.read_json(image.digest)
        config_digest = str((manifest.get("config") or {}).get("digest", ""))
        if not _DIGEST_RE.match(config_digest):
            return {}
        return source.read_json(config_digest)
    except (ContainerError, json.JSONDecodeError, OSError, AttributeError):
        return {}


def read_layers(archive: ImageArchive, image: ImageRef,
                limits: ArchiveLimits, stats: ArchiveStats,
                on_layer: Optional[Callable[[int, int, str], None]] = None,
                ) -> list[LayerFile]:
    """Read every layer in order and resolve each file's final visibility.

    Returns every file that was readable, including ones later deleted, with
    ``effective`` saying which. Both matter and they are different claims.
    """
    source = archive._source
    if source is None:
        raise ContainerError("archive is closed")

    layers = layer_digests(archive, image, source)
    if len(layers) > limits.max_layers:
        stats.refuse(f"image has more than {limits.max_layers} layers")
        layers = layers[:limits.max_layers]

    files: list[LayerFile] = []
    # path -> index into `files` for the currently visible version
    visible: dict[str, int] = {}
    opaque_dirs: set[str] = set()

    for index, (layer_id, media) in enumerate(layers):
        if limits.expired():
            stats.truncated = True
            stats.note("time budget reached partway through the layer stack")
            break

        if media in _UNREADABLE_LAYER_MEDIA:
            stats.refuse(_UNREADABLE_LAYER_MEDIA[media], layer_id)
            continue

        if archive.kind == "docker-archive":
            handle = source.open_name(layer_id)          # type: ignore[attr-defined]
        else:
            handle = source.open(layer_id)
        if handle is None:
            stats.refuse("layer blob missing from the archive", layer_id)
            continue

        if on_layer:
            on_layer(index + 1, len(layers), layer_id)

        try:
            with handle:
                for member in iter_tar_members(handle, limits, stats,
                                               layer_digest=layer_id,
                                               layer_index=index, depth=1):
                    target, opaque = _whiteout_target(member.path)
                    if target or opaque:
                        # A deletion marker. Everything it covers becomes
                        # historical; the marker itself is not a file.
                        if opaque:
                            opaque_dirs.add(target)
                            prefix = f"{target}/" if target else ""
                            for path, slot in list(visible.items()):
                                if not prefix or path.startswith(prefix):
                                    files[slot].effective = False
                                    files[slot].superseded_by = index
                                    visible.pop(path, None)
                        else:
                            slot = visible.pop(target, None)
                            if slot is not None:
                                files[slot].effective = False
                                files[slot].superseded_by = index
                        continue

                    if not member.data:
                        continue          # directories and links carry nothing

                    previous = visible.get(member.path)
                    if previous is not None:
                        files[previous].effective = False
                        files[previous].superseded_by = index

                    files.append(LayerFile(
                        path=member.path, data=member.data, layer_index=index,
                        layer_digest=layer_id, effective=True,
                    ))
                    visible[member.path] = len(files) - 1
        except ContainerError as exc:
            stats.refuse(f"layer unreadable ({exc})", layer_id)
            continue

        stats.layers_read += 1

    return files


def inspect(path: str | Path, limits: Optional[ArchiveLimits] = None
            ) -> dict[str, Any]:
    """Describe an archive without reading a single layer.

    Exists so the console can offer a picker for a multi-image archive rather
    than making the operator guess a selector, and so an unsupported file
    fails here with a reason instead of halfway through a scan.
    """
    archive = open_archive(path, limits)
    try:
        return archive.to_dict()
    finally:
        archive.close()

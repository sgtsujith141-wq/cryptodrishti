"""Build small, deterministic container images in a temporary directory.

Fixtures are generated rather than committed. Three reasons: a committed image
is a binary blob nobody reviews, a generated one can be malformed on purpose
without shipping a malformed file, and nothing here can be mistaken for real
key material because it is all obviously synthetic and created microseconds
before it is used.

Nothing built here contains a real private key, a real certificate for a real
name, or any secret. The "private key" fixtures are literal placeholder text
inside PEM markers, which is exactly what the detector keys on.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from pathlib import Path
from typing import Iterable, Optional

# A fixed timestamp so two builds of the same content produce the same bytes.
_EPOCH = 1_700_000_000


def tar_bytes(entries: Iterable[tuple[str, bytes]], *,
              links: Optional[list[tuple[str, str, str]]] = None,
              specials: Optional[list[tuple[str, int]]] = None,
              gzipped: bool = False,
              absolute: bool = False) -> bytes:
    """Pack entries into a tar. Used for layers and for hostile archives.

    ``links`` are (name, target, kind) with kind in {"sym", "hard"}.
    ``specials`` are (name, tarfile type) for device/FIFO members.
    ``absolute`` writes names with a leading slash, which is never legal.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo("/" + name if absolute else name)
            info.size = len(data)
            info.mtime = _EPOCH
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
        for name, target, kind in (links or []):
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
            info.linkname = target
            info.mtime = _EPOCH
            tar.addfile(info)
        for name, kind in (specials or []):
            info = tarfile.TarInfo(name)
            info.type = kind
            info.mtime = _EPOCH
            info.devmajor, info.devminor = 1, 3
            tar.addfile(info)
    raw = buffer.getvalue()
    return gzip.compress(raw, mtime=_EPOCH) if gzipped else raw


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class OCIBuilder:
    """Assemble an OCI image layout, then write it as a directory or a tar."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.manifests: list[dict] = []

    def _put(self, data: bytes) -> tuple[str, int]:
        digest = digest_of(data)
        self.blobs[digest] = data
        return digest, len(data)

    def add_image(self, layers: list[bytes], *, tag: str = "",
                  platform: tuple[str, str] = ("linux", "amd64"),
                  env: Optional[list[str]] = None,
                  layer_media: str = "application/vnd.oci.image.layer.v1.tar+gzip",
                  ) -> str:
        config = {
            "architecture": platform[1], "os": platform[0],
            "config": {"Env": env or ["PATH=/usr/bin"]},
            "rootfs": {"type": "layers",
                       "diff_ids": [digest_of(b) for b in layers]},
            "history": [{"created_by": f"layer {i}"} for i in range(len(layers))],
        }
        config_bytes = json.dumps(config, sort_keys=True).encode()
        config_digest, config_size = self._put(config_bytes)

        layer_nodes = []
        for blob in layers:
            digest, size = self._put(blob)
            layer_nodes.append({"mediaType": layer_media, "digest": digest,
                                "size": size})

        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": config_digest, "size": config_size},
            "layers": layer_nodes,
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        manifest_digest, manifest_size = self._put(manifest_bytes)

        node = {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest, "size": manifest_size,
                "platform": {"os": platform[0], "architecture": platform[1]}}
        if tag:
            node["annotations"] = {"org.opencontainers.image.ref.name": tag}
        self.manifests.append(node)
        return manifest_digest

    def index(self) -> dict:
        return {"schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": self.manifests}

    def write_dir(self, root: Path, index_override: Optional[dict] = None) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
        (root / "index.json").write_text(
            json.dumps(index_override if index_override is not None else self.index()))
        for digest, data in self.blobs.items():
            algorithm, _, hexdigest = digest.partition(":")
            blob_dir = root / "blobs" / algorithm
            blob_dir.mkdir(parents=True, exist_ok=True)
            (blob_dir / hexdigest).write_bytes(data)
        return root

    def write_tar(self, path: Path, index_override: Optional[dict] = None) -> Path:
        entries: list[tuple[str, bytes]] = [
            ("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode()),
            ("index.json", json.dumps(
                index_override if index_override is not None else self.index()).encode()),
        ]
        for digest, data in self.blobs.items():
            algorithm, _, hexdigest = digest.partition(":")
            entries.append((f"blobs/{algorithm}/{hexdigest}", data))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(tar_bytes(entries))
        return path


def write_docker_archive(path: Path, images: list[dict]) -> Path:
    """Write a `docker save` style archive.

    Each image is {"tag": str, "layers": [bytes], "env": [str]}. Layers are
    stored uncompressed at <index>/layer.tar, as docker save does.
    """
    entries: list[tuple[str, bytes]] = []
    manifest: list[dict] = []

    for n, image in enumerate(images):
        config = {"architecture": "amd64", "os": "linux",
                  "config": {"Env": image.get("env") or ["PATH=/usr/bin"]},
                  "rootfs": {"type": "layers", "diff_ids": []}}
        config_name = f"{hashlib.sha256(str(n).encode()).hexdigest()}.json"
        entries.append((config_name, json.dumps(config, sort_keys=True).encode()))

        layer_names = []
        for i, blob in enumerate(image["layers"]):
            name = f"{n}_{i}/layer.tar"
            entries.append((name, blob))
            layer_names.append(name)

        manifest.append({"Config": config_name,
                         "RepoTags": [image["tag"]] if image.get("tag") else [],
                         "Layers": layer_names})

    entries.insert(0, ("manifest.json", json.dumps(manifest).encode()))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(tar_bytes(entries))
    return path


# --------------------------------------------------------------------------
# Synthetic layer contents
#
# Deliberately obvious placeholders. Nothing below is, or resembles, real key
# material -- the PEM bodies are the word "SYNTHETIC" repeated.
# --------------------------------------------------------------------------

SYNTHETIC_PEM_KEY = (
    b"-----BEGIN RSA PRIVATE KEY-----\n"
    + b"U1lOVEhFVElDLUZJWFRVUkUtTk9ULUEtUkVBTC1LRVk=\n" * 4
    + b"-----END RSA PRIVATE KEY-----\n"
)

CRYPTO_APP_PY = b"""\
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding

hashlib.md5(b"legacy checksum")
hashlib.sha3_512(b"modern digest")
padding.PSS(mgf=None, salt_length=32)
"""

REQUIREMENTS = b"cryptography==41.0.0\npycryptodome==3.19.0\n"

NGINX_CONF = b"""\
server {
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA;
}
"""

PLAIN_README = b"This image contains no cryptography whatsoever.\n"


def fake_elf(symbols: list[bytes]) -> bytes:
    """A byte string with an ELF magic and recognisable symbol names.

    Not a valid ELF: section-header parsing will fail and the analyser falls
    back to printable-string matching at reduced confidence, which is exactly
    the path we want to exercise and exactly what it reports having done.
    """
    body = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
    body += b"".join(s + b"\x00" for s in symbols)
    return body + b"\x00" * 512

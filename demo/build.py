"""Build the parts of the demo estate that must not be committed.

The container image, its layers and a certificate are generated here rather
than checked in: a committed image is a binary nobody reviews, a committed
certificate expires and starts failing for the wrong reason, and a committed
private key is a private key in a repository however loudly the filename says
otherwise.

Everything produced is obviously synthetic and offline. Nothing in this module
opens a socket.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "benchmark"))

# The OCI packaging is already written, tested and reviewed in the benchmark
# generator. Importing it keeps one implementation of manifest construction
# rather than a second copy that drifts.
import generate as _fixtures  # noqa: E402

ESTATE = Path(__file__).resolve().parent / "estate"
BUILT = Path(__file__).resolve().parent / "built"

# Demonstration 5: a container image. Layer 0 ships an application, a config
# and a key; layer 1 adds a dependency manifest and DELETES the key. The key
# stays extractable from the archive, so it is still inventoried -- as
# historical, not as part of what the image runs.
LAYER0 = {
    "app/checkout.py": b"""\
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding

hashlib.sha3_512(b"receipt")
padding.PSS(mgf=None, salt_length=32)
""",
    "etc/nginx/nginx.conf": b"""\
server {
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
}
""",
    "etc/ssl/private/deploy.key": _fixtures.SYNTHETIC_KEY,
}

LAYER1 = {
    "app/requirements.txt": b"pycryptodome==3.19.0\n",
    # The whiteout marker: layer 1 deletes the key layer 0 shipped.
    "etc/ssl/private/.wh.deploy.key": b"",
}


def build(quiet: bool = False) -> dict[str, Path]:
    """Create the generated demo artefacts. Safe to run repeatedly."""
    BUILT.mkdir(parents=True, exist_ok=True)

    archive = BUILT / "checkout-service.tar"
    _write_image(archive)

    certs = BUILT / "certs"
    certs.mkdir(exist_ok=True)
    (certs / "gateway.pem").write_bytes(
        _fixtures.self_signed("gateway.demo.invalid", key_encipherment=True))
    (certs / "signing-ca.pem").write_bytes(
        _fixtures.self_signed("ca.demo.invalid", key_cert_sign=True))

    out = {"image": archive, "certs": certs, "estate": ESTATE}
    if not quiet:
        for name, path in out.items():
            print(f"  {name:8} {path}")
    return out


def _write_image(path: Path) -> Path:
    import hashlib
    import json

    layer0 = _fixtures._tar(list(LAYER0.items()), gzipped=True)
    layer1 = _fixtures._tar(list(LAYER1.items()), gzipped=True)

    blobs: dict[str, bytes] = {}

    def put(data: bytes) -> tuple[str, int]:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        return digest, len(data)

    config = {"architecture": "amd64", "os": "linux",
              "config": {"Env": ["PATH=/usr/bin",
                                 "SSL_CERT_FILE=/etc/ssl/certs/ca.pem"]},
              "rootfs": {"type": "layers",
                         "diff_ids": ["sha256:" + hashlib.sha256(b).hexdigest()
                                      for b in (layer0, layer1)]}}
    config_digest, config_size = put(json.dumps(config, sort_keys=True).encode())

    layers = []
    for blob in (layer0, layer1):
        digest, size = put(blob)
        layers.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                       "digest": digest, "size": size})

    manifest = {"schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": config_digest, "size": config_size},
                "layers": layers}
    manifest_digest, manifest_size = put(
        json.dumps(manifest, sort_keys=True).encode())

    index = {"schemaVersion": 2,
             "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": [{"mediaType": manifest["mediaType"],
                            "digest": manifest_digest, "size": manifest_size,
                            "annotations": {
                                "org.opencontainers.image.ref.name":
                                    "checkout-service:2.4"},
                            "platform": {"os": "linux", "architecture": "amd64"}}]}

    entries = [("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode()),
               ("index.json", json.dumps(index).encode())]
    for digest, data in blobs.items():
        algorithm, _, hexdigest = digest.partition(":")
        entries.append((f"blobs/{algorithm}/{hexdigest}", data))

    path.write_bytes(_fixtures._tar(entries))
    return path


if __name__ == "__main__":
    print("building demo fixtures (offline, synthetic):")
    build()

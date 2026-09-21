"""Build the parts of the corpus that must not be committed.

Binaries, certificates and container images are generated into a temporary
directory at benchmark time rather than checked in. Three reasons: a committed
binary is a blob nobody reviews, a committed certificate expires and starts
failing for the wrong reason, and a committed private key is a private key in
a repository however loudly the filename says otherwise.

Everything here is obviously synthetic. The certificates are self-signed for
`benchmark.invalid`, generated microseconds before use and discarded after;
the "ELF" files are byte strings with an ELF magic and recognisable symbol
names, not linkable objects.
"""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import tarfile
from pathlib import Path

_EPOCH = 1_700_000_000


def _tar(entries, gzipped=False) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = _EPOCH
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    raw = buffer.getvalue()
    return gzip.compress(raw, mtime=_EPOCH) if gzipped else raw


def fake_elf(symbols: list[bytes], banner: bytes = b"") -> bytes:
    """An ELF-magic blob carrying recognisable symbol names.

    Not a linkable object: the section headers are absent, so the analyser
    falls back to printable-string matching at reduced confidence. That is the
    path being measured, and the tool reports having taken it.
    """
    body = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
    body += b"".join(s + b"\x00" for s in symbols)
    if banner:
        body += banner + b"\x00"
    return body + b"\x00" * 600


def self_signed(common_name: str, *, digest: str = "sha256",
                key_size: int = 2048, key_cert_sign: bool = False,
                key_encipherment: bool = False, days: int = 365) -> bytes:
    """A throwaway self-signed certificate, in memory, as PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    algorithm = {"sha256": hashes.SHA256(), "sha1": hashes.SHA1(),
                 "sha384": hashes.SHA384()}[digest]
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=key_encipherment, data_encipherment=False,
                key_agreement=False, key_cert_sign=key_cert_sign,
                crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
    )
    return builder.sign(key, algorithm).public_bytes(serialization.Encoding.PEM)


# A PEM body that is the word SYNTHETIC in base64, repeated. Nothing here is,
# or resembles, real key material -- the detector keys on the markers.
SYNTHETIC_KEY = (
    b"-----BEGIN RSA PRIVATE KEY-----\n"
    + b"U1lOVEhFVElDLUJFTkNITUFSSy1GSVhUVVJFLU5PVC1BLUtFWQ==\n" * 3
    + b"-----END RSA PRIVATE KEY-----\n"
)

CONTAINER_APP = b"""\
import hashlib
hashlib.sha3_512(b"in a layer")
hashlib.md5(b"in a layer")
"""

CONTAINER_CONF = b"""\
server {
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
}
"""


def build(root: Path) -> Path:
    """Materialise the generated corpus under ``root/generated``."""
    out = root / "generated"

    # ---- binaries -------------------------------------------------------
    binaries = out / "binary"
    binaries.mkdir(parents=True, exist_ok=True)
    (binaries / "libfake-crypto.so").write_bytes(fake_elf(
        [b"RSA_sign", b"SHA256_Init", b"MD5_Init", b"AES_encrypt"],
        banner=b"OpenSSL 3.0.2 15 Mar 2022"))
    # A negative: a binary with no cryptographic symbols at all.
    (binaries / "libplain.so").write_bytes(fake_elf(
        [b"parse_config", b"render_row", b"open_socket"]))

    # ---- certificates ---------------------------------------------------
    certs = out / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    (certs / "server.pem").write_bytes(
        self_signed("server.benchmark.invalid", key_encipherment=True))
    (certs / "ca.pem").write_bytes(
        self_signed("ca.benchmark.invalid", key_cert_sign=True))
    # A SHA-1-signed certificate would be the more interesting fixture, but
    # the installed `cryptography` refuses to *create* SHA-1 signatures --
    # correctly, it is a deprecated primitive. So SHA-1 certificate detection
    # is not covered by this corpus, and the benchmark reports that gap rather
    # than quietly leaving it out.
    (certs / "strong-sha384.pem").write_bytes(
        self_signed("strong.benchmark.invalid", digest="sha384"))
    (certs / "server.key").write_bytes(SYNTHETIC_KEY)

    # ---- container image ------------------------------------------------
    images = out / "images"
    images.mkdir(parents=True, exist_ok=True)
    _write_oci(images / "benchmark-image.tar")
    return out


def _write_oci(path: Path) -> Path:
    """A two-layer OCI archive, the second layer deleting a key from the first."""
    import hashlib as _h

    layer0 = _tar([("app/main.py", CONTAINER_APP),
                   ("etc/nginx.conf", CONTAINER_CONF),
                   ("etc/ssl/private/server.key", SYNTHETIC_KEY)], gzipped=True)
    layer1 = _tar([("app/requirements.txt", b"pycryptodome==3.19.0\n"),
                   ("etc/ssl/private/.wh.server.key", b"")], gzipped=True)

    blobs: dict[str, bytes] = {}

    def put(data: bytes) -> tuple[str, int]:
        digest = "sha256:" + _h.sha256(data).hexdigest()
        blobs[digest] = data
        return digest, len(data)

    config = {"architecture": "amd64", "os": "linux",
              "config": {"Env": ["PATH=/usr/bin"]},
              "rootfs": {"type": "layers",
                         "diff_ids": ["sha256:" + _h.sha256(b).hexdigest()
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
    manifest_digest, manifest_size = put(json.dumps(manifest, sort_keys=True).encode())

    index = {"schemaVersion": 2,
             "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": [{"mediaType": manifest["mediaType"],
                            "digest": manifest_digest, "size": manifest_size,
                            "annotations": {
                                "org.opencontainers.image.ref.name": "benchmark:1.0"},
                            "platform": {"os": "linux", "architecture": "amd64"}}]}

    entries = [("oci-layout", json.dumps({"imageLayoutVersion": "1.0.0"}).encode()),
               ("index.json", json.dumps(index).encode())]
    for digest, data in blobs.items():
        algorithm, _, hexdigest = digest.partition(":")
        entries.append((f"blobs/{algorithm}/{hexdigest}", data))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_tar(entries))
    return path


# --------------------------------------------------------------------------
# A local TLS listener
#
# The network sensor is the only one that needs something to talk to. It gets
# a loopback server on an ephemeral port, started for the benchmark and shut
# down after. Nothing outside this machine is contacted, and the relaxation
# that allows a loopback target is set explicitly for the probe and unset
# afterwards -- the benchmark does not get to leave the SSRF guard weakened.
# --------------------------------------------------------------------------

class LocalTLS:
    """A throwaway TLS server on 127.0.0.1, for the network sensor."""

    def __init__(self, root: Path, max_version: str = "1.3"):
        self.root = root
        self.max_version = max_version
        self.port = 0
        self._server = None
        self._thread = None

    def __enter__(self) -> "LocalTLS":
        import http.server
        import socket
        import ssl
        import threading

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        certs = self.root / "tls"
        certs.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (certs / "key.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        (certs / "cert.pem").write_bytes(
            _cert_for("localhost", key))

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if self.max_version == "1.2":
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certs / "cert.pem", certs / "key.pem")

        class Quiet(http.server.SimpleHTTPRequestHandler):
            """A probe closes without sending a request, which is not an error.

            The default handler logs a stack trace for every reset connection,
            which would bury the benchmark output in noise about the benchmark
            working correctly.
            """

            def log_message(self, *a, **kw):
                pass

            def handle_one_request(self):
                try:
                    super().handle_one_request()
                except (ConnectionError, OSError):
                    self.close_connection = True

        handler = Quiet
        class Server(http.server.HTTPServer):
            def handle_error(self, request, client_address):
                pass          # a reset probe is the expected case here

        self._server = Server(("127.0.0.1", self.port), handler)
        self._server.socket = context.wrap_socket(self._server.socket,
                                                  server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()


def _cert_for(common_name: str, key) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)

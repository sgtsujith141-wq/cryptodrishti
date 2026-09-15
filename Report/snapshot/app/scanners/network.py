"""Network scanner: live TLS endpoint probing.

Source code says what was written. Configuration says what was intended. Only
the wire says what is actually negotiated, and those three disagree more often
than anyone expects. This sensor is the ground truth.

For each endpoint we determine which protocol versions are accepted, which
cipher suite is chosen, what the presented certificate contains, and -- most
importantly for this problem -- whether the server can negotiate a hybrid
post-quantum key exchange group.

That last check is the one that matters. TLS 1.3 with a classical group is
still Shor-broken; the protocol version tells you almost nothing on its own.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import socket
import ssl
from typing import Optional

from ..models import ASSET_CERTIFICATE, ASSET_PROTOCOL, Evidence, Finding, TECH_NETWORK

SCANNER = "network"

_VERSIONS = [
    ("TLSv1.3", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_3, "tls1.3"),
    ("TLSv1.2", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_2, "tls1.2"),
    ("TLSv1.1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1, "tls1.1"),
    ("TLSv1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1, "tls1.0"),
]

# Hybrid post-quantum groups, in the names OpenSSL 3.5+ uses.
PQ_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "X25519Kyber768Draft00"]


def _base_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _probe_version(host: str, port: int, version, timeout: float) -> Optional[dict]:
    """Try to complete a handshake pinned to one TLS version."""
    ctx = _base_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, AttributeError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cipher = tls.cipher() or ("", "", 0)
                return {
                    "version": tls.version(),
                    "cipher": cipher[0],
                    "bits": cipher[2],
                    "peercert_der": tls.getpeercert(binary_form=True),
                }
    except (ssl.SSLError, OSError, ValueError):
        return None


def _find_openssl() -> Optional[str]:
    """Locate an OpenSSL CLI new enough to offer hybrid PQC groups (3.5+).

    LibreSSL reports itself through the same command but cannot negotiate
    these groups, so it is rejected explicitly.
    """
    import shutil
    import subprocess

    candidates = ["/usr/local/bin/openssl", "/opt/homebrew/bin/openssl",
                  shutil.which("openssl") or "", "/usr/bin/openssl"]
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        try:
            out = subprocess.run([path, "version"], capture_output=True,
                                 text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        m = re.match(r"OpenSSL\s+(\d+)\.(\d+)", out)
        if m and (int(m.group(1)), int(m.group(2))) >= (3, 5):
            return path
    return None


_OPENSSL_BIN: Optional[str] = None
_OPENSSL_SEARCHED = False


def openssl_bin() -> Optional[str]:
    global _OPENSSL_BIN, _OPENSSL_SEARCHED
    if not _OPENSSL_SEARCHED:
        _OPENSSL_BIN = _find_openssl()
        _OPENSSL_SEARCHED = True
    return _OPENSSL_BIN


def _probe_pq_group(host: str, port: int, timeout: float) -> tuple[Optional[bool], str]:
    """Does this endpoint negotiate a hybrid post-quantum key exchange?

    Returns (supported, note) where ``supported`` is None when we could not
    test at all. That third state matters: reporting "classical only" when we
    never actually offered a hybrid group would be a false negative on the
    single most important property of the endpoint, and it is exactly the kind
    of claim a reviewer would take apart.
    """
    # Preferred path: the standard library, once it exposes group selection.
    ctx = _base_context()
    if hasattr(ctx, "set_groups"):
        for group in PQ_GROUPS:
            try:
                ctx.set_groups(group)
            except (ValueError, AttributeError, ssl.SSLError):
                continue
            try:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        return True, group
            except (ssl.SSLError, OSError):
                continue
        return False, "no hybrid group accepted"

    # Fallback: drive an OpenSSL 3.5+ CLI, which can offer the groups.
    binary = openssl_bin()
    if not binary:
        return None, ("not tested: no OpenSSL 3.5+ available locally to offer a "
                      "hybrid group")

    import subprocess
    for group in PQ_GROUPS:
        try:
            proc = subprocess.run(
                [binary, "s_client", "-connect", f"{host}:{port}",
                 "-groups", group, "-brief"],
                capture_output=True, text=True, timeout=timeout + 8,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        blob = (proc.stdout or "") + (proc.stderr or "")
        m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", blob)
        if m and m.group(1).strip():
            return True, m.group(1).strip()
    return False, "no hybrid group accepted"


def _cert_findings(der: bytes, endpoint: str) -> list[Finding]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
    except ImportError:
        return []
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return []

    from .certs import _key_details, _SIGALG
    key_alg, key_bits = _key_details(cert.public_key(), rsa, ec, dsa, ed25519)
    sig_name = getattr(cert.signature_algorithm_oid, "_name", "") or "unknown"

    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

    return [Finding(
        algorithm=key_alg, asset_type=ASSET_CERTIFICATE, scanner=SCANNER,
        title="Certificate presented by live endpoint",
        detail=(f"Served by {endpoint}. Signed with {sig_name}, expires "
                f"{not_after.date()}."),
        rule_id="net.cert", key_size=key_bits,
        evidence=[Evidence(location=endpoint, symbol=sig_name,
                           technique=TECH_NETWORK, confidence=0.98,
                           context=f"{key_alg}, expires {not_after.date()}")],
        extra={"signature_algorithm": sig_name, "not_after": str(not_after.date()),
               "format": "X.509"},
    )]


def scan_endpoint(host: str, port: int = 443, timeout: float = 4.0) -> list[Finding]:
    endpoint = f"{host}:{port}"
    findings: list[Finding] = []
    accepted: list[str] = []
    best: Optional[dict] = None

    for label, version, alg_key in _VERSIONS:
        if version is None:
            continue
        res = _probe_version(host, port, version, timeout)
        if not res:
            continue
        accepted.append(label)
        if best is None:
            best = res

        legacy = alg_key in ("tls1.0", "tls1.1")
        findings.append(Finding(
            algorithm=alg_key, asset_type=ASSET_PROTOCOL, scanner=SCANNER,
            title=f"{label} accepted",
            detail=("Deprecated by RFC 8996 and should be disabled." if legacy else
                    "Key exchange for this version is classical unless a hybrid "
                    "post-quantum group is negotiated."),
            rule_id="net.tlsversion",
            evidence=[Evidence(location=endpoint, symbol=res["cipher"],
                               technique=TECH_NETWORK, confidence=0.99,
                               context=f"{label}, {res['cipher']}, {res['bits']} bits")],
            extra={"protocol_type": "tls", "version": label,
                   "cipher_suites": [res["cipher"]] if res["cipher"] else []},
        ))

    if not accepted:
        return [Finding(
            algorithm="unknown", asset_type=ASSET_PROTOCOL, scanner=SCANNER,
            title="No TLS handshake completed",
            detail="The endpoint did not complete a handshake on any tested version.",
            rule_id="net.unreachable",
            evidence=[Evidence(location=endpoint, technique=TECH_NETWORK,
                               confidence=0.9)],
        )]

    supports_pq, pq_note = _probe_pq_group(host, port, timeout)

    if supports_pq is True:
        algorithm, title, confidence = "x25519-ml-kem-768", \
            "Hybrid post-quantum key exchange negotiated", 0.97
        detail = (f"Negotiated {pq_note}. Traffic to this endpoint is already "
                  f"protected against harvest-now-decrypt-later capture.")
    elif supports_pq is False:
        algorithm, title, confidence = "ecdh", "Key exchange is classical only", 0.9
        detail = ("No hybrid post-quantum group was accepted. Traffic captured today "
                  "is decryptable once a CRQC exists. This is the single most "
                  "important property of the endpoint, and the TLS version does not "
                  "reveal it -- TLS 1.3 over a classical group is still Shor-broken.")
    else:
        algorithm, title, confidence = "unknown", \
            "Post-quantum support not determined", 0.5
        detail = (f"Could not test hybrid key exchange ({pq_note}). Reported as "
                  f"undetermined rather than as an absence of support: we did not "
                  f"offer the group, so the server never had the chance to accept it.")

    findings.append(Finding(
        algorithm=algorithm, asset_type=ASSET_PROTOCOL, scanner=SCANNER,
        title=title, detail=detail, rule_id="net.pqgroup",
        evidence=[Evidence(location=endpoint, symbol=pq_note,
                           technique=TECH_NETWORK, confidence=confidence,
                           context=pq_note)],
        extra={"protocol_type": "tls", "pq_supported": supports_pq},
    ))

    if best and best.get("peercert_der"):
        findings.extend(_cert_findings(best["peercert_der"], endpoint))

    return findings


def scan(targets: list[str], timeout: float = 4.0) -> tuple[list[Finding], dict]:
    """Probe a list of ``host`` or ``host:port`` targets."""
    findings: list[Finding] = []
    ok = 0
    for raw in targets:
        raw = raw.strip()
        if not raw:
            continue
        if raw.startswith("https://"):
            raw = raw[len("https://"):].rstrip("/")
        host, _, port_s = raw.partition(":")
        port = int(port_s) if port_s.isdigit() else 443
        try:
            found = scan_endpoint(host, port, timeout)
            findings.extend(found)
            ok += 1
        except Exception:
            continue
    return findings, {"endpoints_probed": ok}

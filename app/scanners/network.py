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

Every destination reaching this module has already been through
``netpolicy.vet``: parsed, resolved, and checked address by address. We
connect to the vetted literal address and pass the hostname only as SNI, so
the destination cannot change between the check and the connection.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import socket
import ssl
from typing import Optional

from .. import netpolicy
from ..netpolicy import Destination, DestinationRefused, NetPolicy
from ..models import ASSET_CERTIFICATE, ASSET_PROTOCOL, Evidence, Finding, TECH_NETWORK

SCANNER = "network"

_VERSIONS = [
    ("TLSv1.3", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_3, "tls1.3"),
    ("TLSv1.2", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_2, "tls1.2"),
    ("TLSv1.1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1, "tls1.1"),
    ("TLSv1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1, "tls1.0"),
]

# Hybrid post-quantum groups we offer, in the names OpenSSL 3.5+ uses. These
# are the standardised ML-KEM hybrids; the pre-standard Kyber draft groups are
# deliberately not offered, because negotiating one would record an obsolete
# identifier in the inventory as though it were a current posture.
PQ_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768"]

# Draft groups we recognise if a server names one, so the finding can say the
# endpoint is on a superseded identifier rather than reporting it as current.
OBSOLETE_PQ_GROUPS = {
    "X25519Kyber768Draft00": "pre-standard CRYSTALS-Kyber draft, superseded by "
                             "X25519MLKEM768 (FIPS 203)",
    "X25519Kyber512Draft00": "pre-standard CRYSTALS-Kyber draft, superseded by "
                             "X25519MLKEM768 (FIPS 203)",
    "P256Kyber768Draft00": "pre-standard CRYSTALS-Kyber draft, superseded by "
                           "SecP256r1MLKEM768 (FIPS 203)",
}


def _base_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _probe_version(dest: Destination, version, timeout: float) -> Optional[dict]:
    """Try to complete a handshake pinned to one TLS version."""
    ctx = _base_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, AttributeError):
        return None
    try:
        with netpolicy.connect(dest, timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=dest.host) as tls:
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


def _probe_pq_group(dest: Destination, timeout: float) -> tuple[Optional[bool], str]:
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
                with netpolicy.connect(dest, timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=dest.host):
                        return True, group
            except (ssl.SSLError, OSError):
                continue
        return False, "no hybrid group accepted"

    # Fallback: drive an OpenSSL 3.5+ CLI, which can offer the groups. The CLI
    # is given the vetted literal address with the hostname carried separately
    # as SNI, so it cannot re-resolve the name to somewhere we refused.
    binary = openssl_bin()
    if not binary:
        return None, ("not tested: no OpenSSL 3.5+ available locally to offer a "
                      "hybrid group")

    import subprocess
    address = dest.addresses[0]
    connect_arg = (f"[{address}]:{dest.port}" if ":" in address
                   else f"{address}:{dest.port}")
    for group in PQ_GROUPS:
        try:
            proc = subprocess.run(
                [binary, "s_client", "-connect", connect_arg,
                 "-servername", dest.host, "-groups", group, "-brief"],
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


def scan_endpoint(dest: Destination, timeout: float = 4.0) -> list[Finding]:
    """Probe one vetted destination."""
    endpoint = dest.label
    findings: list[Finding] = []
    accepted: list[str] = []
    best: Optional[dict] = None

    # A destination reached only because the private-network relaxation was
    # enabled is annotated on every finding it produces. An inventory that
    # quietly mixes internet-facing and lab results is worse than one that
    # refused, because the reader cannot tell which is which.
    relaxation = (" Probed under CD_ALLOW_PRIVATE_TARGETS, which permits internal "
                  "addresses; treat this as a lab observation."
                  if dest.private_allowed else "")
    probe_extra = {"probed_address": dest.addresses[0],
                   "private_target": dest.private_allowed}

    for label, version, alg_key in _VERSIONS:
        if version is None:
            continue
        res = _probe_version(dest, version, timeout)
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
                    "post-quantum group is negotiated.") + relaxation,
            rule_id="net.tlsversion",
            evidence=[Evidence(location=endpoint, symbol=res["cipher"],
                               technique=TECH_NETWORK, confidence=0.99,
                               context=f"{label}, {res['cipher']}, {res['bits']} bits")],
            extra={"protocol_type": "tls", "version": label,
                   "cipher_suites": [res["cipher"]] if res["cipher"] else [],
                   **probe_extra},
        ))

    if not accepted:
        return [Finding(
            algorithm="unknown", asset_type=ASSET_PROTOCOL, scanner=SCANNER,
            title="No TLS handshake completed",
            detail="The endpoint did not complete a handshake on any tested version."
                   + relaxation,
            rule_id="net.unreachable",
            evidence=[Evidence(location=endpoint, technique=TECH_NETWORK,
                               confidence=0.9)],
            extra=dict(probe_extra),
        )]

    supports_pq, pq_note = _probe_pq_group(dest, timeout)

    obsolete = OBSOLETE_PQ_GROUPS.get(pq_note)
    if supports_pq is True and obsolete:
        # Negotiating a pre-standard draft group is not the same posture as
        # negotiating the standardised one, and recording it as though it were
        # would overstate the endpoint's readiness.
        algorithm, title, confidence = "unknown", \
            "Pre-standard post-quantum group negotiated", 0.9
        detail = (f"Negotiated {pq_note}, a {obsolete}. This is not the standardised "
                  f"hybrid group and should be migrated to X25519MLKEM768.")
    elif supports_pq is True:
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
        title=title, detail=detail + relaxation, rule_id="net.pqgroup",
        evidence=[Evidence(location=endpoint, symbol=pq_note,
                           technique=TECH_NETWORK, confidence=confidence,
                           context=pq_note)],
        extra={"protocol_type": "tls", "pq_supported": supports_pq,
               "pq_group": pq_note if supports_pq else None,
               "pq_group_obsolete": bool(obsolete), **probe_extra},
    ))

    if best and best.get("peercert_der"):
        for finding in _cert_findings(best["peercert_der"], endpoint):
            finding.extra.update(probe_extra)
            findings.append(finding)

    return findings


def scan(targets: list[str], timeout: float = 4.0,
         policy: Optional[NetPolicy] = None) -> tuple[list[Finding], dict]:
    """Probe a list of operator-supplied destinations.

    Every destination is vetted before a socket is opened. Refusals are
    returned in the stats rather than raised, so one disallowed entry does not
    discard the rest of the scan -- and so the operator is told about each one
    instead of wondering why a host produced no findings.
    """
    policy = policy or NetPolicy.from_env()
    accepted, refused = netpolicy.vet_all(targets, policy)

    findings: list[Finding] = []
    ok = 0
    errors: list[dict[str, str]] = []
    for dest in accepted:
        try:
            findings.extend(scan_endpoint(dest, timeout))
            ok += 1
        except Exception as exc:
            errors.append({"destination": dest.label, "error": str(exc)})

    stats: dict = {
        "endpoints_requested": len([t for t in targets if t and t.strip()]),
        "endpoints_probed": ok,
        "network_policy": policy.describe(),
    }
    if refused:
        stats["endpoints_refused"] = refused
    if errors:
        stats["endpoint_errors"] = errors
    return findings, stats

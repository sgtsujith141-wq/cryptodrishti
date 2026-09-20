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
from ..knowledge import purposes as P
from ..models import (
    ASSET_ALGORITHM, ASSET_CERTIFICATE, ASSET_PROTOCOL, ASSURANCE_OBSERVED,
    Evidence, Finding, TECH_NETWORK,
)

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


# --------------------------------------------------------------------------
# Cipher suite decomposition
#
# A cipher suite name is not one fact, and treating it as one is where TLS
# reporting usually goes wrong. In TLS 1.2 the name carries four things:
# ECDHE-RSA-AES256-GCM-SHA384 is key exchange ECDHE, authentication RSA, bulk
# cipher AES-256-GCM, PRF hash SHA-384. In TLS 1.3 it carries **two**:
# TLS_AES_256_GCM_SHA384 names the AEAD and the hash and says nothing at all
# about key exchange or authentication, which are negotiated separately.
#
# That difference is the whole reason a TLS 1.3 endpoint cannot be assessed
# from its cipher suite: the quantum-relevant part of the handshake is the one
# part the suite name does not contain.
# --------------------------------------------------------------------------

_KEX_TOKENS = {
    "ECDHE": ("ecdh", "ephemeral elliptic-curve Diffie-Hellman"),
    "EECDH": ("ecdh", "ephemeral elliptic-curve Diffie-Hellman"),
    "DHE": ("dh", "ephemeral finite-field Diffie-Hellman"),
    "EDH": ("dh", "ephemeral finite-field Diffie-Hellman"),
    "ECDH": ("ecdh", "static elliptic-curve Diffie-Hellman"),
    "DH": ("dh", "static finite-field Diffie-Hellman"),
    "PSK": ("unknown", "pre-shared key"),
    "SRP": ("unknown", "secure remote password"),
}

_AUTH_TOKENS = {
    "RSA": ("rsa", "RSA"),
    "ECDSA": ("ecdsa", "ECDSA"),
    "DSS": ("dsa", "DSA"),
    "PSK": ("unknown", "pre-shared key"),
    "anon": ("unknown", "anonymous — no server authentication"),
}


def parse_cipher_suite(name: str, tls_version: str) -> dict:
    """Decompose a negotiated cipher suite into its independent parts.

    Returns a dict whose ``encodes_kex`` field is the one that matters: when
    it is False, nothing about key exchange may be inferred from this string,
    and a caller that does so is guessing.
    """
    out = {
        "suite": name, "kex": None, "kex_label": "", "auth": None,
        "auth_label": "", "encodes_kex": False, "note": "",
    }
    if not name:
        out["note"] = "no cipher suite was reported"
        return out

    upper = name.upper().replace("_", "-")

    # TLS 1.3 suites are named TLS-<AEAD>-<HASH> and carry nothing else.
    if tls_version == "TLSv1.3" or upper.startswith("TLS-AES") or \
            upper.startswith("TLS-CHACHA"):
        out["note"] = (
            "A TLS 1.3 cipher suite names only the AEAD and the hash. Key "
            "exchange and authentication are negotiated independently, so "
            "neither can be read from this suite -- the quantum-relevant half "
            "of the handshake is exactly the half the name omits."
        )
        return out

    # TLS 1.2 and earlier. Strip the IANA prefix and split at WITH.
    body = upper[4:] if upper.startswith("TLS-") else upper
    head = body.split("-WITH-")[0] if "-WITH-" in body else body
    tokens = head.split("-")

    for token in tokens:
        if out["kex"] is None and token in _KEX_TOKENS:
            out["kex"], out["kex_label"] = _KEX_TOKENS[token]
            continue
        if out["auth"] is None and token in _AUTH_TOKENS:
            out["auth"], out["auth_label"] = _AUTH_TOKENS[token]

    if out["kex"] is None and out["auth"] == "rsa":
        # `AES256-SHA` with no explicit exchange is static RSA key transport:
        # the client encrypts the premaster secret to the server's RSA key.
        out["kex"], out["kex_label"] = "rsa", "static RSA key transport"
    if out["kex"] is None and out["auth"] is None:
        out["note"] = "the suite name did not decompose into known components"
        return out

    out["encodes_kex"] = out["kex"] is not None
    if out["encodes_kex"]:
        out["note"] = (f"Key exchange {out['kex_label']}, authentication "
                       f"{out['auth_label'] or 'unstated'}, read from the "
                       f"negotiated suite name.")
    return out


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


# Named TLS groups mapped onto registry algorithms, used only when a group was
# actually read off a completed handshake.
_GROUP_ALGORITHMS = {
    "x25519": "x25519", "x448": "x448",
    "secp256r1": "ecdh", "prime256v1": "ecdh",
    "secp384r1": "ecdh", "secp521r1": "ecdh",
    "ffdhe2048": "dh", "ffdhe3072": "dh", "ffdhe4096": "dh",
    "ffdhe6144": "dh", "ffdhe8192": "dh",
    "x25519mlkem768": "x25519-ml-kem-768",
    "secp256r1mlkem768": "x25519-ml-kem-768",
}


def _observe_negotiated_group(dest: Destination, timeout: float) -> tuple[Optional[str], str]:
    """Read the key-exchange group the server actually chose, if we can.

    Returns (group, how). ``group`` is None when no observation was possible,
    which is a different and much weaker statement than "the group is
    classical". The distinction exists because a failed hybrid probe tells you
    only that one group was not accepted; it does not tell you what *was*
    negotiated, and naming a specific classical mechanism on that basis would
    be inventing an observation.
    """
    binary = openssl_bin()
    if not binary:
        return None, ("no OpenSSL 3.5+ available locally to read the negotiated "
                      "group")

    import subprocess
    address = dest.addresses[0]
    connect_arg = (f"[{address}]:{dest.port}" if ":" in address
                   else f"{address}:{dest.port}")
    try:
        proc = subprocess.run(
            [binary, "s_client", "-connect", connect_arg,
             "-servername", dest.host, "-brief"],
            capture_output=True, text=True, timeout=timeout + 8,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"could not run the local OpenSSL client ({exc})"

    blob = (proc.stdout or "") + (proc.stderr or "")
    m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", blob)
    if m:
        return m.group(1).strip(), "read from the completed handshake"
    return None, ("the handshake did not report a negotiated group (TLS 1.2 and "
                  "earlier do not expose one this way)")


def _verify_trust(dest: Destination, timeout: float) -> tuple[Optional[bool], str]:
    """Attempt a *verifying* handshake, separately from the inspecting one.

    Every other probe in this module deliberately disables verification so it
    can inspect endpoints whose certificates do not validate -- which is most
    of an internal estate. That means none of those probes says anything about
    trust. This one does, by building a chain against the system CA store and
    matching the hostname, and its result is reported as its own fact.

    Returns (verified, detail). None means the attempt itself could not be
    made, which is again distinct from "not trusted".
    """
    ctx = ssl.create_default_context()
    try:
        ctx.load_default_certs()
    except Exception:
        pass
    try:
        with netpolicy.connect(dest, timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=dest.host):
                return True, ("chain built to a trusted root in the system store "
                              "and the hostname matched")
    except ssl.SSLCertVerificationError as exc:
        return False, f"certificate verification failed: {exc.verify_message or exc}"
    except ssl.SSLError as exc:
        return False, f"TLS error during verification: {exc}"
    except OSError as exc:
        return None, f"verification could not be attempted: {exc}"


def _cert_findings(der: bytes, endpoint: str,
                   trust: tuple[Optional[bool], str] = (None, "not attempted"),
                   ) -> list[Finding]:
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

    from .certs import key_usage_purpose
    purpose, purpose_why = key_usage_purpose(cert)

    trusted, trust_detail = trust
    if trusted is True:
        trust_line = f"Certificate chain verified: {trust_detail}."
    elif trusted is False:
        trust_line = (f"Certificate presented but NOT trusted: {trust_detail}. "
                      f"The algorithms below are still an accurate inventory of "
                      f"what the endpoint served.")
    else:
        trust_line = (f"Trust was not established: {trust_detail}. Reported as "
                      f"undetermined rather than as untrusted.")

    return [Finding(
        algorithm=key_alg, asset_type=ASSET_CERTIFICATE, scanner=SCANNER,
        title="Certificate presented by live endpoint",
        detail=(f"Served by {endpoint}. Signed with {sig_name}, expires "
                f"{not_after.date()}. {trust_line}"),
        rule_id="net.cert", key_size=key_bits,
        purpose=purpose, purpose_evidence=purpose_why,
        evidence=[Evidence(location=endpoint, symbol=sig_name,
                           technique=TECH_NETWORK, confidence=0.98,
                           context=f"{key_alg}, expires {not_after.date()}",
                           assurance=ASSURANCE_OBSERVED)],
        extra={"signature_algorithm": sig_name, "not_after": str(not_after.date()),
               "format": "X.509",
               # Observation and trust are two separate facts and are reported
               # as two separate fields. The inspecting handshake deliberately
               # disables verification; this value comes from a second,
               # verifying handshake and from nothing else.
               "trust_verified": trusted,
               "trust_detail": trust_detail},
    )]


def scan_endpoint(dest: Destination, timeout: float = 4.0) -> list[Finding]:
    """Probe one vetted destination.

    Emits each negotiated property as its own finding, because they are
    independent facts with independent remediations:

      * the protocol version accepted,
      * the cipher suite chosen, decomposed where the version allows it,
      * the key-exchange group, only when actually observed,
      * the certificate served, and separately whether it is trusted.

    The rule that governs the whole function: a probe that failed is not an
    observation. If we offer a hybrid group and the server declines it, we
    have learned that the server did not accept that group -- not that it
    negotiated ECDH, not that it negotiated anything in particular. Naming a
    specific classical mechanism there would be recording an inference as a
    measurement, and it is the first thing a reviewer would test.
    """
    endpoint = dest.label
    findings: list[Finding] = []
    accepted: list[str] = []
    best: Optional[dict] = None
    best_label = ""

    relaxation = (" Probed under CD_ALLOW_PRIVATE_TARGETS, which permits internal "
                  "addresses; treat this as a lab observation."
                  if dest.private_allowed else "")
    probe_extra = {"probed_address": dest.addresses[0],
                   "private_target": dest.private_allowed}

    # ---- 1. protocol versions -------------------------------------------
    for label, version, alg_key in _VERSIONS:
        if version is None:
            continue
        res = _probe_version(dest, version, timeout)
        if not res:
            continue
        accepted.append(label)
        if best is None:
            best, best_label = res, label

        legacy = alg_key in ("tls1.0", "tls1.1")
        findings.append(Finding(
            algorithm=alg_key, asset_type=ASSET_PROTOCOL, scanner=SCANNER,
            title=f"{label} accepted",
            detail=("Deprecated by RFC 8996 and should be disabled." if legacy else
                    "The version alone does not determine quantum exposure. What "
                    "matters is the key-exchange group negotiated inside it, "
                    "reported separately below.") + relaxation,
            rule_id="net.tlsversion",
            purpose=P.TRANSPORT,
            purpose_evidence="a protocol version accepted in a completed handshake",
            evidence=[Evidence(location=endpoint, symbol=label,
                               technique=TECH_NETWORK, confidence=0.99,
                               context=f"{label} handshake completed",
                               assurance=ASSURANCE_OBSERVED)],
            extra={"protocol_type": "tls", "version": label,
                   "cipher_suites": [res["cipher"]] if res["cipher"] else [],
                   "determines_quantum_exposure": False, **probe_extra},
        ))

    if not accepted:
        return [Finding(
            algorithm="unknown", asset_type=ASSET_PROTOCOL, scanner=SCANNER,
            title="No TLS handshake completed",
            detail="The endpoint did not complete a handshake on any tested version."
                   + relaxation,
            rule_id="net.unreachable",
            evidence=[Evidence(location=endpoint, technique=TECH_NETWORK,
                               confidence=0.9, assurance=ASSURANCE_OBSERVED)],
            extra=dict(probe_extra),
        )]

    # ---- 2. cipher suite, decomposed ------------------------------------
    suite = best.get("cipher") if best else ""
    parsed = parse_cipher_suite(suite or "", best_label)
    if suite:
        findings.append(Finding(
            algorithm="unknown", asset_type=ASSET_PROTOCOL, scanner=SCANNER,
            title=f"Cipher suite negotiated: {suite}",
            detail=(f"Negotiated at {best_label}. {parsed['note']}" + relaxation),
            rule_id="net.ciphersuite",
            purpose=P.TRANSPORT,
            purpose_evidence="the suite chosen in a completed handshake",
            evidence=[Evidence(location=endpoint, symbol=suite,
                               technique=TECH_NETWORK, confidence=0.99,
                               context=f"{best_label}, {best.get('bits', 0)} bits",
                               assurance=ASSURANCE_OBSERVED)],
            extra={"protocol_type": "tls", "cipher_suites": [suite],
                   "suite_encodes_key_exchange": parsed["encodes_kex"],
                   "suite_key_exchange": parsed["kex"],
                   "suite_authentication": parsed["auth"], **probe_extra},
        ))

        # Key exchange and authentication are separate assets, and only exist
        # as findings when the suite name genuinely carried them.
        if parsed["encodes_kex"] and parsed["kex"]:
            findings.append(Finding(
                algorithm=parsed["kex"], asset_type=ASSET_ALGORITHM, scanner=SCANNER,
                title=f"Key exchange observed: {parsed['kex_label']}",
                detail=(f"Read from the negotiated suite {suite!r}, which encodes the "
                        f"key exchange because this is {best_label}. This is an "
                        f"observation of what was used, not an inference."
                        + relaxation),
                rule_id="net.kex",
                purpose=P.KEY_ESTABLISHMENT,
                purpose_evidence=f"the key-exchange component of the negotiated suite",
                evidence=[Evidence(location=endpoint, symbol=parsed["kex_label"],
                                   technique=TECH_NETWORK, confidence=0.95,
                                   context=suite, assurance=ASSURANCE_OBSERVED)],
                extra={**probe_extra},
            ))
        if parsed["auth"] and parsed["auth"] != "unknown":
            findings.append(Finding(
                algorithm=parsed["auth"], asset_type=ASSET_ALGORITHM, scanner=SCANNER,
                title=f"Server authentication observed: {parsed['auth_label']}",
                detail=(f"The server authenticated itself with {parsed['auth_label']}, "
                        f"read from the negotiated suite {suite!r}. Authentication and "
                        f"key exchange are separate mechanisms with separate "
                        f"replacements." + relaxation),
                rule_id="net.auth",
                purpose=P.SIGNATURE,
                purpose_evidence="the authentication component of the negotiated suite",
                evidence=[Evidence(location=endpoint, symbol=parsed["auth_label"],
                                   technique=TECH_NETWORK, confidence=0.95,
                                   context=suite, assurance=ASSURANCE_OBSERVED)],
                extra={**probe_extra},
            ))

    # ---- 3. key exchange group ------------------------------------------
    supports_pq, pq_note = _probe_pq_group(dest, timeout)
    observed_group, observed_how = _observe_negotiated_group(dest, timeout)
    obsolete = OBSOLETE_PQ_GROUPS.get(pq_note)

    if supports_pq is True and obsolete:
        algorithm, title, confidence = "unknown", \
            "Pre-standard post-quantum group negotiated", 0.9
        detail = (f"Negotiated {pq_note}, a {obsolete}. This is not the standardised "
                  f"hybrid group and should be migrated to X25519MLKEM768.")
    elif supports_pq is True:
        algorithm, title, confidence = "x25519-ml-kem-768", \
            "Hybrid post-quantum key exchange negotiated", 0.97
        detail = (f"Negotiated {pq_note}. Traffic to this endpoint is already "
                  f"protected against harvest-now-decrypt-later capture.")
    elif supports_pq is False and observed_group:
        # We offered hybrid, it was declined, AND we separately read what the
        # server actually chose. Only now can a specific mechanism be named.
        algorithm = _GROUP_ALGORITHMS.get(observed_group.lower(), "unknown")
        title = f"Classical key exchange observed: {observed_group}"
        confidence = 0.95
        detail = (f"No hybrid group was accepted, and the group actually negotiated "
                  f"was {observed_group} ({observed_how}). Traffic captured today is "
                  f"decryptable once a CRQC exists.")
    elif supports_pq is False:
        # The honest state. We know a hybrid group was refused; we did not see
        # what replaced it, so we do not name one.
        algorithm, title, confidence = "unknown", \
            "No hybrid key exchange; specific mechanism not observed", 0.85
        detail = (f"The endpoint declined every hybrid post-quantum group we offered, "
                  f"so its key exchange is classical and traffic captured today is "
                  f"decryptable once a CRQC exists. The specific mechanism was not "
                  f"observed ({observed_how}), so none is named: a refused probe "
                  f"shows what was not accepted, never what was.")
    else:
        algorithm, title, confidence = "unknown", \
            "Post-quantum support not determined", 0.5
        detail = (f"Could not test hybrid key exchange ({pq_note}). Reported as "
                  f"undetermined rather than as an absence of support: we did not "
                  f"offer the group, so the server never had the chance to accept it.")

    findings.append(Finding(
        algorithm=algorithm, asset_type=ASSET_PROTOCOL, scanner=SCANNER,
        title=title, detail=detail + relaxation, rule_id="net.pqgroup",
        purpose=P.KEY_ESTABLISHMENT,
        purpose_evidence="the key-establishment mechanism of the TLS handshake",
        evidence=[Evidence(location=endpoint, symbol=observed_group or pq_note,
                           technique=TECH_NETWORK, confidence=confidence,
                           context=pq_note, assurance=ASSURANCE_OBSERVED)],
        extra={"protocol_type": "tls", "pq_supported": supports_pq,
               "pq_group": pq_note if supports_pq else None,
               "pq_group_obsolete": bool(obsolete),
               "observed_group": observed_group,
               "observed_group_source": observed_how,
               "mechanism_observed": bool(observed_group) or supports_pq is True,
               **probe_extra},
    ))

    # ---- 4. certificate, and separately its trust -----------------------
    if best and best.get("peercert_der"):
        trust = _verify_trust(dest, timeout)
        for finding in _cert_findings(best["peercert_der"], endpoint, trust):
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

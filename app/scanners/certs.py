"""Certificate and key material scanner.

Certificates are the most directly quantifiable quantum liability in an
estate. Each one carries two algorithms -- the subject's public key and the
algorithm that signed it -- plus an explicit expiry date. A certificate signed
with RSA-2048 and valid until 2039 is not an abstract risk; it is a dated one,
and the date is written on the artefact.

Handles PEM and DER encoded X.509, PKCS#12 bundles, and bare private keys.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import warnings
from pathlib import Path
from typing import Iterator, Optional

from .. import config, fspolicy
from ..fspolicy import FsPolicy
from ..knowledge import purposes as P
from ..models import (
    ASSET_CERTIFICATE, ASSET_MATERIAL, ASSURANCE_OBSERVED,
    Evidence, Finding, TECH_CERT_PARSE,
)

SCANNER = "certificate"

CERT_EXTS = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".p7b", ".cert"}
KEY_EXTS = {".key", ".pk8"}
KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key", "privkey.pem"}

_PEM_CERT = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)
_PEM_KEY = re.compile(
    rb"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----", re.DOTALL)

# Signature algorithm OID -> our registry key.
_SIGALG = {
    "sha1WithRSAEncryption": ("rsa", "sha1"),
    "sha256WithRSAEncryption": ("rsa", "sha256"),
    "sha384WithRSAEncryption": ("rsa", "sha384"),
    "sha512WithRSAEncryption": ("rsa", "sha512"),
    "md5WithRSAEncryption": ("rsa", "md5"),
    "ecdsa-with-SHA1": ("ecdsa", "sha1"),
    "ecdsa-with-SHA256": ("ecdsa", "sha256"),
    "ecdsa-with-SHA384": ("ecdsa", "sha384"),
    "ecdsa-with-SHA512": ("ecdsa", "sha512"),
    "dsa-with-sha1": ("dsa", "sha1"),
    "dsa-with-sha256": ("dsa", "sha256"),
    "ed25519": ("ed25519", "sha512"),
}


def _import_x509():
    """Import lazily so the rest of the tool works without the dependency."""
    # Real estates are full of certificates that violate RFC 5280 in small
    # ways. We parse them anyway and report what we find; the library's
    # deprecation warnings about them are noise on a projector.
    warnings.filterwarnings(
        "ignore", category=DeprecationWarning, module="cryptography.*")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
        return x509, rsa, ec, dsa, ed25519
    except ImportError:
        return None


def iter_cert_files(root: Path, max_files: int = 4000,
                    policy: Optional[FsPolicy] = None) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if policy and policy.exhausted():
            return
        # Certificate directories are worth descending into even when the
        # generic skip list would prune them.
        always = {d for d in dirnames if d in ("certs", "pki", "ssl", "tls")}
        fspolicy.filter_dirnames(dirpath, dirnames, config.SKIP_DIRS - always,
                                 root, policy)
        for name in filenames:
            if policy and not policy.count_entry():
                return
            low = name.lower()
            p = Path(dirpath) / name
            if (Path(low).suffix in CERT_EXTS or Path(low).suffix in KEY_EXTS
                    or low in KEY_NAMES):
                if policy and not fspolicy.readable(p, root, policy):
                    continue
                try:
                    if p.stat().st_size > 4_000_000:
                        continue
                except OSError:
                    continue
                yield p
                count += 1
                if count >= max_files:
                    return


# NIST post-quantum algorithm OIDs, under the 2.16.840.1.101.3.4 arc.
# Certificates using these are *already migrated*, and detecting them is how
# the inventory reports progress rather than only debt. Installed versions of
# the cryptography library often cannot parse these key types yet, so we
# resolve them from the OID directly.
PQC_OIDS = {
    "2.16.840.1.101.3.4.3.17": ("ml-dsa-44", "ML-DSA-44"),
    "2.16.840.1.101.3.4.3.18": ("ml-dsa-65", "ML-DSA-65"),
    "2.16.840.1.101.3.4.3.19": ("ml-dsa-87", "ML-DSA-87"),
    "2.16.840.1.101.3.4.4.1": ("ml-kem-512", "ML-KEM-512"),
    "2.16.840.1.101.3.4.4.2": ("ml-kem-768", "ML-KEM-768"),
    "2.16.840.1.101.3.4.4.3": ("ml-kem-1024", "ML-KEM-1024"),
}
# 2.16.840.1.101.3.4.3.20 through .31 are the twelve SLH-DSA parameter sets.
# We resolve the family with certainty and do not claim a specific parameter
# set we have not verified.
_SLH_DSA_ARC = tuple(f"2.16.840.1.101.3.4.3.{n}" for n in range(20, 32))


def oid_to_algorithm(oid: str) -> Optional[tuple[str, str]]:
    if oid in PQC_OIDS:
        return PQC_OIDS[oid]
    if oid in _SLH_DSA_ARC:
        return "slh-dsa-128s", "SLH-DSA"
    return None


def key_usage_purpose(cert) -> tuple[str, str]:
    """Resolve what a certificate's subject key is for, from its KeyUsage.

    This is the one place where a certificate tells you, in a field designed
    for the question, what the key inside it does. ``keyEncipherment`` and
    ``keyAgreement`` mean key establishment; ``digitalSignature``,
    ``keyCertSign`` and ``cRLSign`` mean signing. RSA certificates are the
    reason this matters: without KeyUsage there is nothing in an RSA
    certificate that distinguishes a TLS server key used for key transport
    from a CA key used for signing, and the two need different replacements.

    A certificate asserting *both* is genuinely dual-use, which is a real and
    common configuration, and is reported as unresolved rather than as
    whichever we happened to check first.
    """
    try:
        from cryptography import x509
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except Exception:
        return P.UNKNOWN, ("the certificate carries no KeyUsage extension, so it "
                           "does not state what its key is for")

    signing = bool(getattr(ku, "digital_signature", False)
                   or getattr(ku, "key_cert_sign", False)
                   or getattr(ku, "crl_sign", False)
                   or getattr(ku, "content_commitment", False))
    establishment = bool(getattr(ku, "key_encipherment", False)
                         or getattr(ku, "key_agreement", False)
                         or getattr(ku, "data_encipherment", False))

    flags = [n for n, v in (
        ("digitalSignature", getattr(ku, "digital_signature", False)),
        ("contentCommitment", getattr(ku, "content_commitment", False)),
        ("keyEncipherment", getattr(ku, "key_encipherment", False)),
        ("dataEncipherment", getattr(ku, "data_encipherment", False)),
        ("keyAgreement", getattr(ku, "key_agreement", False)),
        ("keyCertSign", getattr(ku, "key_cert_sign", False)),
        ("cRLSign", getattr(ku, "crl_sign", False)),
    ) if v]
    named = ", ".join(flags) or "none set"

    if signing and establishment:
        return P.UNKNOWN, (f"KeyUsage asserts both signing and key establishment "
                           f"({named}); the key is dual-use, so a single "
                           f"replacement cannot be chosen for it")
    if signing:
        return P.SIGNATURE, f"KeyUsage asserts {named}"
    if establishment:
        return P.KEY_ESTABLISHMENT, f"KeyUsage asserts {named}"
    return P.UNKNOWN, f"KeyUsage sets no usage this tool can interpret ({named})"


def _key_details(pubkey, rsa, ec, dsa, ed25519) -> tuple[str, Optional[int]]:
    """Resolve a public key object to (algorithm key, size in bits)."""
    if isinstance(pubkey, rsa.RSAPublicKey):
        return f"rsa-{pubkey.key_size}", pubkey.key_size
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        name = pubkey.curve.name.lower()
        mapping = {"secp256r1": "ecdsa-p-256", "secp384r1": "ecdsa-p-384",
                   "secp521r1": "ecdsa-p-521", "secp256k1": "ecdsa-secp256k1"}
        return mapping.get(name, "ecdsa"), pubkey.curve.key_size
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "dsa", pubkey.key_size
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "ed25519", 256
    return "unknown", None


def _safe_key_details(cert, mods) -> tuple[str, Optional[int], str]:
    """Resolve the subject key, tolerating algorithms the library cannot load.

    Returns (algorithm key, bits, note). A parser that dies on an unfamiliar
    key type is useless precisely where it matters most -- on the certificates
    that have already moved to post-quantum algorithms.
    """
    _, rsa, ec, dsa, ed25519 = mods
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return (*_key_details(cert.public_key(), rsa, ec, dsa, ed25519), "")
    except Exception as exc:
        oid = ""
        message = str(exc)
        match = re.search(r"([0-9]+(?:\.[0-9]+){3,})", message)
        if match:
            oid = match.group(1)
        try:
            oid = oid or cert.public_key_algorithm_oid.dotted_string
        except Exception:
            pass

        resolved = oid_to_algorithm(oid) if oid else None
        if resolved:
            key, label = resolved
            return key, None, (
                f"Subject key is {label} (OID {oid}), a NIST post-quantum algorithm. "
                f"The installed cryptography library cannot parse this key type, so it "
                f"was resolved from the OID.")
        return "unknown", None, (
            f"Subject key algorithm could not be resolved"
            + (f" (OID {oid})" if oid else "") + ". Reported as unresolved.")


def _parse_certificate(der_or_pem: bytes, rel: str, mods) -> list[Finding]:
    x509, rsa, ec, dsa, ed25519 = mods
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if b"-----BEGIN" in der_or_pem:
                cert = x509.load_pem_x509_certificate(der_or_pem)
            else:
                cert = x509.load_der_x509_certificate(der_or_pem)
    except Exception:
        return []

    try:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        subject = issuer = "<unparseable>"

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:                     # older cryptography
        not_before = cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=dt.timezone.utc)

    now = dt.datetime.now(dt.timezone.utc)
    expired = not_after < now
    remaining_years = (not_after - now).days / 365.25

    try:
        sig_oid = cert.signature_algorithm_oid.dotted_string
    except Exception:
        sig_oid = ""
    sig_name = getattr(cert.signature_algorithm_oid, "_name", "") or sig_oid or "unknown"
    sig_alg, sig_digest = _SIGALG.get(sig_name, ("unknown", "unknown"))
    pqc = oid_to_algorithm(sig_oid) if sig_oid else None
    if pqc:
        sig_alg, sig_digest = pqc[0], "n/a"
        sig_name = pqc[1]

    key_alg, key_bits, key_note = _safe_key_details(cert, mods)

    problems = []
    if expired:
        problems.append(f"expired {abs(remaining_years):.1f} years ago")
    if sig_digest in ("sha1", "md5"):
        problems.append(f"signed with {sig_digest.upper()}, which is collision-broken")
    if key_bits and key_alg.startswith("rsa") and key_bits < 2048:
        problems.append(f"{key_bits}-bit RSA is below the classical minimum")
    if remaining_years > 100:
        # Test and root CA material routinely carries a year-3000 expiry. Saying
        # "988.7 years" reads as a bug rather than as the finding it is.
        problems.append(
            f"expires {not_after.date()}, an implausible lifetime that guarantees "
            f"the key outlives its algorithm")
    elif remaining_years > 4:
        problems.append(
            f"valid for a further {remaining_years:.0f} years, past the 2030 "
            f"NIST IR 8547 deprecation of classical public key algorithms")

    detail = ("Certificate carries two algorithms -- the subject key and the signature "
              "over it -- and an explicit expiry, which makes its exposure directly "
              "datable.")
    if key_note:
        detail += " " + key_note
    if problems:
        detail += " Issues: " + "; ".join(problems) + "."

    key_purpose, key_purpose_why = key_usage_purpose(cert)
    if key_purpose == P.UNKNOWN:
        detail += (" The key's purpose is not resolved: " + key_purpose_why + ".")

    ev = Evidence(
        location=rel, symbol=sig_name, technique=TECH_CERT_PARSE, confidence=0.98,
        context=f"{key_alg} key, {sig_name} signature, expires {not_after.date()}",
        snippet=f"subject={subject[:120]}",
        assurance=ASSURANCE_OBSERVED,
    )

    out = [Finding(
        algorithm=key_alg, asset_type=ASSET_CERTIFICATE, scanner=SCANNER,
        title="X.509 certificate", detail=detail, rule_id="cert.x509",
        key_size=key_bits, evidence=[ev],
        purpose=key_purpose, purpose_evidence=key_purpose_why,
        extra={
            "subject": subject[:200], "issuer": issuer[:200],
            "not_before": str(not_before.date()), "not_after": str(not_after.date()),
            "signature_algorithm": sig_name, "expired": expired,
            "remaining_years": round(remaining_years, 2),
            # `subject == issuer` is an observation about two name fields. It is
            # not a verified self-signature, and it is not a trust decision.
            "self_issued": subject == issuer,
            "self_signed": subject == issuer,
            # Stated on every certificate finding so no reader has to infer it.
            # Parsing a certificate establishes what it contains, never that it
            # is trusted: no chain was built, no CA store consulted, no
            # revocation checked, no name matched against a host.
            "trust_verified": False,
            "trust_note": ("Parsed from disk. Chain building, CA trust, revocation "
                           "and name matching were not attempted, so this is an "
                           "observation of the certificate's contents only."),
            "key_usage_purpose": key_purpose,
            "problems": problems, "format": "X.509",
        },
    )]

    # The signing algorithm is its own migration unit: re-issuing the
    # certificate is a different action from rotating the subject key.
    if sig_alg != "unknown" and sig_alg != key_alg:
        out.append(Finding(
            algorithm=sig_alg, asset_type=ASSET_CERTIFICATE, scanner=SCANNER,
            title="Certificate signature algorithm",
            detail=f"This certificate was signed using {sig_name}.",
            rule_id="cert.sigalg",
            purpose=P.SIGNATURE,
            purpose_evidence=("this algorithm produced the signature over the "
                              "certificate, which is a signing operation by "
                              "definition"),
            evidence=[Evidence(location=rel, symbol=sig_name,
                               technique=TECH_CERT_PARSE, confidence=0.98,
                               context=sig_name, assurance=ASSURANCE_OBSERVED)],
            extra={"format": "X.509", "trust_verified": False},
        ))
    # The digest inside the signature is its own cryptographic asset. Only the
    # broken ones were inventoried, which meant a CBOM of a healthy estate
    # listed no hash functions at all from its certificates -- and "which
    # digest are our certificates signed with" is a question a migration
    # programme has to answer for every certificate, not only the bad ones.
    if sig_digest not in ("unknown", "n/a", "") and sig_digest not in ("sha1", "md5"):
        out.append(Finding(
            algorithm=sig_digest, asset_type=ASSET_CERTIFICATE, scanner=SCANNER,
            title=f"Certificate signature digest ({sig_digest.upper()})",
            detail=(f"This certificate's signature is computed over a "
                    f"{sig_digest.upper()} digest. The digest is a migration unit "
                    f"in its own right: re-issuing with a different signature "
                    f"algorithm changes it."),
            rule_id="cert.digest",
            purpose=P.HASHING,
            purpose_evidence="the digest inside the certificate signature algorithm",
            evidence=[Evidence(location=rel, symbol=sig_name,
                               technique=TECH_CERT_PARSE, confidence=0.98,
                               context=f"{sig_name} over {sig_digest}",
                               assurance=ASSURANCE_OBSERVED)],
            extra={"format": "X.509", "trust_verified": False,
                   "digest": sig_digest},
        ))

    if sig_digest in ("sha1", "md5"):
        out.append(Finding(
            algorithm=sig_digest, asset_type=ASSET_CERTIFICATE, scanner=SCANNER,
            title=f"Certificate signed with {sig_digest.upper()}",
            detail=("A collision-broken digest in a certificate signature is a "
                    "present-tense forgery risk, independent of quantum computing."),
            rule_id="cert.weakdigest",
            purpose=P.HASHING,
            purpose_evidence="the digest used inside the certificate signature",
            evidence=[Evidence(location=rel, symbol=sig_name,
                               technique=TECH_CERT_PARSE, confidence=0.98,
                               assurance=ASSURANCE_OBSERVED)],
            extra={"format": "X.509", "trust_verified": False},
        ))
    return out


def scan_file(path: Path, root: Path, mods) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)

    findings: list[Finding] = []

    for m in _PEM_CERT.finditer(data):
        findings.extend(_parse_certificate(m.group(0), rel, mods))

    if not findings and path.suffix.lower() in {".der", ".cer", ".crt"}:
        findings.extend(_parse_certificate(data, rel, mods))

    for m in _PEM_KEY.finditer(data):
        label = m.group(1).decode("ascii", "ignore")
        findings.append(Finding(
            algorithm="unknown", asset_type=ASSET_MATERIAL, scanner=SCANNER,
            title=f"Private key file ({label.title()})",
            detail=("Private key material on disk. Every such key is a migration "
                    "unit: it must be regenerated, not merely reconfigured."),
            rule_id="cert.privatekey",
            purpose_evidence=("a private key file does not state what the key is "
                              "used for"),
            evidence=[Evidence(location=rel, symbol=label,
                               technique=TECH_CERT_PARSE, confidence=0.95,
                               assurance=ASSURANCE_OBSERVED)],
            extra={"material_type": "private-key", "format": "PEM"},
        ))

    return findings


def scan(root: str | Path, max_files: int = 4000,
         policy: Optional[FsPolicy] = None) -> tuple[list[Finding], dict]:
    mods = _import_x509()
    if mods is None:
        return [], {"certificates_scanned": 0,
                    "note": "cryptography library unavailable; certificate scanning skipped"}

    root = Path(root).resolve()
    findings: list[Finding] = []
    n = 0
    for path in iter_cert_files(root, max_files, policy):
        n += 1
        findings.extend(scan_file(path, root, mods))
    return findings, {"certificate_files_scanned": n}

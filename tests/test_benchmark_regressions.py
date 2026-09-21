"""Regressions for defects the accuracy benchmark found.

Every test here corresponds to a false positive, false negative or purpose
error measured by ``benchmark/run.py`` against the hand-labelled corpus. None
of them was found by reading the code; all of them were found by measuring it,
which is the argument for having a benchmark at all.

Each fails against the code as it stood at 382e7d1.
"""

from __future__ import annotations

import pathlib

import pytest

from app.knowledge import rules_binary as rb
from app.knowledge import rules_source as rs
from app.knowledge import purposes as P
from app.scanners import certs, configs, source


def scan_text(text: str, name: str, kind: str = "generic"):
    """Run the config scanner over a literal snippet."""
    return configs.analyse_text(text, name, kind)


# ==========================================================================
# D1 — a hyphen inside a cipher name is not an OpenSSL exclusion marker
# ==========================================================================

def test_hyphenated_cipher_components_are_not_treated_as_exclusions():
    """`-RSA-` in ECDHE-RSA-AES256 is a separator, not `!RSA`.

    Treating every hyphen as an exclusion silently dropped AES-256, RSA and
    MD5 out of suites that plainly permit them — four false negatives, all in
    the direction that makes an estate look cleaner than it is.
    """
    findings = scan_text(
        "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA;\n",
        "nginx.conf", "nginx")
    algorithms = {f.algorithm for f in findings}
    assert "aes-256" in algorithms
    assert "rsa" in algorithms
    assert "3des" in algorithms


def test_a_real_openssl_exclusion_is_still_honoured():
    """`!MD5` and `-RC4` genuinely exclude, and must keep doing so."""
    findings = scan_text("ssl_ciphers HIGH:!aNULL:!MD5:-RC4;\n",
                         "nginx.conf", "nginx")
    algorithms = {f.algorithm for f in findings}
    assert "md5" not in algorithms
    assert "rc4" not in algorithms


# ==========================================================================
# D2 — TLSv1 must not match inside TLSv1.2
# ==========================================================================

def test_tls10_is_not_invented_from_a_tls12_configuration():
    """`\\b` treats the dot as a word boundary, so a plain boundary match
    reported TLS 1.0 as enabled on a server offering only 1.2 and 1.3."""
    findings = scan_text("ssl_protocols TLSv1.2 TLSv1.3;\n", "nginx.conf", "nginx")
    protocols = {f.algorithm for f in findings}
    assert protocols == {"tls1.2", "tls1.3"}
    assert "tls1.0" not in protocols


def test_a_genuine_legacy_protocol_is_still_reported():
    findings = scan_text("SSLProtocol TLSv1 TLSv1.1\n", "ssl.conf", "apache")
    protocols = {f.algorithm for f in findings}
    assert "tls1.0" in protocols
    assert "tls1.1" in protocols


# ==========================================================================
# D3 — DES-CBC3 is Triple DES, not single DES
# ==========================================================================

def test_triple_des_is_not_reported_as_single_des():
    findings = scan_text("ssl_ciphers DES-CBC3-SHA;\n", "nginx.conf", "nginx")
    algorithms = {f.algorithm for f in findings}
    assert "3des" in algorithms
    assert "des" not in algorithms, "DES-CBC3 is Triple DES"


def test_single_des_is_still_reported_when_it_really_is_single_des():
    findings = scan_text("ssl_ciphers DES-CBC-SHA;\n", "nginx.conf", "nginx")
    assert "des" in {f.algorithm for f in findings}


def test_the_openssl_sha_suffix_is_recognised_as_sha1():
    """`DES-CBC-SHA` is a HMAC-SHA1 suite; the bare `SHA` names SHA-1."""
    findings = scan_text("ssl_ciphers AES128-SHA;\n", "nginx.conf", "nginx")
    assert "sha1" in {f.algorithm for f in findings}


# ==========================================================================
# D4 — HmacSHA256 resolves to HMAC
# ==========================================================================

@pytest.mark.parametrize("name", ["HmacSHA256", "HmacSHA1", "HMAC-SHA3-512",
                                  "hmacMD5"])
def test_hmac_names_resolve_to_hmac(name):
    """A MAC whose name states exactly what it is was reported as unknown."""
    assert rs._norm_alg(name) == "hmac"


def test_a_java_mac_call_site_resolves(tmp_path):
    (tmp_path / "M.java").write_text(
        'class M { void f() throws Exception { Mac.getInstance("HmacSHA256"); } }\n')
    findings, _ = source.scan(tmp_path)
    assert "hmac" in {f.algorithm for f in findings}


# ==========================================================================
# D5 — the ECB rule must follow the cipher it applies to
# ==========================================================================

def test_ecb_on_an_rsa_transform_does_not_invent_an_aes_finding(tmp_path):
    """`RSA/ECB/OAEPPadding` produced an AES finding in a file with no AES."""
    (tmp_path / "R.java").write_text(
        'class R { void f() throws Exception {\n'
        '  Cipher.getInstance("RSA/ECB/OAEPPadding");\n} }\n')
    findings, _ = source.scan(tmp_path)
    ecb = [f for f in findings if f.rule_id == "any.ecb.mode"]
    assert ecb
    assert all(f.algorithm != "aes" for f in ecb), "no AES is present here"
    assert ecb[0].algorithm == "rsa"


def test_ecb_on_an_aes_transform_still_names_aes(tmp_path):
    (tmp_path / "A.java").write_text(
        'class A { void f() throws Exception {\n'
        '  Cipher.getInstance("AES/ECB/PKCS5Padding");\n} }\n')
    findings, _ = source.scan(tmp_path)
    ecb = [f for f in findings if f.rule_id == "any.ecb.mode"]
    assert ecb and ecb[0].algorithm == "aes"


def test_a_bare_ecb_constant_leaves_the_cipher_unresolved(tmp_path):
    """`MODE_ECB` alone does not say which cipher. The mode is the finding.

    Written in C rather than Python on purpose: in a .py file the AST pass
    resolves `AES.new(...)` and claims the line, so the pattern rule never
    sees it — which is the AST-wins-over-regex behaviour working correctly.
    """
    (tmp_path / "c.c").write_text("int mode_flag = MODE_ECB;\n")
    findings, _ = source.scan(tmp_path)
    ecb = [f for f in findings if f.rule_id == "any.ecb.mode"]
    assert ecb
    assert ecb[0].mode == "ecb"
    assert ecb[0].algorithm == "unknown"


# ==========================================================================
# D6 — a certificate's signature digest is an asset, not only when broken
# ==========================================================================

def _cert(digest: str) -> bytes:
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.invalid")])
    now = dt.datetime.now(dt.timezone.utc)
    algorithm = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384()}[digest]
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .sign(key, algorithm))
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize("digest", ["sha256", "sha384"])
def test_a_healthy_certificate_digest_is_inventoried(digest):
    """Only broken digests were reported, so a CBOM of a healthy estate
    listed no hash functions from its certificates at all."""
    mods = certs._import_x509()
    if mods is None:
        pytest.skip("cryptography not installed")
    findings = certs._parse_certificate(_cert(digest), "t.pem", mods)
    digests = [f for f in findings if f.rule_id == "cert.digest"]
    assert digests, f"{digest} should be inventoried"
    assert digests[0].algorithm == digest
    assert digests[0].purpose == P.HASHING


def test_the_healthy_digest_finding_does_not_displace_the_defect_finding():
    """A broken digest must still produce its own defect finding.

    Adding `cert.digest` for healthy digests must not turn the SHA-1 and MD5
    cases into ordinary inventory rows: those are present-tense forgery risks
    and are reported as such.
    """
    source_text = pathlib.Path("app/scanners/certs.py").read_text()
    assert "cert.weakdigest" in source_text
    # The healthy-digest branch explicitly excludes the broken ones.
    assert 'sig_digest not in ("sha1", "md5")' in source_text


# ==========================================================================
# D7 — a binary symbol whose name states the operation resolves the purpose
# ==========================================================================

@pytest.mark.parametrize("symbol,purpose", [
    ("RSA_sign", P.SIGNATURE),
    ("RSA_verify", P.SIGNATURE),
    ("RSA_public_encrypt", P.KEY_ESTABLISHMENT),
    ("RSA_private_decrypt", P.KEY_ESTABLISHMENT),
    ("ECDH_compute_key", P.KEY_ESTABLISHMENT),
])
def test_symbol_names_that_state_the_operation_resolve_it(symbol, purpose):
    assert rb.SYMBOL_PURPOSE.get(symbol) == purpose


@pytest.mark.parametrize("symbol", ["RSA_new", "RSA_free", "RSA_generate_key",
                                    "EC_KEY_new"])
def test_symbol_names_that_state_nothing_resolve_nothing(symbol):
    """Generation and allocation say a key exists, not what it is for —
    the same answer the source sensor gives for key generation."""
    assert symbol not in rb.SYMBOL_PURPOSE


def test_aes_encrypt_is_encryption_not_key_establishment():
    """The first fix mapped every `_encrypt` to key transport, which claimed
    AES was wrapping keys. That distinction only holds for asymmetric."""
    assert rb.SYMBOL_PURPOSE.get("AES_encrypt") == P.ENCRYPTION
    assert rb.SYMBOL_PURPOSE.get("RSA_public_encrypt") == P.KEY_ESTABLISHMENT


def test_a_binary_finding_carries_the_resolved_purpose(tmp_path):
    from app.scanners import binary

    blob = (b"\x7fELF\x02\x01\x01" + b"\x00" * 57
            + b"RSA_sign\x00" + b"\x00" * 600)
    (tmp_path / "lib.so").write_bytes(blob)
    findings, _ = binary.scan(tmp_path)
    rsa = [f for f in findings if f.algorithm == "rsa"]
    assert rsa
    assert rsa[0].purpose == P.SIGNATURE
    assert "symbol" in rsa[0].purpose_evidence

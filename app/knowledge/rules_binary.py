"""Binary detection signatures.

Cryptography survives compilation in three recoverable forms:

1. **Symbol names.** Dynamically linked binaries keep the names of imported
   functions in ``.dynstr``. ``RSA_new`` in that table is unambiguous evidence.

2. **Constants.** Every block cipher and hash needs tables that cannot be
   computed cheaply at run time, so they sit in ``.rodata`` verbatim: AES
   S-boxes, SHA-256 round constants, the MD5 sine table. These survive
   stripping, because they are data rather than code. This is the technique
   that reaches firmware and vendor binaries with no symbols at all.

3. **Version strings.** Crypto libraries embed their own build banner, which
   pins the exact version and therefore its known weaknesses.

Constants are quoted here as the leading bytes of each published table, which
is enough to identify it while keeping the signature small.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ConstantSignature:
    name: str
    algorithm: str
    pattern: bytes
    note: str
    confidence: float = 0.9


# --------------------------------------------------------------------------
# Constant tables
# --------------------------------------------------------------------------

# Every signature below was verified by recomputing the table from its
# defining formula and confirming the match against a real OpenSSL build.
# An unverified signature is worse than a missing one: it produces findings
# that cannot be defended when challenged.
CONSTANTS: list[ConstantSignature] = [
    ConstantSignature(
        "AES forward S-box", "aes",
        bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
        "First 16 bytes of the AES substitution box (FIPS 197). Present in "
        "essentially every software AES implementation.",
        0.95,
    ),
    ConstantSignature(
        "AES inverse S-box", "aes",
        bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
        "First 16 bytes of the AES inverse S-box, used by the decryption path.",
        0.95,
    ),
    ConstantSignature(
        "SHA-256 round constants", "sha256",
        bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba5"),
        "First four SHA-256 round constants (FIPS 180-4), big-endian.",
        0.95,
    ),
    ConstantSignature(
        "SHA-256 round constants (LE)", "sha256",
        bytes.fromhex("982f8a4291443771cffbc0b5a5dbb5e9"),
        "First four SHA-256 round constants stored little-endian.",
        0.9,
    ),
    ConstantSignature(
        "SHA-512 round constants", "sha512",
        bytes.fromhex("428a2f98d728ae227137449123ef65cd"),
        "First two SHA-512 round constants (FIPS 180-4).",
        0.95,
    ),
    ConstantSignature(
        "MD5 sine table", "md5",
        bytes.fromhex("78a46ad756b7c7e8db702024eecebdc1"),
        "First four entries of the MD5 T table, little-endian. MD5 is "
        "collision-broken and must not appear in a signature path.",
        0.95,
    ),
    ConstantSignature(
        "SHA-1 / MD5 initial state", "sha1",
        bytes.fromhex("0123456789abcdeffedcba9876543210"),
        "The shared Merkle-Damgard initialisation vector. Weak on its own, so "
        "reported at reduced confidence.",
        0.6,
    ),
    ConstantSignature(
        "SHA-1 round constant K0", "sha1",
        bytes.fromhex("9979825a"),
        "SHA-1 round constant 0x5a827999, little-endian.",
        0.7,
    ),
]


# --------------------------------------------------------------------------
# Symbol names
# --------------------------------------------------------------------------

# symbol prefix/name -> (algorithm key, human label, confidence)
SYMBOLS: dict[str, tuple[str, str, float]] = {}

# Symbols whose *name* states what the algorithm is doing. `RSA_sign` is a
# signing call however little else the binary tells us, and leaving RSA's
# purpose unresolved there threw away evidence that was sitting in the symbol
# table -- the same purpose distinction M2 fixed for source, missing from the
# sensor that reaches vendor binaries where no source exists.
SYMBOL_PURPOSE: dict[str, str] = {}

_SIGN_TOKENS = ("_sign", "_verify", "digestsign", "digestverify")
_ENCRYPT_TOKENS = ("_encrypt", "_decrypt")
_AGREE_TOKENS = ("compute_key", "_derive", "_encaps", "_decaps")

# Algorithms for which encrypt/decrypt means key transport rather than bulk
# encryption. `RSA_public_encrypt` wraps a session key; `AES_encrypt` encrypts
# data. Mapping both to key establishment -- which an earlier version of this
# function did -- claimed AES was doing something it never does.
_ASYMMETRIC = ("rsa", "elgamal")


def _purpose_from_name(name: str, algorithm: str) -> str:
    """Read the operation off the symbol name, or return an empty string.

    Only names that *state* the operation resolve anything. `RSA_new` says a
    key exists and nothing about what it is for, so it stays unresolved --
    which is the same answer the source sensor gives for key generation.
    """
    lowered = name.lower()
    if any(t in lowered for t in _SIGN_TOKENS):
        return "signature"
    if any(t in lowered for t in _AGREE_TOKENS):
        return "key-establishment"
    if any(t in lowered for t in _ENCRYPT_TOKENS):
        return ("key-establishment" if algorithm.startswith(_ASYMMETRIC)
                else "encryption")
    return ""


def _syms(names: list[str], algorithm: str, label: str, conf: float = 0.92) -> None:
    for n in names:
        SYMBOLS[n] = (algorithm, label, conf)
        purpose = _purpose_from_name(n, algorithm)
        if purpose:
            SYMBOL_PURPOSE[n] = purpose


_syms(["RSA_new", "RSA_free", "RSA_generate_key", "RSA_generate_key_ex",
       "RSA_public_encrypt", "RSA_private_decrypt", "RSA_sign", "RSA_verify",
       "RSA_padding_add_PKCS1_type_1", "EVP_PKEY_CTX_set_rsa_keygen_bits"],
      "rsa", "RSA")

_syms(["ECDSA_do_sign", "ECDSA_do_verify", "ECDSA_sign", "ECDSA_verify",
       "EC_KEY_new", "EC_KEY_generate_key", "EC_POINT_mul", "EC_GROUP_new_by_curve_name"],
      "ecdsa", "ECDSA / elliptic curve")

_syms(["DH_new", "DH_generate_key", "DH_compute_key", "ECDH_compute_key",
       "EVP_PKEY_derive"], "dh", "Diffie-Hellman key agreement")

_syms(["DSA_do_sign", "DSA_do_verify", "DSA_generate_key"], "dsa", "DSA")

_syms(["MD5_Init", "MD5_Update", "MD5_Final", "EVP_md5"], "md5", "MD5")
_syms(["SHA1_Init", "SHA1_Update", "SHA1_Final", "EVP_sha1"], "sha1", "SHA-1")
_syms(["SHA256_Init", "SHA256_Update", "EVP_sha256"], "sha256", "SHA-256")
_syms(["SHA512_Init", "SHA512_Update", "EVP_sha512"], "sha512", "SHA-512")

_syms(["DES_set_key", "DES_ecb_encrypt", "DES_ncbc_encrypt",
       "DES_ede3_cbc_encrypt", "EVP_des_ede3_cbc"], "3des", "DES / Triple-DES")
_syms(["RC4", "RC4_set_key", "EVP_rc4"], "rc4", "RC4")

_syms(["EVP_aes_128_cbc", "EVP_aes_128_gcm"], "aes-128", "AES-128")
_syms(["EVP_aes_256_cbc", "EVP_aes_256_gcm", "EVP_aes_256_xts"], "aes-256", "AES-256")
_syms(["AES_set_encrypt_key", "AES_encrypt", "AES_cbc_encrypt"], "aes", "AES")

_syms(["EVP_PKEY_ML_KEM_512", "EVP_PKEY_ML_KEM_768", "EVP_PKEY_ML_KEM_1024",
       "OQS_KEM_new", "OQS_KEM_kyber_768_keypair", "pqcrystals_kyber768_ref_keypair"],
      "ml-kem-768", "ML-KEM (post-quantum)", 0.9)
_syms(["EVP_PKEY_ML_DSA_44", "EVP_PKEY_ML_DSA_65", "EVP_PKEY_ML_DSA_87",
       "OQS_SIG_new", "pqcrystals_dilithium3_ref_keypair"],
      "ml-dsa-65", "ML-DSA (post-quantum)", 0.9)

_syms(["SSL_CTX_new", "TLS_method", "SSL_connect", "SSL_CTX_set_cipher_list"],
      "tls1.2", "TLS", 0.75)
_syms(["RAND_pseudo_bytes"], "weak-rng", "Deprecated PRNG", 0.85)


# --------------------------------------------------------------------------
# Version banners
# --------------------------------------------------------------------------

VERSION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("OpenSSL", re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?(?:-[a-z0-9]+)?)"), "openssl"),
    ("BoringSSL", re.compile(rb"BoringSSL\s+([0-9a-f]{7,40})"), "boringssl"),
    ("LibreSSL", re.compile(rb"LibreSSL\s+(\d+\.\d+\.\d+)"), "libressl"),
    ("GnuTLS", re.compile(rb"GnuTLS\s+(\d+\.\d+\.\d+)"), "gnutls"),
    ("NSS", re.compile(rb"NSS/(\d+\.\d+(?:\.\d+)?)"), "nss"),
    ("libgcrypt", re.compile(rb"libgcrypt\s+(\d+\.\d+\.\d+)"), "libgcrypt"),
    ("wolfSSL", re.compile(rb"wolfSSL\s+(\d+\.\d+\.\d+)"), "wolfssl"),
    ("mbedTLS", re.compile(rb"mbed\s?TLS\s+(\d+\.\d+\.\d+)"), "mbedtls"),
    ("BouncyCastle", re.compile(rb"BouncyCastle.*?(\d+\.\d+)"), "bouncycastle"),
]

# Versions with known material weaknesses, used to raise the finding's detail.
KNOWN_WEAK_VERSIONS = {
    "openssl": [
        (re.compile(r"^0\."), "End of life since 2015. Unsupported and unpatched."),
        (re.compile(r"^1\.0\."), "End of life since 2019 (1.0.2) / 2016 (1.0.1). "
                                 "No security patches; predates TLS 1.3."),
        (re.compile(r"^1\.1\.0"), "End of life since 2019."),
        (re.compile(r"^1\.1\.1"), "End of life since September 2023 for the public branch. "
                                  "No post-quantum support."),
        (re.compile(r"^3\.[0-4]\."), "Supported, but predates OpenSSL 3.5 and therefore has "
                                     "no native ML-KEM / ML-DSA."),
    ],
}


def version_note(library: str, version: str) -> str:
    for pattern, note in KNOWN_WEAK_VERSIONS.get(library, []):
        if pattern.match(version):
            return note
    return ""

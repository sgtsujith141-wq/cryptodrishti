"""Source-code detection rules.

Each rule is a compiled pattern plus a resolver that turns the match into a
concrete algorithm key and any parameters it can determine (mode, padding,
key size). Resolvers are what separate this from grep: a match on
``Cipher.getInstance("AES/ECB/PKCS5Padding")`` must yield *aes*, *ecb* and
*pkcs5*, not merely "something crypto happened here".

Confidence is assigned per rule and reflects how specific the pattern is. A
rule that matches an unambiguous API call earns a high score; one that matches
a bare identifier earns a low one and is reported as such. We would rather
report `unknown` at 0.4 than claim RSA at 1.0 and be wrong in front of a
cryptographer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from . import purposes as P
from ..models import (
    ASSET_ALGORITHM, ASSET_MATERIAL, ASSET_PROTOCOL,
    ASSURANCE_CAPABILITY, ASSURANCE_OBSERVED, ASSURANCE_USED, TECH_PATTERN,
)

# --------------------------------------------------------------------------
# Language mapping
# --------------------------------------------------------------------------

EXT_LANG = {
    ".java": "java", ".kt": "java", ".scala": "java", ".groovy": "java",
    ".py": "python", ".pyi": "python",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".hpp": "c", ".cxx": "c",
    ".go": "go",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js",
    ".ts": "js", ".tsx": "js",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".swift": "swift",
    ".m": "c", ".mm": "c",
}

# --------------------------------------------------------------------------
# Resolvers
# --------------------------------------------------------------------------

# Normalised names for algorithms as they appear in source strings.
# Every alias maps onto the algorithm it actually names. Earlier versions
# folded distinct algorithms together -- MD2 onto MD5, BLAKE2b onto SHA-512 --
# which produced an inventory that named the wrong artefact. For a CBOM, whose
# whole purpose is to be a record of what is present, that is a correctness
# failure rather than a cosmetic one.
_ALG_ALIASES = {
    "aes": "aes", "aes128": "aes-128", "aes192": "aes-192", "aes256": "aes-256",
    "rijndael": "aes",
    "rsa": "rsa", "dsa": "dsa", "ec": "ecdsa", "ecdsa": "ecdsa", "ecdh": "ecdh",
    "eddsa": "ed25519",
    "dh": "dh", "diffiehellman": "dh", "elgamal": "elgamal",
    "des": "des", "desede": "3des", "tripledes": "3des", "3des": "3des",
    "desede3": "3des",
    "rc4": "rc4", "arcfour": "rc4", "arc4": "rc4", "rc2": "rc2",
    "blowfish": "blowfish", "cast5": "cast5", "cast": "cast5",
    "idea": "idea", "seed": "seed", "camellia": "camellia",
    "chacha20": "chacha20", "chacha": "chacha20",

    # Hashes. Each output length is its own algorithm.
    "md2": "md2", "md4": "md4", "md5": "md5",
    "sha1": "sha1", "sha-1": "sha1",
    "sha224": "sha224", "sha-224": "sha224",
    "sha256": "sha256", "sha-256": "sha256",
    "sha384": "sha384", "sha-384": "sha384",
    "sha512": "sha512", "sha-512": "sha512",
    "sha512224": "sha512-224", "sha512-224": "sha512-224",
    "sha512256": "sha512-256", "sha512-256": "sha512-256",
    "sha3224": "sha3-224", "sha3-224": "sha3-224", "sha3_224": "sha3-224",
    "sha3256": "sha3-256", "sha3-256": "sha3-256", "sha3_256": "sha3-256",
    "sha3384": "sha3-384", "sha3-384": "sha3-384", "sha3_384": "sha3-384",
    "sha3512": "sha3-512", "sha3-512": "sha3-512", "sha3_512": "sha3-512",
    "shake128": "shake128", "shake-128": "shake128", "shake_128": "shake128",
    "shake256": "shake256", "shake-256": "shake256", "shake_256": "shake256",
    "blake2b": "blake2b", "blake2b512": "blake2b", "blake2b-512": "blake2b",
    "blake2s": "blake2s", "blake2s256": "blake2s", "blake2s-256": "blake2s",
    "blake3": "blake3",

    "ed25519": "ed25519", "ed448": "ed448",
    "x25519": "x25519", "x448": "x448",
    "hmac": "hmac",
}

# Names that look parameterised but are indivisible. `sha3-512` must never be
# reduced to a family called `sha3`, which is what the generic fallback did.
_ATOMIC_PREFIXES = ("sha3", "shake", "blake2", "blake3", "sha512-", "sha512_")

_MODES = {"ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "ccm", "xts", "gcm-siv"}


def _norm_alg(raw: str) -> str:
    """Map a source-level algorithm name onto a registry key.

    The last step used to truncate at the first dash or underscore, which is
    right for ``aes_gcm`` and catastrophic for ``sha3-512``: it produced the
    family ``sha3``, which is not registered, so every SHA-3 variant except
    SHA3-256 resolved to ``unknown``. Compound hash names are now atomic.
    """
    s = re.sub(r"[^a-z0-9_-]", "", raw.strip().lower())
    if not s:
        return "unknown"
    if s in _ALG_ALIASES:
        return _ALG_ALIASES[s]

    # Normalise separators before the atomic check: SHA3_512, SHA3-512 and
    # SHA3512 are the same algorithm written three ways.
    flat = s.replace("_", "").replace("-", "")
    if flat in _ALG_ALIASES:
        return _ALG_ALIASES[flat]

    # AES_256, AES-256 and friends.
    m = re.match(r"^(aes|rsa|camellia)[-_]?(\d{3,4})$", s)
    if m:
        return f"{m.group(1)}-{m.group(2)}"

    # An indivisible name that did not match above is genuinely unrecognised.
    # Truncating it would manufacture a different algorithm's identity.
    if flat.startswith(_ATOMIC_PREFIXES):
        return "unknown"

    base = re.sub(r"[-_].*$", "", s)
    return _ALG_ALIASES.get(base, "unknown")


# Public-key algorithms passed to a *cipher* API are doing key transport,
# whatever the padding says. Symmetric algorithms there are bulk encryption.
_ASYMMETRIC_KEYS = ("rsa", "elgamal")


def resolve_java_transform(m: re.Match) -> dict:
    """``AES/ECB/PKCS5Padding`` -> algorithm, mode, padding.

    A ``Cipher.getInstance`` call settles purpose: an asymmetric algorithm
    reached through the cipher API is transporting a key, and a symmetric one
    is encrypting data. That is why this resolver can name a purpose while
    ``KeyPairGenerator.getInstance("RSA")`` cannot.
    """
    transform = (m.groupdict().get("transform") or m.group(1) or "").strip()
    parts = [p.strip() for p in transform.split("/")]
    alg = _norm_alg(parts[0]) if parts else "unknown"
    mode = parts[1].lower() if len(parts) > 1 and parts[1].lower() in _MODES else None
    padding = parts[2].lower() if len(parts) > 2 else None

    if alg.startswith(_ASYMMETRIC_KEYS):
        purpose = P.KEY_ESTABLISHMENT
        why = (f"reached through the JCE Cipher API as {transform!r}; a public-key "
               f"algorithm used as a cipher is transporting a symmetric key")
    else:
        purpose = P.ENCRYPTION
        why = f"reached through the JCE Cipher API as {transform!r}"

    return {"algorithm": alg, "mode": mode, "padding": padding,
            "context": transform, "purpose": purpose, "purpose_evidence": why}


# Signature algorithm names that do not use the `<digest>with<signer>` form.
_SIGNATURE_NAMES = {
    "rsassapss": "rsa", "rsapss": "rsa", "pss": "rsa",
    "ed25519": "ed25519", "ed448": "ed448",
    "eddsa": "ed25519", "ecdsa": "ecdsa", "dsa": "dsa",
    "mldsa": "ml-dsa-65", "mldsa44": "ml-dsa-44", "mldsa65": "ml-dsa-65",
    "mldsa87": "ml-dsa-87", "slhdsa": "slh-dsa-128s",
}


def resolve_java_signature(m: re.Match) -> dict:
    """``SHA1withRSA`` -> the *signing* algorithm, noting the digest.

    The whole point of this resolver is that a ``Signature.getInstance`` call
    is unambiguously a signature, so RSA reached this way gets a signature
    recommendation rather than a KEM. It also keeps the digest half as its own
    recorded algorithm, because ``SHA3-512withRSA`` names two artefacts.
    """
    raw = (m.groupdict().get("transform") or m.group(1) or "").strip()
    low = raw.lower()
    out: dict = {"context": raw, "purpose": P.SIGNATURE,
                 "purpose_evidence": f"selected through the JCE Signature API as {raw!r}"}

    if "with" in low:
        digest_raw, _, signer_raw = low.partition("with")
        # `SHA256withRSAandMGF1` is RSASSA-PSS; the trailing `and<MGF>` names
        # the mask generation function, not a second signature algorithm.
        signer_raw = re.split(r"and(?:mgf|MGF)", signer_raw)[0].strip("-_ ")
        alg = _norm_alg(signer_raw)
        if alg == "unknown":
            alg = _SIGNATURE_NAMES.get(re.sub(r"[^a-z0-9]", "", signer_raw), "unknown")
        out["algorithm"] = alg
        digest = _norm_alg(digest_raw)
        if digest != "unknown":
            out["extra"] = {"digest": digest}
        return out

    flat = re.sub(r"[^a-z0-9]", "", low)
    out["algorithm"] = _SIGNATURE_NAMES.get(flat) or _norm_alg(raw)
    return out


def resolve_named(alg: str) -> Callable[[re.Match], dict]:
    """A rule whose algorithm is fixed regardless of what matched."""
    def _r(m: re.Match) -> dict:
        return {"algorithm": alg, "context": m.group(0)[:120]}
    return _r


def resolve_capture(m: re.Match) -> dict:
    """Take the algorithm name straight from the first named/first group."""
    raw = m.groupdict().get("transform") or (m.group(1) if m.re.groups else m.group(0))
    return {"algorithm": _norm_alg(raw or ""), "context": (raw or "").strip()}


def resolve_openssl_evp(m: re.Match) -> dict:
    """``EVP_aes_128_cbc`` -> aes-128 + cbc."""
    raw = m.group(0)
    body = raw.replace("EVP_", "").lower()
    bits = re.search(r"_(\d{3,4})_", "_" + body + "_")
    mode = None
    for md in _MODES:
        if body.endswith("_" + md) or ("_" + md + "_") in body:
            mode = md
            break
    fam = body.split("_")[0]
    alg = _norm_alg(f"{fam}{bits.group(1)}" if bits and fam == "aes" else fam)
    return {"algorithm": alg, "mode": mode, "context": raw}


def resolve_node_cipher(m: re.Match) -> dict:
    """``aes-128-cbc`` -> aes-128 + cbc."""
    raw = (m.groupdict().get("transform") or m.group(1) or "").strip().lower()
    parts = raw.split("-")
    mode = parts[-1] if parts and parts[-1] in _MODES else None
    alg = _norm_alg("-".join(parts[:2]) if len(parts) > 1 and parts[1].isdigit() else parts[0])
    return {"algorithm": alg, "mode": mode, "context": raw}


def resolve_keysize(alg: str) -> Callable[[re.Match], dict]:
    """A generator call with an explicit key size, e.g. ``initialize(1024)``."""
    def _r(m: re.Match) -> dict:
        try:
            size = int(m.groupdict().get("size") or m.group(1))
        except (TypeError, ValueError):
            size = None
        key = f"{alg}-{size}" if size else alg
        return {"algorithm": key, "key_size": size, "context": m.group(0)[:120]}
    return _r


# --------------------------------------------------------------------------
# Rule definition
# --------------------------------------------------------------------------

@dataclass
class SourceRule:
    id: str
    languages: tuple[str, ...]
    pattern: str
    resolve: Callable[[re.Match], dict]
    title: str
    detail: str = ""
    confidence: float = 0.75
    asset_type: str = ASSET_ALGORITHM
    flags: int = 0
    # What the matched API is *for*, when the API itself settles it. An
    # `RSA_sign` call is a signature whatever the key is; a
    # `KeyPairGenerator.getInstance("RSA")` call settles nothing, so it leaves
    # this empty and the finding stays purpose-unknown.
    purpose: str = ""
    # What the match proves. Source rules match call sites, so the default is
    # USED; rules that match an import or a provider reference override it.
    assurance: str = ASSURANCE_USED
    _compiled: Optional[re.Pattern] = None

    def compiled(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, self.flags)
        return self._compiled

    def applies_to(self, lang: str) -> bool:
        return "*" in self.languages or lang in self.languages


R = SourceRule
RULES: list[SourceRule] = []


def _add(*rules: SourceRule) -> None:
    RULES.extend(rules)


# ---- Java / JVM ----------------------------------------------------------

_add(
    R("java.cipher.getinstance", ("java",),
      r'Cipher\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,80})"',
      resolve_java_transform,
      "JCE cipher instantiated",
      "The transform string fixes the algorithm, mode and padding at this call site.",
      0.95),

    R("java.keypairgen", ("java",),
      r'KeyPairGenerator\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,40})"',
      resolve_capture,
      "Asymmetric key pair generated",
      "Key pair generation is the point at which a quantum-vulnerable key enters the system.",
      0.95),

    R("java.keygen", ("java",),
      r'KeyGenerator\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,40})"',
      resolve_capture,
      "Symmetric key generated", "", 0.9, purpose=P.ENCRYPTION),

    R("java.signature", ("java",),
      r'Signature\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,50})"',
      resolve_java_signature,
      "Digital signature algorithm selected",
      "Signature schemes are Shor-broken; the digest half only affects collision resistance.",
      0.95),

    R("java.digest", ("java",),
      r'MessageDigest\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,30})"',
      resolve_capture,
      "Hash function selected", "", 0.95, purpose=P.HASHING),

    R("java.mac", ("java",),
      r'Mac\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,40})"',
      resolve_capture, "MAC algorithm selected", "", 0.9, purpose=P.AUTHENTICATION),

    R("java.keysize", ("java",),
      r'\.\s*initialize\s*\(\s*(?P<size>\d{3,5})\s*[,)]',
      resolve_keysize("rsa"),
      "Key size fixed at generation",
      "Reported as RSA unless a nearby getInstance resolves a different family.",
      0.55),

    R("java.ssl.context", ("java",),
      r'SSLContext\s*\.\s*getInstance\s*\(\s*"(?P<transform>TLS[^"]{0,10}|SSL[^"]{0,10})"',
      lambda m: {"algorithm": _tls_key(m.group("transform")),
                 "context": m.group("transform")},
      "TLS/SSL context created", "", 0.9, ASSET_PROTOCOL, purpose=P.TRANSPORT),

    R("java.random.weak", ("java",),
      r'new\s+java\.util\.Random\s*\(|(?<![\w.])new\s+Random\s*\(',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "java.util.Random is a linear congruential generator and is predictable from "
      "a small number of outputs. Use SecureRandom.",
      0.8, purpose=P.RANDOMNESS),

    R("java.bouncycastle", ("java",),
      r'org\.bouncycastle\.[\w.]+',
      resolve_named("unknown"),
      "BouncyCastle provider referenced",
      "Provider-level reference; the concrete algorithm depends on the call site.",
      0.4, assurance=ASSURANCE_CAPABILITY),

    # Framework wrapper classes. Application frameworks routinely hide the
    # primitive behind a domain class -- Shiro's Sha256Hash, AesCipherService
    # and so on. A scanner that only knows the JCE API misses all of it, which
    # is the single largest blind spot in rule-based crypto detection.
    R("java.wrapper.hash", ("java",),
      r'\bnew\s+(?P<transform>Md5|Sha1|Sha224|Sha256|Sha384|Sha512|'
      r'Sha3_?224|Sha3_?256|Sha3_?384|Sha3_?512|Blake2b|Blake2s)Hash\s*\(',
      resolve_capture,
      "Hash via framework wrapper class",
      "The primitive is hidden behind a framework class rather than a JCE call. "
      "Resolved from the class name.",
      0.85, purpose=P.HASHING),

    R("java.wrapper.cipher", ("java",),
      r'\bnew\s+(?P<transform>Aes|Blowfish|Des|TripleDes|Rc4)CipherService\s*\(',
      resolve_capture,
      "Cipher via framework wrapper class", "", 0.85, purpose=P.ENCRYPTION),

    R("java.secretkeyspec", ("java",),
      r'new\s+SecretKeySpec\s*\([^)]{0,120}?"(?P<transform>[A-Za-z0-9]{2,20})"\s*\)',
      resolve_capture,
      "Symmetric key material constructed", "", 0.85, purpose=P.ENCRYPTION),

    R("java.securerandom.algo", ("java",),
      r'SecureRandom\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,30})"',
      resolve_named("weak-rng"),
      "Explicit PRNG algorithm selected",
      "SHA1PRNG is not a NIST-approved DRBG and its behaviour varies by provider. "
      "Prefer the platform default constructor or an SP 800-90A DRBG.",
      0.75, purpose=P.RANDOMNESS),

    R("java.keystore", ("java",),
      r'KeyStore\s*\.\s*getInstance\s*\(\s*"(?P<transform>[A-Za-z0-9]{2,12})"',
      resolve_named("unknown"),
      "Key store opened",
      "Key stores hold long-lived private keys and certificates; each is a "
      "migration unit in its own right.",
      0.7, ASSET_MATERIAL),

    # A getInstance call whose argument is *not* a literal. We cannot resolve
    # the algorithm statically, so we report it as unresolved rather than
    # guessing. These are exactly the sites a human reviewer must look at.
    R("java.getinstance.dynamic", ("java",),
      r'\b(?:Cipher|MessageDigest|Signature|KeyGenerator|KeyPairGenerator|Mac)\s*\.\s*'
      r'getInstance\s*\(\s*(?![\'"])(?P<transform>[A-Za-z_][\w.()]{2,40})\s*[,)]',
      resolve_named("unknown"),
      "Cryptographic algorithm selected at runtime",
      "The algorithm is supplied by a variable or method call, so it cannot be "
      "resolved by static analysis. Reported as unresolved for manual review "
      "rather than guessed.",
      0.55),

    R("java.import.crypto", ("java",),
      r'^import\s+(?:javax\.crypto|java\.security)\.[\w.]+;',
      resolve_named("unknown"),
      "Cryptographic API imported",
      "File-level signal that this compilation unit performs cryptography.",
      0.3, ASSET_ALGORITHM, re.MULTILINE, assurance=ASSURANCE_CAPABILITY),
)


def _tls_key(raw: str) -> str:
    r = raw.strip().lower().replace("v", "").replace("tls", "").replace("ssl", "")
    return {"1": "tls1.0", "1.0": "tls1.0", "1.1": "tls1.1",
            "1.2": "tls1.2", "1.3": "tls1.3"}.get(r, "tls1.2")


# ---- Python (pattern rules; the AST pass in scanners/source.py is primary) -

_add(
    R("py.hashlib.weak", ("python",),
      r'hashlib\s*\.\s*(?P<transform>md5|sha1)\s*\(',
      resolve_capture,
      "Weak hash function",
      "MD5 and SHA-1 are collision-broken classically. Never acceptable for signatures.",
      0.95, purpose=P.HASHING),

    R("py.crypto.cipher", ("python",),
      r'(?:Crypto|Cryptodome)\.Cipher\.(?P<transform>AES|DES|DES3|ARC4|Blowfish)',
      resolve_capture, "PyCryptodome cipher used", "", 0.9, purpose=P.ENCRYPTION),

    R("py.rsa.generate", ("python",),
      r'rsa\.generate_private_key\s*\([^)]*key_size\s*=\s*(?P<size>\d{3,5})',
      resolve_keysize("rsa"),
      "RSA key pair generated", "", 0.95),

    R("py.ec.curve", ("python",),
      r'ec\.(?P<transform>SECP256R1|SECP384R1|SECP521R1|SECP256K1)\s*\(',
      lambda m: {"algorithm": {"SECP256R1": "ecdsa-p-256", "SECP384R1": "ecdsa-p-384",
                               "SECP521R1": "ecdsa-p-521", "SECP256K1": "ecdsa-secp256k1"}
                 .get(m.group("transform"), "ecdsa"),
                 "context": m.group("transform")},
      "Elliptic curve selected", "", 0.95),

    R("py.ssl.legacy", ("python",),
      r'ssl\.PROTOCOL_(?P<transform>TLSv1(?:_1|_2)?|SSLv23|SSLv3)',
      lambda m: {"algorithm": {"TLSv1": "tls1.0", "TLSv1_1": "tls1.1",
                               "TLSv1_2": "tls1.2", "SSLv3": "tls1.0",
                               "SSLv23": "tls1.2"}.get(m.group("transform"), "tls1.2"),
                 "context": m.group("transform")},
      "Legacy TLS protocol constant", "", 0.9, ASSET_PROTOCOL, purpose=P.TRANSPORT),

    R("py.random.weak", ("python",),
      r'(?<![\w.])random\s*\.\s*(?:random|randint|choice|randrange)\s*\(',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "Python's random module is a Mersenne Twister; its state is recoverable. "
      "Use the secrets module or os.urandom for anything security-bearing.",
      0.55, purpose=P.RANDOMNESS),
)

# ---- C / C++ / OpenSSL ---------------------------------------------------

_add(
    R("c.openssl.evp", ("c",),
      r'\bEVP_(?:aes|des|rc4|chacha)[a-z0-9_]*\b',
      resolve_openssl_evp, "OpenSSL EVP cipher", "", 0.9, purpose=P.ENCRYPTION),

    # RSA is split by API because the API is what settles the purpose.
    # RSA_sign and RSA_public_encrypt are the same algorithm doing two jobs
    # with two different post-quantum replacements.
    R("c.openssl.rsa.sign", ("c",),
      r'\bRSA_(?:sign|verify|sign_ASN1_OCTET_STRING|verify_ASN1_OCTET_STRING)\b'
      r'|\bEVP_(?:DigestSign|DigestVerify)[A-Za-z]*\s*\(',
      resolve_named("rsa"), "OpenSSL RSA signing API",
      "A signing call site. The replacement is a signature scheme, not a KEM.",
      0.9, purpose=P.SIGNATURE),

    R("c.openssl.rsa.encrypt", ("c",),
      r'\bRSA_(?:public_encrypt|private_decrypt)\b'
      r'|\bEVP_PKEY_(?:encrypt|decrypt)(?:_init)?\s*\(',
      resolve_named("rsa"), "OpenSSL RSA key transport API",
      "Public-key encryption of a short value is key transport. The "
      "replacement is a KEM or a hybrid group.",
      0.9, purpose=P.KEY_ESTABLISHMENT),

    R("c.openssl.rsa.keygen", ("c",),
      r'\bRSA_(?:generate_key(?:_ex)?|new)\b',
      resolve_named("rsa"), "OpenSSL RSA key generation",
      "Key generation is where a quantum-vulnerable key enters the system, but "
      "it does not reveal what the key will be used for. Purpose is left "
      "unresolved rather than assumed.",
      0.9),

    R("c.openssl.ecdsa", ("c",),
      r'\bECDSA_(?:do_sign|do_verify|sign|verify)\b|\bEC_KEY_(?:new|generate_key)\b',
      resolve_named("ecdsa"), "OpenSSL ECDSA / EC key API", "", 0.9,
      purpose=P.SIGNATURE),

    R("c.openssl.dh", ("c",),
      r'\bDH_(?:generate_key|compute_key|new)\b|\bECDH_compute_key\b',
      resolve_named("dh"), "OpenSSL Diffie-Hellman API", "", 0.9,
      purpose=P.KEY_ESTABLISHMENT),

    R("c.openssl.digest.weak", ("c",),
      r'\b(?P<transform>MD5|SHA1)_(?:Init|Update|Final)\b|\bEVP_(?P<t2>md5|sha1)\b',
      lambda m: {"algorithm": _norm_alg(m.group("transform") or m.group("t2") or ""),
                 "context": m.group(0)},
      "Weak hash function", "", 0.9, purpose=P.HASHING),

    R("c.openssl.des", ("c",),
      r'\bDES_(?:set_key|ecb_encrypt|ncbc_encrypt|ede3_cbc_encrypt)\b',
      resolve_named("3des"), "DES / Triple-DES API", "", 0.9, purpose=P.ENCRYPTION),

    R("c.rand.weak", ("c",),
      r'\bRAND_pseudo_bytes\b|(?<![\w.])\brand\s*\(\s*\)',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "RAND_pseudo_bytes is deprecated and rand() is not cryptographically secure.",
      0.6, purpose=P.RANDOMNESS),

    R("c.pqc.mlkem", ("c",),
      r'\b(?:OQS_KEM_kyber|ML_KEM|EVP_PKEY_ML_KEM|mlkem)[a-z0-9_]*\b',
      resolve_named("ml-kem-768"),
      "Post-quantum KEM in use",
      "Evidence of an already-migrated code path. Recorded so the CBOM shows "
      "progress, not only debt.",
      0.85, purpose=P.KEY_ESTABLISHMENT),
)

# ---- Go ------------------------------------------------------------------

_add(
    R("go.rsa.sign", ("go",),
      r'\brsa\.(?:SignPKCS1v15|SignPSS|VerifyPKCS1v15|VerifyPSS)\b',
      resolve_named("rsa"), "Go crypto/rsa signing",
      "A signing call site. The replacement is ML-DSA, not a KEM.",
      0.9, purpose=P.SIGNATURE),
    R("go.rsa.encrypt", ("go",),
      r'\brsa\.(?:EncryptPKCS1v15|DecryptPKCS1v15|EncryptOAEP|DecryptOAEP|'
      r'DecryptPKCS1v15SessionKey)\b',
      resolve_named("rsa"), "Go crypto/rsa key transport",
      "Public-key encryption of a session key. The replacement is a KEM or a "
      "hybrid group.",
      0.9, purpose=P.KEY_ESTABLISHMENT),
    R("go.rsa.keygen", ("go",), r'\brsa\.GenerateKey\b',
      resolve_named("rsa"), "Go crypto/rsa key generation",
      "Generation does not reveal the key's purpose; left unresolved.",
      0.9),
    R("go.ecdsa", ("go",), r'\becdsa\.(?:GenerateKey|Sign|Verify|SignASN1|VerifyASN1)\b',
      resolve_named("ecdsa"), "Go crypto/ecdsa used", "", 0.9,
      purpose=P.SIGNATURE),
    R("go.ecdh", ("go",), r'\becdh\.(?:P256|P384|P521|X25519)\s*\(',
      resolve_named("ecdh"), "Go crypto/ecdh key agreement", "", 0.9,
      purpose=P.KEY_ESTABLISHMENT),
    R("go.ed25519", ("go",), r'\bed25519\.(?:GenerateKey|Sign|Verify)\b',
      resolve_named("ed25519"), "Go crypto/ed25519 used", "", 0.9,
      purpose=P.SIGNATURE),
    R("go.weakhash", ("go",), r'"crypto/(?P<transform>md5|sha1)"|\b(?P<t2>md5|sha1)\.(?:New|Sum)\b',
      lambda m: {"algorithm": _norm_alg(m.group("transform") or m.group("t2") or ""),
                 "context": m.group(0)},
      "Weak hash function", "", 0.9, purpose=P.HASHING),
    R("go.des", ("go",), r'"crypto/des"|\bdes\.New(?:TripleDES)?Cipher\b',
      resolve_named("3des"), "DES / Triple-DES used", "", 0.9, purpose=P.ENCRYPTION),
    R("go.mathrand", ("go",), r'"math/rand"',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "math/rand is deterministic. Use crypto/rand for key material.", 0.7, purpose=P.RANDOMNESS),
)

# ---- Node / JavaScript ---------------------------------------------------

_add(
    R("js.createcipher", ("js",),
      r'createCipheriv\s*\(\s*[\'"](?P<transform>[a-z0-9\-]{3,30})[\'"]',
      resolve_node_cipher, "Node cipher instantiated", "", 0.9, purpose=P.ENCRYPTION),
    R("js.createhash", ("js",),
      r'createHash\s*\(\s*[\'"](?P<transform>md4|md5|sha1|sha224|sha256|sha384|sha512|'
      r'sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256|'
      r'blake2b512|blake2s256)[\'"]',
      resolve_capture, "Hash function selected", "", 0.9, purpose=P.HASHING),
    R("js.generatekeypair", ("js",),
      r'generateKeyPair(?:Sync)?\s*\(\s*[\'"](?P<transform>rsa|ec|ed25519|dsa)[\'"]',
      resolve_capture, "Key pair generated", "", 0.9),
    R("js.mathrandom", ("js",),
      r'\bMath\.random\s*\(\s*\)',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "Math.random is not seeded from a secure source and must never produce key "
      "material, tokens or nonces.", 0.6, purpose=P.RANDOMNESS),
)

# ---- C# / Ruby / PHP -----------------------------------------------------

_add(
    R("cs.crypto", ("csharp",),
      r'\bnew\s+(?P<transform>RSACryptoServiceProvider|DSACryptoServiceProvider|'
      r'MD5CryptoServiceProvider|SHA1Managed|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)\b',
      lambda m: {"algorithm": _norm_alg(
          m.group("transform").replace("CryptoServiceProvider", "").replace("Managed", "")),
          "context": m.group("transform")},
      ".NET cryptographic provider", "", 0.9),
    R("php.weakhash", ("php",),
      r'\b(?P<transform>md5|sha1)\s*\(', resolve_capture,
      "Weak hash function", "", 0.85, purpose=P.HASHING),
    R("php.hash", ("php",),
      r'\bhash\s*\(\s*[\'"](?P<transform>[a-z0-9\-]{3,12})[\'"]',
      resolve_capture, "Hash function selected",
      "PHP's hash() names the algorithm in its first argument.", 0.9,
      purpose=P.HASHING),
    R("php.mcrypt", ("php",),
      r'\bmcrypt_[a-z_]+\s*\(', resolve_named("unknown"),
      "Removed mcrypt extension", "mcrypt was removed in PHP 7.2.", 0.7, purpose=P.ENCRYPTION),
    R("ruby.digest", ("ruby",),
      r'\bDigest::(?P<transform>MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\b',
      resolve_capture, "Hash function selected", "", 0.9, purpose=P.HASHING),
)

# ---- Modern digests -------------------------------------------------------
#
# Previously unreachable. The registry knew only SHA3-256 and the scanner
# mapped SHA3-512 onto it, so no SHA-3 variant except one could be reported at
# its real identity and BLAKE2 could not be reported at all.

_add(
    R("java.digest.sha3", ("java",),
      r'MessageDigest\s*\.\s*getInstance\s*\(\s*"(?P<transform>SHA3-(?:224|256|384|512))"',
      resolve_capture, "SHA-3 hash function selected",
      "Recorded at its actual output length. SHA3-512 is not SHA3-256.",
      0.95, purpose=P.HASHING),

    R("py.hashlib.modern", ("python",),
      r'hashlib\s*\.\s*(?P<transform>sha3_224|sha3_256|sha3_384|sha3_512|'
      r'shake_128|shake_256|blake2b|blake2s)\s*\(',
      resolve_capture, "Hash function selected",
      "Resolved to the exact variant named at the call site.",
      0.95, purpose=P.HASHING),

    R("go.hash.modern", ("go",),
      r'"golang\.org/x/crypto/(?P<transform>sha3|blake2b|blake2s)"'
      r'|\b(?P<t2>sha3|blake2b|blake2s)\.(?:New|Sum|New256|New512|Sum256|Sum512)\b',
      lambda m: {"algorithm": _norm_alg(m.group("transform") or m.group("t2") or ""),
                 "context": m.group(0)},
      "Hash function selected", "", 0.85, purpose=P.HASHING),

    R("c.openssl.digest.modern", ("c",),
      r'\bEVP_(?P<transform>sha3_224|sha3_256|sha3_384|sha3_512|'
      r'shake128|shake256|blake2b512|blake2s256)\b',
      resolve_capture, "Hash function selected", "", 0.9, purpose=P.HASHING),

    R("java.keyagreement", ("java",),
      r'KeyAgreement\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,30})"',
      resolve_capture, "Key agreement algorithm selected",
      "A key agreement call site. The replacement is a KEM or a hybrid group.",
      0.95, purpose=P.KEY_ESTABLISHMENT),
)

# ---- Cross-language: key material and dangerous constructs ---------------

_add(
    R("any.private.key.inline", ("*",),
      r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
      resolve_named("unknown"),
      "Private key embedded in source",
      "A private key committed to a repository is compromised the moment the "
      "repository is cloned, independent of any quantum consideration.",
      0.98, ASSET_MATERIAL, assurance=ASSURANCE_OBSERVED),

    R("any.certificate.inline", ("*",),
      r'-----BEGIN CERTIFICATE-----',
      resolve_named("unknown"),
      "Certificate embedded in source", "", 0.9, ASSET_MATERIAL, assurance=ASSURANCE_OBSERVED),

    R("any.hardcoded.secret", ("*",),
      r'(?i)\b(?:secret_key|private_key|api_secret|encryption_key|aes_key|passphrase)\s*'
      r'[=:]\s*[\'"][A-Za-z0-9+/=_\-]{16,}[\'"]',
      resolve_named("unknown"),
      "Hardcoded secret",
      "Key material in source cannot be rotated without a code change, which is "
      "the opposite of crypto-agility.",
      0.7, ASSET_MATERIAL, assurance=ASSURANCE_OBSERVED),

    R("any.ecb.mode", ("*",),
      r'(?i)\b(?:MODE_ECB|/ECB/|["\']ecb["\']|AES_ECB)\b',
      resolve_named("aes"),
      "ECB mode of operation",
      "ECB leaks plaintext structure because identical blocks encrypt identically. "
      "It is a defect regardless of key size or quantum threat.",
      0.85, purpose=P.ENCRYPTION),
)

# Rules indexed by language for fast dispatch.
_BY_LANG: dict[str, list[SourceRule]] = {}


def rules_for(lang: str) -> list[SourceRule]:
    if lang not in _BY_LANG:
        _BY_LANG[lang] = [r for r in RULES if r.applies_to(lang)]
    return _BY_LANG[lang]


def language_for(path: str) -> Optional[str]:
    for ext, lang in EXT_LANG.items():
        if path.endswith(ext):
            return lang
    return None

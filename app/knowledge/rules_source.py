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

from ..models import (
    ASSET_ALGORITHM, ASSET_MATERIAL, ASSET_PROTOCOL,
    TECH_PATTERN,
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
_ALG_ALIASES = {
    "aes": "aes", "aes128": "aes-128", "aes192": "aes-192", "aes256": "aes-256",
    "rsa": "rsa", "dsa": "dsa", "ec": "ecdsa", "ecdsa": "ecdsa", "ecdh": "ecdh",
    "dh": "dh", "diffiehellman": "dh", "elgamal": "elgamal",
    "des": "des", "desede": "3des", "tripledes": "3des", "3des": "3des",
    "rc4": "rc4", "arcfour": "rc4",
    "blowfish": "unknown", "chacha20": "chacha20", "chacha": "chacha20",
    "md5": "md5", "md2": "md5", "sha1": "sha1", "sha-1": "sha1",
    "sha224": "sha224", "sha-224": "sha224",
    "sha256": "sha256", "sha-256": "sha256",
    "sha384": "sha384", "sha-384": "sha384",
    "sha512": "sha512", "sha-512": "sha512",
    "sha3-256": "sha3-256",
    "ed25519": "ed25519", "x25519": "x25519",
    "hmac": "hmac",
}

_MODES = {"ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "ccm", "xts", "gcm-siv"}


def _norm_alg(raw: str) -> str:
    """Map a source-level algorithm name onto a registry key."""
    s = re.sub(r"[^a-z0-9-]", "", raw.strip().lower())
    if s in _ALG_ALIASES:
        return _ALG_ALIASES[s]
    # AES_256, AES-256 and friends
    m = re.match(r"^(aes|rsa)-?(\d{3,4})$", s)
    if m:
        return f"{m.group(1)}-{m.group(2)}"
    base = re.sub(r"[-_].*$", "", s)
    return _ALG_ALIASES.get(base, "unknown")


def resolve_java_transform(m: re.Match) -> dict:
    """``AES/ECB/PKCS5Padding`` -> algorithm, mode, padding."""
    transform = (m.groupdict().get("transform") or m.group(1) or "").strip()
    parts = [p.strip() for p in transform.split("/")]
    alg = _norm_alg(parts[0]) if parts else "unknown"
    mode = parts[1].lower() if len(parts) > 1 and parts[1].lower() in _MODES else None
    padding = parts[2].lower() if len(parts) > 2 else None
    return {"algorithm": alg, "mode": mode, "padding": padding, "context": transform}


def resolve_java_signature(m: re.Match) -> dict:
    """``SHA1withRSA`` -> the *signing* algorithm, noting the digest."""
    raw = (m.groupdict().get("transform") or m.group(1) or "").strip()
    low = raw.lower().replace("-", "")
    sig = re.split(r"with", low)
    if len(sig) == 2:
        digest, signer = sig[0], sig[1]
        alg = _norm_alg(signer)
        return {"algorithm": alg, "context": raw, "extra": {"digest": _norm_alg(digest)}}
    return {"algorithm": _norm_alg(raw), "context": raw}


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
      "Symmetric key generated", "", 0.9),

    R("java.signature", ("java",),
      r'Signature\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,50})"',
      resolve_java_signature,
      "Digital signature algorithm selected",
      "Signature schemes are Shor-broken; the digest half only affects collision resistance.",
      0.95),

    R("java.digest", ("java",),
      r'MessageDigest\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,30})"',
      resolve_capture,
      "Hash function selected", "", 0.95),

    R("java.mac", ("java",),
      r'Mac\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,40})"',
      resolve_capture, "MAC algorithm selected", "", 0.9),

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
      "TLS/SSL context created", "", 0.9, ASSET_PROTOCOL),

    R("java.random.weak", ("java",),
      r'new\s+java\.util\.Random\s*\(|(?<![\w.])new\s+Random\s*\(',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "java.util.Random is a linear congruential generator and is predictable from "
      "a small number of outputs. Use SecureRandom.",
      0.8),

    R("java.bouncycastle", ("java",),
      r'org\.bouncycastle\.[\w.]+',
      resolve_named("unknown"),
      "BouncyCastle provider referenced",
      "Provider-level reference; the concrete algorithm depends on the call site.",
      0.4),

    # Framework wrapper classes. Application frameworks routinely hide the
    # primitive behind a domain class -- Shiro's Sha256Hash, AesCipherService
    # and so on. A scanner that only knows the JCE API misses all of it, which
    # is the single largest blind spot in rule-based crypto detection.
    R("java.wrapper.hash", ("java",),
      r'\bnew\s+(?P<transform>Md5|Sha1|Sha224|Sha256|Sha384|Sha512)Hash\s*\(',
      resolve_capture,
      "Hash via framework wrapper class",
      "The primitive is hidden behind a framework class rather than a JCE call. "
      "Resolved from the class name.",
      0.85),

    R("java.wrapper.cipher", ("java",),
      r'\bnew\s+(?P<transform>Aes|Blowfish|Des|TripleDes|Rc4)CipherService\s*\(',
      resolve_capture,
      "Cipher via framework wrapper class", "", 0.85),

    R("java.secretkeyspec", ("java",),
      r'new\s+SecretKeySpec\s*\([^)]{0,120}?"(?P<transform>[A-Za-z0-9]{2,20})"\s*\)',
      resolve_capture,
      "Symmetric key material constructed", "", 0.85),

    R("java.securerandom.algo", ("java",),
      r'SecureRandom\s*\.\s*getInstance\s*\(\s*"(?P<transform>[^"]{2,30})"',
      resolve_named("weak-rng"),
      "Explicit PRNG algorithm selected",
      "SHA1PRNG is not a NIST-approved DRBG and its behaviour varies by provider. "
      "Prefer the platform default constructor or an SP 800-90A DRBG.",
      0.75),

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
      0.3, ASSET_ALGORITHM, re.MULTILINE),
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
      0.95),

    R("py.crypto.cipher", ("python",),
      r'(?:Crypto|Cryptodome)\.Cipher\.(?P<transform>AES|DES|DES3|ARC4|Blowfish)',
      resolve_capture, "PyCryptodome cipher used", "", 0.9),

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
      "Legacy TLS protocol constant", "", 0.9, ASSET_PROTOCOL),

    R("py.random.weak", ("python",),
      r'(?<![\w.])random\s*\.\s*(?:random|randint|choice|randrange)\s*\(',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "Python's random module is a Mersenne Twister; its state is recoverable. "
      "Use the secrets module or os.urandom for anything security-bearing.",
      0.55),
)

# ---- C / C++ / OpenSSL ---------------------------------------------------

_add(
    R("c.openssl.evp", ("c",),
      r'\bEVP_(?:aes|des|rc4|chacha)[a-z0-9_]*\b',
      resolve_openssl_evp, "OpenSSL EVP cipher", "", 0.9),

    R("c.openssl.rsa", ("c",),
      r'\bRSA_(?:generate_key(?:_ex)?|new|public_encrypt|private_decrypt|sign|verify)\b',
      resolve_named("rsa"), "OpenSSL RSA API", "", 0.9),

    R("c.openssl.ecdsa", ("c",),
      r'\bECDSA_(?:do_sign|do_verify|sign|verify)\b|\bEC_KEY_(?:new|generate_key)\b',
      resolve_named("ecdsa"), "OpenSSL ECDSA / EC key API", "", 0.9),

    R("c.openssl.dh", ("c",),
      r'\bDH_(?:generate_key|compute_key|new)\b|\bECDH_compute_key\b',
      resolve_named("dh"), "OpenSSL Diffie-Hellman API", "", 0.9),

    R("c.openssl.digest.weak", ("c",),
      r'\b(?P<transform>MD5|SHA1)_(?:Init|Update|Final)\b|\bEVP_(?P<t2>md5|sha1)\b',
      lambda m: {"algorithm": _norm_alg(m.group("transform") or m.group("t2") or ""),
                 "context": m.group(0)},
      "Weak hash function", "", 0.9),

    R("c.openssl.des", ("c",),
      r'\bDES_(?:set_key|ecb_encrypt|ncbc_encrypt|ede3_cbc_encrypt)\b',
      resolve_named("3des"), "DES / Triple-DES API", "", 0.9),

    R("c.rand.weak", ("c",),
      r'\bRAND_pseudo_bytes\b|(?<![\w.])\brand\s*\(\s*\)',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "RAND_pseudo_bytes is deprecated and rand() is not cryptographically secure.",
      0.6),

    R("c.pqc.mlkem", ("c",),
      r'\b(?:OQS_KEM_kyber|ML_KEM|EVP_PKEY_ML_KEM|mlkem)[a-z0-9_]*\b',
      resolve_named("ml-kem-768"),
      "Post-quantum KEM in use",
      "Evidence of an already-migrated code path. Recorded so the CBOM shows "
      "progress, not only debt.",
      0.85),
)

# ---- Go ------------------------------------------------------------------

_add(
    R("go.rsa", ("go",), r'\brsa\.(?:GenerateKey|SignPKCS1v15|EncryptPKCS1v15|SignPSS)\b',
      resolve_named("rsa"), "Go crypto/rsa used", "", 0.9),
    R("go.ecdsa", ("go",), r'\becdsa\.(?:GenerateKey|Sign|Verify)\b',
      resolve_named("ecdsa"), "Go crypto/ecdsa used", "", 0.9),
    R("go.ed25519", ("go",), r'\bed25519\.(?:GenerateKey|Sign|Verify)\b',
      resolve_named("ed25519"), "Go crypto/ed25519 used", "", 0.9),
    R("go.weakhash", ("go",), r'"crypto/(?P<transform>md5|sha1)"|\b(?P<t2>md5|sha1)\.(?:New|Sum)\b',
      lambda m: {"algorithm": _norm_alg(m.group("transform") or m.group("t2") or ""),
                 "context": m.group(0)},
      "Weak hash function", "", 0.9),
    R("go.des", ("go",), r'"crypto/des"|\bdes\.New(?:TripleDES)?Cipher\b',
      resolve_named("3des"), "DES / Triple-DES used", "", 0.9),
    R("go.mathrand", ("go",), r'"math/rand"',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "math/rand is deterministic. Use crypto/rand for key material.", 0.7),
)

# ---- Node / JavaScript ---------------------------------------------------

_add(
    R("js.createcipher", ("js",),
      r'createCipheriv\s*\(\s*[\'"](?P<transform>[a-z0-9\-]{3,30})[\'"]',
      resolve_node_cipher, "Node cipher instantiated", "", 0.9),
    R("js.createhash", ("js",),
      r'createHash\s*\(\s*[\'"](?P<transform>md5|sha1|sha256|sha512)[\'"]',
      resolve_capture, "Hash function selected", "", 0.9),
    R("js.generatekeypair", ("js",),
      r'generateKeyPair(?:Sync)?\s*\(\s*[\'"](?P<transform>rsa|ec|ed25519|dsa)[\'"]',
      resolve_capture, "Key pair generated", "", 0.9),
    R("js.mathrandom", ("js",),
      r'\bMath\.random\s*\(\s*\)',
      resolve_named("weak-rng"),
      "Non-cryptographic random number generator",
      "Math.random is not seeded from a secure source and must never produce key "
      "material, tokens or nonces.", 0.6),
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
      r'\b(?:md5|sha1)\s*\(', resolve_capture, "Weak hash function", "", 0.85),
    R("php.mcrypt", ("php",),
      r'\bmcrypt_[a-z_]+\s*\(', resolve_named("unknown"),
      "Removed mcrypt extension", "mcrypt was removed in PHP 7.2.", 0.7),
    R("ruby.weakhash", ("ruby",),
      r'\b(?:Digest::MD5|Digest::SHA1)\b', resolve_capture, "Weak hash function", "", 0.9),
)

# ---- Cross-language: key material and dangerous constructs ---------------

_add(
    R("any.private.key.inline", ("*",),
      r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
      resolve_named("unknown"),
      "Private key embedded in source",
      "A private key committed to a repository is compromised the moment the "
      "repository is cloned, independent of any quantum consideration.",
      0.98, ASSET_MATERIAL),

    R("any.certificate.inline", ("*",),
      r'-----BEGIN CERTIFICATE-----',
      resolve_named("unknown"),
      "Certificate embedded in source", "", 0.9, ASSET_MATERIAL),

    R("any.hardcoded.secret", ("*",),
      r'(?i)\b(?:secret_key|private_key|api_secret|encryption_key|aes_key|passphrase)\s*'
      r'[=:]\s*[\'"][A-Za-z0-9+/=_\-]{16,}[\'"]',
      resolve_named("unknown"),
      "Hardcoded secret",
      "Key material in source cannot be rotated without a code change, which is "
      "the opposite of crypto-agility.",
      0.7, ASSET_MATERIAL),

    R("any.ecb.mode", ("*",),
      r'(?i)\b(?:MODE_ECB|/ECB/|["\']ecb["\']|AES_ECB)\b',
      resolve_named("aes"),
      "ECB mode of operation",
      "ECB leaks plaintext structure because identical blocks encrypt identically. "
      "It is a defect regardless of key size or quantum threat.",
      0.85),
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

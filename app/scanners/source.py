"""Source code scanner.

Two passes:

1. **AST pass** (Python only). Parses the file and inspects real call nodes, so
   a match cannot come from a comment, a docstring or a string literal, and
   keyword arguments such as ``key_size=2048`` resolve to actual values. High
   confidence.

2. **Pattern pass** (every language). Applies the rule pack from
   ``knowledge.rules_source``. Lines that are obviously comments are skipped
   first, which removes the bulk of false positives in C and Java codebases
   where licence headers and design notes mention algorithms by name.

Where both passes see the same line, the AST result wins.
"""

from __future__ import annotations

import ast
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .. import config, fspolicy
from ..fspolicy import FsPolicy
from ..knowledge import rules_source as rs
from ..knowledge import algorithms as K
from ..knowledge import purposes as P
from ..models import (
    ASSET_ALGORITHM, ASSET_PROTOCOL, ASSURANCE_USED, Evidence, Finding,
    TECH_AST, TECH_PATTERN,
)

SCANNER = "source"

# Lines starting with these are treated as comments and skipped by the
# pattern pass. Cheap, and it removes most licence-header noise.
_COMMENT_PREFIXES = ("//", "/*", "*", "#", "--", ";", "<!--")


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    if not s:
        return True
    return s.startswith(_COMMENT_PREFIXES)


def iter_source_files(root: Path, max_files: int = config.MAX_FILES,
                      policy: Optional[FsPolicy] = None) -> Iterator[Path]:
    """Walk a tree, yielding files we know how to read.

    ``policy`` enforces the scan boundary. Without it the walk is unbounded and
    a symlinked file pointing outside the root would be read and its contents
    carried into ``evidence.snippet``; with it, such a file is skipped and
    counted so the operator sees the inventory is partial.
    """
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if policy and policy.exhausted():
            return
        fspolicy.filter_dirnames(dirpath, dirnames, config.SKIP_DIRS, root, policy)
        for name in filenames:
            if policy and not policy.count_entry():
                return
            if rs.language_for(name) is None:
                continue
            p = Path(dirpath) / name
            if policy and not fspolicy.readable(p, root, policy):
                continue
            try:
                if p.stat().st_size > config.MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p
            count += 1
            if count >= max_files:
                return
        if policy and policy.expired():
            return


# --------------------------------------------------------------------------
# Python AST pass
# --------------------------------------------------------------------------

_PY_HASH_WEAK = {"md5": "md5", "sha1": "sha1", "sha224": "sha224",
                 "new": None}  # hashlib.new("md5") handled separately

_PY_CURVES = {
    "SECP256R1": "ecdsa-p-256", "SECP384R1": "ecdsa-p-384",
    "SECP521R1": "ecdsa-p-521", "SECP256K1": "ecdsa-secp256k1",
}

_PY_SSL_PROTO = {
    "PROTOCOL_TLSv1": "tls1.0", "PROTOCOL_TLSv1_1": "tls1.1",
    "PROTOCOL_TLSv1_2": "tls1.2", "PROTOCOL_SSLv3": "tls1.0",
    "PROTOCOL_SSLv23": "tls1.2",
}

# pyca/cryptography hazmat primitives, referenced as attributes.
# Real algorithms, named. Blowfish, CAST5, IDEA, SEED and Camellia were
# previously all reported as "unknown", which turned five identifiable ciphers
# -- three of them with a 64-bit block and a concrete birthday-bound weakness
# -- into an unresolved finding a reviewer could do nothing with.
_PY_CIPHERS = {
    "AES": "aes", "AES128": "aes-128", "AES256": "aes-256",
    "TripleDES": "3des", "ARC4": "rc4", "Blowfish": "blowfish",
    "CAST5": "cast5", "IDEA": "idea", "SEED": "seed",
    "ChaCha20": "chacha20", "Camellia": "camellia",
}

# pyca/cryptography asymmetric padding -> the purpose it settles.
#
# PSS signs and OAEP encrypts, so either resolves the purpose outright.
# PKCS1v15 does *both* -- `padding.PKCS1v15()` is passed to `sign()` and to
# `encrypt()` alike -- so it resolves nothing and must not be guessed.
_PY_PADDING_PURPOSE = {
    "PSS": (P.SIGNATURE, "RSA-PSS padding is a signature scheme"),
    "OAEP": (P.KEY_ESTABLISHMENT, "RSA-OAEP padding is encryption / key transport"),
    "PKCS1v15": ("", "PKCS#1 v1.5 padding is used for both signing and encryption, "
                     "so it does not resolve the purpose"),
    "MGF1": ("", "a mask generation function, shared by PSS and OAEP"),
}

# Method names on a key object that settle purpose.
_PY_METHOD_PURPOSE = {
    "sign": (P.SIGNATURE, "the key is used to sign"),
    "verify": (P.SIGNATURE, "the key is used to verify a signature"),
    "exchange": (P.KEY_ESTABLISHMENT, "the key is used for key agreement"),
    "encrypt": (P.KEY_ESTABLISHMENT,
                "public-key encryption of a short value is key transport"),
    "decrypt": (P.KEY_ESTABLISHMENT,
                "public-key decryption of a short value is key transport"),
}

_PY_MODES = {"ECB", "CBC", "CTR", "GCM", "OFB", "CFB", "CFB8", "XTS", "CCM"}

# Each entry is the algorithm the API actually names. Three of these were
# previously wrong: SHA3_512 mapped onto sha3-256, BLAKE2b onto sha512 and
# BLAKE2s onto sha256. Those are not approximations, they are different
# algorithms -- BLAKE2b is a 64-bit-word sponge-free design with no
# relationship to SHA-2 beyond producing 512 bits -- and a CBOM that names the
# wrong one is a defective record of the estate.
_PY_HASHES = {
    "MD5": "md5", "SHA1": "sha1",
    "SHA224": "sha224", "SHA256": "sha256",
    "SHA384": "sha384", "SHA512": "sha512",
    "SHA512_224": "sha512-224", "SHA512_256": "sha512-256",
    "SHA3_224": "sha3-224", "SHA3_256": "sha3-256",
    "SHA3_384": "sha3-384", "SHA3_512": "sha3-512",
    "SHAKE128": "shake128", "SHAKE256": "shake256",
    "BLAKE2b": "blake2b", "BLAKE2s": "blake2s",
    "SM3": "unknown",
}

# hashlib function names, which use a different spelling from the hazmat
# classes above.
_PY_HASHLIB = {
    "md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256",
    "sha384": "sha384", "sha512": "sha512",
    "sha3_224": "sha3-224", "sha3_256": "sha3-256",
    "sha3_384": "sha3-384", "sha3_512": "sha3-512",
    "shake_128": "shake128", "shake_256": "shake256",
    "blake2b": "blake2b", "blake2s": "blake2s",
}

_PY_PADDINGS = {"PKCS1v15": "rsa", "OAEP": "rsa", "PSS": "rsa", "MGF1": "rsa"}


def _dotted(node: ast.AST) -> str:
    """Render ``a.b.c`` from an Attribute/Name chain."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _const_int(node: ast.AST) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _scan_python_ast(path: Path, text: str, rel: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []

    out: list[Finding] = []

    def emit(alg: str, line: int, symbol: str, title: str, detail: str = "",
             conf: float = 0.95, asset: str = ASSET_ALGORITHM, **extra) -> None:
        snippet = text.splitlines()[line - 1].strip()[:200] if 0 < line <= text.count("\n") + 1 else ""
        purpose = extra.pop("purpose", "") or K.default_purpose(alg)
        why = extra.pop("purpose_evidence", "")
        if not why and purpose != P.UNKNOWN:
            why = f"implied by the algorithm: {K.get(alg).name} serves only this purpose"
        out.append(Finding(
            algorithm=alg, asset_type=asset, scanner=SCANNER,
            title=title, detail=detail, rule_id="py.ast." + symbol,
            key_size=extra.pop("key_size", None),
            mode=extra.pop("mode", None),
            purpose=purpose, purpose_evidence=why,
            evidence=[Evidence(location=rel, line=line, symbol=symbol,
                               snippet=snippet, technique=TECH_AST,
                               confidence=conf, context=extra.pop("context", ""),
                               assurance=ASSURANCE_USED)],
            extra=extra,
        ))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if not name:
            continue
        tail = name.rsplit(".", 1)[-1]
        line = getattr(node, "lineno", 0)

        # hashlib.md5() / hashlib.sha3_512() / hashlib.new("blake2b")
        if name.startswith("hashlib."):
            if tail in _PY_HASHLIB:
                key = _PY_HASHLIB[tail]
                broken = key in ("md5", "sha1", "md2", "md4")
                emit(key, line, name,
                     "Weak hash function" if broken else "Hash function selected",
                     ("MD5 and SHA-1 are collision-broken classically and unacceptable "
                      "for any signature or integrity purpose." if broken else ""),
                     context=tail)
            elif tail == "new" and node.args:
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    emit(rs._norm_alg(a0.value), line, name, "Hash function selected",
                         context=a0.value)

        # cryptography: rsa.generate_private_key(public_exponent=..., key_size=N)
        elif tail == "generate_private_key" and "rsa" in name:
            size = None
            for kw in node.keywords:
                if kw.arg == "key_size":
                    size = _const_int(kw.value)
            emit(f"rsa-{size}" if size else "rsa", line, name,
                 "RSA key pair generated",
                 "Key generation is where a quantum-vulnerable key enters the system. "
                 "It does not reveal whether the key will sign or transport keys, so "
                 "the purpose is left unresolved rather than assumed -- the two have "
                 "different replacements.",
                 key_size=size, purpose=P.UNKNOWN,
                 purpose_evidence="key generation does not determine use")

        # ec.SECP256R1()
        elif tail in _PY_CURVES:
            emit(_PY_CURVES[tail], line, name, "Elliptic curve selected",
                 "Elliptic-curve discrete log is polynomial-time under Shor.",
                 context=tail)

        # Crypto.Cipher.AES.new(...) / DES3.new(...)
        elif tail == "new" and any(
                f".{fam}." in "." + name + "." for fam in ("AES", "DES", "DES3", "ARC4", "Blowfish")):
            fam = next(f for f in ("AES", "DES3", "DES", "ARC4", "Blowfish")
                       if f".{f}." in "." + name + ".")
            emit(rs._norm_alg(fam), line, name, "Block cipher instantiated", context=fam)

        # random.random(), random.randint(...)
        elif name.startswith("random.") and tail in (
                "random", "randint", "choice", "randrange", "getrandbits", "shuffle"):
            emit("weak-rng", line, name, "Non-cryptographic random number generator",
                 "Python's random module is a Mersenne Twister; observing a few "
                 "outputs recovers its internal state. Use secrets or os.urandom.",
                 conf=0.85)

    # ---- pyca/cryptography hazmat idioms -------------------------------
    #
    # These are attribute references, not calls -- `algorithms.AES` is passed
    # *into* Cipher(...) rather than invoked on its own -- so they need their
    # own pass. This is the dominant crypto library in modern Python and
    # missing it means missing most real findings.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        full = _dotted(node)
        if not full:
            continue
        head, _, attr = full.rpartition(".")
        head = head.rsplit(".", 1)[-1]
        line = getattr(node, "lineno", 0)
        snippet = (text.splitlines()[line - 1].strip()[:200]
                   if 0 < line <= text.count("\n") + 1 else "")

        alg = title = None
        detail = ""
        mode = None
        purpose = ""
        why = ""

        if head == "algorithms" and attr in _PY_CIPHERS:
            alg, title = _PY_CIPHERS[attr], "Block cipher selected"
            purpose, why = P.ENCRYPTION, "passed to a symmetric cipher construction"
        elif head == "modes" and attr in _PY_MODES:
            alg, title = "aes", "Cipher mode of operation"
            mode = attr.lower()
            purpose, why = P.ENCRYPTION, "a block cipher mode of operation"
            if attr == "ECB":
                detail = ("ECB leaks plaintext structure: identical blocks encrypt "
                          "identically. A defect regardless of key size.")
        elif head == "hashes" and attr in _PY_HASHES:
            alg, title = _PY_HASHES[attr], "Hash function selected"
            purpose, why = P.HASHING, "a hash construction"
        elif head == "padding" and attr in _PY_PADDINGS:
            alg, title = _PY_PADDINGS[attr], "Asymmetric padding scheme"
            # The padding scheme is the strongest static signal of what an RSA
            # key is doing: PSS only ever signs, OAEP only ever encrypts.
            # PKCS#1 v1.5 does both, so it resolves nothing and says so.
            purpose, why = _PY_PADDING_PURPOSE.get(attr, ("", ""))
            if attr == "PKCS1v15":
                detail = ("PKCS#1 v1.5 padding is used for both signing and encryption, "
                          "so this call site does not reveal the key's purpose. Its "
                          "encryption mode is also vulnerable to Bleichenbacher oracle "
                          "attacks; prefer OAEP.")

        if alg and title:
            out.append(Finding(
                algorithm=alg, asset_type=ASSET_ALGORITHM, scanner=SCANNER,
                title=title, detail=detail, rule_id=f"py.ast.hazmat.{head}",
                mode=mode,
                purpose=purpose or K.default_purpose(alg),
                purpose_evidence=why if purpose else "",
                evidence=[Evidence(location=rel, line=line, symbol=full,
                                   snippet=snippet, technique=TECH_AST,
                                   confidence=0.92, context=attr,
                                   assurance=ASSURANCE_USED)],
            ))

    # ssl.PROTOCOL_* referenced as attributes rather than calls
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _PY_SSL_PROTO:
            full = _dotted(node)
            if full.startswith("ssl."):
                out.append(Finding(
                    algorithm=_PY_SSL_PROTO[node.attr], asset_type=ASSET_PROTOCOL,
                    scanner=SCANNER, title="Legacy TLS protocol constant",
                    rule_id="py.ast.ssl_proto",
                    purpose=P.TRANSPORT,
                    purpose_evidence="a TLS protocol version constant",
                    evidence=[Evidence(location=rel, line=node.lineno, symbol=full,
                                       technique=TECH_AST, confidence=0.9,
                                       context=node.attr, assurance=ASSURANCE_USED)],
                ))

    return out


# --------------------------------------------------------------------------
# Pattern pass
# --------------------------------------------------------------------------

def _scan_patterns(text: str, lang: str, rel: str,
                   skip_lines: set[int]) -> list[Finding]:
    out: list[Finding] = []
    rules = rs.rules_for(lang)
    if not rules:
        return out

    lines = text.splitlines()
    for rule in rules:
        pat = rule.compiled()
        for m in pat.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            if line_no in skip_lines:
                continue
            raw_line = lines[line_no - 1] if line_no <= len(lines) else ""
            if _is_comment(raw_line):
                continue
            try:
                res = rule.resolve(m)
            except Exception:
                continue
            alg = res.get("algorithm") or "unknown"

            # Purpose resolution order, most specific first:
            #   1. what the resolver worked out from this exact match,
            #   2. what the matched API is for, when the API settles it,
            #   3. what the algorithm can only be for, when it has one purpose.
            # RSA reaches none of the three from a bare key-generation call, so
            # it stays unknown -- which is the whole point.
            purpose = res.get("purpose") or rule.purpose or K.default_purpose(alg)
            why = res.get("purpose_evidence") or ""
            if not why and purpose != P.UNKNOWN:
                why = (f"the {rule.id} rule matches an API used only for "
                       f"{P.LABEL[purpose].lower()}" if rule.purpose else
                       f"implied by the algorithm: {K.get(alg).name} serves only "
                       f"this purpose")

            out.append(Finding(
                algorithm=alg,
                asset_type=rule.asset_type,
                scanner=SCANNER,
                title=rule.title,
                detail=rule.detail,
                rule_id=rule.id,
                key_size=res.get("key_size"),
                mode=res.get("mode"),
                padding=res.get("padding"),
                purpose=purpose,
                purpose_evidence=why,
                evidence=[Evidence(
                    location=rel, line=line_no,
                    symbol=m.group(0)[:80].strip(),
                    snippet=raw_line.strip()[:200],
                    technique=TECH_PATTERN,
                    confidence=rule.confidence,
                    context=res.get("context", ""),
                    assurance=rule.assurance,
                )],
                extra=res.get("extra", {}) or {},
            ))
    return out


def scan_file(path: Path, root: Path) -> list[Finding]:
    lang = rs.language_for(path.name)
    if lang is None:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if not text.strip():
        return []

    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)

    findings: list[Finding] = []
    skip: set[int] = set()

    if lang == "python":
        ast_findings = _scan_python_ast(path, text, rel)
        findings.extend(ast_findings)
        skip = {e.line for f in ast_findings for e in f.evidence if e.line}

    findings.extend(_scan_patterns(text, lang, rel, skip))
    return findings


def scan(root: str | Path, max_files: int = config.MAX_FILES,
         workers: int = config.SCAN_WORKERS,
         on_progress=None,
         policy: Optional[FsPolicy] = None) -> tuple[list[Finding], dict]:
    """Scan a directory tree. Returns (findings, stats).

    `on_progress(done, total, noun)` is called as files complete. Without it a
    large tree reports nothing for a minute and is indistinguishable from a
    hang, which is the single most common thing to go wrong on stage.
    """
    root = Path(root).resolve()
    files = list(iter_source_files(root, max_files, policy))
    findings: list[Finding] = []

    if not files:
        return findings, {"files_scanned": 0, "languages": {}}

    langs: dict[str, int] = {}
    for f in files:
        lang = rs.language_for(f.name) or "other"
        langs[lang] = langs.get(lang, 0) + 1

    total = len(files)
    if on_progress:
        on_progress(0, total, "files")
    read = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, result in enumerate(pool.map(lambda p: scan_file(p, root), files), 1):
            findings.extend(result)
            read = i
            # Often enough to look alive, rarely enough to stay cheap.
            if on_progress and (i % 25 == 0 or i == total):
                on_progress(i, total, "files")
            if policy and policy.expired():
                # Stop consuming results rather than letting a deadline pass
                # silently; the partial state is reported below.
                break

    stats: dict = {
        "files_scanned": read,
        "files_enumerated": len(files),
        "languages": dict(sorted(langs.items(), key=lambda kv: -kv[1])),
    }
    if policy and read < len(files):
        stats["source_incomplete"] = (
            f"stopped after {read:,} of {len(files):,} files: scan deadline reached")
    return findings, stats

"""Dependency scanner.

Most applications do not call cryptography directly -- they depend on a
library that does, often several levels down. A source scan that only reads
first-party code therefore misses the majority of an estate's real
cryptographic surface.

This sensor reads package manifests and maps each library to what it can do
and whether it has post-quantum support, which turns "we use BouncyCastle"
into "we use BouncyCastle 1.68, which predates ML-KEM; the upgrade path is
1.79 or later".
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator, Optional

from .. import config
from ..models import ASSET_LIBRARY, Evidence, Finding, TECH_MANIFEST

SCANNER = "dependency"

# library -> (algorithms it provides, minimum version with PQC support, note)
CRYPTO_LIBRARIES: dict[str, tuple[list[str], Optional[str], str]] = {
    "cryptography":  (["rsa", "ecdsa", "aes", "sha256"], "43.0",
                      "pyca/cryptography. PQC exposure depends on the linked OpenSSL."),
    "pycryptodome":  (["rsa", "aes", "3des", "md5"], None,
                      "No post-quantum primitives. Migration requires a different library."),
    "pycrypto":      (["rsa", "aes", "des"], None,
                      "Unmaintained since 2014 and known-vulnerable. Replace outright."),
    "paramiko":      (["rsa", "ecdsa", "ed25519"], None, "SSH implementation."),
    "pyopenssl":     (["rsa", "ecdsa", "tls1.2"], None, "Wrapper over the linked OpenSSL."),
    "rsa":           (["rsa"], None, "Pure-Python RSA."),
    "ecdsa":         (["ecdsa"], None, "Pure-Python ECDSA."),
    "bcrypt":        (["sha256"], None, "Password hashing; not affected by Shor."),
    "bouncycastle":  (["rsa", "ecdsa", "aes", "3des"], "1.79",
                      "BouncyCastle gained ML-KEM and ML-DSA in 1.79."),
    "bcprov-jdk18on": (["rsa", "ecdsa", "aes"], "1.79", "BouncyCastle provider."),
    "openssl":       (["rsa", "ecdsa", "dh", "aes"], "3.5",
                      "OpenSSL gained native ML-KEM, ML-DSA and SLH-DSA in 3.5."),
    "libssl-dev":    (["rsa", "ecdsa", "aes"], "3.5", "OpenSSL development package."),
    "node-forge":    (["rsa", "aes", "md5", "sha1"], None, "Pure-JavaScript crypto."),
    "crypto-js":     (["aes", "md5", "sha1", "3des"], None,
                      "Includes MD5, SHA-1 and Triple-DES; commonly misused."),
    "jsonwebtoken":  (["rsa", "ecdsa", "hmac"], None, "JWT signing."),
    "jose":          (["rsa", "ecdsa", "aes"], None, "JOSE/JWT suite."),
    "golang.org/x/crypto": (["ed25519", "aes", "sha256"], None, "Go extended crypto."),
    "openssl-sys":   (["rsa", "ecdsa", "aes"], "3.5", "Rust OpenSSL bindings."),
    "ring":          (["ecdsa", "ed25519", "aes"], None, "Rust crypto primitives."),
    "rustls":        (["ecdsa", "tls1.3"], None, "Rust TLS stack."),
    "liboqs":        (["ml-kem-768", "ml-dsa-65"], "0.9",
                      "Open Quantum Safe. Presence indicates active PQC work."),
    "oqs-provider":  (["ml-kem-768", "ml-dsa-65"], None,
                      "OpenSSL provider for post-quantum algorithms."),
}

MANIFESTS = {
    "requirements.txt": "pip", "pyproject.toml": "pip", "setup.py": "pip",
    "Pipfile": "pip", "package.json": "npm", "package-lock.json": "npm",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "go.mod": "go", "Cargo.toml": "cargo", "composer.json": "composer",
    "Gemfile": "bundler",
}

_PIP = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]=?\s*([0-9][\w.\-]*))?", re.M)
_MAVEN = re.compile(
    r"<artifactId>\s*([^<]+?)\s*</artifactId>\s*(?:<version>\s*([^<]+?)\s*</version>)?",
    re.S)
_GRADLE = re.compile(r"['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]")
_GO = re.compile(r"^\s*([\w./\-]+)\s+v([\w.\-]+)", re.M)
_CARGO = re.compile(r'^\s*([A-Za-z0-9_\-]+)\s*=\s*["{]?\s*(?:version\s*=\s*)?"?([0-9][\w.\-]*)?',
                    re.M)


def iter_manifests(root: Path, max_files: int = 500) -> Iterator[tuple[Path, str]]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in config.SKIP_DIRS]
        for name in filenames:
            kind = MANIFESTS.get(name)
            if kind:
                yield Path(dirpath) / name, kind
                count += 1
                if count >= max_files:
                    return


def _extract(text: str, kind: str, path: Path) -> list[tuple[str, str]]:
    """Return (package, version) pairs from a manifest."""
    out: list[tuple[str, str]] = []
    try:
        if kind == "pip":
            out = [(m.group(1), m.group(2) or "") for m in _PIP.finditer(text)
                   if m.group(1) and not m.group(1).startswith("#")]
        elif kind == "npm":
            data = json.loads(text)
            for section in ("dependencies", "devDependencies"):
                for k, v in (data.get(section) or {}).items():
                    out.append((k, str(v).lstrip("^~>=< ")))
        elif kind == "maven":
            out = [(m.group(1), m.group(2) or "") for m in _MAVEN.finditer(text)]
        elif kind == "gradle":
            out = [(m.group(2), m.group(3)) for m in _GRADLE.finditer(text)]
        elif kind == "go":
            out = [(m.group(1), m.group(2)) for m in _GO.finditer(text)]
        elif kind == "cargo":
            out = [(m.group(1), m.group(2) or "") for m in _CARGO.finditer(text)]
        elif kind in ("composer", "bundler"):
            out = [(m.group(1), m.group(2) or "") for m in _PIP.finditer(text)]
    except (json.JSONDecodeError, ValueError):
        return []
    return out


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)[:4]
    return tuple(int(p) for p in parts) if parts else (0,)


def scan(root: str | Path, max_files: int = 500) -> tuple[list[Finding], dict]:
    root = Path(root).resolve()
    findings: list[Finding] = []
    n = 0

    for path, kind in iter_manifests(root, max_files):
        n += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)

        for package, version in _extract(text, kind, path):
            key = package.lower().strip()
            entry = CRYPTO_LIBRARIES.get(key)
            if entry is None:
                # Match a coordinate like org.bouncycastle:bcprov-jdk18on
                key = key.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
                entry = CRYPTO_LIBRARIES.get(key)
            if entry is None:
                continue

            algorithms, pqc_min, note = entry
            detail = note
            if pqc_min and version:
                if _version_tuple(version) < _version_tuple(pqc_min):
                    detail += (f" Detected {version}, which is below {pqc_min}; "
                               f"post-quantum algorithms are unavailable until upgrade.")
                else:
                    detail += f" Detected {version}, which has post-quantum support."
            elif pqc_min:
                detail += f" Post-quantum support requires {pqc_min} or later."

            findings.append(Finding(
                algorithm="unknown", asset_type=ASSET_LIBRARY, scanner=SCANNER,
                title=f"Cryptographic library: {package}"
                      + (f" {version}" if version else ""),
                detail=detail, rule_id="dep.library",
                evidence=[Evidence(location=rel, symbol=package,
                                   technique=TECH_MANIFEST, confidence=0.9,
                                   context=f"{kind} manifest"
                                           + (f", version {version}" if version else ""))],
                extra={"library": key, "version": version, "ecosystem": kind,
                       "provides": algorithms},
            ))

            # Each algorithm the library provides is a real part of the estate's
            # cryptographic surface, even though no first-party code names it.
            for alg in algorithms:
                findings.append(Finding(
                    algorithm=alg, asset_type=ASSET_LIBRARY, scanner=SCANNER,
                    title=f"{alg} reachable via {package}",
                    detail=f"Provided by the {package} dependency declared in {rel}.",
                    rule_id="dep.provides",
                    evidence=[Evidence(location=rel, symbol=f"{package}:{alg}",
                                       technique=TECH_MANIFEST, confidence=0.55,
                                       context="inferred from library capability, "
                                               "not from a call site")],
                    extra={"library": key, "version": version},
                ))

    return findings, {"manifests_scanned": n}

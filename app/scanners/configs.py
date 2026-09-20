"""Configuration scanner.

Configuration is where cryptographic policy actually lives. An application can
be written perfectly and still negotiate RC4 because a cipher string in
``nginx.conf`` says it may. These files are also the cheapest thing in the
estate to fix -- usually one line and a reload -- which makes them the natural
first wave of any migration programme.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator, Optional

from .. import config, fspolicy
from ..fspolicy import FsPolicy
from ..knowledge.rules_source import _norm_alg
from ..models import ASSET_ALGORITHM, ASSET_PROTOCOL, Evidence, Finding, TECH_CONFIG

SCANNER = "config"

CONFIG_FILES = {
    "nginx.conf": "nginx", "sshd_config": "sshd", "ssh_config": "ssh",
    "openssl.cnf": "openssl", "openssl.conf": "openssl",
    "java.security": "java", "httpd.conf": "apache", "ssl.conf": "apache",
    "haproxy.cfg": "haproxy", "my.cnf": "mysql", "postgresql.conf": "postgres",
    "redis.conf": "redis",
}
CONFIG_SUFFIXES = {".conf", ".cnf", ".cfg", ".properties"}

# Weak primitives that commonly appear inside cipher strings and key exchange
# lists. Order matters: longer names first so RC4 does not shadow nothing.
_CIPHER_TOKENS = [
    ("3DES", "3des"), ("DES-CBC3", "3des"), ("TRIPLEDES", "3des"),
    ("RC4", "rc4"), ("DES", "des"), ("MD5", "md5"), ("SHA1", "sha1"),
    ("NULL", "unknown"), ("EXPORT", "unknown"), ("ANON", "unknown"),
    ("AES128", "aes-128"), ("AES256", "aes-256"),
    ("ECDHE", "ecdh"), ("DHE", "dh"), ("RSA", "rsa"),
]

_PROTOCOL_TOKENS = {
    "SSLv2": "tls1.0", "SSLv3": "tls1.0",
    "TLSv1": "tls1.0", "TLSv1.0": "tls1.0", "TLSv1.1": "tls1.1",
    "TLSv1.2": "tls1.2", "TLSv1.3": "tls1.3",
}

_DIRECTIVES = re.compile(
    r"^\s*(ssl_protocols|ssl_ciphers|ssl_ecdh_curve|SSLProtocol|SSLCipherSuite|"
    r"Ciphers|MACs|KexAlgorithms|HostKeyAlgorithms|PubkeyAcceptedAlgorithms|"
    r"jdk\.tls\.disabledAlgorithms|jdk\.certpath\.disabledAlgorithms|"
    r"ssl-cipher|tls-ciphers|CipherString)\s*[=: ]\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)


def iter_config_files(root: Path, max_files: int = 800,
                      policy: Optional[FsPolicy] = None) -> Iterator[tuple[Path, str]]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if policy and policy.exhausted():
            return
        fspolicy.filter_dirnames(dirpath, dirnames, config.SKIP_DIRS, root, policy)
        for name in filenames:
            if policy and not policy.count_entry():
                return
            kind = CONFIG_FILES.get(name)
            if kind is None and Path(name).suffix.lower() in CONFIG_SUFFIXES:
                kind = "generic"
            if kind is None:
                continue
            p = Path(dirpath) / name
            if policy and not fspolicy.readable(p, root, policy):
                continue
            try:
                if p.stat().st_size > 500_000:
                    continue
            except OSError:
                continue
            yield p, kind
            count += 1
            if count >= max_files:
                return


def scan_file(path: Path, root: Path, kind: str) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)

    findings: list[Finding] = []

    for m in _DIRECTIVES.finditer(text):
        directive, value = m.group(1), m.group(2).strip()
        if value.startswith("#"):
            continue
        line_no = text.count("\n", 0, m.start()) + 1
        upper = value.upper()

        # A disable-list is the opposite of a finding: it is evidence of good
        # hygiene, so we must not report its contents as though they were in use.
        is_disable_list = "disabledalgorithms" in directive.lower()
        if is_disable_list:
            continue

        seen: set[str] = set()

        for token, proto in _PROTOCOL_TOKENS.items():
            if re.search(rf"\b{re.escape(token)}\b", value, re.IGNORECASE):
                if proto in seen:
                    continue
                seen.add(proto)
                legacy = proto in ("tls1.0", "tls1.1")
                findings.append(Finding(
                    algorithm=proto, asset_type=ASSET_PROTOCOL, scanner=SCANNER,
                    title=f"{token} enabled in configuration",
                    detail=("Deprecated by RFC 8996 and should be removed."
                            if legacy else
                            "Enabled here. The negotiated key exchange group, not the "
                            "version, determines quantum exposure."),
                    rule_id="cfg.protocol",
                    evidence=[Evidence(location=rel, line=line_no, symbol=directive,
                                       snippet=value[:180], technique=TECH_CONFIG,
                                       confidence=0.9, context=token)],
                    extra={"protocol_type": "tls", "version": token},
                ))

        for token, alg in _CIPHER_TOKENS:
            if not re.search(rf"(?<![A-Z0-9]){re.escape(token)}(?![A-Z0-9])", upper):
                continue
            # A leading '!' or '-' in an OpenSSL cipher string excludes it.
            if re.search(rf"[!\-]{re.escape(token)}\b", upper):
                continue
            if alg in seen:
                continue
            seen.add(alg)
            findings.append(Finding(
                algorithm=alg, asset_type=ASSET_ALGORITHM, scanner=SCANNER,
                title=f"{token} permitted by {directive}",
                detail=(f"Configuration permits {token}. Cipher policy is usually the "
                        f"cheapest part of a migration to change -- one line and a "
                        f"service reload."),
                rule_id="cfg.cipher",
                evidence=[Evidence(location=rel, line=line_no, symbol=directive,
                                   snippet=value[:180], technique=TECH_CONFIG,
                                   confidence=0.8, context=token)],
            ))

    return findings


def scan(root: str | Path, max_files: int = 800,
         policy: Optional[FsPolicy] = None) -> tuple[list[Finding], dict]:
    root = Path(root).resolve()
    findings: list[Finding] = []
    n = 0
    for path, kind in iter_config_files(root, max_files, policy):
        n += 1
        findings.extend(scan_file(path, root, kind))
    return findings, {"config_files_scanned": n}

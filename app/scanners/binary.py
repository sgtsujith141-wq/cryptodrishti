"""Binary and firmware scanner.

This is the sensor that reaches where source-code analysis cannot: vendor
appliances, SCADA firmware, statically linked blobs, anything shipped without
source. Critical infrastructure is full of such code, and an inventory that
covers only first-party source is not an inventory.

Three techniques, in descending order of confidence:

* **ELF symbol tables.** We parse the section headers and read ``.dynstr`` /
  ``.strtab`` directly, so a symbol match is genuine evidence rather than an
  incidental byte sequence.
* **Constant matching.** S-boxes and round-constant tables sit verbatim in
  read-only data and survive stripping.
* **Version banners.** Pin the exact library build and therefore its known
  weaknesses.

Pure Python, no external tooling, so it runs anywhere the console runs.
"""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from typing import Iterator, Optional

from .. import config, fspolicy
from ..fspolicy import FsPolicy
from ..knowledge import rules_binary as rb
from ..knowledge import algorithms as K
from ..models import (
    ASSET_ALGORITHM, ASSET_LIBRARY, ASSURANCE_CAPABILITY, ASSURANCE_USED,
    Evidence, Finding,
    TECH_BINARY_CONST, TECH_BINARY_STRING, TECH_BINARY_SYMBOL,
)

SCANNER = "binary"

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
}

# Extensions that are binaries even when the magic is unusual (firmware images).
BINARY_EXTS = {".so", ".dylib", ".dll", ".exe", ".bin", ".elf", ".o", ".a",
               ".ko", ".img", ".rom", ".fw", ".efi"}

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")

# Only version-control and cache directories are skipped; a binary scanner
# that skips site-packages or vendor/ misses most of what it exists to find.
BINARY_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".mypy_cache"}


def file_kind(head: bytes, path: Path) -> Optional[str]:
    if head.startswith(ELF_MAGIC):
        return "elf"
    if head.startswith(PE_MAGIC):
        return "pe"
    if head[:4] in MACHO_MAGICS:
        return "macho"
    if path.suffix.lower() in BINARY_EXTS:
        return "raw"
    return None


def iter_binaries(root: Path, max_files: int = 4000,
                  policy: Optional[FsPolicy] = None) -> Iterator[tuple[Path, str]]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if policy and policy.exhausted():
            return
        # Deliberately *not* config.SKIP_DIRS: shipped binaries live inside
        # site-packages, vendor and node_modules, which the source walker skips.
        fspolicy.filter_dirnames(dirpath, dirnames, BINARY_SKIP_DIRS, root, policy)
        for name in filenames:
            if policy and not policy.count_entry():
                return
            p = Path(dirpath) / name
            if policy and not fspolicy.readable(p, root, policy):
                continue
            try:
                st = p.stat()
                if st.st_size < 512 or st.st_size > config.MAX_BINARY_BYTES:
                    continue
                with p.open("rb") as fh:
                    head = fh.read(8)
            except OSError:
                continue
            kind = file_kind(head, p)
            if kind is None:
                continue
            yield p, kind
            count += 1
            if count >= max_files:
                return


# --------------------------------------------------------------------------
# ELF parsing
# --------------------------------------------------------------------------

def _elf_string_sections(data: bytes) -> list[tuple[str, bytes]]:
    """Return the (name, bytes) of an ELF's string tables.

    Parses the ELF header and section headers directly. Returns an empty list
    for anything malformed rather than raising -- a scanner must never die on
    one odd file.
    """
    try:
        if len(data) < 64 or not data.startswith(ELF_MAGIC):
            return []
        is64 = data[4] == 2
        little = data[5] == 1
        end = "<" if little else ">"

        if is64:
            e_shoff, = struct.unpack_from(end + "Q", data, 0x28)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)
        else:
            e_shoff, = struct.unpack_from(end + "I", data, 0x20)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x2E)

        if not e_shoff or not e_shnum or e_shnum > 4096:
            return []

        def section(i: int):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(data):
                return None
            if is64:
                sh_name, sh_type = struct.unpack_from(end + "II", data, off)
                sh_offset, sh_size = struct.unpack_from(end + "QQ", data, off + 0x18)
            else:
                sh_name, sh_type = struct.unpack_from(end + "II", data, off)
                sh_offset, sh_size = struct.unpack_from(end + "II", data, off + 0x10)
            return sh_name, sh_type, sh_offset, sh_size

        shstr = section(e_shstrndx)
        if not shstr:
            return []
        _, _, str_off, str_size = shstr
        shstrtab = data[str_off:str_off + str_size]

        out: list[tuple[str, bytes]] = []
        for i in range(e_shnum):
            s = section(i)
            if not s:
                continue
            sh_name, sh_type, sh_offset, sh_size = s
            if sh_type != 3:               # SHT_STRTAB
                continue
            nul = shstrtab.find(b"\0", sh_name)
            name = shstrtab[sh_name:nul if nul != -1 else None].decode("ascii", "ignore")
            if name in (".dynstr", ".strtab"):
                blob = data[sh_offset:sh_offset + sh_size]
                if blob:
                    out.append((name, blob))
        return out
    except (struct.error, IndexError, ValueError):
        return []


def _symbols_from_strtab(blob: bytes) -> set[str]:
    return {s.decode("ascii", "ignore") for s in blob.split(b"\0") if 2 < len(s) < 96}


# --------------------------------------------------------------------------
# Scanning one binary
# --------------------------------------------------------------------------

def scan_binary(path: Path, root: Path, kind: str) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError:
        return []

    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)

    findings: list[Finding] = []
    seen_algorithms: set[str] = set()

    # ---- 1. symbols ------------------------------------------------------
    #
    # For ELF we parse the section headers and read the real string tables, so
    # a hit is genuine linkage. For Mach-O and PE we fall back to scanning
    # printable strings: the symbol names are still present, but we cannot
    # prove they came from a symbol table, so both the technique and the
    # confidence are reported differently. Overstating this would be the
    # easiest thing in the world and the first thing a reviewer would catch.
    symbol_names: set[str] = set()
    technique = TECH_BINARY_SYMBOL
    conf_scale = 1.0

    if kind == "elf":
        for _, blob in _elf_string_sections(data):
            symbol_names |= _symbols_from_strtab(blob)

    if not symbol_names:
        technique = TECH_BINARY_STRING
        conf_scale = 0.8
        for match in _PRINTABLE.finditer(data):
            token = match.group(0).decode("ascii", "ignore")
            if token in rb.SYMBOLS:
                symbol_names.add(token)

    origin = ("ELF dynamic symbol table" if technique == TECH_BINARY_SYMBOL
              else f"{kind} printable strings")

    for sym in sorted(symbol_names):
        hit = rb.SYMBOLS.get(sym)
        if not hit:
            continue
        alg, label, conf = hit
        findings.append(Finding(
            algorithm=alg, asset_type=ASSET_ALGORITHM, scanner=SCANNER,
            title=f"{label} via linked symbol",
            detail=("Recovered from the ELF dynamic symbol table, so this binary "
                    "genuinely calls the routine rather than merely mentioning it."
                    if technique == TECH_BINARY_SYMBOL else
                    "Recovered from printable strings. This format's symbol table is "
                    "not parsed, so the name could in principle appear without the "
                    "routine being called. Reported at reduced confidence."),
            rule_id="bin.symbol",
            purpose=K.default_purpose(alg),
            purpose_evidence=("implied by the algorithm; a linked symbol names the "
                              "routine but not what the caller does with it"),
            evidence=[Evidence(location=rel, symbol=sym, technique=technique,
                               confidence=round(conf * conf_scale, 2), context=origin,
                               assurance=ASSURANCE_USED)],
        ))
        seen_algorithms.add(alg)

    # ---- 2. constants ----------------------------------------------------
    for sig in rb.CONSTANTS:
        idx = data.find(sig.pattern)
        if idx < 0:
            continue
        # A short signature needs corroboration before we report it loudly.
        conf = sig.confidence
        if len(sig.pattern) <= 4 and sig.algorithm not in seen_algorithms:
            conf = min(conf, 0.4)
        findings.append(Finding(
            algorithm=sig.algorithm, asset_type=ASSET_ALGORITHM, scanner=SCANNER,
            title=f"{sig.name} found in binary data",
            detail=sig.note,
            rule_id="bin.constant",
            purpose=K.default_purpose(sig.algorithm),
            evidence=[Evidence(location=rel, symbol=sig.name,
                               technique=TECH_BINARY_CONST, confidence=conf,
                               context=f"offset 0x{idx:x}, {len(sig.pattern)} byte signature",
                               assurance=ASSURANCE_USED)],
        ))
        seen_algorithms.add(sig.algorithm)

    # ---- 3. version banners ---------------------------------------------
    for label, pattern, libkey in rb.VERSION_PATTERNS:
        m = pattern.search(data)
        if not m:
            continue
        version = m.group(1).decode("ascii", "ignore")
        note = rb.version_note(libkey, version)
        findings.append(Finding(
            algorithm="unknown", asset_type=ASSET_LIBRARY, scanner=SCANNER,
            title=f"{label} {version} embedded",
            detail=note or f"{label} {version} statically identified from its build banner.",
            rule_id="bin.version",
            evidence=[Evidence(location=rel, symbol=f"{label} {version}",
                               technique=TECH_BINARY_STRING, confidence=0.9,
                               context=m.group(0).decode("ascii", "ignore")[:120],
                               # An embedded build banner identifies the library
                               # that is present. What it is used for is not in
                               # evidence, so this is capability.
                               assurance=ASSURANCE_CAPABILITY)],
            extra={"library": libkey, "version": version},
        ))

    return findings


def scan(root: str | Path, max_files: int = 4000,
         on_progress=None,
         policy: Optional[FsPolicy] = None) -> tuple[list[Finding], dict]:
    root = Path(root).resolve()
    findings: list[Finding] = []
    counts: dict[str, int] = {}
    # Materialised so there is a real denominator to report against; the walk
    # itself is cheap next to reading and pattern-matching each binary.
    targets = list(iter_binaries(root, max_files, policy))
    total = len(targets)
    if on_progress:
        on_progress(0, total, "binaries")
    for n, (path, kind) in enumerate(targets, 1):
        counts[kind] = counts.get(kind, 0) + 1
        findings.extend(scan_binary(path, root, kind))
        if on_progress and (n % 5 == 0 or n == total):
            on_progress(n, total, "binaries")
        if policy and policy.expired():
            return findings, {
                "binaries_scanned": n, "binary_kinds": counts,
                "binary_incomplete": (f"stopped after {n:,} of {total:,} binaries: "
                                      f"scan deadline reached"),
            }
    return findings, {"binaries_scanned": total, "binary_kinds": counts}

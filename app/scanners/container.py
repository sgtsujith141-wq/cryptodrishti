"""Container image sensor.

Reaches the place most cryptographic inventory never looks: a shipped image.
An image is where the gap between what a team wrote and what they actually
run is widest -- a base image nobody chose carries an OpenSSL nobody audited,
and a `pip install` in a Dockerfile pulls in a crypto library the source tree
never names.

The sensor does not reimplement detection. Each file read out of a layer goes
to whichever existing analyser handles that kind of file, so an ELF inside an
image is analysed by exactly the code that analyses an ELF on disk, at the
same confidence, recording the same technique. What the sensor adds is
**provenance**: which image, which layer, and whether the file is still there.

That last part is the one worth being careful about. A file deleted by a later
layer is still extractable from the archive, so it is still a finding -- but
it is a historical one, and reporting it as part of the running filesystem
would be wrong. Every finding says which it is.

No daemon, no network, no privileged access, and nothing is ever written to
disk. See ``app/container.py`` for the archive safety model.
"""

from __future__ import annotations

import posixpath
import time
from pathlib import Path
from typing import Any, Callable, Optional

from .. import container as C
from ..container import ArchiveLimits, ArchiveStats, ContainerError, ImageRef
from ..knowledge import purposes as P
from ..models import (
    ASSET_LIBRARY, ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED,
    Evidence, Finding, TECH_CONTAINER,
)
from . import binary, certs, configs, deps, source

SCANNER = "container"

# Files worth reading out of a layer, and which analyser handles each. Anything
# else is skipped without being read, which is most of an image.
_MAX_TEXT_BYTES = 2_000_000
_MAX_BINARY_BYTES = 64_000_000

# Paths that are noise in every image: package manager caches, locale data and
# documentation. Skipping them by name is far cheaper than reading them.
_SKIP_PREFIXES = (
    "usr/share/man/", "usr/share/doc/", "usr/share/locale/", "usr/share/zoneinfo/",
    "var/cache/", "var/log/", "usr/share/i18n/",
)


def _skip(path: str) -> bool:
    return any(path.startswith(p) for p in _SKIP_PREFIXES)


def _provenance(image: ImageRef, lf: C.LayerFile, archive_path: Path) -> dict[str, Any]:
    """The container-specific evidence every finding from an image carries."""
    return {
        "container": {
            "archive": archive_path.name,
            "image": image.name,
            "image_digest": image.digest or None,
            "platform": image.platform or None,
            "layer_index": lf.layer_index,
            "layer_digest": lf.layer_digest,
            "path": lf.path,
            "state": lf.state,
            "effective": lf.effective,
            "superseded_by_layer": lf.superseded_by if lf.superseded_by >= 0 else None,
        }
    }


def _location(image: ImageRef, lf: C.LayerFile) -> str:
    """A readable, unambiguous location for one file inside one image."""
    return f"{image.name}:/{lf.path}"


def _historical_note(lf: C.LayerFile) -> str:
    if lf.effective:
        return ""
    return (f" This file is NOT in the image's final filesystem -- layer "
            f"{lf.superseded_by} removed or replaced it. It remains extractable "
            f"from the archive, so it is inventoried as a historical artefact, "
            f"not as active content.")


def _decorate(findings: list[Finding], image: ImageRef, lf: C.LayerFile,
              archive_path: Path, technique_ran: str,
              analyser: str) -> list[Finding]:
    """Attach container provenance without altering what the analyser decided.

    The analyser's algorithm, purpose, confidence and assurance are left
    exactly as they were. Only the location is rewritten to name the image and
    layer, and the technique is recorded as the one that actually ran -- the
    layer analysis is how we reached the bytes, not how the bytes were
    identified, and claiming otherwise would overstate what happened.

    The scanner name keeps the inner analyser (``container/binary`` rather than
    a flat ``container``). Normalisation groups by scanner, so a flat name
    would merge an MD5 call site in application source with an MD5 symbol in a
    shipped library into one asset -- which is exactly the distinction a
    directory scan preserves, and losing it inside an image would be a
    fidelity regression nobody would notice until the inventory was wrong.
    """
    note = _historical_note(lf)
    provenance = _provenance(image, lf, archive_path)
    location = _location(image, lf)

    for f in findings:
        f.scanner = f"{SCANNER}/{analyser}"
        for e in f.evidence:
            e.location = location
            e.context = (e.context + f" | layer {lf.layer_index} "
                         f"{lf.layer_digest[:19]} ({lf.state})").strip(" |")
        f.extra.update(provenance)
        f.extra["inner_technique"] = technique_ran
        if note:
            f.detail = (f.detail or "") + note
        if not lf.effective:
            # A historical finding is real but not live. The distinction is
            # recorded on the finding itself so nothing downstream has to dig
            # through extra to know it.
            f.title = f"{f.title} (historical layer)"
    return findings


def _analyse_file(lf: C.LayerFile, image: ImageRef, archive_path: Path,
                  cert_mods) -> list[Finding]:
    """Route one layer file to whichever existing analyser handles it."""
    name = posixpath.basename(lf.path)
    out: list[Finding] = []

    # -- dependency manifests: capability, exactly as on disk ---------------
    kind = deps.manifest_kind(name)
    if kind and len(lf.data) <= _MAX_TEXT_BYTES:
        text = lf.data.decode("utf-8", "ignore")
        out += _decorate(deps.analyse_manifest(text, kind, lf.path), image, lf,
                         archive_path, "dependency-manifest", "dependency")

    # -- cryptographic configuration: declared ------------------------------
    cfg_kind = configs.config_kind(name)
    if cfg_kind and len(lf.data) <= _MAX_TEXT_BYTES:
        text = lf.data.decode("utf-8", "ignore")
        out += _decorate(configs.analyse_text(text, lf.path, cfg_kind), image, lf,
                         archive_path, "config-parse", "config")

    # -- source present in the image: used ----------------------------------
    if len(lf.data) <= _MAX_TEXT_BYTES:
        text = lf.data.decode("utf-8", "ignore")
        found = source.analyse_text(text, lf.path, name)
        if found:
            out += _decorate(found, image, lf, archive_path, "source-analysis", "source")

    # -- certificates and key material: observed ----------------------------
    if cert_mods is not None and len(lf.data) <= _MAX_TEXT_BYTES:
        suffix = posixpath.splitext(name)[1].lower()
        looks_like_cert = (suffix in certs.CERT_EXTS or suffix in certs.KEY_EXTS
                           or name in certs.KEY_NAMES or b"-----BEGIN" in lf.data[:4096])
        if looks_like_cert:
            found: list[Finding] = []
            for match in certs._PEM_CERT.finditer(lf.data):
                found += certs._parse_certificate(match.group(0), lf.path, cert_mods)
            if not found and suffix in {".der", ".cer", ".crt"}:
                found += certs._parse_certificate(lf.data, lf.path, cert_mods)
            for match in certs._PEM_KEY.finditer(lf.data):
                label = match.group(1).decode("ascii", "ignore")
                found.append(Finding(
                    algorithm="unknown", asset_type="related-crypto-material",
                    scanner=SCANNER, title=f"Private key file ({label.title()})",
                    detail=("Private key material inside a container image. Every "
                            "such key is a migration unit: it must be regenerated, "
                            "not merely reconfigured."),
                    rule_id="cert.privatekey",
                    evidence=[Evidence(location=lf.path, symbol=label,
                                       technique=TECH_CONTAINER, confidence=0.95,
                                       assurance=ASSURANCE_OBSERVED)],
                    extra={"material_type": "private-key", "format": "PEM"},
                ))
            out += _decorate(found, image, lf, archive_path, "certificate-parse", "certificate")

    # -- binaries and shared libraries: used --------------------------------
    if len(lf.data) >= 512 and len(lf.data) <= _MAX_BINARY_BYTES:
        bin_kind = binary.file_kind(lf.data[:8], Path(name))
        if bin_kind is not None:
            out += _decorate(binary.analyse_bytes(lf.data, lf.path, bin_kind),
                             image, lf, archive_path,
                             f"binary-analysis ({bin_kind})", "binary")

    return out


def _metadata_findings(config: dict, image: ImageRef,
                       archive_path: Path) -> list[Finding]:
    """Cryptographically relevant image metadata.

    The config blob is where a base image records what it is. It is metadata,
    not an execution, so anything derived from it is DECLARED at most.
    """
    out: list[Finding] = []
    labels = (config.get("config") or {}).get("Labels") or {}
    env = (config.get("config") or {}).get("Env") or []

    interesting = [e for e in env if isinstance(e, str) and any(
        token in e.upper() for token in
        ("SSL", "TLS", "CRYPTO", "CIPHER", "OPENSSL", "CA_BUNDLE", "CERT"))]

    if interesting:
        out.append(Finding(
            algorithm="unknown", asset_type=ASSET_LIBRARY,
            scanner=f"{SCANNER}/metadata",
            title="Cryptographic configuration in image environment",
            detail=("The image config sets environment variables that steer TLS or "
                    "certificate behaviour at run time. These are declared settings "
                    "baked into the image, not observed negotiations."),
            rule_id="container.env",
            purpose=P.TRANSPORT,
            purpose_evidence="named in the image configuration",
            evidence=[Evidence(
                location=f"{image.name}:<image config>",
                symbol=interesting[0].split("=")[0],
                snippet="; ".join(interesting[:5])[:200],
                technique=TECH_CONTAINER, confidence=0.7,
                assurance=ASSURANCE_DECLARED,
                context="image config blob")],
            extra={"container": {"archive": archive_path.name, "image": image.name,
                                 "path": "<image config>", "state": "effective",
                                 "effective": True, "layer_index": -1,
                                 "layer_digest": ""},
                   "env": interesting[:10], "labels": labels},
        ))
    return out


def scan(archive_path: str | Path, image: str = "",
         limits: Optional[ArchiveLimits] = None,
         policy=None,
         on_progress: Optional[Callable[[int, int, str], None]] = None,
         ) -> tuple[list[Finding], dict[str, Any]]:
    """Scan one image inside one local archive.

    ``image`` selects which manifest to read. An archive holding more than one
    image and no selector is an error that names the choices, because each
    image is a different estate and picking one silently would produce an
    inventory of something the operator did not ask for.
    """
    path = Path(archive_path).expanduser().resolve()
    limits = limits or ArchiveLimits()
    if policy is not None and getattr(policy, "deadline", None) is not None:
        limits.deadline = policy.deadline

    archive = C.open_archive(path, limits)
    stats: dict[str, Any] = {}
    try:
        selected = C.select_image(archive, image)
        source_blobs = archive._source
        config = C.image_config(archive, selected, source_blobs)

        def layer_progress(done: int, total: int, digest: str) -> None:
            if on_progress:
                on_progress(done, total, "layers")

        files = C.read_layers(archive, selected, limits, archive.stats,
                              on_layer=layer_progress)

        cert_mods = certs._import_x509()
        findings: list[Finding] = _metadata_findings(config, selected, path)

        read = skipped = 0
        for lf in files:
            if limits.expired():
                archive.stats.truncated = True
                archive.stats.note("time budget reached during file analysis")
                break
            if _skip(lf.path):
                skipped += 1
                continue
            read += 1
            try:
                findings.extend(_analyse_file(lf, selected, path, cert_mods))
            except Exception as exc:                 # one bad file, not a dead scan
                archive.stats.refuse(
                    f"analysis failed ({type(exc).__name__})", lf.path)

        effective = sum(1 for f in findings
                        if (f.extra.get("container") or {}).get("effective", True))
        stats = {
            "container_archive": str(path),
            "container_format": archive.kind,
            "container_format_description": C.SUPPORTED_FORMATS[archive.kind],
            "container_image": selected.name,
            "container_image_digest": selected.digest or None,
            "container_platform": selected.platform or None,
            "container_images_available": [i.to_dict() for i in archive.images],
            "container_layers": archive.stats.layers_read,
            "container_files_analysed": read,
            "container_files_skipped": skipped,
            "container_findings_effective": effective,
            "container_findings_historical": len(findings) - effective,
            "container_archive_stats": archive.stats.to_dict(),
        }
        if archive.stats.truncated:
            stats["container_incomplete"] = (
                "a resource limit was reached; this image was not read in full")
        return findings, stats
    finally:
        archive.close()

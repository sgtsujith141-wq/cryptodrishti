"""Offline validation against the official CycloneDX JSON Schemas.

Two checks exist in this codebase and they are not the same thing.

``cbom.validate`` is a hand-written structural check: required fields, enum
membership, bom-ref uniqueness. It is fast, has no dependencies, and runs
anywhere. It is **not** conformance, and it never claimed to be.

This module is conformance. It validates a document against the actual schema
published by the CycloneDX project, vendored under ``app/schemas/cyclonedx``
at a pinned commit recorded in ``PROVENANCE.md``. The schemas are checksummed
on load, because a validator you can quietly edit is not a validator.

Both are kept. The structural check stays the default for the fast paths — a
scan that emits a CBOM should not need a 260 KB schema parsed — and the
official check is what CI runs and what the operator can ask for. Reporting
the structural result as though it were schema conformance would be the exact
kind of overclaim this tool exists not to make.
"""

from __future__ import annotations

import functools
import hashlib
import json
from pathlib import Path
from typing import Any, Optional

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas" / "cyclonedx"

# Export versions this tool can produce *and* validate. A version appears here
# only when both halves are real.
SUPPORTED_VERSIONS = ("1.6", "1.7")
DEFAULT_VERSION = "1.6"

_SCHEMA_FILE = {
    "1.6": "bom-1.6.schema.json",
    "1.7": "bom-1.7.schema.json",
}

# Schemas referenced by $ref from the main documents. Registered by filename,
# which is how CycloneDX writes the references.
_REFERENCED = ("spdx.schema.json", "jsf-0.82.schema.json",
               "cryptography-defs.schema.json")


class SchemaUnavailable(RuntimeError):
    """Official validation could not run. Never silently treated as a pass."""


def provenance() -> dict[str, Any]:
    """Where the schemas came from, for anything that reports a result."""
    return {
        "source": "https://github.com/CycloneDX/specification",
        "pinned_commit": "0bd48c88d1b1877c7a3536252e06893850763190",
        "commit_date": "2026-02-25T06:42:12Z",
        "retrieved": "2026-09-21",
        "licence": "Apache-2.0",
        "location": str(SCHEMA_DIR.relative_to(SCHEMA_DIR.parents[2]))
        if SCHEMA_DIR.parents[2] in SCHEMA_DIR.parents else str(SCHEMA_DIR),
        "versions": list(SUPPORTED_VERSIONS),
    }


def available() -> bool:
    """Whether official validation can run in this environment."""
    try:
        import jsonschema  # noqa: F401
        import referencing  # noqa: F401
    except ImportError:
        return False
    return all((SCHEMA_DIR / name).is_file() for name in _SCHEMA_FILE.values())


def unavailable_reason() -> str:
    try:
        import jsonschema  # noqa: F401
        import referencing  # noqa: F401
    except ImportError:
        return ("the `jsonschema` package is not installed; install it with "
                "`pip install -r requirements.txt` to enable official "
                "schema validation")
    missing = [n for n in _SCHEMA_FILE.values() if not (SCHEMA_DIR / n).is_file()]
    if missing:
        return f"vendored schema file(s) missing: {', '.join(missing)}"
    return ""


def verify_checksums() -> list[str]:
    """Confirm the vendored schemas are the ones that were pinned.

    A drifted schema is reported loudly. Validation against a locally edited
    copy of a standard is worth less than no validation at all, because it
    looks like the real thing.
    """
    manifest = SCHEMA_DIR / "CHECKSUMS.json"
    if not manifest.is_file():
        return ["CHECKSUMS.json is missing; the vendored schemas cannot be verified"]
    try:
        expected = json.loads(manifest.read_text())
    except json.JSONDecodeError as exc:
        return [f"CHECKSUMS.json is not valid JSON: {exc}"]

    problems: list[str] = []
    for name, record in expected.items():
        path = SCHEMA_DIR / name
        if not path.is_file():
            problems.append(f"{name} is missing")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != record.get("sha256"):
            problems.append(
                f"{name} does not match its recorded checksum — it has been "
                f"modified since it was vendored")
    return problems


@functools.lru_cache(maxsize=4)
def _validator(version: str):
    """Build and cache a validator for one spec version."""
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    filename = _SCHEMA_FILE.get(version)
    if filename is None:
        raise SchemaUnavailable(
            f"CycloneDX {version} is not supported by this tool. Supported: "
            f"{', '.join(SUPPORTED_VERSIONS)}.")

    resources = []
    for name in _REFERENCED:
        path = SCHEMA_DIR / name
        if path.is_file():
            resources.append(
                (name, Resource(contents=json.loads(path.read_text()),
                                specification=DRAFT7)))
    registry = Registry().with_resources(resources)
    main = json.loads((SCHEMA_DIR / filename).read_text())
    return Draft7Validator(main, registry=registry)


def validate(doc: dict[str, Any], version: Optional[str] = None
             ) -> tuple[bool, list[str]]:
    """Validate against the official schema. Raises if it cannot run.

    Raising rather than returning ``(True, [])`` is deliberate: a caller that
    cannot tell "valid" from "not checked" will report the second as the
    first, and the whole point of this module is that the difference matters.
    """
    if not available():
        raise SchemaUnavailable(unavailable_reason())

    drift = verify_checksums()
    if drift:
        raise SchemaUnavailable("; ".join(drift))

    version = version or str(doc.get("specVersion") or DEFAULT_VERSION)
    validator = _validator(version)

    problems: list[str] = []
    for error in sorted(validator.iter_errors(doc),
                        key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in error.absolute_path) or "(document root)"
        problems.append(f"{where}: {error.message}")
    return (not problems), problems


def report(doc: dict[str, Any], version: Optional[str] = None) -> dict[str, Any]:
    """A result structure safe to serve over HTTP or print in CI.

    Carries ``checked`` separately from ``valid`` so that "we could not run
    the check" can never be read as "it passed".
    """
    version = version or str(doc.get("specVersion") or DEFAULT_VERSION)
    out: dict[str, Any] = {
        "spec_version": version,
        "validator": "official CycloneDX JSON Schema",
        "schema": provenance(),
        "checked": False,
        "valid": None,
        "problems": [],
    }
    try:
        valid, problems = validate(doc, version)
    except SchemaUnavailable as exc:
        out["reason_unavailable"] = str(exc)
        return out
    out["checked"] = True
    out["valid"] = valid
    out["problems"] = problems[:100]
    if len(problems) > 100:
        out["problems_truncated"] = len(problems) - 100
    return out

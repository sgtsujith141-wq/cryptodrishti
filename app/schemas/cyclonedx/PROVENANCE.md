# Vendored CycloneDX JSON Schemas

These files are **not ours**. They are copied verbatim from the CycloneDX
specification project so that validation works offline, with no network call at
validation time and no dependency on a URL staying up.

## Source

| Field | Value |
|---|---|
| Upstream | <https://github.com/CycloneDX/specification> |
| Path | `schema/` |
| Pinned commit | `0bd48c88d1b1877c7a3536252e06893850763190` |
| Commit date | 2026-02-25T06:42:12Z |
| Retrieved | 2026-09-21 |
| Licence | Apache-2.0 (see the upstream `LICENSE`) |

## Files

| File | Role |
|---|---|
| `bom-1.6.schema.json` | CycloneDX 1.6, the default export version |
| `bom-1.7.schema.json` | CycloneDX 1.7, the selectable export version |
| `cryptography-defs.schema.json` | Referenced by 1.7 only: algorithm family and elliptic curve enums |
| `spdx.schema.json` | Referenced by both: SPDX licence identifiers |
| `jsf-0.82.schema.json` | Referenced by both: JSON Signature Format |

`CHECKSUMS.json` records a SHA-256 for each file. `app/schema_validation.py`
verifies them on load, so a schema that has been edited locally — by accident
or otherwise — is reported rather than silently trusted. A validator you can
quietly modify is not a validator.

## Why pinned rather than fetched

A schema fetched at validation time makes the result depend on the network and
on whatever upstream happens to say that day. Two runs of the same tool over
the same estate would then be able to disagree, which is exactly what a
conformance check exists to prevent. Updating means replacing these files and
the commit above deliberately, in a reviewable change.

## Updating

```bash
COMMIT=<new commit sha>
for f in bom-1.6.schema.json bom-1.7.schema.json cryptography-defs.schema.json \
         spdx.schema.json jsf-0.82.schema.json; do
  curl -sSfo "app/schemas/cyclonedx/$f" \
    "https://raw.githubusercontent.com/CycloneDX/specification/$COMMIT/schema/$f"
done
python -c "import hashlib,pathlib,json; d=pathlib.Path('app/schemas/cyclonedx'); \
  (d/'CHECKSUMS.json').write_text(json.dumps({p.name:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in sorted(d.glob('*.json')) if p.name!='CHECKSUMS.json'},indent=2)+'\n')"
```

Then update the table above and run the suite.

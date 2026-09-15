# Cryptographic Discovery & Quantum Risk Analysis

**SIH 2026 · Problem statement SIH26164 · National Technical Research Organisation**

Discovers every cryptographic artefact across a codebase and its infrastructure,
scores each one for exposure to quantum attack, recommends a post-quantum
replacement, and emits a standards-conformant **CycloneDX 1.6 CBOM**.

## Run it

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python run.py
```

Then open <http://127.0.0.1:8000>. Point the console at any directory on disk to
scan it.

To open with the console already populated, pass a path to scan first:

```bash
./.venv/bin/python run.py --seed --seed-path /path/to/some/repo
```

**On demonstration targets.** The `demo/targets/` directory used during
development held local clones of OpenSSL, Django, Paramiko and Shiro. Those are
third-party repositories totalling several hundred megabytes, so they are not
committed here. Clone whichever you want to reproduce those results:

```bash
mkdir -p demo/targets && git clone --depth 1 https://github.com/openssl/openssl demo/targets/openssl
```

The application makes **no outbound network requests**. Every asset is vendored
locally, so it runs fully air-gapped. The only exception is the network sensor,
which connects exactly to the endpoints you name.

## Six sensors

| Sensor | Technique |
|---|---|
| `source` | Python AST analysis; curated rule packs for Java, C/C++, Go, JS/TS, C#, Ruby, PHP |
| `dependency` | Package manifests mapped to library crypto capability and PQC support |
| `binary` | ELF symbol tables, cryptographic constant matching, library version banners |
| `certificate` | X.509, PEM/DER, private key material, including post-quantum certificates |
| `config` | nginx, Apache, sshd, OpenSSL, Java security policy |
| `network` | Live TLS probing, including hybrid post-quantum group negotiation |

## How risk is scored

Mosca's inequality — `X + Y > Z`, where X is data confidentiality lifetime, Y is
migration time and Z is years to a cryptographically relevant quantum computer.

Z is unknowable, so it is modelled as a distribution and reported as a
probability rather than asserted as a date. Every score is a transparent product
of named factors, each surfaced in the interface beside its input value.

## Layout

```
run.py              entry point
app/
  knowledge/        algorithm registry, detection rules, PQC recommendations
  scanners/         the six sensors
  engine/           normalisation, Mosca risk model, recommender
  cbom.py           CycloneDX 1.6 emitter and structural validator
  web/              console (vanilla JS, zero dependencies)
deck/index.html     presentation deck (offline, arrow keys, P for notes)
presenter/          timed script and Q&A sheet
demo/targets/       cloned repositories used for demonstration (not committed)
```

## Verify it

```bash
./.venv/bin/python -m app.cli scan app --cbom /tmp/cbom.json
```

Prints the ranked inventory and writes a CBOM whose structural conformance is
checked against the CycloneDX 1.6 shape.

## Tech stack

Python 3 · FastAPI · Uvicorn · Pydantic · `cryptography` · SQLite · vanilla
JavaScript front end (no build step, no framework, no CDN).

## Status

Working prototype, built for SIH 2026. What runs today:

- All six sensors execute and produce findings.
- Mosca risk scoring, the PQC recommender and the CycloneDX 1.6 CBOM emitter
  are implemented; emitted CBOMs pass the structural validator.
- The web console renders scan results, per-asset risk breakdowns and CBOM
  export.

Known limits:

- Source analysis is a full AST pass for Python only; the other languages are
  matched by curated regex rule packs, so recall there is lower.
- The binary sensor parses section headers and symbol tables for ELF only.
  Mach-O and PE binaries fall back to raw string scanning, so hits there are
  weaker evidence than genuine linkage.
- Scan history lives in a local SQLite file under `data/`. There is no
  authentication, no multi-user support and no migration story; it is a
  single-operator tool.
- Not packaged for distribution — run it from the source tree.

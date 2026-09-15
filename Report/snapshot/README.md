# Cryptographic Discovery & Quantum Risk Analysis

**SIH 2026 · Problem statement SIH26164 · National Technical Research Organisation**

Discovers every cryptographic artefact across a codebase and its infrastructure,
scores each one for exposure to quantum attack, recommends a post-quantum
replacement, and emits a standards-conformant **CycloneDX 1.6 CBOM**.

## Run it

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python run.py --seed --seed-path demo/targets/openssl
```

Then open <http://127.0.0.1:8000>.

`--seed` runs a scan first so the console opens already populated. Drop it to
start empty.

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
demo/targets/       cloned repositories used for demonstration
```

## Verify it

```bash
./.venv/bin/python -m app.cli scan demo/targets/openssl --cbom /tmp/cbom.json
```

Prints the ranked inventory and writes a CBOM whose structural conformance is
checked against the CycloneDX 1.6 shape.

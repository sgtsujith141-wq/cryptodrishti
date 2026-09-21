# Demo

A reproducible demonstration that runs in one command and needs no network, no
credentials and no cloud account.

```bash
python run.py --preflight-offline   # check every dependency the demo needs
python run.py --demo                # build fixtures, scan, assess
python run.py                       # console on 127.0.0.1:8000
```

## What `--demo` does

1. **Builds the generated fixtures** — `demo/build.py` writes a container image
   archive and a pair of certificates into `demo/built/`. It reuses the OCI
   packaging from `benchmark/generate.py` rather than duplicating it, so the
   demo image and the benchmark image cannot drift apart.
2. **Clears previous scans**, so the console opens on a known state.
3. **Scans the synthetic estate** in [`estate/`](estate/), deliberately pointed
   at one endpoint (`169.254.169.254`, the link-local metadata address) that the
   destination policy refuses. The scan therefore finishes **PARTIAL**, with the
   refusal recorded as its reason.
4. **Scans the container image archive**, replaying layers so that a private key
   written in one layer and removed in the next is reported as **historical** —
   not on the running filesystem, still extractable from the archive.
5. **Saves an operator override** on the RSA signing asset — a 25-year shelf
   life, raised criticality, `restricted` sensitivity, hardware-backed — and
   rescores the estate against it.

## What you should see

| Scan | Kind | Assets | Quantum-vulnerable | State |
|---|---|---|---|---|
| `demo-estate` | repository | 23 | 16 | **PARTIAL** — 1 endpoint refused by network policy |
| `checkout-service:2.4` | image | 15 | 9 | COMPLETE |

The eleven things the demo is built to show:

| # | Shown by |
|---|---|
| 1 | An RSA **signing** finding, recommended ML-DSA-65 (`svc-payments/signing.py:15`) |
| 2 | An RSA **key-establishment** finding, recommended a hybrid KEM — a different answer for the same algorithm (`svc-gateway/transport.py:16`) |
| 3 | A **capability-only** dependency: a library that could do RSA, with no call site (`svc-gateway/requirements.txt`) |
| 4 | Source evidence with file, line, symbol, technique and confidence |
| 5 | Cross-sensor **correlation** on a shared concrete artefact |
| 6 | A **container image** scan, with effective and historical assets |
| 7 | **Per-asset assessment** — every risk input labelled with its provenance |
| 8 | A saved **operator override** that survives a rescan |
| 9 | A **partial scan** with its warning, shown in history and carried into the CBOM |
| 10 | **CBOM export** in CycloneDX 1.6 and 1.7, validated against the official schema |
| 11 | A complete **HTML report** reaching every finding, not a top-N |

## Safety

Every key in this directory is synthetic and is marked as such in its own bytes.
`run.py --preflight-offline` **fails** if any file here carrying a
`PRIVATE KEY` marker does not also carry the synthetic marker, so a real key
cannot be committed here by accident.

Nothing in the demo reaches the network. The one endpoint it is pointed at is
refused before a socket is opened — that refusal is the point of the step.

## Layout

```
estate/     committed synthetic source, manifests and configuration
            (see estate/README.md for what each file demonstrates)
build.py    generates the container image and certificates at demo time
built/      generated output — NOT committed, rebuilt by `run.py --demo`
targets/    optional local clones of real third-party repositories — NOT committed
```

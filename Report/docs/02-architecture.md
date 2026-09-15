# Architecture

## The pipeline

Deliberately linear and inspectable. Each stage has one job and hands a typed
structure to the next.

```
  ┌──────────┐   ┌───────────┐   ┌──────────────┐   ┌───────────┐   ┌────────┐
  │ SENSORS  │ → │ NORMALISE │ → │ CLASSIFY &   │ → │ RECOMMEND │ → │  EMIT  │
  │ six      │   │ 2,102 →   │   │ SCORE        │   │ per       │   │ CBOM · │
  │ readers  │   │ 77 assets │   │ 52-alg base  │   │ profile   │   │ report │
  └──────────┘   └───────────┘   └──────────────┘   └───────────┘   └────────┘
```

**1 · Sensors.** Six independent readers produce raw findings, each carrying
evidence: file, line, matched symbol, detection technique, confidence.

**2 · Normalise.** 2,102 raw hits collapse into 77 distinct assets. Evidence is
merged and confidence fused. An inventory that lists one algorithm three
hundred times is a log, not an inventory.

**3 · Classify and score.** Each asset resolved against the algorithm knowledge
base, then scored: quantum class, classical key strength, deployment context,
number of call sites, detection confidence, NIST deprecation dates, and the
Mosca exposure term.

**4 · Recommend.** A migration target chosen per asset under the selected
deployment profile, with the real byte cost stated.

**5 · Emit.** CycloneDX 1.6 CBOM, a printable assessment report, and the
interactive console.

---

## Module map

| Path | Responsibility |
|---|---|
| `run.py` | Single entry point — `--seed`, `--seed-path`, `--seed-endpoints`, `--preflight`, `--demo-reset`, `--port`, `--open` |
| `app/config.py` | `PRODUCT_NAME`, paths, scan limits, Q-Day defaults, secrecy lifetimes |
| `app/models.py` | `Evidence`, `Finding`, `ScanTarget`, `ScanResult` |
| `app/knowledge/algorithms.py` | 52 algorithms across 29 families |
| `app/knowledge/rules_source.py` | 49 detection rules across 9 languages |
| `app/knowledge/rules_binary.py` | 8 verified constants, 72 symbols, 9 version patterns |
| `app/scanners/source.py` | Python `ast` plus the rule pack |
| `app/scanners/deps.py` | Dependency manifests → crypto capability |
| `app/scanners/certs.py` | X.509 parsing, including post-quantum OIDs |
| `app/scanners/configs.py` | TLS / SSH / IPsec parameters |
| `app/scanners/binary.py` | ELF sections, symbols, constant matching |
| `app/scanners/network.py` | Live TLS handshake, hybrid PQC groups |
| `app/engine/normalize.py` | Grouping, evidence merge, confidence fusion |
| `app/engine/risk.py` | Quantum classification, risk score, Mosca model |
| `app/engine/recommend.py` | Constrained migration target selection |
| `app/orchestrator.py` | Sensor sequencing and progress reporting |
| `app/cbom.py` | CycloneDX 1.6 emitter and structural validator |
| `app/store.py` | SQLite persistence |
| `app/api.py` | 13 HTTP routes |
| `app/report.py` | Printable HTML assessment |
| `app/preflight.py` | 15 pre-presentation self-checks |
| `app/web/` | The console — plain HTML, CSS, JavaScript |

---

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Language | Python 3.14 | Native `ast` gives real parsing for Python targets with zero dependencies |
| API | FastAPI + Uvicorn | Typed request models, async server, single process |
| Storage | SQLite, one file | Zero setup, survives restarts, pre-seedable for a demo |
| X.509 | `cryptography` | Correct, well-tested, handles post-quantum OIDs |
| Frontend | Vanilla HTML/CSS/JS | No build step, no npm, nothing to compile or fetch |
| Charts | Hand-written SVG | No charting library, therefore no CDN and no bundle |
| Typography | System fonts | A web font is an external request |
| Binary parsing | Pure Python | Avoids a YARA or LIEF dependency |
| Scan concurrency | Thread pool | I/O-bound file reading parallelises; CPU-bound regex is the floor |

---

## Concurrency and progress

Scans run on a background thread. The orchestrator assigns each sensor a weight
and maps its internal progress into that slice of the overall bar, so the
percentage advances *continuously* rather than once per sensor.

The job record carries a `tick` that increments on every report. The console
watches it, which is what allows the interface to distinguish a slow sensor
from a stalled one — a percentage alone cannot.

---

## The air-gap guarantee

No component makes an outbound request. Verified three ways:

1. `grep` across all web assets for `http://` or `https://` — the only match is
   the SVG namespace URI, which is an identifier and never fetched
2. `--preflight` includes an air-gap check as one of its 15 assertions
3. Demonstrated physically by unplugging the network cable mid-presentation

The optional live TLS probe is the single feature that uses the network, is
explicitly opt-in, and the tool functions fully without it.

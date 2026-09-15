# CryptoDrishti — Project Report

**Smart India Hackathon 2026 · Problem Statement SIH26164**
Enterprise Cryptographic Discovery & Analysis Tool
Issued by the National Technical Research Organisation (NTRO)
Theme: Blockchain & Cybersecurity · Category: Software

---

## Outcome

Presented at the internal round. **Positive reception, and a point of contact
offered for an internship.**

---

## What is in this folder

| Path | What it is |
|---|---|
| `CryptoDrishti-Project-Report.html` | **The main report.** Open this first — the complete professional record, printable, self-contained. |
| `Product/index.html` | **The product website.** A landing page for CryptoDrishti — what it is, the problem, how it works, the results. Self-contained; open it in any browser. |
| `SIH26164-build-kit.html` | The presentation build kit written before the pitch: everything mapped onto the official SIH slide template. |
| `docs/01-problem-and-context.md` | The problem statement, the cryptography behind it, and the Indian policy mandate |
| `docs/02-architecture.md` | System design, the five-stage pipeline, module map |
| `docs/03-technical-reference.md` | Full technical reference: sensors, knowledge base, engines, API |
| `docs/04-milestones.md` | Chronological build log — every milestone, in order |
| `docs/05-design-evolution.md` | Fourteen interface iterations, what was rejected and why |
| `docs/06-verification.md` | How correctness was established; measured results |
| `docs/07-engineering-decisions.md` | The judgement calls, and the real bugs found and fixed |
| `docs/playbook.html` | The original working playbook written during the build |
| `assets/screenshots/` | Interface screenshots, final build |
| `snapshot/` | The exact source at the state presented, plus the full design history |

## Running the snapshot

```bash
cd snapshot
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python run.py --demo-reset     # seed the canonical demo state
python run.py                  # console at http://127.0.0.1:8000
python run.py --preflight      # 15 self-checks before presenting
```

> **Note.** `--preflight` runs its own scan and leaves it as the newest record.
> Always finish with `--demo-reset` so the console shows the canonical figures.

## The numbers, for reference

| Measure | Value |
|---|---|
| Cryptographic assets found in OpenSSL | 77 (from 2,102 raw detections) |
| Quantum vulnerable | 58 — 75.3% |
| Critical severity | 18 |
| Peak exposure past Q-Day | 4.5 years |
| Scan duration | 7.8 s across six sensors |
| CBOM validation | PASS — 77 components, CycloneDX 1.6 |
| External network requests | 0 |
| Third-party dependencies | 4 |

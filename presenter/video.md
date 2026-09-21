# Demonstration video — script and shot list

> ## Recording status: **NOT RECORDED**
>
> This file is a script and a shot list. No video file exists in this
> repository, none has been produced, and nothing has been uploaded anywhere.
> When a recording is made, add it as the first row of the table below and
> change this banner. Until then, treat any claim that a demo video exists as
> false.

Target length **4:00**, hard ceiling 5:00. Written to be recorded in seven
takes, one per shot, and cut together — a single continuous take is not worth
the attempts it costs.

| Asset | Path | State |
|---|---|---|
| Recording | — | not produced |
| Script | `presenter/video.md` (this file) | ready |
| Shot list | below | ready |

---

## Before you record

```bash
.venv/bin/python run.py --preflight-offline   # must print ALL CLEAR
.venv/bin/python run.py --demo                # rebuild the exact demo state
.venv/bin/python run.py                       # console on 127.0.0.1:8000
```

Recording setup:

* Capture the browser window only, not the whole desktop. Nothing in the frame
  should be from outside this project.
* 1920×1080, 30 fps is enough. The console is legible at that size; check by
  playing back thirty seconds before committing to a full take.
* Turn the **Explain** annotations **off** — they are a learning aid and they
  clutter a recording.
* Pick Light or Dark once and keep it for every shot.
* Close every other tab. A visible bookmark bar or an unrelated tab is the
  fastest way to look unprepared.
* Record system audio off; narrate over the cut, or to the picture, but do not
  fight the fan noise.

---

## Shot list

Seven shots. Each row is one take. The "expected output" column is what must be
on screen — if it is not, the take is wrong and no amount of narration fixes it.

| # | Shot | Duration | Expected output on screen |
|---|---|---|---|
| 1 | Terminal: `run.py --demo` running to completion | 0:20 | the two scans reported, ending with the override saved |
| 2 | Console, Assessment panel, `demo-estate` loaded | 0:25 | 23 assets, 16 quantum-vulnerable |
| 3 | Inventory, the first three `rsa` rows | 1:00 | scores 100 / 74 / 66 with three different recommendations |
| 4 | Evidence drawer open on the top finding | 0:45 | file, line, technique, confidence, assurance, Mosca inputs |
| 5 | Exposure window | 0:35 | X, Y, Z and the exposure figure, each labelled by provenance |
| 6 | Scan history, then the container scan reopened | 0:40 | `demo-estate` **PARTIAL** with its reason; `checkout-service:2.4` **COMPLETE** |
| 7 | Machine-readable output, Validate clicked | 0:35 | validation result against the official CycloneDX schema |

Total 4:00 of picture. Cut on the click, not after it.

---

## Narration

### Shot 1 — one command (0:00 – 0:20)

> "Everything in this video comes from one command. It builds a small synthetic
> service estate and a container image, scans both, and records one operator
> decision. No network, no cloud account, no agent."

*(Let the terminal finish on camera. Do not cut away from a running command —
the point of the shot is that it completes.)*

### Shot 2 — what came back (0:20 – 0:45)

> "Twenty-three distinct cryptographic assets. Sixteen of them do not survive a
> quantum computer. Distinct is the important word: this is not a log of
> detector hits, it is an inventory of assets."

### Shot 3 — the three RSAs (0:45 – 1:45)

> "Here is the idea the tool is built around.
>
> Three RSA findings in one scan. The first is a signing call, and the
> recommendation is ML-DSA-65. The second is RSA-OAEP doing key establishment,
> and the recommendation is a hybrid key exchange — a completely different
> migration. The third, we can see RSA is permitted but not what it is for, and
> the tool says 'purpose must be resolved first' rather than guessing.
>
> Same algorithm, three answers. Most tools give you one."

*(Hover each row long enough to read. This is the shot that has to land; expect
to take it more than once.)*

### Shot 4 — the evidence (1:45 – 2:30)

> "Every finding opens onto what produced it: the file, the line, the symbol,
> the detection technique, a confidence score, and how strong the evidence is
> that this asset is actually used — capability, declared, used or observed.
>
> A library that *can* do RSA is not evidence that RSA is used, and this
> inventory keeps that distinction instead of flattening it."

### Shot 5 — the exposure arithmetic (2:30 – 3:05)

> "Exposure is Mosca's inequality: how long the data must stay secret, plus how
> long migration takes, against years until a quantum computer exists.
>
> Nobody knows that last number, so the tool does not assert it. It is a
> scenario the operator chooses, and every figure on this screen is labelled
> with where its value came from — observed, derived, operator-set, or default."

### Shot 6 — partial scans and the container (3:05 – 3:45)

> "This scan is marked PARTIAL, with the reason: an endpoint was refused by the
> network policy. A partial scan presented as a complete inventory is the worst
> thing this tool could produce, so it is labelled everywhere it appears.
>
> And this one is a container image, read layer by layer. A private key written
> in one layer and deleted in the next is reported as historical — gone at
> runtime, still extractable from the archive."

### Shot 7 — the standard (3:45 – 4:00)

> "Output is a CycloneDX CBOM, validated offline against the official schema,
> vendored here at a pinned commit. CycloneDX 1.6 or 1.7, both genuinely valid.
>
> The source, the tests and the benchmark corpus are all in the repository."

---

## What not to say on camera

The same rules as the live script, and they matter more here because a recording
is quotable and cannot be qualified afterwards:

* no national or regulatory deadline;
* no date by which a quantum computer will arrive;
* no claim about what a named competing product can or cannot do;
* no accuracy figure without the sentence that it measures a synthetic corpus
  written by this project;
* no price, cost, latency or market-size figure.

## Fallback

If a take will not come out clean, record shots 1, 3 and 7 only and cut to
1:30. Those three carry the argument: one command, purpose resolution, and a
standards-valid output. The rest is supporting detail.

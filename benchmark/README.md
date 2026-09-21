# Detection accuracy benchmark

```bash
python benchmark/run.py                                  # print the report
python benchmark/run.py --json results/run.json          # save results
python benchmark/run.py --baseline results/baseline-382e7d1.json   # before/after
python benchmark/run.py --no-tls                         # skip the loopback probe
```

## What these numbers are, and are not

They are precision and recall **over the fixtures in `corpus/`**, which were
written by hand to exercise the detectors. They measure this corpus.

They are **not** an estimate of accuracy on real-world code. This project has
never measured that, does not claim to, and a synthetic corpus cannot stand in
for one — not least because the person who wrote the fixtures also wrote the
detectors, and knows what they look for.

A perfect score here means the corpus has stopped finding defects, which is a
reason to make the corpus harder, not a reason to celebrate. Every defect this
benchmark has found is listed below.

## Ground truth

`manifest.json` is hand-written. Each entry says what a line **is**, decided by
reading the fixture — not by running CryptoDrishti and recording the output. The
manifest is versioned and carries a changelog; where labels have been corrected,
the correction and its justification are recorded there, along with its effect on
the score, so the change is auditable rather than invisible.

Two labels are marked `purpose_ambiguous` and excluded from purpose scoring: a
bare elliptic-curve object serves ECDSA or ECDH, and deciding which would be
inventing an answer the fixture does not contain.

## Matching

| Aspect | Rule |
|---|---|
| Unit | a distinct `(file, line, algorithm)` |
| Algorithm | exact registry key — `sha3-512` does not satisfy `sha3-256` |
| Line | exact, except file-level entries (`line: null`) |
| Duplicates | actual findings are reduced to distinct keys first, so one artefact reported by two rules counts **once** and cannot inflate TP |
| Scope | only files the manifest labels are judged; a finding elsewhere is out of scope, not a false positive |
| Negatives | any finding at all in a negative file is a false positive |
| Purpose / assurance | scored over true positives only — getting the purpose of something you never found is not an achievement |

## Corpus

Source fixtures are committed. Binaries, certificates and container images are
**generated** at benchmark time by `generate.py`: a committed binary is a blob
nobody reviews, a committed certificate expires and starts failing for the wrong
reason, and a committed private key is a private key in a repository however
loudly the filename says otherwise. Everything generated is obviously synthetic —
the PEM bodies are the word `SYNTHETIC` in base64.

The network sensor is probed against a loopback TLS server started and stopped by
the benchmark. Its results are **excluded from the metrics**: what a handshake
negotiates depends on the local OpenSSL build, so an expected-results label would
be a label for one machine. Structural properties that *are* stable — that
version, cipher suite and key exchange are reported separately, and that trust is
never assumed — are asserted instead.

### Known gaps in the corpus

- **No SHA-1-signed certificate.** The installed `cryptography` refuses to create
  SHA-1 signatures, correctly. SHA-1 certificate detection is therefore not
  covered here.
- **Mach-O and PE binaries** are not fixtured; only ELF-magic blobs are.
- **Difficult negatives are limited** to comments, prose, crypto-shaped
  identifiers, a disable-list and a symbol-free binary.

## Defects this benchmark found

Each was measured first, then fixed, then covered by a regression test in
`tests/test_benchmark_regressions.py`.

| # | Defect | Effect |
|---|---|---|
| 1 | A hyphen inside a cipher name was treated as an OpenSSL exclusion marker, so `ECDHE-RSA-AES256` dropped RSA and AES-256 | 4 false negatives |
| 2 | `TLSv1` matched inside `TLSv1.2` — `\b` treats the dot as a boundary | TLS 1.0 reported as enabled on a 1.2/1.3-only server |
| 3 | `DES` matched inside `DES-CBC3`, which is Triple DES | single DES invented |
| 4 | `HmacSHA256` did not resolve — a MAC whose name states what it is was reported as `unknown` | 1 FN + 1 FP |
| 5 | The ECB rule asserted `aes` for every match, including `RSA/ECB/OAEPPadding` | an AES finding in a file with no AES |
| 6 | Certificate signature digests were inventoried only when broken | a healthy estate's CBOM listed no certificate hash functions |
| 7 | Binary symbols whose names state the operation (`RSA_sign`) left the purpose unresolved | the M2 purpose work was missing from the sensor that reaches vendor binaries |

Defect 7's first fix introduced defect 7b — every `_encrypt` mapped to key
establishment, which claimed `AES_encrypt` was wrapping keys. The benchmark
caught that too, on the next run.

# Presenter material

| File | What it is | State |
|---|---|---|
| `script.md` | Eight-minute presentation script, timed, with every demo click named | ready |
| `video.md` | How the demonstration video is produced, and its scene list | **video exists** — `submission/CryptoDrishti-SIH26164-Demo.mp4`, assembled from real captures with synthesised narration |
| `qa.md` | Technical Q&A, with the figures that may be quoted and their sources | ready |

All three were rewritten against the code as it stands. An earlier draft
asserted national policy deadlines, characterised three named commercial
products, and quoted figures from a demo that no longer exists. None of it could
be verified from this repository, so it was removed rather than reworded.

The standing rule across all three files: **do not state a number you have not
seen print on your own machine, and do not state an external fact this
repository cannot source.** Each file ends with a list of what that rules out.

## Rebuilding the state the scripts assume

```bash
.venv/bin/python run.py --preflight-offline   # must print ALL CLEAR
.venv/bin/python run.py --demo                # build, scan, override
.venv/bin/python run.py                       # console on 127.0.0.1:8000
```

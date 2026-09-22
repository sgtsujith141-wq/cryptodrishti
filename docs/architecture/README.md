# Architecture diagram

`architecture.mmd` is the editable source and the only place the structure and
the labels are written down. Everything else here is generated from it:

| File | What it is |
|---|---|
| `architecture.mmd` | the source — structure, nodes, edges, every label |
| `render.py` | renders both variants; the palettes live here, not in the source |
| `architecture.svg` / `.png` | light variant, used in the README and on GitHub |
| `architecture-dark.svg` / `.png` | dark variant, used in the submission deck beside dark-theme screenshots |

```bash
python docs/architecture/render.py
```

Two palettes, one source: the light and dark exports cannot disagree about
what the system does, because neither one holds any text of its own. The
palette is swapped by replacing everything from the first `classDef` line to
the end of the source, which is the only part `render.py` touches.

The diagram flows **left to right** — inputs, the gate each one passes through,
the seven sensors, the analysis chain, the outputs. It was drawn top-to-bottom
until the analysis subgraph ended up as a tall empty band with four nodes
stacked down one edge; turning the flow on its side packs the same content into
roughly a 2.5:1 frame, which is also the shape of a slide.

## What the diagram deliberately does not show

There is no cloud, KMS, HSM or container-registry box. Those integrations are
**not implemented**, and drawing them — even greyed out, even labelled
"future" — would read as coverage this tool does not have. The diagram shows
what runs.

## What it distinguishes

- **Container archives get their own path.** They enter through
  `app/container.py`, which vets every archive member and streams it into
  memory; nothing from an image is ever written to disk. The container sensor
  then reuses the five file-based sensors rather than reimplementing detection.
- **The TLS probe is the one outbound path.** It is drawn with a dashed border
  because it is the only sensor that leaves the machine, and only to an
  endpoint the operator named and the destination policy vetted. Every other
  sensor is offline.
- **Security sits between input and sensor, not around them.** `fspolicy`,
  `container` and `netpolicy` are gates the target passes through, which is
  where the checks actually are in the code.

# Architecture diagram

`architecture.mmd` is the editable source; `architecture.svg` and
`architecture.png` are the exported assets.

```bash
npx -y @mermaid-js/mermaid-cli@11 -i architecture.mmd -o architecture.svg -b white
npx -y @mermaid-js/mermaid-cli@11 -i architecture.mmd -o architecture.png -b white -w 2400
```

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

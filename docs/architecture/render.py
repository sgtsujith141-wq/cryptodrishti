#!/usr/bin/env python3
"""Render the architecture diagram, light and dark, from one source.

    python docs/architecture/render.py

`architecture.mmd` holds the structure and every label. It is the only place
either of those is written down. The palette lives here instead, so the light
export (for the README and GitHub) and the dark export (for the submission
deck, which sits beside dark-theme product screenshots) cannot drift apart in
what they actually say -- only in what colour they say it.

Everything from the first `classDef` line to the end of the source is treated
as the palette and replaced. Structure, nodes, edges and text above that line
are never touched.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "architecture.mmd"

PALETTES = {
    "light": {
        "background": "white",
        "theme": "default",
        "body": """classDef input fill:#EEF2FF,stroke:#4338CA,color:#1E1B4B
    classDef gate fill:#FEF2F2,stroke:#B91C1C,color:#450A0A
    classDef sensor fill:#F0FDF4,stroke:#15803D,color:#052E16
    classDef core fill:#FFFBEB,stroke:#B45309,color:#451A03
    classDef out fill:#F8FAFC,stroke:#334155,color:#0F172A
    classDef offline stroke-dasharray: 4 3

    class D1,D2,D3 input
    class G1,G2,G3,G4 gate
    class S1,S2,S3,S4,S5,S6 sensor
    class N1,N2,N3,N4 core
    class P1,A1,X1,X2,V1 out
    class S7 sensor
    class S7 offline

    style IN fill:#FFFFFF,stroke:#CBD5E1
    style GATE fill:#FFFFFF,stroke:#CBD5E1
    style SENSE fill:#FFFFFF,stroke:#CBD5E1
    style CORE fill:#FFFFFF,stroke:#CBD5E1
    style OUT fill:#FFFFFF,stroke:#CBD5E1""",
    },
    # Tuned to the console's own dark palette, so a slide carrying both the
    # diagram and a screenshot reads as one product rather than two.
    "dark": {
        "background": "#0E0F11",
        "theme": "dark",
        "body": """classDef input fill:#1B1F33,stroke:#8590F0,color:#DDE2FF
    classDef gate fill:#2C1719,stroke:#D9503C,color:#FFD8D2
    classDef sensor fill:#13261F,stroke:#3FAE86,color:#CDF2E3
    classDef core fill:#2B2315,stroke:#E0B45A,color:#F7E7C6
    classDef out fill:#1B1D22,stroke:#959AA4,color:#E6E8EC
    classDef offline stroke-dasharray: 4 3

    class D1,D2,D3 input
    class G1,G2,G3,G4 gate
    class S1,S2,S3,S4,S5,S6 sensor
    class N1,N2,N3,N4 core
    class P1,A1,X1,X2,V1 out
    class S7 sensor
    class S7 offline

    style IN fill:#0E0F11,stroke:#33373E
    style GATE fill:#0E0F11,stroke:#33373E
    style SENSE fill:#0E0F11,stroke:#33373E
    style CORE fill:#0E0F11,stroke:#33373E
    style OUT fill:#0E0F11,stroke:#33373E""",
    },
}


def source_without_palette() -> str:
    text = SOURCE.read_text()
    cut = text.index("classDef input")
    return text[:cut]


def render(variant: str, body: str, background: str, theme: str) -> bool:
    mmd = HERE / f".render-{variant}.mmd"
    mmd.write_text(source_without_palette() + body + "\n")
    suffix = "" if variant == "light" else f"-{variant}"
    ok = True
    for ext, extra in (("svg", []), ("png", ["-w", "2400"])):
        out = HERE / f"architecture{suffix}.{ext}"
        cmd = ["npx", "-y", "@mermaid-js/mermaid-cli@11",
               "-i", str(mmd), "-o", str(out),
               "-b", background, "-t", theme] + extra
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=600)
        if result.returncode != 0 or not out.is_file():
            print(f"  FAILED {out.name}: {result.stderr.strip()[:300]}",
                  file=sys.stderr)
            ok = False
        else:
            print(f"  {out.name}  ({out.stat().st_size:,} bytes)")
    mmd.unlink(missing_ok=True)
    return ok


def main() -> int:
    if not shutil.which("npx"):
        print("npx is required to render the diagram", file=sys.stderr)
        return 1
    if not SOURCE.is_file():
        print(f"missing source: {SOURCE}", file=sys.stderr)
        return 1
    ok = True
    for variant, spec in PALETTES.items():
        print(f"{variant}:")
        ok &= render(variant, spec["body"], spec["background"], spec["theme"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

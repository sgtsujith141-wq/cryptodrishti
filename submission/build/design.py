#!/usr/bin/env python3
"""The CryptoDrishti submission design system.

One place for the tokens the deck, the panels and the film all share, so the
three cannot drift into looking like three different projects.

The palette and the type stack are lifted from the product's own dark theme
(`app/web/style.css`), not invented for the submission. That is the point: the
identity in the deck is the identity of the thing being presented.
"""

from __future__ import annotations

# --- surfaces, darkest to lightest ----------------------------------------
PAPER = "#101012"      # the console's page
SURF = "#1A1A1D"       # a card
SURF2 = "#212125"      # a nested card
SUNK = "#27272B"       # a well
RULE = "#2E2E33"       # hairline
RULE2 = "#3C3C42"

# --- ink ------------------------------------------------------------------
INK = "#EDEBE6"
INK2 = "#ADA9A1"
INK3 = "#86827A"
INK4 = "#6B675F"

# --- the classification palette, which carries meaning --------------------
BROKEN = "#D9503C"     # Shor-broken
WEAKENED = "#E0B45A"   # Grover-weakened
UNKNOWN = "#8A939F"    # unresolved
HYBRID = "#B99CE0"
SAFE = "#3FAE86"

ACCENT = BROKEN        # the one accent, used sparingly

# --- type -----------------------------------------------------------------
SANS = ('-apple-system, BlinkMacSystemFont, "Helvetica Neue", Helvetica, '
        "Arial, sans-serif")
MONO = ('ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace')

# Sans carries argument, mono carries evidence. A file path, an algorithm
# name, a score or a target is always mono -- so a reader can tell at a glance
# which words came out of the tool and which are ours.

BASE_CSS = f"""
*, *::before, *::after {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; background: {PAPER}; }}
body {{
  font-family: {SANS};
  color: {INK};
  -webkit-font-smoothing: antialiased;
  text-rendering: geometricPrecision;
}}
.mono {{ font-family: {MONO}; }}
.eyebrow {{
  font-family: {MONO}; font-size: 12px; letter-spacing: .14em;
  text-transform: uppercase; color: {INK4}; font-weight: 600;
}}
.rule {{ height: 1px; background: {RULE}; border: 0; }}
.card {{
  background: {SURF}; border: 1px solid {RULE}; border-radius: 3px;
}}
.dim {{ color: {INK3}; }}
.muted {{ color: {INK2}; }}
"""


def page(body: str, css: str = "", width: int = 1600, height: int = 900) -> str:
    """Wrap panel markup in a complete document at a fixed size."""
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><style>
{BASE_CSS}
html, body {{ width: {width}px; height: {height}px; overflow: hidden; }}
{css}
</style></head><body>{body}</body></html>"""

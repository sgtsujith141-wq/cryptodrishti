"""Central configuration.

The product name lives here and nowhere else. Every surface -- web UI, CBOM
metadata, reports, CLI banner -- reads it from this module, so renaming the
product is a one-line change.
"""

from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

PRODUCT_NAME = "CryptoDrishti"
PRODUCT_TAGLINE = "Cryptographic discovery and quantum risk analysis"
PRODUCT_VERSION = "0.9.0"
VENDOR = "SIH 2026 / SIH26164"

# Problem statement context, surfaced in the UI footer and the CBOM metadata.
PS_ID = "SIH26164"
PS_ORG = "National Technical Research Organisation (NTRO)"

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
APP_DIR = ROOT / "app"
WEB_DIR = APP_DIR / "web"
DATA_DIR = ROOT / "data"
DEMO_DIR = ROOT / "demo"
TARGETS_DIR = DEMO_DIR / "targets"

DB_PATH = Path(os.environ.get("CD_DB", DATA_DIR / "scans.sqlite3"))

# --------------------------------------------------------------------------
# Scan limits
#
# These exist so a scan of a large real-world repository finishes inside a
# live demo. They are deliberately generous but finite.
# --------------------------------------------------------------------------

MAX_FILES = int(os.environ.get("CD_MAX_FILES", 25_000))
MAX_FILE_BYTES = 2_000_000          # skip anything larger; crypto lives in normal files
MAX_BINARY_BYTES = 64_000_000       # binaries can legitimately be large
SCAN_WORKERS = int(os.environ.get("CD_WORKERS", 8))

# Directory entries a single scan may visit. MAX_FILES bounds what is *read*;
# this bounds what is *walked*, which is the term that runs away when someone
# points the tool at a home directory or a mounted volume.
MAX_ENTRIES = int(os.environ.get("CD_MAX_ENTRIES", 400_000))

# Wall-clock budget for one scan, in seconds. Neither a file count nor a byte
# count bounds a walk over a filesystem where stat() is slow, so the only
# honest bound is time. 0 disables it. When it expires the scan ends cleanly
# and is reported as incomplete rather than being killed.
SCAN_TIME_BUDGET = float(os.environ.get("CD_SCAN_SECONDS", 600))

# Scans that may run at once. Each one is a thread pool over a filesystem
# walk, so an unbounded number of them is a denial-of-service primitive
# against the machine the console runs on.
MAX_CONCURRENT_SCANS = int(os.environ.get("CD_MAX_CONCURRENT_SCANS", 2))

# In-memory scan job records retained for progress polling.
MAX_TRACKED_JOBS = int(os.environ.get("CD_MAX_TRACKED_JOBS", 200))

# Directories that never contain first-party source worth reporting.
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".venv", "venv", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    "dist", "build", ".eggs", "site-packages", ".gradle", "target",
}

# --------------------------------------------------------------------------
# Risk model defaults
#
# Q-Day is genuinely unknown. We model it as a distribution rather than a
# date, and every one of these is user-adjustable in the UI. Defaults follow
# the broad expert consensus range reported by the Global Risk Institute's
# annual quantum threat timeline surveys.
# --------------------------------------------------------------------------

QDAY_EARLIEST = 2030
QDAY_LIKELY = 2034
QDAY_LATEST = 2044

# Default migration time Y, in years, when an asset has no better estimate.
DEFAULT_MIGRATION_YEARS = 3.0

# Default data shelf life X, in years, by sensitivity tier.
SHELF_LIFE_BY_SENSITIVITY = {
    "restricted": 25.0,   # defence, intelligence, long-lived state secrets
    "confidential": 10.0,  # financial records, health, PII under retention law
    "internal": 5.0,
    "public": 1.0,
}
DEFAULT_SENSITIVITY = "confidential"

# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

HOST = os.environ.get("CD_HOST", "127.0.0.1")
PORT = int(os.environ.get("CD_PORT", 8000))


def ensure_dirs() -> None:
    """Create the writable directories the app needs. Safe to call repeatedly."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    TARGETS_DIR.mkdir(parents=True, exist_ok=True)

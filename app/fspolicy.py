"""Filesystem boundary policy for the filesystem sensors.

A scan root arrives from an HTTP request. Four things follow from that.

**The root is the boundary.** Every file a sensor opens must resolve inside
the resolved root. ``os.walk`` does not follow directory symlinks, which is
why this was easy to miss, but it *does* hand back symlinked **files** -- a
link named ``config.py`` pointing at ``~/.ssh/id_rsa`` is walked, read, and
its contents land in ``evidence.snippet``. ``escapes()`` closes that.

**Some paths are never worth reading.** ``/proc`` and ``/sys`` are synthetic
and walking them is somewhere between meaningless and a hang. A credential
store has no cryptographic inventory value that could justify reading it.
Both are refused by name rather than relying on the boundary check.

**A refusal is a finding.** Skipped paths are counted and returned, because a
scan that silently declined to read part of the tree has produced an
incomplete inventory and the operator has to know that.

**Bounds are wall-clock, not just counts.** ``MAX_FILES`` does not stop a walk
over a filesystem where ``stat`` is slow, so a deadline is carried alongside.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Directories that are synthetic, enormous, or recursive by construction.
# Walking any of these is never the operator's intent.
NEVER_TRAVERSE = (
    "/proc", "/sys", "/dev", "/run", "/lost+found",
    "/private/var/vm", "/System/Volumes/Data", "/Volumes/.timemachine",
    "/.fseventsd", "/.Spotlight-V100", "/.DocumentRevisions-V100",
)

# Files whose contents are credentials and nothing else. The certificate
# sensor deliberately reports *that* a private key exists -- that is a real
# finding -- but it records only the PEM label, never the key body, and these
# files carry no cryptographic artefact worth the exfiltration risk.
NEVER_READ_NAMES = frozenset({
    "shadow", "gshadow", "master.passwd", "sudoers",
    ".netrc", "_netrc", ".git-credentials", ".npmrc", ".pypirc",
    "credentials",                     # ~/.aws/credentials
    ".htpasswd", "authorized_keys",
})

NEVER_READ_SUFFIXES = frozenset({".keychain", ".keychain-db", ".kdbx", ".jks-password"})


class PathRefused(ValueError):
    """A path was rejected by policy. The message is operator-facing."""


@dataclass
class FsPolicy:
    """Boundaries and bounds for one scan."""

    root: Path
    deadline: Optional[float] = None       # monotonic time after which to stop
    follow_symlinks_outside: bool = False
    max_entries: int = 400_000             # directory entries visited, not files read

    # Populated as the walk proceeds, then reported.
    skipped: dict[str, int] = field(default_factory=dict)
    examples: list[str] = field(default_factory=list)
    _entries: int = 0

    def note(self, reason: str, path: str = "") -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1
        if path and len(self.examples) < 20:
            self.examples.append(f"{reason}: {path}")

    # -- bounds ----------------------------------------------------------

    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

    def count_entry(self) -> bool:
        """Count one visited entry. False once the entry budget is spent."""
        self._entries += 1
        if self._entries > self.max_entries:
            self.note("entry budget exhausted")
            return False
        return True

    def exhausted(self) -> bool:
        return self.expired() or self._entries > self.max_entries

    # -- reporting -------------------------------------------------------

    def report(self) -> dict:
        out: dict = {"skipped": dict(self.skipped), "entries_visited": self._entries}
        if self.examples:
            out["skipped_examples"] = list(self.examples)
        if self.expired():
            out["incomplete"] = "scan deadline reached; the inventory is partial"
        elif self._entries > self.max_entries:
            out["incomplete"] = "entry budget exhausted; the inventory is partial"
        return out


def resolve_root(path: str | Path) -> Path:
    """Resolve a scan root, or refuse it.

    Refuses before any sensor runs, so a bad target fails loudly at the start
    rather than producing a thin result that looks like a clean estate.
    """
    try:
        root = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathRefused(f"Scan root cannot be resolved: {exc}")

    if not root.exists():
        raise PathRefused(f"Scan root does not exist: {root}")

    text = str(root)
    for denied in NEVER_TRAVERSE:
        if text == denied or text.startswith(denied.rstrip("/") + "/"):
            raise PathRefused(
                f"{root} is inside {denied}, a synthetic or system filesystem "
                f"this tool will not walk.")
    return root


def should_traverse(dirpath: str) -> bool:
    """Whether a directory encountered mid-walk may be descended into."""
    real = os.path.realpath(dirpath)
    for denied in NEVER_TRAVERSE:
        if real == denied or real.startswith(denied.rstrip("/") + "/"):
            return False
    return True


def escapes(path: Path, root: Path) -> bool:
    """True when ``path`` resolves outside ``root``.

    This is the symlink check. ``os.walk`` will hand back a symlinked file
    inside the tree whose target is anywhere on the machine; resolving it and
    comparing against the root is the only reliable way to tell.
    """
    try:
        real = path.resolve()
    except (OSError, RuntimeError):
        return True
    try:
        real.relative_to(root)
        return False
    except ValueError:
        return True


def readable(path: Path, root: Path, policy: Optional[FsPolicy] = None) -> bool:
    """Whether a sensor may open this file. Records the reason when it may not."""
    name = path.name
    low = name.lower()

    if low in NEVER_READ_NAMES or path.suffix.lower() in NEVER_READ_SUFFIXES:
        if policy:
            policy.note("credential store, never read", str(path))
        return False

    if path.is_symlink() and escapes(path, root):
        if policy and policy.follow_symlinks_outside:
            return True
        if policy:
            policy.note("symlink escaping the scan root", str(path))
        return False

    if escapes(path, root):
        if policy:
            policy.note("path resolves outside the scan root", str(path))
        return False

    return True


def filter_dirnames(dirpath: str, dirnames: list[str], skip: set[str],
                    root: Path, policy: Optional[FsPolicy] = None) -> None:
    """Prune a walk's ``dirnames`` in place.

    Removes the caller's own skip set, synthetic filesystems, and directory
    symlinks that leave the root -- ``os.walk`` does not follow those by
    default, but pruning them keeps them out of the visited count and makes
    the refusal visible in the report.
    """
    keep: list[str] = []
    for d in dirnames:
        if d in skip:
            continue
        full = os.path.join(dirpath, d)
        if not should_traverse(full):
            if policy:
                policy.note("synthetic or system filesystem", full)
            continue
        if os.path.islink(full) and escapes(Path(full), root):
            if policy:
                policy.note("directory symlink escaping the scan root", full)
            continue
        keep.append(d)
    dirnames[:] = keep

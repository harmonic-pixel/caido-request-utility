"""
progress.py — a one-line progress bar for the phases that take a while.

Stdlib only, and it writes to **stderr only when a terminal is attached**: the
tools pipe their real output to a file often enough (`--json > findings.json`)
that a thousand carriage returns in the middle of it would be a bug, not a
feature. With no terminal, every call here does nothing.

    for i, item in enumerate(items):
        progress.track(i, len(items), "scanning")
        ...
    progress.clear()
"""

from __future__ import annotations

import sys

_WIDTH = 28


def _live() -> bool:
    return sys.stderr.isatty()


def track(done: int, total: int, label: str) -> None:
    """Draw `label [####····] done/total (nn%)`, overwriting the same line."""
    if not _live():
        return
    total = max(total, 1)
    done = min(done, total)
    filled = _WIDTH * done // total
    sys.stderr.write(
        f"\r  {label} [{'#' * filled}{'.' * (_WIDTH - filled)}] "
        f"{done}/{total} ({100 * done // total:3d}%)"
    )
    sys.stderr.flush()


def count(done: int, label: str) -> None:
    """For a phase whose total is not known until it ends."""
    if not _live():
        return
    sys.stderr.write(f"\r  {label} {done} rows")
    sys.stderr.flush()


def clear() -> None:
    """Wipe the progress line so it does not sit above the real output."""
    if not _live():
        return
    sys.stderr.write("\r\033[K")
    sys.stderr.flush()

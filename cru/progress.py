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
_enabled = True
# How wide the last line was. `\r` returns to column 0 but erases nothing, so a
# shorter line leaves the tail of a longer one behind it — `scanning
# (mixedcontent)` followed by `scanning (xss)` reads as `scanning (xss)ntent)`.
# Padding to the previous width covers it, and needs no escape sequence.
_last = 0


def disable() -> None:
    """Turn progress off for the rest of the run (`--no-progress`)."""
    global _enabled
    _enabled = False


def _live() -> bool:
    return _enabled and sys.stderr.isatty()


def _draw(line: str) -> None:
    global _last
    if not _live():
        return
    sys.stderr.write("\r" + line.ljust(_last))
    _last = len(line)
    sys.stderr.flush()


def track(done: int, total: int, label: str) -> None:
    """Draw `label [####....] done/total (nn%)`, overwriting the same line."""
    total = max(total, 1)
    done = min(done, total)
    filled = _WIDTH * done // total
    _draw(
        f"  {label} [{'#' * filled}{'.' * (_WIDTH - filled)}] "
        f"{done}/{total} ({100 * done // total:3d}%)"
    )


def count(done: int, label: str) -> None:
    """For a phase whose total is not known until it ends."""
    _draw(f"  {label} {done} rows")


def clear() -> None:
    """Wipe the progress line so it does not sit above the real output."""
    global _last
    if not _live():
        return
    sys.stderr.write("\r" + " " * _last + "\r")
    _last = 0
    sys.stderr.flush()

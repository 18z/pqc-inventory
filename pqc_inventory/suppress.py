"""Suppression rules for local hash / checksum inventory noise.

Down-ranks or drops SHA/hash helpers so they do not clutter priority tops.
Does **not** guess sensitivity or invent lifetimes — only filters noise.
"""

from __future__ import annotations

from typing import Any, Literal

HashPolicy = Literal["drop", "downrank", "keep"]

# Cap used when down-ranking local hash / checksum findings
HASH_DOWNRANK_SCORE_CAP = 8

_HASH_FAMILIES = {"SHA/Hash"}
_HASH_EXPOSURES = {"hash_local"}


def is_hash_noise(finding: Any) -> bool:
    """True if finding is local hash / checksum inventory noise."""
    exposure = getattr(finding, "exposure", "") or ""
    if exposure in _HASH_EXPOSURES:
        return True
    fams = set(getattr(finding, "families", None) or [])
    fams.add(getattr(finding, "family", "") or "")
    if fams & _HASH_FAMILIES and exposure in ("", "hash_local"):
        return True
    # Pure hash family with only hash exposure
    if fams <= _HASH_FAMILIES and getattr(finding, "quantum_risk", "") == "info":
        return True
    return False


def apply_hash_suppression(
    findings: list[Any],
    policy: HashPolicy = "downrank",
) -> list[Any]:
    """Apply hash/checksum suppression policy; return (possibly filtered) list.

    - ``keep``: no change
    - ``downrank``: cap ``priority_score``, mark ``suppressed=True``, note in reason
    - ``drop``: omit hash noise from the returned list (raw hits retained upstream)
    """
    if policy == "keep":
        for f in findings:
            if not hasattr(f, "suppressed"):
                f.suppressed = False
        return findings

    kept: list[Any] = []
    for f in findings:
        if not is_hash_noise(f):
            f.suppressed = False
            kept.append(f)
            continue
        if policy == "drop":
            f.suppressed = True
            continue
        # downrank
        f.suppressed = True
        old = getattr(f, "priority_score", 0) or 0
        capped = min(old, HASH_DOWNRANK_SCORE_CAP)
        f.priority_score = capped
        reason = getattr(f, "priority_reason", "") or ""
        note = f"hash/checksum suppressed (downrank cap={HASH_DOWNRANK_SCORE_CAP})"
        f.priority_reason = f"{reason}; {note}" if reason else note
        kept.append(f)
    return kept

"""Baseline / known-findings fingerprints (qscan-aligned).

A baseline records fingerprints of findings already triaged so CI / --fail-on
only fails on **new** findings.

Fingerprint (line-insensitive)::

    sha256_hex(rule_id + "|" + file + "|" + normalize_whitespace(snippet))

Line/column are excluded so line shifts do not resurface old findings.
Whitespace in the snippet is collapsed so reformatting does not either.
For merged findings, use the primary ``rule_id`` (first) + file + snippet.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

BASELINE_VERSION = 1

FINGERPRINT_SARIF_KEY = "pqc-inventory/v1"


def normalize_whitespace(snippet: str | None) -> str:
    """Collapse all whitespace runs to a single space and trim."""
    if not snippet:
        return ""
    return re.sub(r"\s+", " ", snippet).strip()


def fingerprint_finding(finding: Any) -> str:
    """Stable line-insensitive fingerprint (hex SHA-256)."""
    rule_id = getattr(finding, "rule_id", None) or ""
    file_path = getattr(finding, "file", None) or ""
    snippet = normalize_whitespace(getattr(finding, "snippet", None))
    payload = f"{rule_id}|{file_path}|{snippet}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def baseline_from_findings(findings: list[Any]) -> dict[str, Any]:
    """Build a versioned baseline: sorted unique fingerprints."""
    fps = sorted({fingerprint_finding(f) for f in findings})
    return {"version": BASELINE_VERSION, "fingerprints": fps}


def save_baseline(path: str | Path, findings: list[Any]) -> dict[str, Any]:
    """Write baseline JSON (pretty, trailing newline). Return the baseline."""
    baseline = baseline_from_findings(findings)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    return baseline


def load_baseline(path: str | Path) -> dict[str, Any]:
    """Load and validate a baseline file.

    Raises:
        FileNotFoundError: path missing
        ValueError: invalid JSON shape / unsupported version
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"baseline file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid baseline JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON object")
    if "version" not in data:
        raise ValueError("baseline missing required field: version")
    version = data["version"]
    if version != BASELINE_VERSION:
        raise ValueError(
            f"unsupported baseline version: {version} (expected {BASELINE_VERSION})"
        )
    fps = data.get("fingerprints")
    if not isinstance(fps, list):
        raise ValueError("baseline fingerprints must be a list")
    cleaned = [x for x in fps if isinstance(x, str)]
    return {"version": BASELINE_VERSION, "fingerprints": cleaned}


def apply_baseline(
    findings: list[Any],
    baseline: dict[str, Any],
) -> tuple[list[Any], list[Any]]:
    """Mark baseline matches; return (new_findings, suppressed).

    Sets ``baseline_suppressed`` on each finding. Does not change severity.
    Order within each group is preserved from the input.
    """
    accepted = set(baseline.get("fingerprints") or [])
    new_findings: list[Any] = []
    suppressed: list[Any] = []
    for f in findings:
        fp = fingerprint_finding(f)
        if fp in accepted:
            f.baseline_suppressed = True
            suppressed.append(f)
        else:
            f.baseline_suppressed = False
            new_findings.append(f)
    return new_findings, suppressed

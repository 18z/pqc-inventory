"""Explicit lifetime / exposure / owner overrides (never invent values).

Sources (highest precedence first):
1. CLI --set-lifetime / --set-exposure / --set-owner (line-specific, then file-wide)
2. --overrides JSON file (line-specific, then file-wide)
3. In-file annotations (line-pending, then file-level)

Unoverridden ``data_lifetime_years`` stays ``None``; exposure stays
auto-classified unless explicitly overridden. No guessed lifetimes or
sensitivity labels.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

VALID_EXPOSURES = {
    "trust_boundary",
    "public_key",
    "library_import",
    "symmetric",
    "hash_local",
    "other",
}

# Comment forms:
#   # pqc-inventory: lifetime=15 exposure=public_key owner=payments
#   // pqc-inventory: lifetime=10 exposure=trust_boundary
#   # pqc-inventory-file: lifetime=5 owner=default
_ANNOTATION_RE = re.compile(
    r"(?:#|//)\s*pqc-inventory(?P<file_level>-file)?:\s*(?P<body>.+)$"
)
_KV_RE = re.compile(
    r"(?P<key>lifetime|data_lifetime_years|years|exposure|owner)\s*=\s*"
    r"(?P<val>[^\s,]+)",
    re.IGNORECASE,
)


@dataclass
class OverrideSpec:
    """A single explicit override targeting a file (optional line)."""

    file: str
    line: int | None = None
    data_lifetime_years: int | float | None = None
    exposure: str | None = None
    owner: str | None = None
    source: str = "cli"

    def touches_lifetime(self) -> bool:
        return self.data_lifetime_years is not None

    def touches_exposure(self) -> bool:
        return self.exposure is not None

    def touches_owner(self) -> bool:
        return bool(self.owner)


@dataclass
class AnnotationState:
    """Per-file annotation cursor while scanning lines."""

    file_level: OverrideSpec | None = None
    pending: OverrideSpec | None = None


def parse_annotation_body(body: str) -> dict[str, Any]:
    """Parse ``key=value`` pairs from an annotation body."""
    out: dict[str, Any] = {}
    for m in _KV_RE.finditer(body.strip()):
        key = m.group("key").lower()
        val = m.group("val").strip().strip("\"'")
        if key in ("lifetime", "data_lifetime_years", "years"):
            try:
                num = float(val)
                out["data_lifetime_years"] = int(num) if num == int(num) else num
            except ValueError:
                continue
        elif key == "exposure":
            exp = val.lower()
            if exp in VALID_EXPOSURES:
                out["exposure"] = exp
        elif key == "owner":
            out["owner"] = val
    return out


def parse_annotation_line(line: str, file_rel: str, lineno: int) -> OverrideSpec | None:
    """Return an OverrideSpec if *line* is a pqc-inventory annotation."""
    m = _ANNOTATION_RE.search(line.rstrip())
    if not m:
        return None
    parsed = parse_annotation_body(m.group("body"))
    if not parsed:
        return None
    file_level = bool(m.group("file_level"))
    return OverrideSpec(
        file=file_rel,
        line=None if file_level else lineno,
        data_lifetime_years=parsed.get("data_lifetime_years"),
        exposure=parsed.get("exposure"),
        owner=parsed.get("owner"),
        source="annotation-file" if file_level else "annotation",
    )


def parse_cli_override(raw: str, *, field_name: str, source: str = "cli") -> OverrideSpec:
    """Parse ``FILE[:LINE]=VALUE`` for a single override field.

    Examples::
        python_app/crypto_demo.py:10=15
        js_app/crypto_demo.js=trust_boundary
    """
    if "=" not in raw:
        raise ValueError(f"override must look like FILE[:LINE]=VALUE, got {raw!r}")
    target, _, value = raw.partition("=")
    target = target.strip()
    value = value.strip()
    if not target or not value:
        raise ValueError(f"override must look like FILE[:LINE]=VALUE, got {raw!r}")

    line: int | None = None
    file_part = target
    if ":" in target:
        # Split on last colon only when the suffix is an int (line number).
        left, right = target.rsplit(":", 1)
        if right.isdigit():
            file_part = left
            line = int(right)

    spec = OverrideSpec(file=file_part, line=line, source=source)
    if field_name == "lifetime":
        num = float(value)
        spec.data_lifetime_years = int(num) if num == int(num) else num
    elif field_name == "exposure":
        exp = value.lower()
        if exp not in VALID_EXPOSURES:
            raise ValueError(
                f"unknown exposure {value!r}; expected one of {sorted(VALID_EXPOSURES)}"
            )
        spec.exposure = exp
    elif field_name == "owner":
        spec.owner = value
    else:
        raise ValueError(f"unknown override field {field_name!r}")
    return spec


def load_overrides_json(path: str | Path) -> list[OverrideSpec]:
    """Load overrides from a JSON file (no invented values)."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    items = data.get("overrides", data if isinstance(data, list) else [])
    specs: list[OverrideSpec] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        file_rel = item.get("file") or item.get("path") or ""
        if not file_rel:
            continue
        lifetime = item.get("data_lifetime_years", item.get("lifetime"))
        exposure = item.get("exposure")
        owner = item.get("owner") or ""
        if exposure is not None:
            exposure = str(exposure).lower()
            if exposure not in VALID_EXPOSURES:
                continue
        line = item.get("line")
        specs.append(
            OverrideSpec(
                file=str(file_rel),
                line=int(line) if line is not None else None,
                data_lifetime_years=lifetime,
                exposure=exposure,
                owner=str(owner) if owner else None,
                source="overrides-file",
            )
        )
    return specs


def _path_matches(finding_file: str, spec_file: str) -> bool:
    ff = finding_file.replace("\\", "/")
    sf = spec_file.replace("\\", "/")
    return ff == sf or ff.endswith("/" + sf) or ff.endswith(sf)


def _specificity(spec: OverrideSpec) -> tuple[int, int]:
    """Higher is more specific: line-targeted beats file-wide; source rank."""
    source_rank = {
        "cli": 3,
        "overrides-file": 2,
        "annotation": 1,
        "annotation-file": 0,
    }
    return (1 if spec.line is not None else 0, source_rank.get(spec.source, 0))


def collect_matching(
    specs: Iterable[OverrideSpec],
    finding_file: str,
    finding_line: int | None,
) -> list[OverrideSpec]:
    matched: list[OverrideSpec] = []
    for spec in specs:
        if not _path_matches(finding_file, spec.file):
            continue
        if spec.line is not None:
            if finding_line is None or spec.line != finding_line:
                continue
        matched.append(spec)
    return matched


def apply_overrides_to_finding(finding: Any, specs: list[OverrideSpec]) -> dict[str, str]:
    """Apply explicit overrides onto a Finding / MergedFinding.

    Returns a dict of field -> source for fields that were overridden.
    Does **not** invent lifetime/exposure when no matching override exists.
    """
    applied: dict[str, str] = {}
    matched = collect_matching(specs, finding.file, getattr(finding, "line", None))
    if not matched:
        # Ensure attribute exists for serializers
        if not hasattr(finding, "overrides_applied") or finding.overrides_applied is None:
            finding.overrides_applied = {}
        return applied

    # Sort ascending specificity so later writes win
    matched.sort(key=_specificity)

    for spec in matched:
        if spec.touches_lifetime():
            finding.data_lifetime_years = spec.data_lifetime_years
            applied["data_lifetime_years"] = spec.source
        if spec.touches_exposure():
            finding.exposure = spec.exposure  # type: ignore[assignment]
            applied["exposure"] = spec.source
        if spec.touches_owner():
            finding.owner = spec.owner or ""
            applied["owner"] = spec.source

    finding.overrides_applied = dict(applied)
    return applied


def merge_annotation_specs(
    file_rel: str,
    annotations_by_line: dict[int, OverrideSpec],
    file_level: OverrideSpec | None,
) -> list[OverrideSpec]:
    """Flatten per-file annotation maps into OverrideSpec list."""
    specs: list[OverrideSpec] = []
    if file_level is not None:
        specs.append(file_level)
    for lineno, spec in sorted(annotations_by_line.items()):
        # Pending annotations are stored keyed by the finding line they bind to
        specs.append(
            OverrideSpec(
                file=file_rel,
                line=lineno,
                data_lifetime_years=spec.data_lifetime_years,
                exposure=spec.exposure,
                owner=spec.owner,
                source=spec.source,
            )
        )
    return specs


# Public field names for the inventory summary (not invented values).
_SUMMARY_FIELD = {
    "data_lifetime_years": "lifetime",
    "exposure": "exposure",
    "owner": "owner",
}
_FIELD_ORDER = {"lifetime": 0, "exposure": 1, "owner": 2}


def summarize_overrides_applied(findings: Iterable[Any]) -> dict[str, Any]:
    """Build the top-level ``overrides_applied`` object from applied findings.

    Only fields that were actually written onto a finding are listed.
    ``count`` is the number of findings that received at least one override
    (0 when none). Sources are the real override sources, never guessed.
    """
    items: list[dict[str, Any]] = []
    sources: set[str] = set()
    for finding in findings:
        applied = getattr(finding, "overrides_applied", None) or {}
        if not applied:
            continue
        fields: list[str] = []
        item_sources: list[str] = []
        for field_key, src in applied.items():
            public = _SUMMARY_FIELD.get(str(field_key), str(field_key))
            if public not in fields:
                fields.append(public)
            src_s = str(src) if src else ""
            if src_s and src_s not in item_sources:
                item_sources.append(src_s)
            if src_s:
                sources.add(src_s)
        fields.sort(key=lambda name: (_FIELD_ORDER.get(name, 9), name))
        item_sources.sort()
        items.append(
            {
                "file": getattr(finding, "file", ""),
                "line": getattr(finding, "line", None),
                "fields": fields,
                "sources": item_sources,
            }
        )
    items.sort(key=lambda item: (item["file"], item["line"] if item["line"] is not None else -1))
    return {
        "count": len(items),
        "sources": sorted(sources),
        "items": items,
    }

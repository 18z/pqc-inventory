"""Denoise / merge overlapping findings so prioritized reports stay readable.

Same file+line (or same file + overlapping snippet within a family cluster)
that hit multiple rules are collapsed into one parent finding listing combined
rule ids / families. Optional children retain the raw hits.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

from pqc_inventory.rules import PRIORITY_BY_RISK, REASON_BY_RISK
from pqc_inventory.scanner import Finding

RISK_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _worse_risk(a: str, b: str) -> str:
    return a if RISK_RANK.get(a, 9) <= RISK_RANK.get(b, 9) else b


def _norm_snippet(s: str) -> str:
    return " ".join((s or "").split()).lower()


def _overlap_snippets(a: str, b: str) -> bool:
    """True if snippets share a substantial token prefix/substring."""
    na, nb = _norm_snippet(a), _norm_snippet(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    shorter, longer = (na, nb) if len(na) <= len(nb) else (nb, na)
    if len(shorter) >= 12 and shorter in longer:
        return True
    # token overlap (≥2 significant tokens)
    ta = {t for t in shorter.replace("(", " ").replace(")", " ").replace(",", " ").split() if len(t) > 2}
    tb = {t for t in longer.replace("(", " ").replace(")", " ").replace(",", " ").split() if len(t) > 2}
    if len(ta) >= 2 and len(ta & tb) >= 2:
        return True
    return False


def _family_related(a: str, b: str) -> bool:
    if a == b:
        return True
    # ECDSA vs ECDSA/ECDH, JWT vs JWT/JOSE, etc.
    parts_a = {p.lower() for p in a.replace("/", " ").split()}
    parts_b = {p.lower() for p in b.replace("/", " ").split()}
    return bool(parts_a & parts_b)


@dataclass
class MergedFinding:
    """Parent finding after denoise merge (keeps buyer-interview fields)."""

    rule_id: str
    family: str
    file: str
    line: int | None
    snippet: str
    quantum_risk: str
    priority: int
    reason: str
    description: str
    language: str
    owner: str = ""
    data_lifetime_years: int | float | None = None
    # Merge metadata
    rule_ids: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    descriptions: list[str] = field(default_factory=list)
    merged_count: int = 1
    children: list[dict] = field(default_factory=list)
    # Priority scoring (filled by priority.enrich)
    exposure: str = ""
    priority_score: int = 0
    priority_reason: str = ""
    overrides_applied: dict = field(default_factory=dict)
    suppressed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _cluster_key_same_line(f: Finding) -> tuple:
    return (f.file, f.line if f.line is not None else -1)


def _should_merge_pair(a: Finding, b: Finding) -> bool:
    if a.file != b.file:
        return False
    # Exact same line
    if a.line is not None and a.line == b.line:
        return True
    # Adjacent / near lines with overlapping snippet and related family
    if a.line is not None and b.line is not None and abs(a.line - b.line) <= 1:
        if _overlap_snippets(a.snippet, b.snippet) and _family_related(a.family, b.family):
            return True
    # Same file + identical normalized snippet (even if line differs slightly)
    if _norm_snippet(a.snippet) and _norm_snippet(a.snippet) == _norm_snippet(b.snippet):
        if a.line is not None and b.line is not None and abs(a.line - b.line) <= 2:
            return True
    return False


def _build_clusters(findings: list[Finding]) -> list[list[Finding]]:
    """Greedy clustering: merge if any member should merge with candidate."""
    if not findings:
        return []
    # Stable order by file, line, rule_id
    ordered = sorted(findings, key=lambda f: (f.file, f.line or 0, f.rule_id))
    clusters: list[list[Finding]] = []
    for f in ordered:
        placed = False
        for cluster in clusters:
            if any(_should_merge_pair(f, m) for m in cluster):
                cluster.append(f)
                placed = True
                break
        if not placed:
            clusters.append([f])
    return clusters


def _pick_primary(group: list[Finding]) -> Finding:
    return sorted(
        group,
        key=lambda f: (
            RISK_RANK.get(f.quantum_risk, 9),
            f.rule_id,
        ),
    )[0]


def merge_findings(findings: Iterable[Finding]) -> list[MergedFinding]:
    """Collapse duplicate/overlapping hits into merged parent findings."""
    groups = _build_clusters(list(findings))
    merged: list[MergedFinding] = []
    for group in groups:
        primary = _pick_primary(group)
        risk = primary.quantum_risk
        for g in group[1:]:
            risk = _worse_risk(risk, g.quantum_risk)
        rule_ids = sorted({g.rule_id for g in group})
        families = sorted({g.family for g in group})
        descriptions = sorted({g.description for g in group})
        # Prefer non-empty owner / lifetime from any child
        owner = next((g.owner for g in group if g.owner), primary.owner)
        lifetime = primary.data_lifetime_years
        for g in group:
            if g.data_lifetime_years is not None:
                lifetime = g.data_lifetime_years
                break
        children = [
            {
                "rule_id": g.rule_id,
                "family": g.family,
                "file": g.file,
                "line": g.line,
                "snippet": g.snippet,
                "quantum_risk": g.quantum_risk,
                "description": g.description,
            }
            for g in sorted(group, key=lambda x: x.rule_id)
            if len(group) > 1
        ]
        desc = primary.description
        if len(descriptions) > 1:
            desc = f"{primary.description} (+{len(descriptions) - 1} overlapping rules)"
        merged.append(
            MergedFinding(
                rule_id=primary.rule_id,
                family=primary.family,
                file=primary.file,
                line=primary.line,
                snippet=primary.snippet,
                quantum_risk=risk,
                priority=PRIORITY_BY_RISK[risk],
                reason=REASON_BY_RISK[risk],
                description=desc,
                language=primary.language,
                owner=owner,
                data_lifetime_years=lifetime,
                rule_ids=rule_ids,
                families=families,
                descriptions=descriptions,
                merged_count=len(group),
                children=children,
            )
        )
    return merged

"""Denoise / merge overlapping findings so prioritized reports stay readable.

Same file+line (or same file + overlapping snippet within a family cluster)
that hit multiple rules are collapsed into one parent finding listing combined
rule ids / families. Optional children retain the raw hits.
"""

from __future__ import annotations

import re

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


# Protocol-level TLS/SSL vs the cipher-suite algorithm on the same logical site.
# Window is tight so a nearby unrelated keygen is a different site and is kept.
TLS_SITE_LINE_WINDOW = 6
PROTOCOL_TLS_RULE_IDS = frozenset({"py-ssl", "js-tls"})


def _rule_ids(f) -> list[str]:
    ids = list(getattr(f, "rule_ids", None) or [])
    if not ids and getattr(f, "rule_id", None):
        ids = [f.rule_id]
    return [i for i in ids if i]


def _is_tls_algorithm_rule(rule_id: str) -> bool:
    return "tls-cipher" in (rule_id or "")


def is_protocol_only_tls_finding(f) -> bool:
    """True when the finding is only a protocol-level TLS/SSL label (no algorithm)."""
    ids = _rule_ids(f)
    if not ids or any(_is_tls_algorithm_rule(i) for i in ids):
        return False
    fams = set(getattr(f, "families", None) or [])
    fams.add(getattr(f, "family", "") or "")
    fams.discard("")
    if fams - {"TLS/SSL"}:
        return False
    if "TLS/SSL" not in fams and not any(i in PROTOCOL_TLS_RULE_IDS for i in ids):
        return False
    return all(i in PROTOCOL_TLS_RULE_IDS for i in ids)


def is_tls_site_algorithm(f) -> bool:
    """True when the finding is a cryptographic algorithm attached to a TLS site."""
    if is_protocol_only_tls_finding(f):
        return False
    ids = _rule_ids(f)
    if any(_is_tls_algorithm_rule(i) for i in ids):
        return True
    snippet = getattr(f, "snippet", "") or ""
    if re.search(
        r"(?i)\b(set_ciphers|ciphers\s*[:=]|sslcontext|wrap_socket|create_default_context|"
        r"tls\.(?:createserver|connect)|https\.(?:createserver|request))\b",
        snippet,
    ) and re.search(r"(?i)\b(rsa|ecdsa|ecdh|ecdhe|aes|chacha)\b", snippet):
        return True
    return False


def tls_protocol_algorithm_same_site(a, b) -> bool:
    """Protocol-only TLS and a TLS algorithm on the same file:line or nearby site.

    Genuinely different sites (other file, or farther than the site window,
    or an algorithm that is not TLS configuration) are not the same site.
    """
    if getattr(a, "file", None) != getattr(b, "file", None):
        return False
    if is_protocol_only_tls_finding(a) and is_tls_site_algorithm(b):
        proto, alg = a, b
    elif is_protocol_only_tls_finding(b) and is_tls_site_algorithm(a):
        proto, alg = b, a
    else:
        return False
    if proto.line is None or alg.line is None:
        return False
    return abs(int(proto.line) - int(alg.line)) <= TLS_SITE_LINE_WINDOW


def count_tls_double_labeled_sites(findings: Iterable) -> int:
    """How many protocol-only TLS findings still sit beside a TLS algorithm.

    Each remaining protocol finding that shares a logical site with a separate
    algorithm finding is one double-counted pair (duplicate priority credit).
    """
    items = list(findings)
    n = 0
    for p in items:
        if not is_protocol_only_tls_finding(p):
            continue
        if any(
            a is not p and tls_protocol_algorithm_same_site(p, a) for a in items
        ):
            n += 1
    return n


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
    baseline_suppressed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _cluster_key_same_line(f: Finding) -> tuple:
    return (f.file, f.line if f.line is not None else -1)


def _should_merge_pair(a: Finding, b: Finding) -> bool:
    if a.file != b.file:
        return False
    # Protocol-level TLS and the suite algorithm are one site (score once).
    if tls_protocol_algorithm_same_site(a, b):
        return True
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
    # Prefer the more specific algorithm over a protocol-only TLS duplicate.
    return sorted(
        group,
        key=lambda f: (
            1 if is_protocol_only_tls_finding(f) else 0,
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
        # Protocol-only TLS is a duplicate label, not a second risk credit,
        # when a more specific algorithm is already in the same site.
        has_algorithm = any(not is_protocol_only_tls_finding(g) for g in group)
        risk = primary.quantum_risk
        for g in group:
            if g is primary:
                continue
            if has_algorithm and is_protocol_only_tls_finding(g):
                continue
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
    return collapse_tls_protocol_duplicates(merged)


def collapse_tls_protocol_duplicates(findings: Iterable) -> list:
    """Drop or merge protocol-only TLS duplicates into the algorithm finding.

    Same file:line or same logical site (nearby TLS configuration) is scored
    once. A protocol finding with no algorithm on that site is kept. Different
    sites are kept as separate assets.
    """
    items = list(findings)
    if not items:
        return []

    alg_indexes = [i for i, f in enumerate(items) if is_tls_site_algorithm(f)]
    absorb_into: dict[int, list[int]] = {i: [] for i in alg_indexes}
    absorbed_proto: set[int] = set()

    for pi, proto in enumerate(items):
        if not is_protocol_only_tls_finding(proto):
            continue
        best: int | None = None
        best_dist = 10**9
        for ai in alg_indexes:
            alg = items[ai]
            if not tls_protocol_algorithm_same_site(proto, alg):
                continue
            dist = abs(int(proto.line or 0) - int(alg.line or 0))
            if dist < best_dist or (dist == best_dist and (best is None or ai < best)):
                best = ai
                best_dist = dist
        if best is not None:
            absorb_into[best].append(pi)
            absorbed_proto.add(pi)

    if not absorbed_proto:
        return items

    out: list = []
    consumed = set(absorbed_proto)
    for ai, f in enumerate(items):
        if ai in consumed:
            continue
        protos = absorb_into.get(ai) or []
        if not protos:
            out.append(f)
            continue
        group = [f] + [items[pi] for pi in protos]
        out.append(_merge_tls_group(group))
    return out


def _merge_tls_group(group: list) -> MergedFinding:
    """Keep the algorithm finding; fold protocol-only hits into rule_ids / merged_count."""
    primary = _pick_primary(group)
    has_algorithm = any(not is_protocol_only_tls_finding(g) for g in group)
    risk = primary.quantum_risk
    for g in group:
        if g is primary:
            continue
        if has_algorithm and is_protocol_only_tls_finding(g):
            continue
        risk = _worse_risk(risk, g.quantum_risk)

    rule_ids = sorted({rid for g in group for rid in _rule_ids(g)})
    families = sorted({fam for g in group for fam in (list(getattr(g, "families", None) or []) or [g.family]) if fam})
    if not families:
        families = [primary.family]
    descriptions = sorted({g.description for g in group if getattr(g, "description", "")})
    owner = next((g.owner for g in group if getattr(g, "owner", "")), getattr(primary, "owner", "") or "")
    lifetime = getattr(primary, "data_lifetime_years", None)
    for g in group:
        if getattr(g, "data_lifetime_years", None) is not None:
            lifetime = g.data_lifetime_years
            break
    children = []
    for g in sorted(group, key=lambda x: getattr(x, "rule_id", "")):
        children.append(
            {
                "rule_id": g.rule_id,
                "family": g.family,
                "file": g.file,
                "line": g.line,
                "snippet": g.snippet,
                "quantum_risk": g.quantum_risk,
                "description": g.description,
            }
        )
    desc = primary.description
    if len(descriptions) > 1:
        desc = f"{primary.description} (+{len(descriptions) - 1} overlapping rules)"
    overrides = {}
    for g in group:
        overrides.update(getattr(g, "overrides_applied", None) or {})
    return MergedFinding(
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
        merged_count=sum(int(getattr(g, "merged_count", 1) or 1) for g in group),
        children=children,
        overrides_applied=overrides,
        suppressed=any(getattr(g, "suppressed", False) for g in group),
    )

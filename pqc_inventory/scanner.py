"""Static directory scanner for crypto library / API usage."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from pqc_inventory.rules import (
    JS_RULES,
    MANIFEST_RULES,
    PYTHON_RULES,
    PRIORITY_BY_RISK,
    REASON_BY_RISK,
    Rule,
)

# Extensions / filenames we care about
PY_EXTS = {".py"}
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "Pipfile",
    "poetry.lock",
    "package-lock.json",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}


@dataclass
class Finding:
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
    # Buyer-interview fields (scanner leaves empty/unknown; optional sidecar later)
    owner: str = ""
    data_lifetime_years: int | float | None = None
    # Optional scoring fields (raw hits may leave defaults; merged findings fill them)
    exposure: str = ""
    priority_score: int = 0
    priority_reason: str = ""
    rule_ids: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    merged_count: int = 1
    children: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        if not d.get("rule_ids"):
            d["rule_ids"] = [self.rule_id]
        if not d.get("families"):
            d["families"] = [self.family]
        return d


@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)  # MergedFinding | Finding
    raw_findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    def counts_by_risk(self) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            risk = f.quantum_risk if hasattr(f, "quantum_risk") else f["quantum_risk"]
            counts[risk] = counts.get(risk, 0) + 1
        return counts

    def counts_by_family(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            fams = getattr(f, "families", None) or [getattr(f, "family", None)]
            for fam in fams:
                if not fam:
                    continue
                out[fam] = out.get(fam, 0) + 1
        return dict(sorted(out.items(), key=lambda x: (-x[1], x[0])))

    def prioritized(self) -> list:
        """Sort by priority_score descending; tie-break by risk, file, line."""
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}

        def key(f):
            score = getattr(f, "priority_score", 0) or 0
            risk = getattr(f, "quantum_risk", "info")
            return (-score, order.get(risk, 9), getattr(f, "file", ""), getattr(f, "line", 0) or 0)

        ranked = sorted(self.findings, key=key)
        for i, f in enumerate(ranked, start=1):
            f.priority = i  # display rank: 1 = most urgent
        return ranked


def _language_for(path: Path) -> str | None:
    name = path.name
    if name in MANIFEST_NAMES:
        return "manifest"
    ext = path.suffix.lower()
    if ext in PY_EXTS:
        return "python"
    if ext in JS_EXTS:
        return "javascript"
    return None


def _rules_for(language: str) -> list[Rule]:
    if language == "python":
        return PYTHON_RULES
    if language == "javascript":
        return JS_RULES
    if language == "manifest":
        return MANIFEST_RULES
    return []


def _iter_source_files(root: Path) -> Iterable[Path]:
    root = root.resolve()
    if root.is_file():
        if _language_for(root):
            yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if _language_for(path):
            yield path


def _match_line(rule: Rule, line: str) -> bool:
    return re.search(rule.pattern, line) is not None


def scan_file(path: Path, root: Path) -> list[Finding]:
    language = _language_for(path)
    if not language:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    findings: list[Finding] = []
    # Dedup: same rule_id + line once
    seen: set[tuple[str, int]] = set()

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith("#") and language == "python":
            if language == "python" and stripped.lstrip().startswith("#"):
                continue
        for rule in _rules_for(language):
            if not _match_line(rule, stripped):
                continue
            key = (rule.id, lineno)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    family=rule.family,
                    file=rel,
                    line=lineno,
                    snippet=stripped.strip()[:200],
                    quantum_risk=rule.risk,
                    priority=PRIORITY_BY_RISK[rule.risk],
                    reason=REASON_BY_RISK[rule.risk],
                    description=rule.description,
                    language=language,
                    rule_ids=[rule.id],
                    families=[rule.family],
                )
            )
    return findings


def scan_directory(target: str | Path, *, merge: bool = True) -> ScanResult:
    """Scan *target* path for crypto usage findings.

    By default, overlapping same-site hits are merged and priority-scored so
    the prioritized report is readable (not "everything priority 1").
    """
    from pqc_inventory.merge import merge_findings
    from pqc_inventory.priority import enrich_finding_priority

    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target not found: {root}")

    result = ScanResult(target=str(root))
    for path in _iter_source_files(root):
        result.files_scanned += 1
        result.raw_findings.extend(scan_file(path, root if root.is_dir() else root.parent))

    if merge:
        merged = merge_findings(result.raw_findings)
        for m in merged:
            enrich_finding_priority(m)
        result.findings = merged
    else:
        for f in result.raw_findings:
            enrich_finding_priority(f)
        result.findings = list(result.raw_findings)

    # Assign display ranks
    result.prioritized()
    return result

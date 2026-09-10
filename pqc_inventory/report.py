"""Generate inventory.json, report.md, cbom.cdx.json, and results.sarif."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pqc_inventory import __version__
from pqc_inventory.cbom import build_cbom
from pqc_inventory.sarif import build_sarif
from pqc_inventory.overrides import summarize_overrides_applied
from pqc_inventory.scanner import ScanResult

SCOPE_BANNER = (
    "**Scope:** This is a **static scan of source code and dependency manifests only**, "
    "**not runtime** (not network traffic, binaries, negotiated TLS, or a complete CBOM)."
)

PLANNING_REFS = """
## Planning references (not certification)

These are **planning references only**. This tool does **not** certify compliance with
EO 14412, CNSA 2.0, NIST IR 8547, or any other mandate.

| Reference | Note |
|-----------|------|
| EO 14412 CBOM minimum elements | CISA + NIST public guidance due ~270 days after 2026-06-22 (≈ 2027-03) |
| EO 14412 PQC key establishment | HVA / high-impact systems target **2030-12-31** |
| EO 14412 PQC digital signatures | HVA / high-impact systems target **2031-12-31** |
| NSA CNSA 2.0 | Migration planning reference |
| NIST IR 8547 | Transition planning reference |

CBOM `metadata.properties` repeats these under `pqc-inventory:ref:*` for downstream tooling.
""".strip()

NEXT_STEPS = """
## Plain-language next steps (for compliance / crypto owners)

1. **Triage by priority score (not raw HIGH count)** — Score blends quantum risk,
   data lifetime, and exposure (trust-boundary TLS/JWT vs local hash helper).
2. **Inventory & ownership** — Set `owner` / `data_lifetime_years` / `exposure` via
   in-file annotations or CLI overrides only (never guessed by the scanner);
   assets that must remain confidential/authentic for 10+ years need earlier PQC planning.
3. **Prefer hybrid / NIST PQC** — Track library support for ML-KEM (FIPS 203), ML-DSA (FIPS 204),
   and SLH-DSA (FIPS 205). Prefer vendor hybrids (classical + PQC) during transition.
4. **Symmetric & hashes** — AES-128 is weakened under Grover (~64-bit effective search);
   prefer AES-256 / ChaCha20. SHA-256+ / SHA-3 remain fine for integrity; avoid MD5/SHA-1.
5. **TLS** — Confirm cipher suites and CA/PKI roadmap; monitor OpenSSL / browser PQC pilots.
6. **This tool is defensive-only** — It does not migrate keys, break crypto, or suggest exploits.
   Use results as an inventory input for your crypto-agility program.
""".strip()


def build_inventory(result: ScanResult, baseline: dict | None = None) -> dict:
    prioritized = result.prioritized()
    # When --baseline is applied, primary list is new-only (qscan-aligned).
    baseline_applied = bool(baseline and "new_count" in baseline)
    if baseline_applied:
        prioritized = [
            f for f in prioritized if not getattr(f, "baseline_suppressed", False)
        ]

    raw_count = len(result.raw_findings) if result.raw_findings else len(result.findings)

    def _counts_by_risk(findings: list) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            risk = getattr(f, "quantum_risk", None) or "info"
            counts[risk] = counts.get(risk, 0) + 1
        return counts

    def _counts_by_family(findings: list) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in findings:
            fams = getattr(f, "families", None) or [getattr(f, "family", None)]
            for fam in fams:
                if not fam:
                    continue
                out[fam] = out.get(fam, 0) + 1
        return dict(sorted(out.items(), key=lambda x: (-x[1], x[0])))

    summary_findings = prioritized if baseline_applied else result.findings
    inv = {
        "tool": "pqc-inventory",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.target,
        "files_scanned": result.files_scanned,
        "summary": {
            "total_findings": len(summary_findings),
            "raw_findings_before_merge": raw_count,
            "by_risk": _counts_by_risk(summary_findings)
            if baseline_applied
            else result.counts_by_risk(),
            "by_family": _counts_by_family(summary_findings)
            if baseline_applied
            else result.counts_by_family(),
        },
        "findings": [f.to_dict() for f in prioritized],
        "overrides_applied": summarize_overrides_applied(result.findings),
        "scope": {
            "defensive_only": True,
            "analysis": (
                "static scan of source code and dependency manifests only, "
                "not runtime (not network traffic, binaries, negotiated TLS, or a complete CBOM)"
            ),
            "non_goals": [
                "No attack tools or exploits",
                "No key-breaking or cryptanalysis",
                "No automatic migration / re-encryption engine",
                "No guessed data lifetime or sensitivity (explicit overrides only)",
                "Static source code + dependency manifests only",
            ],
        },
        "priority_formula": {
            "score": "risk_points + lifetime_points + exposure_points",
            "risk_points": {"high": 100, "medium": 40, "low": 15, "info": 5},
            "lifetime_points": (
                "known: min(50, round(years*2)); null/unknown: 20 "
                "(conservative mid + unknown penalty)"
            ),
            "exposure_points": {
                "trust_boundary": 30,
                "public_key": 22,
                "library_import": 12,
                "symmetric": 6,
                "hash_local": 2,
                "other": 8,
            },
            "sort": "priority_score descending; priority field is display rank (1=most urgent)",
        },
    }
    if baseline:
        inv["baseline"] = baseline
    return inv


def render_markdown(inventory: dict) -> str:
    summary = inventory["summary"]
    by_risk = summary["by_risk"]
    raw = summary.get("raw_findings_before_merge", summary["total_findings"])
    lines: list[str] = [
        "# PQC Cryptographic Asset Inventory Report",
        "",
        f"> {SCOPE_BANNER}",
        "",
        f"- **Tool**: {inventory['tool']} v{inventory['version']}",
        f"- **Target**: `{inventory['target']}`",
        f"- **Generated (UTC)**: {inventory['generated_at']}",
        f"- **Files scanned**: {inventory['files_scanned']}",
        f"- **Findings (merged)**: {summary['total_findings']} "
        f"(raw hits before merge: {raw})",
        "",
    ]

    bl = inventory.get("baseline")
    if bl:
        lines += ["## Baseline", ""]
        if bl.get("written"):
            lines.append(
                f"- **Wrote baseline**: `{bl.get('path')}` "
                f"(version {bl.get('version')}, "
                f"{bl.get('fingerprint_count', 0)} fingerprint(s))"
            )
        if "new_count" in bl:
            lines += [
                f"- **Baseline file**: `{bl.get('path')}` (version {bl.get('version')})",
                f"- **Suppressed (known)**: {bl.get('suppressed_count', 0)}",
                f"- **New (not in baseline)**: {bl.get('new_count', 0)}",
                "",
                "_Primary prioritized list below shows **new** findings only._",
            ]
        lines += [""]

    lines += [
        "## Risk summary",
        "",
        "| Risk | Count |",
        "|------|------:|",
        f"| high | {by_risk.get('high', 0)} |",
        f"| medium | {by_risk.get('medium', 0)} |",
        f"| low | {by_risk.get('low', 0)} |",
        f"| info | {by_risk.get('info', 0)} |",
        "",
        "## Findings by algorithm / API family",
        "",
    ]
    families = summary.get("by_family") or {}
    if families:
        lines += ["| Family | Count |", "|--------|------:|"]
        for fam, cnt in families.items():
            lines.append(f"| {fam} | {cnt} |")
    else:
        lines.append("_No crypto findings._")
    lines += [
        "",
        "## Prioritized findings",
        "",
        "_Sorted by **priority_score** (quantum risk + data lifetime + exposure). "
        "Same-site multi-rule hits are merged so the top-N is readable._",
        "",
    ]

    findings = inventory.get("findings") or []
    if not findings:
        lines.append("_No findings._")
    else:
        for i, f in enumerate(findings, start=1):
            loc = f"`{f['file']}`"
            if f.get("line"):
                loc += f":{f['line']}"
            owner = f.get("owner")
            if owner is None:
                owner = ""
            lifetime = f.get("data_lifetime_years")
            lifetime_display = "unknown" if lifetime is None else lifetime
            rule_ids = f.get("rule_ids") or [f.get("rule_id")]
            families_list = f.get("families") or [f.get("family")]
            merged_n = f.get("merged_count", 1)
            score = f.get("priority_score", "")
            preason = f.get("priority_reason", "")
            exposure = f.get("exposure", "")
            overrides_applied = f.get("overrides_applied") or {}
            overrides_display = (
                ", ".join(f"{k}←{v}" for k, v in overrides_applied.items())
                if overrides_applied
                else "(none)"
            )
            suppressed_display = "yes" if f.get("suppressed") else "no"
            lines += [
                f"### {i}. [{f['quantum_risk'].upper()}] {f['family']} — {f['description']}",
                "",
                f"- **Location**: {loc}",
                f"- **Rules**: {', '.join(f'`{r}`' for r in rule_ids)}"
                + (f" _(merged {merged_n} hits)_" if merged_n and merged_n > 1 else ""),
                f"- **Families**: {', '.join(families_list)}",
                f"- **Priority rank**: {f.get('priority', i)}",
                f"- **Priority score**: {score}",
                f"- **Priority reason**: {preason}",
                f"- **Exposure**: {exposure}",
                f"- **Quantum risk**: {f['quantum_risk']}",
                f"- **Owner**: {owner}",
                f"- **Data lifetime (years)**: {lifetime_display}",
                f"- **Overrides applied**: {overrides_display}",
                f"- **Suppressed**: {suppressed_display}",
                f"- **Risk rationale**: {f['reason']}",
                f"- **Snippet**: `{f['snippet']}`",
                "",
            ]

    lines += ["", NEXT_STEPS, ""]
    lines += ["", PLANNING_REFS, ""]
    lines += [
        "## Quantum-risk legend",
        "",
        "- **high** — RSA, classical ECDSA/ECDH/EdDSA (long-term trust), finite-field DH",
        "- **medium** — Ambiguous TLS/crypto wrappers without clear PQC",
        "- **low** — AES/ChaCha (note Grover; prefer 256-bit keys)",
        "- **info** — SHA-2/3 integrity hashing",
        "",
        "## Scope reminder",
        "",
        SCOPE_BANNER,
        "",
        "This report is produced by a **defensive** static inventory scanner. "
        "It does **not** implement attacks, exploits, migration engines, or key-breaking.",
        "",
    ]
    return "\n".join(lines)


def write_outputs(
    result: ScanResult,
    out_dir: str | Path,
    *,
    baseline: dict | None = None,
) -> tuple[Path, Path, Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    inventory = build_inventory(result, baseline=baseline)
    json_path = out / "inventory.json"
    md_path = out / "report.md"
    cbom_path = out / "cbom.cdx.json"
    sarif_path = out / "results.sarif"

    json_path.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(inventory), encoding="utf-8")

    cbom = build_cbom(target=result.target, findings=result.prioritized())
    cbom_path.write_text(json.dumps(cbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    sarif = build_sarif(result)
    sarif_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return json_path, md_path, cbom_path, sarif_path

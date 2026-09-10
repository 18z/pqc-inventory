"""End-to-end scan of samples/vulnerable-app."""

from __future__ import annotations

import json
from pathlib import Path

from pqc_inventory.report import write_outputs
from pqc_inventory.scanner import scan_directory

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def test_e2e_sample_scan(tmp_path: Path):
    assert SAMPLE.is_dir(), f"missing sample at {SAMPLE}"
    result = scan_directory(SAMPLE)
    assert result.files_scanned >= 3
    assert len(result.findings) >= 5
    assert len(result.raw_findings) >= len(result.findings)

    risks = {f.quantum_risk for f in result.findings}
    assert "high" in risks, "expected high-risk RSA/EC findings in sample"

    families = set()
    for f in result.findings:
        families.update(getattr(f, "families", None) or [f.family])
    assert any("RSA" in fam or fam == "RSA" for fam in families)

    json_path, md_path, cbom_path, sarif_path = write_outputs(result, tmp_path / "out")
    assert json_path.is_file() and json_path.stat().st_size > 0
    assert md_path.is_file() and md_path.stat().st_size > 0
    assert cbom_path.is_file() and cbom_path.name == "cbom.cdx.json"
    assert sarif_path.is_file() and sarif_path.name == "results.sarif"

    inventory = json.loads(json_path.read_text(encoding="utf-8"))
    assert inventory["summary"]["total_findings"] == len(result.findings)
    assert inventory["scope"]["defensive_only"] is True
    assert "static scan" in inventory["scope"]["analysis"]
    assert "not runtime" in inventory["scope"]["analysis"]
    applied = inventory["overrides_applied"]
    assert applied["count"] == len(applied["items"])
    assert applied["count"] > 0
    assert isinstance(applied["sources"], list)
    assert "priority_formula" in inventory
    non_goals = " ".join(inventory["scope"]["non_goals"]).lower()
    assert "migration" in non_goals
    assert "lifetime" in non_goals or "guessed" in non_goals

    assert inventory["findings"], "expected at least one finding"
    # Some sample annotations set lifetime/owner; others stay empty/unknown
    assert any(f.get("data_lifetime_years") is not None for f in inventory["findings"])
    assert any(f.get("data_lifetime_years") is None for f in inventory["findings"])
    for finding in inventory["findings"]:
        assert "owner" in finding
        assert "data_lifetime_years" in finding
        assert "priority_score" in finding
        assert "priority_reason" in finding
        assert "exposure" in finding
        assert "rule_ids" in finding
        assert "overrides_applied" in finding
        assert "suppressed" in finding

    # Scores should differentiate ranking (not flat priority=1 for all HIGH)
    scores = [f["priority_score"] for f in inventory["findings"]]
    # Sort order in inventory is prioritized(); suppressed sort last
    non_sup = [f for f in inventory["findings"] if not f.get("suppressed")]
    non_scores = [f["priority_score"] for f in non_sup]
    assert non_scores == sorted(non_scores, reverse=True)

    md = md_path.read_text(encoding="utf-8")
    assert "Prioritized findings" in md
    assert "high" in md.lower()
    assert "**Owner**:" in md
    assert "Data lifetime (years)" in md
    assert "Overrides applied" in md
    assert "Priority score" in md
    assert "Priority reason" in md
    assert "static scan of source code and dependency manifests only" in md
    # Banner sits immediately after the title and says this is not runtime.
    assert md.startswith("# PQC Cryptographic Asset Inventory Report\n\n> ")
    assert "**not runtime**" in md
    assert "negotiated TLS" in md
    assert "complete CBOM" in md
    # No duplicate scope tail (regression for 2026-09-09 banner cleanup)
    assert md.count("static scan of source code and dependency manifests only") == 2  # header + scope reminder
    assert "static analysis of source code + dependency manifests only —" not in md
    assert "Planning references (not certification)" in md
    assert "does **not** certify compliance" in md

    analysis = inventory["scope"]["analysis"]
    assert analysis.count("static") == 1
    assert "complete coverage guarantee" not in analysis

    cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert isinstance(cbom["components"], list)
    assert cbom["components"], "expected at least one crypto component"
    assert cbom["components"][0]["type"] == "cryptographic-asset"
    assert "cryptoProperties" in cbom["components"][0]
    props = {p["name"]: p["value"] for p in cbom["metadata"]["properties"]}
    assert "pqc-inventory:scope" in props
    assert "pqc-inventory:compliance-note" in props
    assert "does not certify" in props["pqc-inventory:compliance-note"]
    for key in (
        "pqc-inventory:ref:eo-14412-cbom-min-elements",
        "pqc-inventory:ref:eo-14412-pqc-key-est",
        "pqc-inventory:ref:eo-14412-pqc-signatures",
        "pqc-inventory:ref:cnsa-2.0",
        "pqc-inventory:ref:nist-ir-8547",
    ):
        assert key in props, key

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "pqc-inventory"
    sarif_results = run["results"]
    active = [f for f in result.findings if not getattr(f, "suppressed", False)]
    assert len(sarif_results) == len(active)
    # Suppressed findings must not appear as SARIF alerts
    for f in result.findings:
        if not getattr(f, "suppressed", False):
            continue
        sline = f.line if f.line is not None else 1
        leaked = [
            r
            for r in sarif_results
            if r["ruleId"] == f.rule_id
            and r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == f.file
            and r["locations"][0]["physicalLocation"]["region"]["startLine"] == sline
        ]
        assert not leaked, f"suppressed finding leaked into SARIF: {f.rule_id} {f.file}:{sline}"

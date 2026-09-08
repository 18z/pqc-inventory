"""End-to-end scan of samples/vulnerable-app."""

from __future__ import annotations

import json
from pathlib import Path

from pqc_inventory.report import SCOPE_BANNER, write_outputs
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

    json_path, md_path, cbom_path = write_outputs(result, tmp_path / "out")
    assert json_path.is_file() and json_path.stat().st_size > 0
    assert md_path.is_file() and md_path.stat().st_size > 0
    assert cbom_path.is_file() and cbom_path.name == "cbom.cdx.json"

    inventory = json.loads(json_path.read_text(encoding="utf-8"))
    assert inventory["summary"]["total_findings"] == len(result.findings)
    assert inventory["scope"]["defensive_only"] is True
    assert "static analysis" in inventory["scope"]["analysis"]
    assert "priority_formula" in inventory

    assert inventory["findings"], "expected at least one finding"
    for finding in inventory["findings"]:
        assert "owner" in finding
        assert finding["owner"] == ""
        assert "data_lifetime_years" in finding
        assert finding["data_lifetime_years"] is None
        assert "priority_score" in finding
        assert "priority_reason" in finding
        assert "exposure" in finding
        assert "rule_ids" in finding

    # Scores should differentiate ranking (not flat priority=1 for all HIGH)
    scores = [f["priority_score"] for f in inventory["findings"]]
    assert scores == sorted(scores, reverse=True)

    md = md_path.read_text(encoding="utf-8")
    assert "Prioritized findings" in md
    assert "high" in md.lower()
    assert "**Owner**:" in md
    assert "**Data lifetime (years)**: unknown" in md
    assert "Priority score" in md
    assert "Priority reason" in md
    assert "static analysis of source code" in md
    assert SCOPE_BANNER.split("—")[0].strip("* ") in md or "static analysis" in md

    cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert isinstance(cbom["components"], list)
    assert cbom["components"], "expected at least one crypto component"
    assert cbom["components"][0]["type"] == "cryptographic-asset"
    assert "cryptoProperties" in cbom["components"][0]

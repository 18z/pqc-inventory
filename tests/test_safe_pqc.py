"""SAFE / NIST PQC positive detections: inventory yes, SARIF/fail-on no."""

from __future__ import annotations

import json
from pathlib import Path

from pqc_inventory.cli import evaluate_fail
from pqc_inventory.priority import RISK_POINTS, classify_exposure, compute_priority_score
from pqc_inventory.report import write_outputs
from pqc_inventory.sarif import build_sarif
from pqc_inventory.scanner import Finding, ScanResult, scan_directory

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def _safe_finding(**kwargs) -> Finding:
    base = dict(
        rule_id="py-ml-kem",
        family="ML-KEM",
        file="pqc_migrated.py",
        line=8,
        snippet='ML_KEM_768 = "ML-KEM-768"',
        quantum_risk="safe",
        priority=5,
        reason="Already-migrated / NIST PQC",
        description="NIST ML-KEM",
        language="python",
        exposure="pqc_migrated",
        priority_score=22,
        priority_reason="score=22",
        rule_ids=["py-ml-kem"],
        families=["ML-KEM"],
        suppressed=False,
    )
    base.update(kwargs)
    return Finding(**base)


def test_rules_detect_pqc_in_sample():
    result = scan_directory(SAMPLE)
    safe = [f for f in result.findings if f.quantum_risk == "safe"]
    assert safe, "expected at least one SAFE / NIST PQC finding in sample"
    families = set()
    for f in safe:
        families.update(getattr(f, "families", None) or [f.family])
    assert families & {"ML-KEM", "ML-DSA", "SLH-DSA", "PQC"}


def test_sarif_excludes_safe():
    high = Finding(
        rule_id="py-rsa",
        family="RSA",
        file="a.py",
        line=1,
        snippet="rsa.generate_private_key()",
        quantum_risk="high",
        priority=1,
        reason="RSA",
        description="RSA",
        language="python",
        exposure="public_key",
        priority_score=142,
        rule_ids=["py-rsa"],
        families=["RSA"],
    )
    safe = _safe_finding()
    doc = build_sarif(ScanResult(target="/tmp", findings=[high, safe], files_scanned=1))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "py-rsa"
    assert all(r["ruleId"] != "py-ml-kem" for r in results)


def test_fail_on_ignores_safe():
    ok, _ = evaluate_fail([_safe_finding()], fail_on="high")
    assert ok is False
    ok, _ = evaluate_fail([_safe_finding()], fail_on="info")
    assert ok is False
    ok, _ = evaluate_fail([_safe_finding()], fail_on="low")
    assert ok is False


def test_safe_risk_points_and_exposure():
    assert RISK_POINTS["safe"] == 0
    assert classify_exposure("ML-KEM") == "pqc_migrated"
    assert classify_exposure("ML-DSA") == "pqc_migrated"
    assert classify_exposure("SLH-DSA") == "pqc_migrated"
    assert classify_exposure("PQC") == "pqc_migrated"
    score, _ = compute_priority_score("safe", None, "pqc_migrated")
    # risk 0 + unknown lifetime 20 + exposure 2
    assert score == 22


def test_report_and_cbom_still_list_safe(tmp_path: Path):
    result = scan_directory(SAMPLE)
    json_path, md_path, cbom_path, sarif_path = write_outputs(result, tmp_path / "out")
    inv = json.loads(json_path.read_text(encoding="utf-8"))
    safe_inv = [f for f in inv["findings"] if f["quantum_risk"] == "safe"]
    assert safe_inv, "SAFE findings must remain in inventory.json"
    md = md_path.read_text(encoding="utf-8")
    assert "SAFE" in md or "safe" in md
    cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
    names = {c["name"] for c in cbom["components"]}
    assert names & {"ML-KEM", "ML-DSA", "SLH-DSA", "PQC"}
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    for r in sarif["runs"][0]["results"]:
        # no SAFE-level alerts
        props = r.get("properties") or {}
        # rule ids for PQC safe should not appear as results
        assert not r["ruleId"].endswith("ml-kem") or props.get("family") != "ML-KEM"
    safe_rule_ids = {f.rule_id for f in result.findings if f.quantum_risk == "safe"}
    sarif_rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert not (safe_rule_ids & sarif_rule_ids), (
        f"SAFE rules leaked into SARIF: {safe_rule_ids & sarif_rule_ids}"
    )


def test_e2e_sarif_count_excludes_safe(tmp_path: Path):
    result = scan_directory(SAMPLE)
    _, _, _, sarif_path = write_outputs(result, tmp_path / "out")
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    active_alerts = [
        f
        for f in result.findings
        if not getattr(f, "suppressed", False) and f.quantum_risk != "safe"
    ]
    assert len(sarif["runs"][0]["results"]) == len(active_alerts)

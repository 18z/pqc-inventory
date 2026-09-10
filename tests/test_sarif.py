"""SARIF 2.1.0 emission for GitHub code scanning."""

from __future__ import annotations

import json
from pathlib import Path

from pqc_inventory import __version__
from pqc_inventory.report import write_outputs
from pqc_inventory.sarif import build_sarif
from pqc_inventory.scanner import Finding, ScanResult, scan_directory

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def _finding(**kwargs) -> Finding:
    base = dict(
        rule_id="py-rsa",
        family="RSA",
        file="app.py",
        line=10,
        snippet="rsa.generate_private_key()",
        quantum_risk="high",
        priority=1,
        reason="RSA is quantum-vulnerable",
        description="RSA key generation",
        language="python",
        exposure="public_key",
        priority_score=142,
        priority_reason="score=142",
        rule_ids=["py-rsa"],
        families=["RSA"],
        owner="payments",
        data_lifetime_years=15,
        suppressed=False,
    )
    base.update(kwargs)
    return Finding(**base)


def test_build_sarif_schema_and_levels():
    high = _finding()
    med = _finding(
        rule_id="py-tls",
        family="TLS/SSL",
        line=20,
        quantum_risk="medium",
        description="TLS usage",
        rule_ids=["py-tls"],
        families=["TLS/SSL"],
        priority_score=80,
        data_lifetime_years=None,
        owner="",
    )
    low = _finding(
        rule_id="py-aes",
        family="AES",
        line=30,
        quantum_risk="low",
        description="AES",
        rule_ids=["py-aes"],
        families=["AES"],
        priority_score=40,
        data_lifetime_years=None,
        owner="",
    )
    info = _finding(
        rule_id="py-hashlib",
        family="SHA/Hash",
        line=40,
        quantum_risk="info",
        description="hashlib",
        rule_ids=["py-hashlib"],
        families=["SHA/Hash"],
        priority_score=10,
        data_lifetime_years=None,
        owner="",
        exposure="hash_local",
    )
    result = ScanResult(target="/tmp/x", findings=[high, med, low, info], files_scanned=1)
    doc = build_sarif(result)
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "pqc-inventory"
    assert driver["version"] == __version__
    assert "static" in driver["properties"]["note"].lower()
    assert "does not certify" in driver["properties"]["note"].lower()
    assert len(run["results"]) == 4
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["py-rsa"] == "error"
    assert levels["py-tls"] == "warning"
    assert levels["py-aes"] == "note"
    assert levels["py-hashlib"] == "note"
    rsa = next(r for r in run["results"] if r["ruleId"] == "py-rsa")
    assert rsa["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert rsa["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert rsa["partialFingerprints"]["pqcInventory/v1"] == "app.py|10|py-rsa"
    assert rsa["properties"]["priority_score"] == 142
    assert rsa["properties"]["family"] == "RSA"
    assert rsa["properties"]["exposure"] == "public_key"
    assert rsa["properties"]["owner"] == "payments"
    assert rsa["properties"]["data_lifetime_years"] == 15
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids >= {"py-rsa", "py-tls", "py-aes", "py-hashlib"}


def test_suppressed_excluded_from_sarif_results():
    active = _finding()
    suppressed = _finding(
        rule_id="py-hashlib",
        family="SHA/Hash",
        line=99,
        quantum_risk="info",
        description="hash",
        rule_ids=["py-hashlib"],
        families=["SHA/Hash"],
        suppressed=True,
        priority_score=5,
        owner="",
        data_lifetime_years=None,
        exposure="hash_local",
    )
    result = ScanResult(
        target="/tmp/x", findings=[active, suppressed], files_scanned=1
    )
    doc = build_sarif(result)
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "py-rsa"
    assert all(r["ruleId"] != "py-hashlib" for r in results)


def test_none_line_defaults_to_one():
    f = _finding(line=None)
    result = ScanResult(target="/tmp/x", findings=[f], files_scanned=1)
    doc = build_sarif(result)
    r = doc["runs"][0]["results"][0]
    assert r["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert r["partialFingerprints"]["pqcInventory/v1"] == "app.py|1|py-rsa"


def test_merged_rule_ids_appear_in_driver_rules():
    f = _finding(
        rule_id="py-rsa",
        rule_ids=["py-rsa", "py-cryptography-rsa"],
        merged_count=2,
    )
    result = ScanResult(target="/tmp/x", findings=[f], files_scanned=1)
    doc = build_sarif(result)
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "py-rsa" in rule_ids
    assert "py-cryptography-rsa" in rule_ids
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["merged_rule_ids"] == ["py-rsa", "py-cryptography-rsa"]


def test_write_outputs_emits_results_sarif(tmp_path: Path):
    result = scan_directory(SAMPLE)
    paths = write_outputs(result, tmp_path / "out")
    assert len(paths) == 4
    json_path, md_path, cbom_path, sarif_path = paths
    assert sarif_path.name == "results.sarif"
    assert sarif_path.is_file()
    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    active = [f for f in result.findings if not getattr(f, "suppressed", False)]
    assert len(doc["runs"][0]["results"]) == len(active)

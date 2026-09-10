"""Baseline / known-findings fingerprints (qscan-aligned)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pqc_inventory.baseline import (
    BASELINE_VERSION,
    FINGERPRINT_SARIF_KEY,
    apply_baseline,
    baseline_from_findings,
    fingerprint_finding,
    load_baseline,
    normalize_whitespace,
    save_baseline,
)
from pqc_inventory.cli import main
from pqc_inventory.sarif import build_sarif
from pqc_inventory.scanner import Finding, ScanResult

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def _f(
    *,
    rule_id: str = "py-rsa",
    file: str = "app.py",
    line: int | None = 10,
    snippet: str = "rsa.generate_private_key()",
    risk: str = "high",
    score: int = 150,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        family="RSA",
        file=file,
        line=line,
        snippet=snippet,
        quantum_risk=risk,
        priority=1,
        reason="t",
        description="t",
        language="python",
        priority_score=score,
    )


def test_normalize_whitespace():
    assert normalize_whitespace("  foo   bar\t\nbaz  ") == "foo bar baz"
    assert normalize_whitespace(None) == ""
    assert normalize_whitespace("") == ""


def test_fingerprint_line_insensitive_and_whitespace():
    a = _f(line=10, snippet="rsa.generate_private_key()")
    b = _f(line=99, snippet="rsa.generate_private_key()")
    d = _f(line=50, snippet="rsa.generate_private_key()")
    e = _f(line=1, snippet="rsa.generate_private_key()\n")
    f = _f(line=2, snippet="  rsa.generate_private_key()  ")
    assert fingerprint_finding(a) == fingerprint_finding(b)
    assert fingerprint_finding(d) == fingerprint_finding(e) == fingerprint_finding(f)
    payload = "py-rsa|app.py|rsa.generate_private_key()"
    assert fingerprint_finding(a) == hashlib.sha256(payload.encode()).hexdigest()
    assert fingerprint_finding(a) != fingerprint_finding(_f(rule_id="py-ecdsa"))
    assert fingerprint_finding(a) != fingerprint_finding(_f(file="other.py"))


def test_fingerprint_whitespace_collapse_internal():
    a = _f(snippet="import   rsa")
    b = _f(snippet="import rsa")
    assert fingerprint_finding(a) == fingerprint_finding(b)


def test_baseline_from_findings_sorted_unique():
    findings = [_f(line=1), _f(line=2), _f(rule_id="py-aes", snippet="AES.new()")]
    bl = baseline_from_findings(findings)
    assert bl["version"] == BASELINE_VERSION
    assert bl["fingerprints"] == sorted(set(bl["fingerprints"]))
    assert len(bl["fingerprints"]) == 2


def test_save_load_roundtrip(tmp_path: Path):
    path = tmp_path / "baseline.json"
    findings = [_f(), _f(rule_id="py-aes", snippet="AES.new()")]
    save_baseline(path, findings)
    loaded = load_baseline(path)
    assert loaded["version"] == 1
    assert loaded["fingerprints"] == baseline_from_findings(findings)["fingerprints"]


def test_load_missing_raises(tmp_path: Path):
    try:
        load_baseline(tmp_path / "nope.json")
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_load_bad_version(tmp_path: Path):
    path = tmp_path / "bl.json"
    path.write_text(json.dumps({"version": 99, "fingerprints": []}), encoding="utf-8")
    try:
        load_baseline(path)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "unsupported baseline version" in str(exc)


def test_apply_baseline_marks_and_splits():
    known = _f(snippet="known()")
    novel = _f(rule_id="py-aes", snippet="AES.new()")
    bl = baseline_from_findings([known])
    new, suppressed = apply_baseline([known, novel], bl)
    assert len(suppressed) == 1 and suppressed[0].baseline_suppressed is True
    assert len(new) == 1 and new[0].baseline_suppressed is False
    assert new[0].rule_id == "py-aes"


def test_cli_write_then_baseline_fail_on(tmp_path: Path):
    out1 = tmp_path / "out1"
    bl_path = tmp_path / "baseline.json"
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(out1),
            "--write-baseline",
            str(bl_path),
            "--fail-on",
            "never",
            "--hash-policy",
            "drop",
        ]
    )
    assert rc == 0
    assert bl_path.is_file()
    data = json.loads(bl_path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert data["fingerprints"] == sorted(set(data["fingerprints"]))
    assert len(data["fingerprints"]) >= 1

    out2 = tmp_path / "out2"
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(out2),
            "--fail-on",
            "high",
            "--hash-policy",
            "drop",
        ]
    )
    assert rc == 1

    out3 = tmp_path / "out3"
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(out3),
            "--baseline",
            str(bl_path),
            "--fail-on",
            "high",
            "--hash-policy",
            "drop",
        ]
    )
    assert rc == 0
    inv = json.loads((out3 / "inventory.json").read_text(encoding="utf-8"))
    assert "baseline" in inv
    assert inv["baseline"]["suppressed_count"] >= 1
    assert inv["baseline"]["new_count"] == 0
    assert inv["summary"]["total_findings"] == 0
    assert inv["findings"] == []
    md = (out3 / "report.md").read_text(encoding="utf-8")
    assert "Suppressed (known)" in md
    assert "New (not in baseline)" in md


def test_cli_missing_baseline_exits_2(tmp_path: Path):
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(tmp_path / "out"),
            "--baseline",
            str(tmp_path / "missing.json"),
            "--fail-on",
            "never",
        ]
    )
    assert rc == 2


def test_cli_bad_baseline_version_exits_2(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": 7, "fingerprints": []}), encoding="utf-8")
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(tmp_path / "out"),
            "--baseline",
            str(bad),
            "--fail-on",
            "never",
        ]
    )
    assert rc == 2


def test_sarif_uses_baseline_fingerprint():
    f = _f()
    result = ScanResult(target="/tmp/x", findings=[f], files_scanned=1)
    doc = build_sarif(result)
    r = doc["runs"][0]["results"][0]
    assert FINGERPRINT_SARIF_KEY in r["partialFingerprints"]
    assert r["partialFingerprints"][FINGERPRINT_SARIF_KEY] == fingerprint_finding(f)
    assert "pqcInventory/v1" not in r["partialFingerprints"]


def test_sarif_omits_baseline_suppressed():
    known = _f()
    known.baseline_suppressed = True
    novel = _f(rule_id="py-aes", snippet="AES.new()", risk="low", score=40)
    result = ScanResult(target="/tmp/x", findings=[known, novel], files_scanned=1)
    doc = build_sarif(result)
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "py-aes"


def test_inventory_notes_written_baseline(tmp_path: Path):
    out = tmp_path / "out"
    bl = tmp_path / "bl.json"
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(out),
            "--write-baseline",
            str(bl),
            "--fail-on",
            "never",
            "--hash-policy",
            "drop",
        ]
    )
    assert rc == 0
    inv = json.loads((out / "inventory.json").read_text(encoding="utf-8"))
    assert inv["baseline"]["written"] is True
    assert inv["baseline"]["fingerprint_count"] >= 1

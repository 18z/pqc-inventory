"""Readiness score + CI step summary."""

from __future__ import annotations

from pathlib import Path

from pqc_inventory.readiness import compute_readiness
from pqc_inventory.report import build_inventory, render_step_summary, write_outputs
from pqc_inventory.scanner import Finding, ScanResult


def _finding(risk: str, family: str = "RSA", file: str = "a.py", line: int = 1) -> Finding:
    return Finding(
        rule_id=f"test.{family.lower()}",
        family=family,
        file=file,
        line=line,
        snippet="x = 1",
        quantum_risk=risk,
        priority=1,
        reason=f"{risk} risk",
        description=f"{family} {risk}",
        language="python",
    )


def test_empty_inventory_score_100_with_caveat():
    score, note = compute_readiness([])
    assert score == 100
    assert "not" in note.lower()
    assert "migrated" in note.lower() or "certified" in note.lower() or "detect" in note.lower()


def test_all_high_score_zero():
    findings = [_finding("high"), _finding("high", file="b.py")]
    score, _ = compute_readiness(findings)
    assert score == 0


def test_all_safe_score_100():
    findings = [
        _finding("safe", family="ML-KEM"),
        _finding("safe", family="ML-DSA", file="b.py"),
    ]
    score, _ = compute_readiness(findings)
    assert score == 100


def test_mixed_mean_and_soft_boost():
    findings = [_finding("high"), _finding("safe", family="ML-KEM", file="b.py")]
    score, note = compute_readiness(findings)
    assert score == 55
    assert "static" in note.lower() or "certif" in note.lower()


def test_inventory_includes_readiness_and_step_summary(tmp_path: Path):
    result = ScanResult(
        target=str(tmp_path),
        findings=[_finding("high"), _finding("safe", family="ML-KEM", file="b.py")],
        raw_findings=[],
        files_scanned=2,
    )
    inv = build_inventory(result)
    assert inv["readiness_score"] == 55
    assert "readiness_note" in inv

    out = tmp_path / "out"
    write_outputs(result, out)
    assert (out / "inventory.json").is_file()
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "Readiness score" in md
    assert "| safe |" in md

    step = render_step_summary(inv)
    assert "55" in step
    assert "high" in step
    assert "safe" in step


def test_write_step_summary_env(tmp_path: Path, monkeypatch):
    result = ScanResult(
        target=str(tmp_path),
        findings=[_finding("medium")],
        raw_findings=[],
        files_scanned=1,
    )
    summary_path = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    write_outputs(result, tmp_path / "out")
    body = summary_path.read_text(encoding="utf-8")
    assert "pqc-inventory" in body
    assert "Readiness" in body or "readiness" in body.lower()

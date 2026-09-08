"""Cut C: exit codes for --fail-on / --fail-score."""

from __future__ import annotations

from pathlib import Path

from pqc_inventory.cli import evaluate_fail, main
from pqc_inventory.scanner import Finding

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def _f(risk: str, score: int, suppressed: bool = False) -> Finding:
    return Finding(
        rule_id="t",
        family="RSA" if risk == "high" else "AES",
        file="x.py",
        line=1,
        snippet="x",
        quantum_risk=risk,
        priority=1,
        reason="t",
        description="t",
        language="python",
        priority_score=score,
        suppressed=suppressed,
    )


def test_evaluate_fail_on_high():
    ok, _ = evaluate_fail([_f("info", 10)], fail_on="high")
    assert ok is False
    bad, reason = evaluate_fail([_f("high", 150)], fail_on="high")
    assert bad is True
    assert "fail-on high" in reason


def test_evaluate_fail_ignores_suppressed():
    ok, _ = evaluate_fail([_f("high", 150, suppressed=True)], fail_on="high")
    assert ok is False


def test_evaluate_fail_score():
    ok, _ = evaluate_fail([_f("high", 100)], fail_score=140)
    assert ok is False
    bad, reason = evaluate_fail([_f("high", 150)], fail_score=140)
    assert bad is True
    assert "fail-score" in reason


def test_cli_fail_on_high_exits_1(tmp_path: Path):
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(tmp_path / "out"),
            "--fail-on",
            "high",
            "--hash-policy",
            "drop",
        ]
    )
    assert rc == 1


def test_cli_fail_on_never_exits_0(tmp_path: Path):
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(tmp_path / "out"),
            "--fail-on",
            "never",
            "--hash-policy",
            "drop",
        ]
    )
    assert rc == 0


def test_cli_missing_path_exits_2(tmp_path: Path):
    rc = main(
        [
            "scan",
            str(tmp_path / "missing-dir"),
            "--out",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 2

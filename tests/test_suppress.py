"""Cut A: hash / checksum suppression."""

from __future__ import annotations

from pathlib import Path

from pqc_inventory.scanner import Finding, scan_directory
from pqc_inventory.suppress import HASH_DOWNRANK_SCORE_CAP, apply_hash_suppression, is_hash_noise

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def _hash_finding() -> Finding:
    return Finding(
        rule_id="py-hashlib",
        family="SHA/Hash",
        file="a.py",
        line=1,
        snippet="hashlib.sha256(b'x')",
        quantum_risk="info",
        priority=4,
        reason="hash",
        description="hashlib",
        language="python",
        exposure="hash_local",
        priority_score=27,
        priority_reason="score=27",
        rule_ids=["py-hashlib"],
        families=["SHA/Hash"],
    )


def test_is_hash_noise():
    assert is_hash_noise(_hash_finding())


def test_downrank_caps_score():
    f = _hash_finding()
    out = apply_hash_suppression([f], policy="downrank")
    assert len(out) == 1
    assert out[0].suppressed is True
    assert out[0].priority_score <= HASH_DOWNRANK_SCORE_CAP
    assert "suppressed" in out[0].priority_reason


def test_drop_removes_hash():
    f = _hash_finding()
    rsa = Finding(
        rule_id="py-rsa",
        family="RSA",
        file="a.py",
        line=2,
        snippet="rsa.generate_private_key()",
        quantum_risk="high",
        priority=1,
        reason="rsa",
        description="rsa",
        language="python",
        exposure="public_key",
        priority_score=142,
        rule_ids=["py-rsa"],
        families=["RSA"],
    )
    out = apply_hash_suppression([f, rsa], policy="drop")
    assert len(out) == 1
    assert out[0].family == "RSA"


def test_sample_hash_policy_drop():
    kept = scan_directory(SAMPLE, hash_policy="keep")
    dropped = scan_directory(SAMPLE, hash_policy="drop")
    assert len(dropped.findings) < len(kept.findings)
    assert not any(
        getattr(f, "exposure", "") == "hash_local" for f in dropped.findings
    )


def test_sample_hash_policy_downrank_sorts_low():
    result = scan_directory(SAMPLE, hash_policy="downrank")
    ranked = result.prioritized()
    suppressed = [f for f in ranked if f.suppressed]
    if suppressed:
        # suppressed should not occupy the top rank when non-suppressed exist
        non = [f for f in ranked if not f.suppressed]
        if non:
            assert ranked[0].suppressed is False

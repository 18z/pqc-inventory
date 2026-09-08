"""Tests for finding merge/denoise and lifetime/exposure priority scoring."""

from __future__ import annotations

from pathlib import Path

from pqc_inventory.merge import merge_findings
from pqc_inventory.priority import (
    UNKNOWN_LIFETIME_POINTS,
    classify_exposure,
    compute_priority_score,
    enrich_finding_priority,
)
from pqc_inventory.scanner import Finding, scan_directory

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def _hit(**kwargs) -> Finding:
    defaults = dict(
        rule_id="r1",
        family="RSA",
        file="a.py",
        line=1,
        snippet="rsa.generate_private_key()",
        quantum_risk="high",
        priority=1,
        reason="test",
        description="RSA API",
        language="python",
        owner="",
        data_lifetime_years=None,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_merge_same_file_line_combines_rule_ids():
    a = _hit(rule_id="py-rsa-crypto", family="RSA", line=10, snippet="rsa.generate_private_key()")
    b = _hit(
        rule_id="py-cryptography-lib",
        family="cryptography",
        line=10,
        snippet="from cryptography ... rsa",
        quantum_risk="medium",
        description="cryptography import",
    )
    merged = merge_findings([a, b])
    assert len(merged) == 1
    m = merged[0]
    assert m.merged_count == 2
    assert set(m.rule_ids) == {"py-rsa-crypto", "py-cryptography-lib"}
    assert "RSA" in m.families and "cryptography" in m.families
    assert m.quantum_risk == "high"
    assert len(m.children) == 2


def test_merge_does_not_collapse_unrelated_lines():
    a = _hit(rule_id="py-rsa-crypto", line=10, snippet="rsa.generate_private_key()")
    b = _hit(rule_id="py-aes", family="AES", line=25, snippet="algorithms.AES(key)", quantum_risk="low")
    merged = merge_findings([a, b])
    assert len(merged) == 2


def test_sample_merge_reduces_noise():
    raw = scan_directory(SAMPLE, merge=False)
    merged = scan_directory(SAMPLE, merge=True)
    assert len(raw.raw_findings) >= 5
    assert len(merged.findings) < len(merged.raw_findings)
    assert any(getattr(f, "merged_count", 1) > 1 for f in merged.findings)


def test_exposure_trust_boundary_vs_hash():
    assert classify_exposure("TLS/SSL") == "trust_boundary"
    assert classify_exposure("JWT/JOSE", snippet="const alg = 'RS256'") == "trust_boundary"
    assert classify_exposure("SHA/Hash") == "hash_local"
    assert classify_exposure("RSA") == "public_key"


def test_priority_score_differentiates_high_via_exposure():
    jwt_score, jwt_reason = compute_priority_score("high", None, "trust_boundary")
    rsa_score, _ = compute_priority_score("high", None, "public_key")
    hash_score, _ = compute_priority_score("info", None, "hash_local")
    assert jwt_score > rsa_score > hash_score
    assert "lifetime" in jwt_reason or "unknown" in jwt_reason
    assert jwt_score == 100 + UNKNOWN_LIFETIME_POINTS + 30


def test_lifetime_raises_score():
    short, _ = compute_priority_score("high", 2, "public_key")
    long, _ = compute_priority_score("high", 20, "public_key")
    unknown, _ = compute_priority_score("high", None, "public_key")
    assert long > short
    assert unknown == 100 + UNKNOWN_LIFETIME_POINTS + 22


def test_prioritized_order_not_all_rank_one_by_risk_only():
    result = scan_directory(SAMPLE, merge=True)
    ranked = result.prioritized()
    assert ranked
    scores = [f.priority_score for f in ranked]
    assert scores == sorted(scores, reverse=True)
    ranks = [f.priority for f in ranked]
    assert ranks == list(range(1, len(ranked) + 1))
    high = [f for f in ranked if f.quantum_risk == "high"]
    if len(high) >= 2:
        assert all(f.exposure for f in high)


def test_enrich_sets_fields():
    f = _hit()
    enrich_finding_priority(f)
    assert f.exposure
    assert f.priority_score > 0
    assert "score=" in f.priority_reason

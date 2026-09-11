"""SAFE NIST alias pairs on the same site merge into one inventory finding."""

from __future__ import annotations

from pathlib import Path

from pqc_inventory.merge import merge_findings, safe_alias_same_site
from pqc_inventory.scanner import Finding, scan_directory

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def _safe(**kwargs) -> Finding:
    defaults = dict(
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
        rule_ids=[],
        families=[],
    )
    defaults.update(kwargs)
    if not defaults["rule_ids"]:
        defaults["rule_ids"] = [defaults["rule_id"]]
    if not defaults["families"]:
        defaults["families"] = [defaults["family"]]
    return Finding(**defaults)


def test_kyber_ml_kem_same_site_merges_with_both_rule_ids():
    kem = _safe(
        rule_id="py-ml-kem",
        family="ML-KEM",
        line=8,
        snippet='ML_KEM_768 = "ML-KEM-768"',
        description="NIST ML-KEM",
    )
    kyber = _safe(
        rule_id="py-kyber",
        family="ML-KEM",
        line=9,
        snippet='kyber_alg = "Kyber768"',
        description="Kyber legacy alias for NIST ML-KEM",
    )
    assert safe_alias_same_site(kem, kyber)
    merged = merge_findings([kem, kyber])
    assert len(merged) == 1
    m = merged[0]
    assert m.merged_count == 2
    assert set(m.rule_ids) == {"py-ml-kem", "py-kyber"}
    assert m.family == "ML-KEM"
    assert "ML-KEM" in m.families
    # Canonical label preferred as primary rule.
    assert m.rule_id == "py-ml-kem"
    assert m.quantum_risk == "safe"


def test_dilithium_and_sphincs_alias_groups():
    dsa = _safe(
        rule_id="py-ml-dsa",
        family="ML-DSA",
        line=12,
        snippet='ML_DSA_65 = "ML-DSA-65"',
        description="NIST ML-DSA",
    )
    dil = _safe(
        rule_id="py-dilithium",
        family="ML-DSA",
        line=13,
        snippet='dilithium_alg = "Dilithium3"',
        description="Dilithium legacy alias",
    )
    slh = _safe(
        rule_id="py-slh-dsa",
        family="SLH-DSA",
        line=16,
        snippet='SLH_DSA = "SLH-DSA-SHA2-128s"',
        description="NIST SLH-DSA",
    )
    sph = _safe(
        rule_id="py-sphincs",
        family="SLH-DSA",
        line=17,
        snippet='sphincs_alg = "SPHINCS+"',
        description="SPHINCS+ legacy alias",
    )
    merged = merge_findings([dsa, dil, slh, sph])
    assert len(merged) == 2
    by_fam = {m.family: m for m in merged}
    assert set(by_fam["ML-DSA"].rule_ids) == {"py-ml-dsa", "py-dilithium"}
    assert set(by_fam["SLH-DSA"].rule_ids) == {"py-slh-dsa", "py-sphincs"}


def test_different_safe_families_nearby_stay_separate():
    kem = _safe(rule_id="py-ml-kem", family="ML-KEM", line=8, snippet="ML-KEM-768")
    dsa = _safe(
        rule_id="py-ml-dsa",
        family="ML-DSA",
        line=9,
        snippet="ML-DSA-65",
        description="NIST ML-DSA",
    )
    merged = merge_findings([kem, dsa])
    assert len(merged) == 2


def test_far_apart_same_family_stay_separate():
    a = _safe(rule_id="py-ml-kem", family="ML-KEM", line=8, snippet="ML-KEM-768")
    b = _safe(
        rule_id="py-kyber",
        family="ML-KEM",
        line=40,
        snippet='kyber_alg = "Kyber768"',
        description="Kyber legacy alias",
    )
    assert not safe_alias_same_site(a, b)
    merged = merge_findings([a, b])
    assert len(merged) == 2


def test_sample_safe_alias_pairs_collapse():
    raw = scan_directory(SAMPLE, merge=False)
    merged = scan_directory(SAMPLE, merge=True)
    raw_safe = [f for f in raw.raw_findings if f.quantum_risk == "safe"]
    merged_safe = [f for f in merged.findings if f.quantum_risk == "safe"]
    assert len(raw_safe) >= 14
    assert len(merged_safe) < len(raw_safe)
    # At least the three canonical↔alias pairs per language collapse.
    assert len(merged_safe) <= len(raw_safe) - 6
    # Inventory still lists SAFE; prefer canonical families present.
    families = set()
    for f in merged_safe:
        families.update(getattr(f, "families", None) or [f.family])
    assert families & {"ML-KEM", "ML-DSA", "SLH-DSA", "PQC"}
    # Paired alias merge produces combined rule_ids on sample.
    assert any(
        getattr(f, "merged_count", 1) > 1
        and {"py-ml-kem", "py-kyber"} <= set(f.rule_ids or [])
        for f in merged_safe
    ) or any(
        getattr(f, "merged_count", 1) > 1
        and {"js-ml-kem", "js-kyber"} <= set(f.rule_ids or [])
        for f in merged_safe
    )

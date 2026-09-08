"""TLS protocol + algorithm on the same site must not both be scored."""

from __future__ import annotations

from pqc_inventory.merge import (
    count_tls_double_labeled_sites,
    merge_findings,
)
from pqc_inventory.scanner import Finding, scan_directory

ROOT_SAMPLE_PARENT = __import__("pathlib").Path(__file__).resolve().parents[1]
SAMPLE = ROOT_SAMPLE_PARENT / "samples" / "vulnerable-app"


def _hit(**kwargs) -> Finding:
    defaults = dict(
        rule_id="py-ssl",
        family="TLS/SSL",
        file="tls_site.py",
        line=1,
        snippet="import ssl",
        quantum_risk="medium",
        priority=2,
        reason="test",
        description="protocol",
        language="python",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_same_site_keeps_algorithm_and_drops_protocol_duplicate():
    proto_import = _hit(rule_id="py-ssl", family="TLS/SSL", line=3, snippet="import ssl")
    proto_ctx = _hit(
        rule_id="py-ssl",
        family="TLS/SSL",
        line=8,
        snippet="ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
        description="stdlib ssl / TLS wrapper",
    )
    alg = _hit(
        rule_id="py-tls-cipher-rsa",
        family="RSA",
        line=9,
        snippet='ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")',
        quantum_risk="high",
        description="TLS cipher suite using classical RSA",
    )
    other = _hit(
        rule_id="py-rsa-crypto",
        family="RSA",
        file="tls_site.py",
        line=40,
        snippet="rsa.generate_private_key()",
        quantum_risk="high",
        description="cryptography.io RSA API",
    )
    raw = [proto_import, proto_ctx, alg, other]
    before = count_tls_double_labeled_sites(raw)
    assert before == 2

    merged = merge_findings(raw)
    assert count_tls_double_labeled_sites(merged) == 0
    assert before > count_tls_double_labeled_sites(merged)

    tls_assets = [m for m in merged if "py-tls-cipher-rsa" in (m.rule_ids or [])]
    assert len(tls_assets) == 1
    kept = tls_assets[0]
    assert kept.family == "RSA"
    assert kept.rule_id == "py-tls-cipher-rsa"
    assert "py-ssl" in kept.rule_ids
    assert kept.merged_count >= 3
    # Protocol is not a second scored asset.
    assert sum(1 for m in merged if "py-ssl" in (m.rule_ids or [m.rule_id])) == 1
    # Unrelated local RSA remains its own site.
    assert any(m.rule_id == "py-rsa-crypto" and m.line == 40 for m in merged)
    assert len(merged) == 2


def test_different_files_are_not_the_same_tls_site():
    proto = _hit(file="a.py", line=4, snippet="ctx = ssl.SSLContext()")
    alg = _hit(
        rule_id="py-tls-cipher-rsa",
        family="RSA",
        file="b.py",
        line=5,
        snippet='ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")',
        quantum_risk="high",
        description="TLS cipher suite using classical RSA",
    )
    merged = merge_findings([proto, alg])
    assert len(merged) == 2
    assert count_tls_double_labeled_sites(merged) == 0


def test_sample_fixture_merges_tls_protocol_into_algorithm():
    merged = scan_directory(SAMPLE, merge=True)
    # raw_findings are pre-classification; findings are after TLS site merge.
    before = count_tls_double_labeled_sites(merged.raw_findings)
    after = count_tls_double_labeled_sites(merged.findings)
    assert before >= 1, "fixture should emit protocol+algorithm on one TLS site"
    assert after < before
    assert after == 0

    site = [
        f
        for f in merged.findings
        if f.file.endswith("tls_cipher_site.py") and "py-tls-cipher-rsa" in (f.rule_ids or [])
    ]
    assert len(site) == 1
    assert site[0].family == "RSA"
    assert "py-ssl" in site[0].rule_ids
    assert site[0].merged_count >= 2
    # Local RSA in the same file stays a separate asset.
    local = [
        f
        for f in merged.findings
        if f.file.endswith("tls_cipher_site.py") and "py-rsa-crypto" in (f.rule_ids or [f.rule_id])
    ]
    assert local
    assert site[0] not in local

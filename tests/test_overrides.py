"""Cut B: explicit lifetime / exposure overrides (never invent values)."""

from __future__ import annotations

import json
from pathlib import Path

from pqc_inventory.cli import main
from pqc_inventory.overrides import (
    parse_annotation_line,
    parse_cli_override,
    load_overrides_json,
)
from pqc_inventory.report import write_outputs
from pqc_inventory.scanner import scan_directory

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "vulnerable-app"


def test_parse_annotation_line():
    spec = parse_annotation_line(
        "# pqc-inventory: lifetime=15 exposure=public_key owner=payments",
        "a.py",
        3,
    )
    assert spec is not None
    assert spec.data_lifetime_years == 15
    assert spec.exposure == "public_key"
    assert spec.owner == "payments"
    assert spec.line == 3


def test_parse_file_level_annotation():
    spec = parse_annotation_line("# pqc-inventory-file: owner=team-x", "a.py", 1)
    assert spec is not None
    assert spec.line is None
    assert spec.owner == "team-x"
    assert spec.source == "annotation-file"


def test_parse_cli_override_with_line():
    spec = parse_cli_override("pkg/foo.py:12=15", field_name="lifetime")
    assert spec.file == "pkg/foo.py"
    assert spec.line == 12
    assert spec.data_lifetime_years == 15


def test_sample_annotations_apply_and_spread_scores(tmp_path: Path):
    result = scan_directory(SAMPLE, hash_policy="keep")
    lifetimes = [
        f.data_lifetime_years
        for f in result.findings
        if f.data_lifetime_years is not None
    ]
    assert lifetimes, "expected sample annotations to set some lifetimes"
    # Unoverridden stay None — never invent
    assert any(f.data_lifetime_years is None for f in result.findings)

    overridden = [f for f in result.findings if f.overrides_applied]
    assert overridden
    assert any("data_lifetime_years" in f.overrides_applied for f in overridden)

    scores = {f.priority_score for f in result.findings}
    assert len(scores) >= 3, "overrides should help spread priority scores"

    json_path, md_path, _, _ = write_outputs(result, tmp_path / "out")
    inventory = json.loads(json_path.read_text(encoding="utf-8"))
    assert any(
        f.get("data_lifetime_years") is not None for f in inventory["findings"]
    )
    assert any(f.get("overrides_applied") for f in inventory["findings"])
    md = md_path.read_text(encoding="utf-8")
    assert "Overrides applied" in md
    assert "lifetime" in md.lower() or "15" in md or "10" in md


def test_cli_set_lifetime_override(tmp_path: Path):
    # Use a file without relying solely on annotations: CLI override on RSA line
    out = tmp_path / "out"
    # Find an RSA finding line from a no-extra-override scan first
    base = scan_directory(SAMPLE, hash_policy="drop")
    rsa = next(f for f in base.findings if "RSA" in (f.families or [f.family]))
    target = f"{rsa.file}:{rsa.line}=25"
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(out),
            "--set-lifetime",
            target,
            "--hash-policy",
            "drop",
        ]
    )
    assert rc in (0, 1)  # may fail-on default never → 0
    inv = json.loads((out / "inventory.json").read_text(encoding="utf-8"))
    matched = [
        f
        for f in inv["findings"]
        if f["file"] == rsa.file and f.get("line") == rsa.line
    ]
    assert matched
    assert matched[0]["data_lifetime_years"] == 25
    assert "data_lifetime_years" in (matched[0].get("overrides_applied") or {})


def test_overrides_json_file(tmp_path: Path):
    ov = tmp_path / "ov.json"
    ov.write_text(
        json.dumps(
            {
                "overrides": [
                    {
                        "file": "python_app/crypto_demo.py",
                        "data_lifetime_years": 30,
                        "exposure": "public_key",
                        "owner": "json-owner",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    specs = load_overrides_json(ov)
    assert len(specs) == 1
    result = scan_directory(SAMPLE, extra_overrides=specs, hash_policy="drop")
    py = [f for f in result.findings if f.file.endswith("crypto_demo.py")]
    assert py
    assert any(f.data_lifetime_years == 30 for f in py)
    assert any(f.owner == "json-owner" for f in py)



def test_inventory_overrides_applied_summary_matches_findings(tmp_path: Path):
    result = scan_directory(SAMPLE, hash_policy="keep")
    json_path, _, _, _ = write_outputs(result, tmp_path / "out")
    inventory = json.loads(json_path.read_text(encoding="utf-8"))
    summary = inventory["overrides_applied"]
    assert set(summary) >= {"count", "sources", "items"}
    assert summary["count"] == len(summary["items"])
    assert summary["count"] > 0

    expected_items = []
    for finding in result.findings:
        applied = finding.overrides_applied or {}
        if not applied:
            continue
        fields = []
        if "data_lifetime_years" in applied:
            fields.append("lifetime")
        if "exposure" in applied:
            fields.append("exposure")
        if "owner" in applied:
            fields.append("owner")
        for key in applied:
            if key not in ("data_lifetime_years", "exposure", "owner"):
                fields.append(key)
        item_sources = sorted({str(v) for v in applied.values() if v})
        expected_items.append(
            {
                "file": finding.file,
                "line": finding.line,
                "fields": fields,
                "sources": item_sources,
            }
        )
    expected_items.sort(key=lambda item: (item["file"], item["line"] if item["line"] is not None else -1))
    assert summary["items"] == expected_items
    assert summary["sources"] == sorted({s for item in expected_items for s in item["sources"]})
    # Sample annotations actually applied; no invented CLI/file source.
    assert "annotation" in summary["sources"] or "annotation-file" in summary["sources"]
    assert "cli" not in summary["sources"]


def test_overrides_applied_summary_empty_when_none(tmp_path: Path):
    src = tmp_path / "plain.py"
    src.write_text("private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n", encoding="utf-8")
    result = scan_directory(src, hash_policy="keep")
    assert result.overrides_applied_summary["count"] == 0
    assert result.overrides_applied_summary["sources"] == []
    assert result.overrides_applied_summary["items"] == []
    json_path, _, _, _ = write_outputs(result, tmp_path / "out")
    inventory = json.loads(json_path.read_text(encoding="utf-8"))
    assert inventory["overrides_applied"]["count"] == 0
    assert inventory["overrides_applied"]["items"] == []


def test_cli_override_appears_in_top_level_summary(tmp_path: Path):
    out = tmp_path / "out"
    base = scan_directory(SAMPLE, hash_policy="drop")
    target_finding = next(f for f in base.findings if f.line and "RSA" in (f.families or [f.family]))
    rc = main(
        [
            "scan",
            str(SAMPLE),
            "--out",
            str(out),
            "--set-lifetime",
            f"{target_finding.file}:{target_finding.line}=25",
            "--hash-policy",
            "drop",
        ]
    )
    assert rc == 0
    inv = json.loads((out / "inventory.json").read_text(encoding="utf-8"))
    summary = inv["overrides_applied"]
    assert summary["count"] == len(summary["items"])
    assert "cli" in summary["sources"]
    matched = [
        item
        for item in summary["items"]
        if item["file"] == target_finding.file and item["line"] == target_finding.line
    ]
    assert matched
    assert "lifetime" in matched[0]["fields"]
    assert "cli" in matched[0]["sources"]

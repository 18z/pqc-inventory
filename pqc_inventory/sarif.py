"""Emit SARIF 2.1.0 for GitHub code scanning / similar consumers."""

from __future__ import annotations

from typing import Any

from pqc_inventory import __version__
from pqc_inventory.baseline import FINGERPRINT_SARIF_KEY, fingerprint_finding
from pqc_inventory.scanner import ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_RISK_TO_LEVEL = {
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_DRIVER_NOTE = (
    "Static scan of source code and dependency manifests only. "
    "Does not certify compliance with EO 14412, CNSA 2.0, NIST IR 8547, "
    "or any other mandate."
)


def _level_for(risk: str) -> str:
    return _RISK_TO_LEVEL.get(risk, "note")


def _collect_rule_ids(findings: list) -> list[str]:
    """Unique rule ids: primary first, then any merged rule_ids."""
    ordered: list[str] = []
    seen: set[str] = set()
    for f in findings:
        primary = getattr(f, "rule_id", None) or ""
        extras = list(getattr(f, "rule_ids", None) or [])
        for rid in [primary, *extras]:
            if not rid or rid in seen:
                continue
            seen.add(rid)
            ordered.append(rid)
    return ordered


def _rule_descriptor(rule_id: str, findings: list) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor from the first matching finding."""
    sample = None
    for f in findings:
        if getattr(f, "rule_id", None) == rule_id:
            sample = f
            break
        if rule_id in (getattr(f, "rule_ids", None) or []):
            sample = f
            break
    short = rule_id
    full = getattr(sample, "description", None) or rule_id if sample else rule_id
    risk = getattr(sample, "quantum_risk", "info") if sample else "info"
    reason = getattr(sample, "reason", "") if sample else ""
    help_text = reason or full
    return {
        "id": rule_id,
        "name": short.replace("-", "_").replace(".", "_"),
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": _level_for(risk)},
        "properties": {
            "tags": ["security", "cryptography", "pqc", "quantum"],
            "problem.severity": risk,
        },
    }


def _result_properties(f: Any) -> dict[str, Any]:
    props: dict[str, Any] = {}
    score = getattr(f, "priority_score", None)
    if score is not None:
        props["priority_score"] = score
    family = getattr(f, "family", None)
    if family:
        props["family"] = family
    exposure = getattr(f, "exposure", None)
    if exposure:
        props["exposure"] = exposure
    owner = getattr(f, "owner", None)
    if owner:
        props["owner"] = owner
    lifetime = getattr(f, "data_lifetime_years", None)
    if lifetime is not None:
        props["data_lifetime_years"] = lifetime
    rule_ids = getattr(f, "rule_ids", None) or []
    if rule_ids and len(rule_ids) > 1:
        props["merged_rule_ids"] = list(rule_ids)
    return props


def build_sarif(result: ScanResult) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from a ScanResult.

    Only non-suppressed findings become SARIF results (alerts).
    """
    prioritized = result.prioritized()
    active = [
        f
        for f in prioritized
        if not getattr(f, "suppressed", False)
        and not getattr(f, "baseline_suppressed", False)
    ]
    # Rules cover all findings (including suppressed) so descriptors stay stable,
    # but results only list active alerts.
    all_for_rules = prioritized
    rule_ids = _collect_rule_ids(all_for_rules) or _collect_rule_ids(active)

    rules = [_rule_descriptor(rid, all_for_rules or active) for rid in rule_ids]

    sarif_results: list[dict[str, Any]] = []
    for f in active:
        rule_id = getattr(f, "rule_id", None) or (
            (getattr(f, "rule_ids", None) or ["unknown"])[0]
        )
        file_path = getattr(f, "file", "") or ""
        line = getattr(f, "line", None)
        start_line = line if line is not None else 1
        message = getattr(f, "description", None) or rule_id
        reason = getattr(f, "reason", "") or ""
        if reason and reason not in message:
            message = f"{message}: {reason}"

        entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _level_for(getattr(f, "quantum_risk", "info")),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {"startLine": start_line},
                    }
                }
            ],
            "partialFingerprints": {
                FINGERPRINT_SARIF_KEY: fingerprint_finding(f),
            },
        }
        props = _result_properties(f)
        if props:
            entry["properties"] = props
        sarif_results.append(entry)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqc-inventory",
                        "version": __version__,
                        "informationUri": "https://github.com/18z/pqc-inventory",
                        "rules": rules,
                        "properties": {
                            "note": _DRIVER_NOTE,
                            "scope": (
                                "static source+manifests only; "
                                "does not certify compliance"
                            ),
                        },
                    }
                },
                "results": sarif_results,
            }
        ],
    }

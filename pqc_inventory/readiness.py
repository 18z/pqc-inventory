"""Transparent static-scope migration readiness score (0-100).

Not a compliance certificate. Deterministic from inventory findings only.
"""

from __future__ import annotations

from typing import Any

# Mean of these weights -> score. Documented in inventory.json + README.
RISK_WEIGHTS: dict[str, int] = {
    "high": 0,
    "medium": 40,
    "low": 70,
    "info": 85,
    "safe": 100,
}

EMPTY_NOTE = (
    "No crypto findings in static scope (source + manifests). "
    "Score 100 means nothing detected — not 'fully migrated' or certified."
)

FORMULA_NOTE = (
    "Mean of per-finding weights "
    "(high=0, medium=40, low=70, info=85, safe=100) over the primary "
    "inventory list (new-only when --baseline is applied). "
    "Optional +5 soft boost when SAFE count >= HIGH count and HIGH > 0, "
    "capped at 100. Static-only; not certification."
)


def compute_readiness(findings: list[Any]) -> tuple[int, str]:
    """Return (score 0-100, human note).

    Empty inventory -> 100 with an explicit 'nothing detected' note.
    """
    if not findings:
        return 100, EMPTY_NOTE

    weights: list[int] = []
    high = 0
    safe = 0
    for f in findings:
        if isinstance(f, dict):
            risk = (f.get("quantum_risk") or "info").lower()
        else:
            risk = (getattr(f, "quantum_risk", None) or "info").lower()
        weights.append(RISK_WEIGHTS.get(risk, RISK_WEIGHTS["info"]))
        if risk == "high":
            high += 1
        elif risk == "safe":
            safe += 1

    score = round(sum(weights) / len(weights))
    if high > 0 and safe >= high:
        score = min(100, score + 5)
    return score, FORMULA_NOTE


def readiness_block(findings: list[Any]) -> dict[str, Any]:
    score, note = compute_readiness(findings)
    return {
        "readiness_score": score,
        "readiness_note": note,
        "readiness_formula": {
            "weights": dict(RISK_WEIGHTS),
            "aggregation": (
                "mean of per-finding weights; "
                "+5 soft boost when SAFE>=HIGH and HIGH>0"
            ),
            "empty_inventory": "score 100 with nothing-detected caveat",
            "certification": False,
            "scope": "static source + dependency manifests only",
        },
    }

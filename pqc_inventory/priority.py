"""Lifetime / exposure-weighted priority scoring (defensive inventory only).

Formula (higher score = more urgent):

    priority_score = risk_points + lifetime_points + exposure_points

risk_points:
    high=100, medium=40, low=15, info=5

lifetime_points:
    - known years (explicit override only): min(50, round(data_lifetime_years * 2))
    - null / unknown: 20  (conservative mid + explicit unknown penalty;
      field itself stays null — never invent a lifetime value)

exposure_points (heuristic from family / language / snippet, unless overridden):
    trust_boundary (TLS/SSL, JWT/JOSE, JWT):     30
    public_key     (RSA, ECDSA*, EdDSA, DH, WebCrypto): 22
    library_import (cryptography, node:crypto, forge, PyCryptodome deps): 12
    symmetric      (AES, ChaCha20):                6
    hash_local     (SHA/Hash):                     2
    other:                                         8

When lifetime is null, exposure still differentiates two HIGHs
(e.g. JWT/TLS trust-boundary ranks above a local RSA import helper).
"""

from __future__ import annotations

from typing import Any

RISK_POINTS: dict[str, int] = {
    "high": 100,
    "medium": 40,
    "low": 15,
    "info": 5,
}

# Null lifetime → conservative mid (≈10y * 2) with a small unknown penalty baked in.
# The finding field stays None; only the score component uses this constant.
UNKNOWN_LIFETIME_POINTS = 20
LIFETIME_POINTS_CAP = 50

# Family → exposure class
_TRUST_BOUNDARY_FAMILIES = {
    "TLS/SSL",
    "JWT/JOSE",
    "JWT",
}
_PUBLIC_KEY_FAMILIES = {
    "RSA",
    "ECDSA",
    "ECDSA/ECDH",
    "EdDSA",
    "DH",
    "WebCrypto",
}
_LIBRARY_FAMILIES = {
    "cryptography",
    "PyCryptodome",
    "node:crypto",
    "node-forge",
}
_SYMMETRIC_FAMILIES = {
    "AES",
    "ChaCha20",
}
_HASH_FAMILIES = {
    "SHA/Hash",
}

EXPOSURE_POINTS: dict[str, int] = {
    "trust_boundary": 30,
    "public_key": 22,
    "library_import": 12,
    "symmetric": 6,
    "hash_local": 2,
    "other": 8,
}

EXPOSURE_LABELS: dict[str, str] = {
    "trust_boundary": "network/TLS/JWT trust boundary",
    "public_key": "public-key / asymmetric API",
    "library_import": "crypto library import or dependency",
    "symmetric": "local symmetric cipher",
    "hash_local": "local hash / integrity helper",
    "other": "other crypto usage",
}


def classify_exposure(
    family: str,
    *,
    language: str = "",
    snippet: str = "",
    families: list[str] | None = None,
) -> str:
    """Return exposure class for a finding (or merged finding)."""
    fams = set(families or [])
    fams.add(family)
    snippet_l = (snippet or "").lower()

    # Snippet hints can elevate to trust boundary
    if any(
        k in snippet_l
        for k in (
            "ssl",
            "tls",
            "wrap_socket",
            "create_default_context",
            "rs256",
            "es256",
            "jwt",
            "signjwt",
            "bearer",
        )
    ):
        return "trust_boundary"

    if fams & _TRUST_BOUNDARY_FAMILIES:
        return "trust_boundary"
    if fams & _PUBLIC_KEY_FAMILIES:
        return "public_key"
    if fams & _LIBRARY_FAMILIES or language == "manifest":
        return "library_import"
    if fams & _SYMMETRIC_FAMILIES:
        return "symmetric"
    if fams & _HASH_FAMILIES:
        return "hash_local"
    return "other"


def lifetime_points(data_lifetime_years: int | float | None) -> tuple[int, str]:
    """Return (points, short note). Null → score mid; field stays unknown."""
    if data_lifetime_years is None:
        return UNKNOWN_LIFETIME_POINTS, "lifetime unknown→mid(+unknown penalty)"
    try:
        years = float(data_lifetime_years)
    except (TypeError, ValueError):
        return UNKNOWN_LIFETIME_POINTS, "lifetime unknown→mid(+unknown penalty)"
    pts = min(LIFETIME_POINTS_CAP, int(round(years * 2)))
    return pts, f"lifetime {years:g}y (override)"


def compute_priority_score(
    quantum_risk: str,
    data_lifetime_years: int | float | None,
    exposure: str,
) -> tuple[int, str]:
    """Compute priority_score and a short ranking reason."""
    risk_pts = RISK_POINTS.get(quantum_risk, 5)
    life_pts, life_note = lifetime_points(data_lifetime_years)
    exp_pts = EXPOSURE_POINTS.get(exposure, EXPOSURE_POINTS["other"])
    exp_label = EXPOSURE_LABELS.get(exposure, exposure)
    score = risk_pts + life_pts + exp_pts
    reason = (
        f"score={score} (risk={quantum_risk}:{risk_pts} + {life_note}:{life_pts} "
        f"+ exposure={exp_label}:{exp_pts})"
    )
    return score, reason


def enrich_finding_priority(finding: Any) -> None:
    """Mutate a Finding (or MergedFinding) with exposure, priority_score, priority_reason.

    If ``exposure`` was already set by an explicit override, keep it.
    Never invent ``data_lifetime_years`` — leave None when not overridden.
    """
    overrides = getattr(finding, "overrides_applied", None) or {}
    exposure_overridden = "exposure" in overrides and bool(getattr(finding, "exposure", ""))

    if not exposure_overridden:
        families = getattr(finding, "families", None) or [finding.family]
        exposure = classify_exposure(
            finding.family,
            language=getattr(finding, "language", "") or "",
            snippet=getattr(finding, "snippet", "") or "",
            families=list(families),
        )
        finding.exposure = exposure
    else:
        exposure = finding.exposure

    score, reason = compute_priority_score(
        finding.quantum_risk,
        getattr(finding, "data_lifetime_years", None),
        exposure,
    )
    if exposure_overridden:
        reason = f"{reason} [exposure override]"
    if "data_lifetime_years" in overrides:
        reason = f"{reason} [lifetime override]"
    finding.priority_score = score
    finding.priority_reason = reason

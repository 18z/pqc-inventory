"""Emit a CycloneDX 1.6-oriented Crypto BOM (CBOM) JSON subset.

stdlib JSON only — no heavy deps. Maps detected algorithm / API families to
cryptographic-asset components with cryptoProperties where practical.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pqc_inventory import __version__

# family → (primitive, quantumSafe-ish nist level 0 for classical PK)
_FAMILY_CRYPTO: dict[str, dict[str, Any]] = {
    "RSA": {
        "primitive": "asymmetric-encryption",
        "cryptoFunctions": ["keygen", "encrypt", "sign"],
        "nistQuantumSecurityLevel": 0,
    },
    "ECDSA": {
        "primitive": "signature",
        "cryptoFunctions": ["keygen", "sign", "verify"],
        "nistQuantumSecurityLevel": 0,
    },
    "ECDSA/ECDH": {
        "primitive": "key-agree",
        "cryptoFunctions": ["keygen", "keyagree", "sign"],
        "nistQuantumSecurityLevel": 0,
    },
    "EdDSA": {
        "primitive": "signature",
        "cryptoFunctions": ["keygen", "sign", "verify"],
        "nistQuantumSecurityLevel": 0,
    },
    "DH": {
        "primitive": "key-agree",
        "cryptoFunctions": ["keygen", "keyagree"],
        "nistQuantumSecurityLevel": 0,
    },
    "TLS/SSL": {
        "primitive": "protocol",
        "cryptoFunctions": ["encapsulate", "decapsulate"],
        "nistQuantumSecurityLevel": 0,
    },
    "JWT/JOSE": {
        "primitive": "signature",
        "cryptoFunctions": ["sign", "verify"],
        "nistQuantumSecurityLevel": 0,
    },
    "JWT": {
        "primitive": "signature",
        "cryptoFunctions": ["sign", "verify"],
        "nistQuantumSecurityLevel": 0,
    },
    "WebCrypto": {
        "primitive": "other",
        "cryptoFunctions": ["keygen", "encrypt", "sign"],
        "nistQuantumSecurityLevel": 0,
    },
    "AES": {
        "primitive": "block-cipher",
        "cryptoFunctions": ["encrypt", "decrypt"],
        "nistQuantumSecurityLevel": 1,
    },
    "ChaCha20": {
        "primitive": "stream-cipher",
        "cryptoFunctions": ["encrypt", "decrypt"],
        "nistQuantumSecurityLevel": 1,
    },
    "SHA/Hash": {
        "primitive": "hash",
        "cryptoFunctions": ["digest"],
        "nistQuantumSecurityLevel": 2,
    },
    "cryptography": {
        "primitive": "other",
        "cryptoFunctions": ["other"],
        "nistQuantumSecurityLevel": 0,
    },
    "PyCryptodome": {
        "primitive": "other",
        "cryptoFunctions": ["other"],
        "nistQuantumSecurityLevel": 0,
    },
    "node:crypto": {
        "primitive": "other",
        "cryptoFunctions": ["other"],
        "nistQuantumSecurityLevel": 0,
    },
    "node-forge": {
        "primitive": "other",
        "cryptoFunctions": ["other"],
        "nistQuantumSecurityLevel": 0,
    },
}

_RISK_TO_OID_HINT = {
    "high": "classical-public-key-shor",
    "medium": "ambiguous-or-protocol",
    "low": "symmetric-grover-consideration",
    "info": "hash-integrity",
}


def _component_for_family(family: str, quantum_risk: str, evidence: list[dict]) -> dict:
    meta = _FAMILY_CRYPTO.get(
        family,
        {
            "primitive": "other",
            "cryptoFunctions": ["other"],
            "nistQuantumSecurityLevel": 0,
        },
    )
    bom_ref = f"crypto:{family.lower().replace('/', '-').replace(' ', '-')}"
    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": family,
        "description": (
            f"Detected via static inventory (quantum_risk={quantum_risk}; "
            f"hint={_RISK_TO_OID_HINT.get(quantum_risk, 'other')})"
        ),
        "cryptoProperties": {
            "assetType": "algorithm" if meta["primitive"] != "protocol" else "protocol",
            "algorithmProperties": {
                "primitive": meta["primitive"],
                "executionEnvironment": "unknown",
                "implementationPlatform": "unknown",
                "cryptoFunctions": meta["cryptoFunctions"],
                "nistQuantumSecurityLevel": meta["nistQuantumSecurityLevel"],
            },
        },
        "evidence": {
            "occurrences": [
                {
                    "location": e.get("file", ""),
                    "line": e.get("line"),
                    "rule_ids": e.get("rule_ids", []),
                }
                for e in evidence[:20]
            ]
        },
    }
    return component


def build_cbom(
    *,
    target: str,
    findings: list[Any],
    tool_version: str | None = None,
) -> dict:
    """Build a CycloneDX-compatible CBOM document from merged findings."""
    version = tool_version or __version__
    by_family: dict[str, dict[str, Any]] = {}
    for f in findings:
        if isinstance(f, dict):
            fams = f.get("families") or [f.get("family", "unknown")]
            risk = f.get("quantum_risk", "info")
            evidence_item = {
                "file": f.get("file", ""),
                "line": f.get("line"),
                "rule_ids": f.get("rule_ids") or [f.get("rule_id")],
            }
        else:
            fams = getattr(f, "families", None) or [f.family]
            risk = f.quantum_risk
            evidence_item = {
                "file": f.file,
                "line": f.line,
                "rule_ids": getattr(f, "rule_ids", None) or [f.rule_id],
            }
        for fam in fams:
            slot = by_family.setdefault(fam, {"risk": risk, "evidence": []})
            order = {"high": 0, "medium": 1, "low": 2, "info": 3}
            if order.get(risk, 9) < order.get(slot["risk"], 9):
                slot["risk"] = risk
            slot["evidence"].append(evidence_item)

    components = [
        _component_for_family(fam, data["risk"], data["evidence"])
        for fam, data in sorted(by_family.items())
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pqc-inventory",
                        "version": version,
                        "description": (
                            "Defensive static crypto inventory / quantum-risk scanner "
                            "(source + manifests only)"
                        ),
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": target,
                "description": "Scanned target path (static analysis scope)",
            },
            "properties": [
                {
                    "name": "pqc-inventory:scope",
                    "value": (
                        "static analysis of source code + dependency manifests only; "
                        "not runtime, binaries, network traffic, or complete coverage"
                    ),
                },
                {
                    "name": "pqc-inventory:compliance-note",
                    "value": (
                        "Planning references only; pqc-inventory does not certify "
                        "compliance with EO 14412, CNSA 2.0, NIST IR 8547, or any mandate"
                    ),
                },
                {
                    "name": "pqc-inventory:ref:eo-14412-cbom-min-elements",
                    "value": (
                        "CISA+NIST CBOM minimum elements guidance due ~270 days after "
                        "EO 14412 (2026-06-22) ≈ 2027-03; not finalized at emit time"
                    ),
                },
                {
                    "name": "pqc-inventory:ref:eo-14412-pqc-key-est",
                    "value": "HVA/high-impact PQC key establishment target 2030-12-31",
                },
                {
                    "name": "pqc-inventory:ref:eo-14412-pqc-signatures",
                    "value": "HVA/high-impact PQC digital signatures target 2031-12-31",
                },
                {
                    "name": "pqc-inventory:ref:cnsa-2.0",
                    "value": "NSA CNSA 2.0 — planning reference only",
                },
                {
                    "name": "pqc-inventory:ref:nist-ir-8547",
                    "value": "NIST IR 8547 — planning reference only",
                },
            ],
        },
        "components": components,
    }

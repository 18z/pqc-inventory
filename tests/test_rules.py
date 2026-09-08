"""Unit tests for classifier rules against representative snippets."""

from __future__ import annotations

import re

import pytest

from pqc_inventory.rules import ALL_RULES, JS_RULES, MANIFEST_RULES, PYTHON_RULES, PRIORITY_BY_RISK


@pytest.mark.parametrize(
    "snippet,expected_family,expected_risk",
    [
        ("private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "RSA", "high"),
        ("from ecdsa import SigningKey", "ECDSA", "high"),
        ("ec.generate_private_key(ec.SECP256R1())", "ECDSA/ECDH", "high"),
        ("Ed25519PrivateKey.generate()", "EdDSA", "high"),
        ("ssl.create_default_context()", "TLS/SSL", "medium"),
        ("Cipher(algorithms.AES(key), modes.ECB())", "AES", "low"),
        ("hashlib.sha256(b'data')", "SHA/Hash", "info"),
        ("from Crypto.PublicKey.RSA import generate", "RSA", "high"),
    ],
)
def test_python_snippets(snippet, expected_family, expected_risk):
    matched = [
        r
        for r in PYTHON_RULES
        if re.search(r.pattern, snippet) and r.family == expected_family and r.risk == expected_risk
    ]
    assert matched, f"No rule matched {snippet!r} as {expected_family}/{expected_risk}"


@pytest.mark.parametrize(
    "snippet,expected_family,expected_risk",
    [
        ("crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })", "RSA", "high"),
        ("crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })", "ECDSA/ECDH", "high"),
        ("crypto.generateKeyPairSync('ed25519')", "EdDSA", "high"),
        ("forge.pki.rsa.generateKeyPair({ bits: 2048 })", "RSA", "high"),
        ("const alg = 'RS256';", "JWT/JOSE", "high"),
        ("algorithm: 'RSA-OAEP'", "RSA", "high"),
        ("crypto.createCipheriv('aes-256-gcm', key, iv)", "AES", "low"),
        ("crypto.createHash('sha256')", "SHA/Hash", "info"),
        ("const crypto = require('crypto');", "node:crypto", "medium"),
    ],
)
def test_js_snippets(snippet, expected_family, expected_risk):
    matched = [
        r
        for r in JS_RULES
        if re.search(r.pattern, snippet) and r.family == expected_family and r.risk == expected_risk
    ]
    assert matched, f"No rule matched {snippet!r} as {expected_family}/{expected_risk}"


@pytest.mark.parametrize(
    "snippet,expected_id",
    [
        ("cryptography>=41.0.0", "dep-cryptography"),
        ("ecdsa>=0.18.0", "dep-ecdsa"),
        ('"node-forge": "^1.3.1",', "dep-node-forge"),
        ('"jose": "^5.2.0"', "dep-jose"),
        ("pycryptodome>=3.19.0", "dep-pycryptodome"),
    ],
)
def test_manifest_snippets(snippet, expected_id):
    matched = [r for r in MANIFEST_RULES if r.id == expected_id and re.search(r.pattern, snippet)]
    assert matched, f"Rule {expected_id} did not match {snippet!r}"


def test_all_rules_have_valid_risk_and_priority():
    for rule in ALL_RULES:
        assert rule.risk in PRIORITY_BY_RISK
        assert PRIORITY_BY_RISK[rule.risk] >= 1
        assert rule.languages
        re.compile(rule.pattern)  # must be valid regex

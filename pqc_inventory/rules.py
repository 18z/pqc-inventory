"""Heuristic / regex classifier rules for crypto APIs and quantum risk.

Quantum-risk guidance (defensive inventory only — not an attack tool):
- high:   RSA, classical ECDSA/ECDH/EdDSA as long-term trust, finite-field DH
- medium: ambiguous TLS/crypto wrappers without clear PQC
- low:    AES/ChaCha (Grover reduces keyspace ~sqrt; prefer 256-bit keys)
- info:   SHA-2/3 integrity / hashing (Grover may affect collision resistance)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Risk = Literal["high", "medium", "low", "info"]

# Priority: lower number = higher urgency
PRIORITY_BY_RISK: dict[str, int] = {
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

REASON_BY_RISK: dict[str, str] = {
    "high": (
        "Classical public-key scheme vulnerable to Shor's algorithm; "
        "plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust."
    ),
    "medium": (
        "TLS or crypto wrapper usage without clear PQC hybrid; "
        "verify cipher suites and library PQC readiness."
    ),
    "low": (
        "Symmetric cipher: Grover's algorithm roughly halves effective key bits; "
        "AES-256 / ChaCha20 remain practical; prefer 256-bit keys."
    ),
    "info": (
        "Hash / integrity primitive: generally acceptable post-quantum for integrity; "
        "prefer SHA-256+ or SHA-3; note Grover impact on brute-force."
    ),
}


@dataclass(frozen=True)
class Rule:
    """A single detection pattern."""

    id: str
    family: str  # algorithm / API family label
    pattern: str  # regex (case-sensitive unless noted)
    risk: Risk
    languages: tuple[str, ...]  # "python" | "javascript" | "manifest"
    description: str


# ---------------------------------------------------------------------------
# Python source patterns
# ---------------------------------------------------------------------------
PYTHON_RULES: list[Rule] = [
    Rule(
        id="py-rsa-crypto",
        family="RSA",
        pattern=r"\brsa\.(generate_private_key|encrypt|decrypt|sign|verify)\b",
        risk="high",
        languages=("python",),
        description="cryptography.io RSA API",
    ),
    Rule(
        id="py-rsa-module",
        family="RSA",
        pattern=r"\bimport\s+rsa\b|\bfrom\s+rsa\s+import\b",
        risk="high",
        languages=("python",),
        description="python-rsa / rsa package import",
    ),
    Rule(
        id="py-pycryptodome-rsa",
        family="RSA",
        pattern=r"\bCrypto\.PublicKey\.RSA\b|\bCryptodome\.PublicKey\.RSA\b",
        risk="high",
        languages=("python",),
        description="PyCryptodome RSA",
    ),
    Rule(
        id="py-ecdsa",
        family="ECDSA",
        pattern=r"\becdsa\.(SigningKey|VerifyingKey|NIST\w+)\b|\bfrom\s+ecdsa\s+import\b|\bimport\s+ecdsa\b",
        risk="high",
        languages=("python",),
        description="python-ecdsa classical signatures",
    ),
    Rule(
        id="py-ec-crypto",
        family="ECDSA/ECDH",
        pattern=r"\bec\.(generate_private_key|EllipticCurvePublicKey|ECDH)\b|\bEllipticCurve\b",
        risk="high",
        languages=("python",),
        description="cryptography.io elliptic-curve API",
    ),
    Rule(
        id="py-ed25519",
        family="EdDSA",
        pattern=r"\bEd25519(PrivateKey|PublicKey)\b|\bed25519\b",
        risk="high",
        languages=("python",),
        description="Ed25519 / EdDSA classical signature",
    ),
    Rule(
        id="py-dh",
        family="DH",
        pattern=r"\bdh\.(generate_parameters|DHPrivateKey)\b|\bDiffieHellman\b",
        risk="high",
        languages=("python",),
        description="Finite-field Diffie-Hellman",
    ),
    Rule(
        id="py-ssl",
        family="TLS/SSL",
        pattern=r"\bimport\s+ssl\b|\bssl\.(create_default_context|SSLContext|wrap_socket)\b",
        risk="medium",
        languages=("python",),
        description="stdlib ssl / TLS wrapper (check cipher suites)",
    ),
    # Cipher-suite algorithm is more specific than the protocol label.
    # Same logical TLS site must not be scored as both protocol and algorithm.
    Rule(
        id="py-tls-cipher-rsa",
        family="RSA",
        pattern=r"(?i)\b(?:ECDHE|DHE|ECDH)-RSA(?:-[A-Z0-9]+)*\b|\bTLS_(?:ECDHE|DHE)_RSA\b",
        risk="high",
        languages=("python",),
        description="TLS cipher suite using classical RSA",
    ),
    Rule(
        id="py-tls-cipher-ecdsa",
        family="ECDSA",
        pattern=r"(?i)\b(?:ECDHE|ECDH)-ECDSA(?:-[A-Z0-9]+)*\b|\bTLS_ECDHE_ECDSA\b",
        risk="high",
        languages=("python",),
        description="TLS cipher suite using classical ECDSA",
    ),
    Rule(
        id="py-tls-cipher-aes",
        family="AES",
        pattern=r"(?i)\bAES(?:128|256)-(?:GCM-SHA\d+|SHA(?:256|384)?)\b",
        risk="low",
        languages=("python",),
        description="TLS cipher suite AES algorithm",
    ),
    Rule(
        id="py-cryptography-lib",
        family="cryptography",
        pattern=r"\bfrom\s+cryptography\b|\bimport\s+cryptography\b",
        risk="medium",
        languages=("python",),
        description="cryptography package (verify algorithms used)",
    ),
    Rule(
        id="py-pycryptodome",
        family="PyCryptodome",
        pattern=r"\bfrom\s+Crypto\b|\bfrom\s+Cryptodome\b|\bimport\s+Crypto\b",
        risk="medium",
        languages=("python",),
        description="PyCryptodome / PyCrypto import",
    ),
    Rule(
        id="py-aes",
        family="AES",
        pattern=r"\balgorithms\.AES\b|\bAES\.new\b|\bCipher\(algorithms\.AES",
        risk="low",
        languages=("python",),
        description="AES symmetric encryption",
    ),
    Rule(
        id="py-chacha",
        family="ChaCha20",
        pattern=r"\bChaCha20\b|\balgorithms\.ChaCha20\b",
        risk="low",
        languages=("python",),
        description="ChaCha20 stream cipher",
    ),
    Rule(
        id="py-hashlib",
        family="SHA/Hash",
        pattern=r"\bhashlib\.(sha256|sha384|sha512|sha3_\d+|blake2|md5|sha1)\b|\bimport\s+hashlib\b",
        risk="info",
        languages=("python",),
        description="hashlib digest / integrity",
    ),
]

# ---------------------------------------------------------------------------
# JavaScript / TypeScript source patterns
# ---------------------------------------------------------------------------
JS_RULES: list[Rule] = [
    Rule(
        id="js-node-crypto-rsa",
        family="RSA",
        pattern=r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]|\bprivateEncrypt\b|\bpublicDecrypt\b|\bcreateSign\s*\(\s*['\"]RSA-",
        risk="high",
        languages=("javascript",),
        description="Node.js crypto RSA",
    ),
    Rule(
        id="js-node-crypto-ec",
        family="ECDSA/ECDH",
        pattern=r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"]|\bcreateECDH\b|\bcreateSign\s*\(\s*['\"]ECDSA",
        risk="high",
        languages=("javascript",),
        description="Node.js crypto EC / ECDH",
    ),
    Rule(
        id="js-node-crypto-ed",
        family="EdDSA",
        pattern=r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"]ed25519['\"]|\b['\"]ed25519['\"]",
        risk="high",
        languages=("javascript",),
        description="Node.js Ed25519",
    ),
    Rule(
        id="js-forge-rsa",
        family="RSA",
        pattern=r"\bforge\.pki\.(rsa|privateKeyFromPem|publicKeyFromPem)\b|\bforge\.rsa\b",
        risk="high",
        languages=("javascript",),
        description="node-forge RSA",
    ),
    Rule(
        id="js-jose-rsa-ec",
        family="JWT/JOSE",
        pattern=r"\b(RS256|RS384|RS512|ES256|ES384|ES512|PS256)\b|\bimport\s+.*\bfrom\s+['\"]jose['\"]",
        risk="high",
        languages=("javascript",),
        description="jose / JWT classical RSA or ECDSA algs",
    ),
    Rule(
        id="js-webcrypto-rsa-ec",
        family="WebCrypto",
        pattern=r"\bsubtle\.(generateKey|sign|verify|encrypt|decrypt)\b[\s\S]{0,80}(RSA-|ECDSA|ECDH)",
        risk="high",
        languages=("javascript",),
        description="Web Crypto API RSA/ECDSA/ECDH",
    ),
    Rule(
        id="js-webcrypto-rsa-alg",
        family="RSA",
        pattern=r"\b(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5)\b",
        risk="high",
        languages=("javascript",),
        description="WebCrypto RSA algorithm name",
    ),
    Rule(
        id="js-webcrypto-ec-alg",
        family="ECDSA/ECDH",
        pattern=r"\b(ECDSA|ECDH)\b.*\b(P-256|P-384|P-521)\b|\bnamedCurve\s*:\s*['\"]P-\d+",
        risk="high",
        languages=("javascript",),
        description="WebCrypto classical EC curves",
    ),
    Rule(
        id="js-tls",
        family="TLS/SSL",
        pattern=r"""require\s*\(\s*['"](?:node:)?(?:tls|https)['"]\s*\)|from\s+['"](?:node:)?(?:tls|https)['"]|\btls\.(createServer|connect)\b|\bhttps\.(createServer|request|get)\b""",
        risk="medium",
        languages=("javascript",),
        description="Node tls/https protocol wrapper (check cipher suites)",
    ),
    Rule(
        id="js-tls-cipher-rsa",
        family="RSA",
        pattern=r"(?i)\b(?:ECDHE|DHE|ECDH)-RSA(?:-[A-Z0-9]+)*\b|\bTLS_(?:ECDHE|DHE)_RSA\b",
        risk="high",
        languages=("javascript",),
        description="TLS cipher suite using classical RSA",
    ),
    Rule(
        id="js-tls-cipher-ecdsa",
        family="ECDSA",
        pattern=r"(?i)\b(?:ECDHE|ECDH)-ECDSA(?:-[A-Z0-9]+)*\b|\bTLS_ECDHE_ECDSA\b",
        risk="high",
        languages=("javascript",),
        description="TLS cipher suite using classical ECDSA",
    ),
    Rule(
        id="js-node-crypto-require",
        family="node:crypto",
        pattern=r"""require\s*\(\s*['"]crypto['"]\s*\)|from\s+['"](?:node:)?crypto['"]""",
        risk="medium",
        languages=("javascript",),
        description="Node crypto module import",
    ),
    Rule(
        id="js-forge-import",
        family="node-forge",
        pattern=r"""require\s*\(\s*['"]node-forge['"]\s*\)|from\s+['"]node-forge['"]""",
        risk="medium",
        languages=("javascript",),
        description="node-forge import",
    ),
    Rule(
        id="js-aes",
        family="AES",
        pattern=r"\bcreateCipheriv\s*\(\s*['\"]aes-|\bAES-(GCM|CBC|CTR)\b|\balgorithm:\s*['\"]AES-",
        risk="low",
        languages=("javascript",),
        description="AES symmetric encryption",
    ),
    Rule(
        id="js-chacha",
        family="ChaCha20",
        pattern=r"\bchacha20|ChaCha20-Poly1305\b",
        risk="low",
        languages=("javascript",),
        description="ChaCha20 / Poly1305",
    ),
    Rule(
        id="js-hash",
        family="SHA/Hash",
        pattern=r"\bcreateHash\s*\(\s*['\"]sha(256|384|512|1)['\"]|\bSHA-(256|384|512)\b",
        risk="info",
        languages=("javascript",),
        description="SHA hash / integrity",
    ),
]

# ---------------------------------------------------------------------------
# Manifest / dependency patterns
# ---------------------------------------------------------------------------
MANIFEST_RULES: list[Rule] = [
    Rule(
        id="dep-pycryptodome",
        family="PyCryptodome",
        pattern=r"(?i)\b(pycryptodome|pycrypto)\b",
        risk="medium",
        languages=("manifest",),
        description="PyCryptodome/PyCrypto dependency",
    ),
    Rule(
        id="dep-cryptography",
        family="cryptography",
        pattern=r"(?i)^\s*cryptography\s*[>=<!~]|[\"']cryptography[\"']\s*:",
        risk="medium",
        languages=("manifest",),
        description="cryptography package dependency",
    ),
    Rule(
        id="dep-rsa",
        family="RSA",
        pattern=r"(?i)^\s*rsa\s*[>=<!~]|[\"']rsa[\"']\s*:",
        risk="high",
        languages=("manifest",),
        description="rsa package dependency",
    ),
    Rule(
        id="dep-ecdsa",
        family="ECDSA",
        pattern=r"(?i)^\s*ecdsa\s*[>=<!~]|[\"']ecdsa[\"']\s*:",
        risk="high",
        languages=("manifest",),
        description="ecdsa package dependency",
    ),
    Rule(
        id="dep-node-forge",
        family="node-forge",
        pattern=r"[\"']node-forge[\"']\s*:",
        risk="medium",
        languages=("manifest",),
        description="node-forge dependency",
    ),
    Rule(
        id="dep-jose",
        family="JWT/JOSE",
        pattern=r"[\"']jose[\"']\s*:",
        risk="medium",
        languages=("manifest",),
        description="jose dependency (check alg usage)",
    ),
    Rule(
        id="dep-pyjwt",
        family="JWT",
        pattern=r"(?i)^\s*PyJWT\s*[>=<!~]|[\"']pyjwt[\"']\s*:",
        risk="medium",
        languages=("manifest",),
        description="PyJWT dependency",
    ),
]

ALL_RULES: list[Rule] = PYTHON_RULES + JS_RULES + MANIFEST_RULES


def classify_risk(family: str, risk: Risk) -> tuple[int, str]:
    """Return (priority, reason) for a finding."""
    return PRIORITY_BY_RISK[risk], REASON_BY_RISK[risk]

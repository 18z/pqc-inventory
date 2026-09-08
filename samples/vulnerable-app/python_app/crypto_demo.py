"""Intentionally uses classical crypto APIs for scanner demo (not production)."""

# pqc-inventory-file: owner=sample-python-team

import hashlib
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import ecdsa

# RSA key generation — quantum high risk (Shor)
# Long-lived payment material: explicit lifetime + exposure override (demo).
# pqc-inventory: lifetime=15 exposure=public_key owner=payments
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Classical ECDSA / ECDH
# pqc-inventory: lifetime=8 exposure=public_key
ec_key = ec.generate_private_key(ec.SECP256R1())

# Ed25519 classical signature
ed_key = ed25519.Ed25519PrivateKey.generate()

# python-ecdsa
sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)

# TLS wrapper — medium (check suites / PQC readiness)
# pqc-inventory: lifetime=5 exposure=trust_boundary owner=edge-tls
ctx = ssl.create_default_context()

# AES — low (prefer 256-bit under Grover)
aes_cipher = Cipher(algorithms.AES(b"0" * 32), modes.ECB())

# Hash integrity — info (no lifetime override; remains unknown)
digest = hashlib.sha256(b"demo").hexdigest()

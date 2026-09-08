"""Intentionally uses classical crypto APIs for scanner demo (not production)."""

import hashlib
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import ecdsa

# RSA key generation — quantum high risk (Shor)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Classical ECDSA / ECDH
ec_key = ec.generate_private_key(ec.SECP256R1())

# Ed25519 classical signature
ed_key = ed25519.Ed25519PrivateKey.generate()

# python-ecdsa
sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)

# TLS wrapper — medium (check suites / PQC readiness)
ctx = ssl.create_default_context()

# AES — low (prefer 256-bit under Grover)
aes_cipher = Cipher(algorithms.AES(b"0" * 32), modes.ECB())

# Hash integrity — info
digest = hashlib.sha256(b"demo").hexdigest()

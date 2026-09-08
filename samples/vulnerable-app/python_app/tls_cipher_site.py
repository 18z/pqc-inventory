"""TLS site fixture: protocol wrapper and cipher-suite algorithm are one site.

A later local RSA keygen is a different site and must stay a separate asset.
"""

import ssl


def edge_tls_site():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    return ctx


# Different site: local key generation, not this TLS configuration.


















def unrelated_local_rsa():
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

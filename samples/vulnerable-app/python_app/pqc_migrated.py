"""Intentional NIST PQC API / string usage for scanner demo (not production).

These hits should classify as quantum_risk=safe (already-migrated), appear in
inventory/CBOM/report, and be omitted from SARIF alerts.
"""

# Example ML-KEM (FIPS 203) encapsulate helper name / string
ML_KEM_768 = "ML-KEM-768"
kyber_alg = "Kyber768"

# Example ML-DSA (FIPS 204) / Dilithium
ML_DSA_65 = "ML-DSA-65"
dilithium_alg = "Dilithium3"

# Example SLH-DSA (FIPS 205) / SPHINCS+
SLH_DSA = "SLH-DSA-SHA2-128s"
sphincs_alg = "SPHINCS+"

# Falcon (alternate / round-3 style name still tracked as PQC)
falcon_alg = "Falcon-512"

# liboqs-style usage hint
# oqs.KeyEncapsulation("ML-KEM-768")

# PQC Cryptographic Asset Inventory Report

> **Scope:** This is a **static scan of source code and dependency manifests only**, **not runtime** (not network traffic, binaries, negotiated TLS, or a complete CBOM).

- **Tool**: pqc-inventory v0.1.1
- **Target**: `/workspace/a3-pqc-inventory/samples/vulnerable-app`
- **Generated (UTC)**: 2026-09-11T01:14:39.288243+00:00
- **Files scanned**: 7
- **Findings (merged)**: 49 (raw hits before merge: 57)

## Risk summary

| Risk | Count |
|------|------:|
| high | 19 |
| medium | 9 |
| low | 2 |
| info | 3 |

## Findings by algorithm / API family

| Family | Count |
|--------|------:|
| RSA | 9 |
| ECDSA/ECDH | 4 |
| ML-DSA | 4 |
| ML-KEM | 4 |
| PQC | 4 |
| SLH-DSA | 4 |
| AES | 3 |
| ECDSA | 3 |
| EdDSA | 3 |
| SHA/Hash | 3 |
| TLS/SSL | 3 |
| cryptography | 3 |
| JWT/JOSE | 2 |
| node-forge | 2 |
| JWT | 1 |
| PyCryptodome | 1 |
| node:crypto | 1 |

## Prioritized findings

_Sorted by **priority_score** (quantum risk + data lifetime + exposure). Same-site multi-rule hits are merged so the top-N is readable._

### 1. [HIGH] RSA — cryptography.io RSA API

- **Location**: `python_app/crypto_demo.py`:14
- **Rules**: `py-rsa-crypto`
- **Families**: RSA
- **Priority rank**: 1
- **Priority score**: 152
- **Priority reason**: score=152 (risk=high:100 + lifetime 15y (override):30 + exposure=public-key / asymmetric API:22) [exposure override] [lifetime override]
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: payments
- **Data lifetime (years)**: 15
- **Overrides applied**: owner←annotation, data_lifetime_years←annotation, exposure←annotation
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)`

### 2. [HIGH] JWT/JOSE — jose / JWT classical RSA or ECDSA algs

- **Location**: `js_app/crypto_demo.js`:23
- **Rules**: `js-jose-rsa-ec`
- **Families**: JWT/JOSE
- **Priority rank**: 2
- **Priority score**: 150
- **Priority reason**: score=150 (risk=high:100 + lifetime 10y (override):20 + exposure=network/TLS/JWT trust boundary:30) [exposure override] [lifetime override]
- **Exposure**: trust_boundary
- **Quantum risk**: high
- **Owner**: auth
- **Data lifetime (years)**: 10
- **Overrides applied**: owner←annotation, data_lifetime_years←annotation, exposure←annotation
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `const alg = 'RS256';`

### 3. [HIGH] RSA — TLS cipher suite using classical RSA (+2 overlapping rules) (+1 overlapping rules)

- **Location**: `python_app/tls_cipher_site.py`:11
- **Rules**: `py-ssl`, `py-tls-cipher-aes`, `py-tls-cipher-rsa` _(merged 4 hits)_
- **Families**: AES, RSA, TLS/SSL
- **Priority rank**: 3
- **Priority score**: 150
- **Priority reason**: score=150 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=network/TLS/JWT trust boundary:30)
- **Exposure**: trust_boundary
- **Quantum risk**: high
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")`

### 4. [HIGH] RSA — Node.js crypto RSA

- **Location**: `js_app/crypto_demo.js`:9
- **Rules**: `js-node-crypto-rsa`
- **Families**: RSA
- **Priority rank**: 4
- **Priority score**: 146
- **Priority reason**: score=146 (risk=high:100 + lifetime 12y (override):24 + exposure=public-key / asymmetric API:22) [exposure override] [lifetime override]
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: key-mgmt
- **Data lifetime (years)**: 12
- **Overrides applied**: owner←annotation, data_lifetime_years←annotation, exposure←annotation
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });`

### 5. [HIGH] ECDSA/ECDH — Node.js crypto EC / ECDH (+1 overlapping rules)

- **Location**: `js_app/crypto_demo.js`:12
- **Rules**: `js-node-crypto-ec`, `js-webcrypto-ec-alg` _(merged 2 hits)_
- **Families**: ECDSA/ECDH
- **Priority rank**: 5
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });`

### 6. [HIGH] ECDSA/ECDH — Node.js crypto EC / ECDH

- **Location**: `js_app/crypto_demo.js`:13
- **Rules**: `js-node-crypto-ec`
- **Families**: ECDSA/ECDH
- **Priority rank**: 6
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `const ecdh = crypto.createECDH('prime256v1');`

### 7. [HIGH] EdDSA — Node.js Ed25519

- **Location**: `js_app/crypto_demo.js`:16
- **Rules**: `js-node-crypto-ed`
- **Families**: EdDSA
- **Priority rank**: 7
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `crypto.generateKeyPairSync('ed25519');`

### 8. [HIGH] RSA — node-forge RSA

- **Location**: `js_app/crypto_demo.js`:19
- **Rules**: `js-forge-rsa`
- **Families**: RSA
- **Priority rank**: 8
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });`

### 9. [HIGH] RSA — WebCrypto RSA algorithm name

- **Location**: `js_app/crypto_demo.js`:26
- **Rules**: `js-webcrypto-rsa-alg`
- **Families**: RSA
- **Priority rank**: 9
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `const rsaAlg = 'RSA-OAEP';`

### 10. [HIGH] ECDSA/ECDH — WebCrypto classical EC curves

- **Location**: `js_app/crypto_demo.js`:27
- **Rules**: `js-webcrypto-ec-alg`
- **Families**: ECDSA/ECDH
- **Priority rank**: 10
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `const ecAlg = { name: 'ECDSA', namedCurve: 'P-256' };`

### 11. [HIGH] EdDSA — Ed25519 / EdDSA classical signature (+2 overlapping rules)

- **Location**: `python_app/crypto_demo.py`:7
- **Rules**: `py-cryptography-lib`, `py-ed25519`, `py-rsa-module` _(merged 4 hits)_
- **Families**: EdDSA, RSA, cryptography
- **Priority rank**: 11
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519`

### 12. [HIGH] ECDSA — python-ecdsa classical signatures

- **Location**: `python_app/crypto_demo.py`:9
- **Rules**: `py-ecdsa`
- **Families**: ECDSA
- **Priority rank**: 12
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `import ecdsa`

### 13. [HIGH] EdDSA — Ed25519 / EdDSA classical signature

- **Location**: `python_app/crypto_demo.py`:21
- **Rules**: `py-ed25519`
- **Families**: EdDSA
- **Priority rank**: 13
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `ed_key = ed25519.Ed25519PrivateKey.generate()`

### 14. [HIGH] ECDSA — python-ecdsa classical signatures

- **Location**: `python_app/crypto_demo.py`:24
- **Rules**: `py-ecdsa`
- **Families**: ECDSA
- **Priority rank**: 14
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)`

### 15. [HIGH] ECDSA — ecdsa package dependency

- **Location**: `python_app/requirements.txt`:2
- **Rules**: `dep-ecdsa`
- **Families**: ECDSA
- **Priority rank**: 15
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `ecdsa>=0.18.0`

### 16. [HIGH] RSA — rsa package dependency

- **Location**: `python_app/requirements.txt`:3
- **Rules**: `dep-rsa`
- **Families**: RSA
- **Priority rank**: 16
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `rsa>=4.9`

### 17. [HIGH] RSA — python-rsa / rsa package import (+1 overlapping rules)

- **Location**: `python_app/tls_cipher_site.py`:35
- **Rules**: `py-cryptography-lib`, `py-rsa-module` _(merged 2 hits)_
- **Families**: RSA, cryptography
- **Priority rank**: 17
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `from cryptography.hazmat.primitives.asymmetric import rsa`

### 18. [HIGH] RSA — cryptography.io RSA API

- **Location**: `python_app/tls_cipher_site.py`:37
- **Rules**: `py-rsa-crypto`
- **Families**: RSA
- **Priority rank**: 18
- **Priority score**: 142
- **Priority reason**: score=142 (risk=high:100 + lifetime unknown→mid(+unknown penalty):20 + exposure=public-key / asymmetric API:22)
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `return rsa.generate_private_key(public_exponent=65537, key_size=2048)`

### 19. [HIGH] ECDSA/ECDH — cryptography.io elliptic-curve API

- **Location**: `python_app/crypto_demo.py`:18
- **Rules**: `py-ec-crypto`
- **Families**: ECDSA/ECDH
- **Priority rank**: 19
- **Priority score**: 138
- **Priority reason**: score=138 (risk=high:100 + lifetime 8y (override):16 + exposure=public-key / asymmetric API:22) [exposure override] [lifetime override]
- **Exposure**: public_key
- **Quantum risk**: high
- **Owner**: sample-python-team
- **Data lifetime (years)**: 8
- **Overrides applied**: owner←annotation-file, data_lifetime_years←annotation, exposure←annotation
- **Suppressed**: no
- **Risk rationale**: Classical public-key scheme vulnerable to Shor's algorithm; plan migration to NIST PQC (ML-KEM / ML-DSA / SLH-DSA) for long-term trust.
- **Snippet**: `ec_key = ec.generate_private_key(ec.SECP256R1())`

### 20. [MEDIUM] JWT/JOSE — jose dependency (check alg usage)

- **Location**: `js_app/package.json`:7
- **Rules**: `dep-jose`
- **Families**: JWT/JOSE
- **Priority rank**: 20
- **Priority score**: 90
- **Priority reason**: score=90 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=network/TLS/JWT trust boundary:30)
- **Exposure**: trust_boundary
- **Quantum risk**: medium
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `"jose": "^5.2.0"`

### 21. [MEDIUM] TLS/SSL — stdlib ssl / TLS wrapper (check cipher suites)

- **Location**: `python_app/crypto_demo.py`:6
- **Rules**: `py-ssl`
- **Families**: TLS/SSL
- **Priority rank**: 21
- **Priority score**: 90
- **Priority reason**: score=90 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=network/TLS/JWT trust boundary:30)
- **Exposure**: trust_boundary
- **Quantum risk**: medium
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `import ssl`

### 22. [MEDIUM] JWT — PyJWT dependency

- **Location**: `python_app/requirements.txt`:5
- **Rules**: `dep-pyjwt`
- **Families**: JWT
- **Priority rank**: 22
- **Priority score**: 90
- **Priority reason**: score=90 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=network/TLS/JWT trust boundary:30)
- **Exposure**: trust_boundary
- **Quantum risk**: medium
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `PyJWT>=2.8.0`

### 23. [MEDIUM] TLS/SSL — stdlib ssl / TLS wrapper (check cipher suites)

- **Location**: `python_app/crypto_demo.py`:28
- **Rules**: `py-ssl`
- **Families**: TLS/SSL
- **Priority rank**: 23
- **Priority score**: 80
- **Priority reason**: score=80 (risk=medium:40 + lifetime 5y (override):10 + exposure=network/TLS/JWT trust boundary:30) [exposure override] [lifetime override]
- **Exposure**: trust_boundary
- **Quantum risk**: medium
- **Owner**: edge-tls
- **Data lifetime (years)**: 5
- **Overrides applied**: owner←annotation, data_lifetime_years←annotation, exposure←annotation
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `ctx = ssl.create_default_context()`

### 24. [MEDIUM] node:crypto — Node crypto module import

- **Location**: `js_app/crypto_demo.js`:3
- **Rules**: `js-node-crypto-require`
- **Families**: node:crypto
- **Priority rank**: 24
- **Priority score**: 72
- **Priority reason**: score=72 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=crypto library import or dependency:12)
- **Exposure**: library_import
- **Quantum risk**: medium
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `const crypto = require('crypto');`

### 25. [MEDIUM] node-forge — node-forge import

- **Location**: `js_app/crypto_demo.js`:4
- **Rules**: `js-forge-import`
- **Families**: node-forge
- **Priority rank**: 25
- **Priority score**: 72
- **Priority reason**: score=72 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=crypto library import or dependency:12)
- **Exposure**: library_import
- **Quantum risk**: medium
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `const forge = require('node-forge');`

### 26. [MEDIUM] node-forge — node-forge dependency

- **Location**: `js_app/package.json`:6
- **Rules**: `dep-node-forge`
- **Families**: node-forge
- **Priority rank**: 26
- **Priority score**: 72
- **Priority reason**: score=72 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=crypto library import or dependency:12)
- **Exposure**: library_import
- **Quantum risk**: medium
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `"node-forge": "^1.3.1",`

### 27. [MEDIUM] cryptography — cryptography package dependency

- **Location**: `python_app/requirements.txt`:1
- **Rules**: `dep-cryptography`
- **Families**: cryptography
- **Priority rank**: 27
- **Priority score**: 72
- **Priority reason**: score=72 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=crypto library import or dependency:12)
- **Exposure**: library_import
- **Quantum risk**: medium
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `cryptography>=41.0.0`

### 28. [MEDIUM] PyCryptodome — PyCryptodome/PyCrypto dependency

- **Location**: `python_app/requirements.txt`:4
- **Rules**: `dep-pycryptodome`
- **Families**: PyCryptodome
- **Priority rank**: 28
- **Priority score**: 72
- **Priority reason**: score=72 (risk=medium:40 + lifetime unknown→mid(+unknown penalty):20 + exposure=crypto library import or dependency:12)
- **Exposure**: library_import
- **Quantum risk**: medium
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: TLS or crypto wrapper usage without clear PQC hybrid; verify cipher suites and library PQC readiness.
- **Snippet**: `pycryptodome>=3.19.0`

### 29. [LOW] AES — AES symmetric encryption

- **Location**: `js_app/crypto_demo.js`:30
- **Rules**: `js-aes`
- **Families**: AES
- **Priority rank**: 29
- **Priority score**: 41
- **Priority reason**: score=41 (risk=low:15 + lifetime unknown→mid(+unknown penalty):20 + exposure=local symmetric cipher:6)
- **Exposure**: symmetric
- **Quantum risk**: low
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Symmetric cipher: Grover's algorithm roughly halves effective key bits; AES-256 / ChaCha20 remain practical; prefer 256-bit keys.
- **Snippet**: `const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));`

### 30. [LOW] AES — AES symmetric encryption

- **Location**: `python_app/crypto_demo.py`:31
- **Rules**: `py-aes`
- **Families**: AES
- **Priority rank**: 30
- **Priority score**: 41
- **Priority reason**: score=41 (risk=low:15 + lifetime unknown→mid(+unknown penalty):20 + exposure=local symmetric cipher:6)
- **Exposure**: symmetric
- **Quantum risk**: low
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: no
- **Risk rationale**: Symmetric cipher: Grover's algorithm roughly halves effective key bits; AES-256 / ChaCha20 remain practical; prefer 256-bit keys.
- **Snippet**: `aes_cipher = Cipher(algorithms.AES(b"0" * 32), modes.ECB())`

### 31. [SAFE] PQC — liboqs / pqcrypto dependency (PQC)

- **Location**: `python_app/requirements.txt`:6
- **Rules**: `dep-liboqs`
- **Families**: PQC
- **Priority rank**: 31
- **Priority score**: 32
- **Priority reason**: score=32 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=crypto library import or dependency:12)
- **Exposure**: library_import
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `# PQC (demo): oqs-python / liboqs bindings — expected SAFE in inventory`

### 32. [SAFE] PQC — liboqs / pqcrypto dependency (PQC)

- **Location**: `python_app/requirements.txt`:7
- **Rules**: `dep-liboqs`
- **Families**: PQC
- **Priority rank**: 32
- **Priority score**: 32
- **Priority reason**: score=32 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=crypto library import or dependency:12)
- **Exposure**: library_import
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `# oqs-python>=0.10.0`

### 33. [SAFE] ML-KEM — NIST ML-KEM (Kyber) post-quantum KEM

- **Location**: `js_app/pqc_migrated.js`:4
- **Rules**: `js-ml-kem`
- **Families**: ML-KEM
- **Priority rank**: 33
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `const ML_KEM = 'ML-KEM-768';`

### 34. [SAFE] ML-KEM — NIST ML-KEM (Kyber) post-quantum KEM

- **Location**: `js_app/pqc_migrated.js`:5
- **Rules**: `js-ml-kem`
- **Families**: ML-KEM
- **Priority rank**: 34
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `const kyber = 'Kyber768';`

### 35. [SAFE] ML-DSA — NIST ML-DSA (Dilithium) post-quantum signature

- **Location**: `js_app/pqc_migrated.js`:6
- **Rules**: `js-ml-dsa`
- **Families**: ML-DSA
- **Priority rank**: 35
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `const ML_DSA = 'ML-DSA-65';`

### 36. [SAFE] ML-DSA — NIST ML-DSA (Dilithium) post-quantum signature

- **Location**: `js_app/pqc_migrated.js`:7
- **Rules**: `js-ml-dsa`
- **Families**: ML-DSA
- **Priority rank**: 36
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `const dilithium = 'Dilithium3';`

### 37. [SAFE] SLH-DSA — NIST SLH-DSA (SPHINCS+) post-quantum signature

- **Location**: `js_app/pqc_migrated.js`:8
- **Rules**: `js-slh-dsa`
- **Families**: SLH-DSA
- **Priority rank**: 37
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `const SLH_DSA = 'SLH-DSA-SHA2-128s';`

### 38. [SAFE] SLH-DSA — NIST SLH-DSA (SPHINCS+) post-quantum signature

- **Location**: `js_app/pqc_migrated.js`:9
- **Rules**: `js-slh-dsa`
- **Families**: SLH-DSA
- **Priority rank**: 38
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `const sphincs = 'SPHINCS+';`

### 39. [SAFE] PQC — Falcon post-quantum signature

- **Location**: `js_app/pqc_migrated.js`:10
- **Rules**: `js-falcon`
- **Families**: PQC
- **Priority rank**: 39
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `const falcon = 'Falcon-512';`

### 40. [SAFE] ML-KEM — NIST ML-KEM (Kyber) post-quantum KEM

- **Location**: `python_app/pqc_migrated.py`:8
- **Rules**: `py-ml-kem`
- **Families**: ML-KEM
- **Priority rank**: 40
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `ML_KEM_768 = "ML-KEM-768"`

### 41. [SAFE] ML-KEM — NIST ML-KEM (Kyber) post-quantum KEM

- **Location**: `python_app/pqc_migrated.py`:9
- **Rules**: `py-ml-kem`
- **Families**: ML-KEM
- **Priority rank**: 41
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `kyber_alg = "Kyber768"`

### 42. [SAFE] ML-DSA — NIST ML-DSA (Dilithium) post-quantum signature

- **Location**: `python_app/pqc_migrated.py`:12
- **Rules**: `py-ml-dsa`
- **Families**: ML-DSA
- **Priority rank**: 42
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `ML_DSA_65 = "ML-DSA-65"`

### 43. [SAFE] ML-DSA — NIST ML-DSA (Dilithium) post-quantum signature

- **Location**: `python_app/pqc_migrated.py`:13
- **Rules**: `py-ml-dsa`
- **Families**: ML-DSA
- **Priority rank**: 43
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `dilithium_alg = "Dilithium3"`

### 44. [SAFE] SLH-DSA — NIST SLH-DSA (SPHINCS+) post-quantum signature

- **Location**: `python_app/pqc_migrated.py`:16
- **Rules**: `py-slh-dsa`
- **Families**: SLH-DSA
- **Priority rank**: 44
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `SLH_DSA = "SLH-DSA-SHA2-128s"`

### 45. [SAFE] SLH-DSA — NIST SLH-DSA (SPHINCS+) post-quantum signature

- **Location**: `python_app/pqc_migrated.py`:17
- **Rules**: `py-slh-dsa`
- **Families**: SLH-DSA
- **Priority rank**: 45
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `sphincs_alg = "SPHINCS+"`

### 46. [SAFE] PQC — Falcon post-quantum signature (NIST round / alternate)

- **Location**: `python_app/pqc_migrated.py`:20
- **Rules**: `py-falcon`
- **Families**: PQC
- **Priority rank**: 46
- **Priority score**: 22
- **Priority reason**: score=22 (risk=safe:0 + lifetime unknown→mid(+unknown penalty):20 + exposure=NIST PQC / already-migrated:2)
- **Exposure**: pqc_migrated
- **Quantum risk**: safe
- **Owner**: 
- **Data lifetime (years)**: unknown
- **Overrides applied**: (none)
- **Suppressed**: no
- **Risk rationale**: Already-migrated / NIST PQC (ML-KEM, ML-DSA, SLH-DSA or known aliases Kyber/Dilithium/Falcon/SPHINCS+). Tracked for inventory completeness — not a vulnerability.
- **Snippet**: `falcon_alg = "Falcon-512"`

### 47. [INFO] SHA/Hash — SHA hash / integrity

- **Location**: `js_app/crypto_demo.js`:33
- **Rules**: `js-hash`
- **Families**: SHA/Hash
- **Priority rank**: 47
- **Priority score**: 8
- **Priority reason**: score=27 (risk=info:5 + lifetime unknown→mid(+unknown penalty):20 + exposure=local hash / integrity helper:2); hash/checksum suppressed (downrank cap=8)
- **Exposure**: hash_local
- **Quantum risk**: info
- **Owner**: sample-js-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: yes
- **Risk rationale**: Hash / integrity primitive: generally acceptable post-quantum for integrity; prefer SHA-256+ or SHA-3; note Grover impact on brute-force.
- **Snippet**: `const hash = crypto.createHash('sha256').update('demo').digest('hex');`

### 48. [INFO] SHA/Hash — hashlib digest / integrity

- **Location**: `python_app/crypto_demo.py`:5
- **Rules**: `py-hashlib`
- **Families**: SHA/Hash
- **Priority rank**: 48
- **Priority score**: 8
- **Priority reason**: score=27 (risk=info:5 + lifetime unknown→mid(+unknown penalty):20 + exposure=local hash / integrity helper:2); hash/checksum suppressed (downrank cap=8)
- **Exposure**: hash_local
- **Quantum risk**: info
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: yes
- **Risk rationale**: Hash / integrity primitive: generally acceptable post-quantum for integrity; prefer SHA-256+ or SHA-3; note Grover impact on brute-force.
- **Snippet**: `import hashlib`

### 49. [INFO] SHA/Hash — hashlib digest / integrity

- **Location**: `python_app/crypto_demo.py`:34
- **Rules**: `py-hashlib`
- **Families**: SHA/Hash
- **Priority rank**: 49
- **Priority score**: 8
- **Priority reason**: score=27 (risk=info:5 + lifetime unknown→mid(+unknown penalty):20 + exposure=local hash / integrity helper:2); hash/checksum suppressed (downrank cap=8)
- **Exposure**: hash_local
- **Quantum risk**: info
- **Owner**: sample-python-team
- **Data lifetime (years)**: unknown
- **Overrides applied**: owner←annotation-file
- **Suppressed**: yes
- **Risk rationale**: Hash / integrity primitive: generally acceptable post-quantum for integrity; prefer SHA-256+ or SHA-3; note Grover impact on brute-force.
- **Snippet**: `digest = hashlib.sha256(b"demo").hexdigest()`


## Plain-language next steps (for compliance / crypto owners)

1. **Triage by priority score (not raw HIGH count)** — Score blends quantum risk,
   data lifetime, and exposure (trust-boundary TLS/JWT vs local hash helper).
2. **Inventory & ownership** — Set `owner` / `data_lifetime_years` / `exposure` via
   in-file annotations or CLI overrides only (never guessed by the scanner);
   assets that must remain confidential/authentic for 10+ years need earlier PQC planning.
3. **Prefer hybrid / NIST PQC** — Track library support for ML-KEM (FIPS 203), ML-DSA (FIPS 204),
   and SLH-DSA (FIPS 205). Prefer vendor hybrids (classical + PQC) during transition.
4. **Symmetric & hashes** — AES-128 is weakened under Grover (~64-bit effective search);
   prefer AES-256 / ChaCha20. SHA-256+ / SHA-3 remain fine for integrity; avoid MD5/SHA-1.
5. **TLS** — Confirm cipher suites and CA/PKI roadmap; monitor OpenSSL / browser PQC pilots.
6. **This tool is defensive-only** — It does not migrate keys, break crypto, or suggest exploits.
   Use results as an inventory input for your crypto-agility program.


## Planning references (not certification)

These are **planning references only**. This tool does **not** certify compliance with
EO 14412, CNSA 2.0, NIST IR 8547, or any other mandate.

| Reference | Note |
|-----------|------|
| EO 14412 CBOM minimum elements | CISA + NIST public guidance due ~270 days after 2026-06-22 (≈ 2027-03) |
| EO 14412 PQC key establishment | HVA / high-impact systems target **2030-12-31** |
| EO 14412 PQC digital signatures | HVA / high-impact systems target **2031-12-31** |
| NSA CNSA 2.0 | Migration planning reference |
| NIST IR 8547 | Transition planning reference |

CBOM `metadata.properties` repeats these under `pqc-inventory:ref:*` for downstream tooling.

## Quantum-risk legend

- **high** — RSA, classical ECDSA/ECDH/EdDSA (long-term trust), finite-field DH
- **medium** — Ambiguous TLS/crypto wrappers without clear PQC
- **low** — AES/ChaCha (note Grover; prefer 256-bit keys)
- **info** — SHA-2/3 integrity hashing

## Scope reminder

**Scope:** This is a **static scan of source code and dependency manifests only**, **not runtime** (not network traffic, binaries, negotiated TLS, or a complete CBOM).

This report is produced by a **defensive** static inventory scanner. It does **not** implement attacks, exploits, migration engines, or key-breaking.

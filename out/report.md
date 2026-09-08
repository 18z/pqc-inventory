# PQC Cryptographic Asset Inventory Report

> **Scope:** static analysis of source code + dependency manifests only — not runtime, binaries, network traffic, or a complete coverage guarantee.

- **Tool**: pqc-inventory v0.1.0
- **Target**: `/workspace/a3-pqc-inventory/samples/vulnerable-app`
- **Generated (UTC)**: 2026-09-08T01:30:22.132208+00:00
- **Files scanned**: 4
- **Findings (merged)**: 30 (raw hits before merge: 34)

## Risk summary

| Risk | Count |
|------|------:|
| high | 16 |
| medium | 9 |
| low | 2 |
| info | 3 |

## Findings by algorithm / API family

| Family | Count |
|--------|------:|
| RSA | 6 |
| ECDSA/ECDH | 4 |
| ECDSA | 3 |
| EdDSA | 3 |
| SHA/Hash | 3 |
| AES | 2 |
| JWT/JOSE | 2 |
| TLS/SSL | 2 |
| cryptography | 2 |
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

### 3. [HIGH] RSA — Node.js crypto RSA

- **Location**: `js_app/crypto_demo.js`:9
- **Rules**: `js-node-crypto-rsa`
- **Families**: RSA
- **Priority rank**: 3
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

### 4. [HIGH] ECDSA/ECDH — Node.js crypto EC / ECDH (+1 overlapping rules)

- **Location**: `js_app/crypto_demo.js`:12
- **Rules**: `js-node-crypto-ec`, `js-webcrypto-ec-alg` _(merged 2 hits)_
- **Families**: ECDSA/ECDH
- **Priority rank**: 4
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

### 5. [HIGH] ECDSA/ECDH — Node.js crypto EC / ECDH

- **Location**: `js_app/crypto_demo.js`:13
- **Rules**: `js-node-crypto-ec`
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
- **Snippet**: `const ecdh = crypto.createECDH('prime256v1');`

### 6. [HIGH] EdDSA — Node.js Ed25519

- **Location**: `js_app/crypto_demo.js`:16
- **Rules**: `js-node-crypto-ed`
- **Families**: EdDSA
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
- **Snippet**: `crypto.generateKeyPairSync('ed25519');`

### 7. [HIGH] RSA — node-forge RSA

- **Location**: `js_app/crypto_demo.js`:19
- **Rules**: `js-forge-rsa`
- **Families**: RSA
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
- **Snippet**: `const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });`

### 8. [HIGH] RSA — WebCrypto RSA algorithm name

- **Location**: `js_app/crypto_demo.js`:26
- **Rules**: `js-webcrypto-rsa-alg`
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
- **Snippet**: `const rsaAlg = 'RSA-OAEP';`

### 9. [HIGH] ECDSA/ECDH — WebCrypto classical EC curves

- **Location**: `js_app/crypto_demo.js`:27
- **Rules**: `js-webcrypto-ec-alg`
- **Families**: ECDSA/ECDH
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
- **Snippet**: `const ecAlg = { name: 'ECDSA', namedCurve: 'P-256' };`

### 10. [HIGH] EdDSA — Ed25519 / EdDSA classical signature (+2 overlapping rules)

- **Location**: `python_app/crypto_demo.py`:7
- **Rules**: `py-cryptography-lib`, `py-ed25519`, `py-rsa-module` _(merged 4 hits)_
- **Families**: EdDSA, RSA, cryptography
- **Priority rank**: 10
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

### 11. [HIGH] ECDSA — python-ecdsa classical signatures

- **Location**: `python_app/crypto_demo.py`:9
- **Rules**: `py-ecdsa`
- **Families**: ECDSA
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
- **Snippet**: `import ecdsa`

### 12. [HIGH] EdDSA — Ed25519 / EdDSA classical signature

- **Location**: `python_app/crypto_demo.py`:21
- **Rules**: `py-ed25519`
- **Families**: EdDSA
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
- **Snippet**: `ed_key = ed25519.Ed25519PrivateKey.generate()`

### 13. [HIGH] ECDSA — python-ecdsa classical signatures

- **Location**: `python_app/crypto_demo.py`:24
- **Rules**: `py-ecdsa`
- **Families**: ECDSA
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
- **Snippet**: `sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)`

### 14. [HIGH] ECDSA — ecdsa package dependency

- **Location**: `python_app/requirements.txt`:2
- **Rules**: `dep-ecdsa`
- **Families**: ECDSA
- **Priority rank**: 14
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

### 15. [HIGH] RSA — rsa package dependency

- **Location**: `python_app/requirements.txt`:3
- **Rules**: `dep-rsa`
- **Families**: RSA
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
- **Snippet**: `rsa>=4.9`

### 16. [HIGH] ECDSA/ECDH — cryptography.io elliptic-curve API

- **Location**: `python_app/crypto_demo.py`:18
- **Rules**: `py-ec-crypto`
- **Families**: ECDSA/ECDH
- **Priority rank**: 16
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

### 17. [MEDIUM] JWT/JOSE — jose dependency (check alg usage)

- **Location**: `js_app/package.json`:7
- **Rules**: `dep-jose`
- **Families**: JWT/JOSE
- **Priority rank**: 17
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

### 18. [MEDIUM] TLS/SSL — stdlib ssl / TLS wrapper (check cipher suites)

- **Location**: `python_app/crypto_demo.py`:6
- **Rules**: `py-ssl`
- **Families**: TLS/SSL
- **Priority rank**: 18
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

### 19. [MEDIUM] JWT — PyJWT dependency

- **Location**: `python_app/requirements.txt`:5
- **Rules**: `dep-pyjwt`
- **Families**: JWT
- **Priority rank**: 19
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

### 20. [MEDIUM] TLS/SSL — stdlib ssl / TLS wrapper (check cipher suites)

- **Location**: `python_app/crypto_demo.py`:28
- **Rules**: `py-ssl`
- **Families**: TLS/SSL
- **Priority rank**: 20
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

### 21. [MEDIUM] node:crypto — Node crypto module import

- **Location**: `js_app/crypto_demo.js`:3
- **Rules**: `js-node-crypto-require`
- **Families**: node:crypto
- **Priority rank**: 21
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

### 22. [MEDIUM] node-forge — node-forge import

- **Location**: `js_app/crypto_demo.js`:4
- **Rules**: `js-forge-import`
- **Families**: node-forge
- **Priority rank**: 22
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

### 23. [MEDIUM] node-forge — node-forge dependency

- **Location**: `js_app/package.json`:6
- **Rules**: `dep-node-forge`
- **Families**: node-forge
- **Priority rank**: 23
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

### 24. [MEDIUM] cryptography — cryptography package dependency

- **Location**: `python_app/requirements.txt`:1
- **Rules**: `dep-cryptography`
- **Families**: cryptography
- **Priority rank**: 24
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

### 25. [MEDIUM] PyCryptodome — PyCryptodome/PyCrypto dependency

- **Location**: `python_app/requirements.txt`:4
- **Rules**: `dep-pycryptodome`
- **Families**: PyCryptodome
- **Priority rank**: 25
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

### 26. [LOW] AES — AES symmetric encryption

- **Location**: `js_app/crypto_demo.js`:30
- **Rules**: `js-aes`
- **Families**: AES
- **Priority rank**: 26
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

### 27. [LOW] AES — AES symmetric encryption

- **Location**: `python_app/crypto_demo.py`:31
- **Rules**: `py-aes`
- **Families**: AES
- **Priority rank**: 27
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

### 28. [INFO] SHA/Hash — SHA hash / integrity

- **Location**: `js_app/crypto_demo.js`:33
- **Rules**: `js-hash`
- **Families**: SHA/Hash
- **Priority rank**: 28
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

### 29. [INFO] SHA/Hash — hashlib digest / integrity

- **Location**: `python_app/crypto_demo.py`:5
- **Rules**: `py-hashlib`
- **Families**: SHA/Hash
- **Priority rank**: 29
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

### 30. [INFO] SHA/Hash — hashlib digest / integrity

- **Location**: `python_app/crypto_demo.py`:34
- **Rules**: `py-hashlib`
- **Families**: SHA/Hash
- **Priority rank**: 30
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

## Quantum-risk legend

- **high** — RSA, classical ECDSA/ECDH/EdDSA (long-term trust), finite-field DH
- **medium** — Ambiguous TLS/crypto wrappers without clear PQC
- **low** — AES/ChaCha (note Grover; prefer 256-bit keys)
- **info** — SHA-2/3 integrity hashing

## Scope reminder

**Scope:** static analysis of source code + dependency manifests only — not runtime, binaries, network traffic, or a complete coverage guarantee.

This report is produced by a **defensive** static inventory scanner. It does **not** implement attacks, exploits, migration engines, or key-breaking.

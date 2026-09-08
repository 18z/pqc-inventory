// Intentionally uses classical crypto for scanner demo (not production).
// pqc-inventory-file: owner=sample-js-team
const crypto = require('crypto');
const forge = require('node-forge');
const { SignJWT } = require('jose');

// Node RSA — high risk
// pqc-inventory: lifetime=12 exposure=public_key owner=key-mgmt
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// Node EC / ECDH — high
crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ecdh = crypto.createECDH('prime256v1');

// Ed25519 — high (classical EdDSA)
crypto.generateKeyPairSync('ed25519');

// node-forge RSA — high
const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });

// jose classical JWT alg — high (trust-boundary exposure override)
// pqc-inventory: lifetime=10 exposure=trust_boundary owner=auth
const alg = 'RS256';

// WebCrypto-style algorithm names
const rsaAlg = 'RSA-OAEP';
const ecAlg = { name: 'ECDSA', namedCurve: 'P-256' };

// AES — low
const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));

// Hash — info (local checksum noise; suppressed by default hash-policy)
const hash = crypto.createHash('sha256').update('demo').digest('hex');

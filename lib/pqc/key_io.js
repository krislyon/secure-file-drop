'use strict';

const fs = require('fs');
const crypto = require('crypto');

function readJson(file) {
  const raw = fs.readFileSync(file, 'utf8');
  return JSON.parse(raw);
}

function writeJson(file, data) {
  const tmp = `${file}.part`;
  fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`);
  fs.renameSync(tmp, file);
}

function loadPublicKey(file) {
  const key = readJson(file);
  if (!key || key.format !== 'SFD-PQ-PUB-1') {
    throw new Error(`File ${file} is not a valid SFD PQ public key`);
  }
  return key;
}

function deriveKeyFromPassphrase(passphrase, salt, kdfParams) {
  const { N, r, p, keyLength } = kdfParams;
  const maxmem = Math.max(32 * 1024 * 1024, 2 * N * r * 128);
  return crypto.scryptSync(passphrase, salt, keyLength, { N, r, p, maxmem });
}

function encryptPrivateKey(privateKey, passphrase, kdfParams = { N: 1 << 15, r: 8, p: 1, keyLength: 32 }) {
  const salt = crypto.randomBytes(16);
  const key = deriveKeyFromPassphrase(passphrase, salt, kdfParams);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(privateKey));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    format: 'SFD-PQ-PRIV-ENC-1',
    kdf: {
      algorithm: 'scrypt',
      salt: salt.toString('base64'),
      N: kdfParams.N,
      r: kdfParams.r,
      p: kdfParams.p,
      keyLength: kdfParams.keyLength,
    },
    cipher: {
      algorithm: 'AES-256-GCM',
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      authTag: authTag.toString('base64'),
    },
  };
}

function decryptPrivateKey(wrapper, passphrase) {
  if (wrapper.format !== 'SFD-PQ-PRIV-ENC-1') {
    throw new Error('Unsupported encrypted private key format');
  }
  if (typeof passphrase !== 'string') {
    throw new Error('Passphrase required to decrypt private key');
  }
  const { kdf, cipher } = wrapper;
  const salt = Buffer.from(kdf.salt, 'base64');
  const key = deriveKeyFromPassphrase(passphrase, salt, kdf);
  const iv = Buffer.from(cipher.iv, 'base64');
  const ciphertext = Buffer.from(cipher.ciphertext, 'base64');
  const authTag = Buffer.from(cipher.authTag, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function loadPrivateKey(file, passphrase) {
  const key = readJson(file);
  if (!key) {
    throw new Error(`File ${file} is empty`);
  }
  if (key.format === 'SFD-PQ-PRIV-1') {
    return key;
  }
  if (key.format === 'SFD-PQ-PRIV-ENC-1') {
    if (typeof passphrase !== 'string') {
      throw new Error('Passphrase required for encrypted private key');
    }
    return decryptPrivateKey(key, passphrase);
  }
  throw new Error(`File ${file} is not a recognised SFD PQ private key`);
}

module.exports = {
  loadPublicKey,
  loadPrivateKey,
  writeJson,
  encryptPrivateKey,
};

#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const { generateKeypair } = require('../lib/pqc/lwe');
const { writeJson, encryptPrivateKey } = require('../lib/pqc/key_io');

function main() {
  const outDir = process.argv[2] || 'keys';
  const label = process.argv[3] || 'SFD PQC Recipient';
  const passphrase = process.env.KEYS_INIT_PASSPHRASE || '';

  const resolvedDir = path.resolve(outDir);
  fs.mkdirSync(resolvedDir, { recursive: true, mode: 0o700 });

  const { publicKey, privateKey } = generateKeypair();
  publicKey.label = label;

  const pubPath = path.join(resolvedDir, 'public_key.json');
  const privPath = path.join(resolvedDir, passphrase ? 'private_key_encrypted.json' : 'private_key.json');

  writeJson(pubPath, publicKey);

  if (passphrase) {
    const wrapped = encryptPrivateKey(privateKey, passphrase);
    writeJson(privPath, wrapped);
  } else {
    writeJson(privPath, privateKey);
  }

  console.log(`Wrote public key: ${pubPath}`);
  console.log(`Wrote private key: ${privPath}`);
  if (passphrase) {
    console.log('Private key encrypted with provided passphrase.');
  } else {
    console.log('Private key stored unencrypted (no passphrase provided).');
  }
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error('Failed to generate keys:', err.message);
    process.exit(1);
  }
}

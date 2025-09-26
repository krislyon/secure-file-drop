#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { decryptKey } = require('./lib/pqc/lwe');
const { loadPrivateKey } = require('./lib/pqc/key_io');

function usage() {
  const script = path.basename(process.argv[1] || 'decrypt_file.js');
  console.log(`Usage: ${script} -k PRIV.json -i INPUT -o OUTPUT\n` +
    'Decrypt an SFD PQC envelope using AES-256-GCM and an LWE private key.\n' +
    '\n' +
    'Options:\n' +
    '  -k, --key     Private key JSON file\n' +
    '  -i, --input   Envelope file (JSON)\n' +
    '  -o, --output  Decrypted output file\n' +
    '  -h, --help    Show this message\n' +
    '\n' +
    'If the private key is encrypted, provide the passphrase via the\n' +
    'SFD_PQ_PRIV_PASSPHRASE environment variable.');
}

function parseArgs() {
  const args = process.argv.slice(2);
  let keyFile;
  let input;
  let output;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    switch (arg) {
      case '-k':
      case '--key':
        keyFile = args[++i];
        break;
      case '-i':
      case '--input':
        input = args[++i];
        break;
      case '-o':
      case '--output':
        output = args[++i];
        break;
      case '-h':
      case '--help':
        usage();
        process.exit(0);
        break;
      default:
        console.error(`Unknown argument: ${arg}`);
        usage();
        process.exit(1);
    }
  }

  return { keyFile, input, output };
}

function readJson(file) {
  const raw = fs.readFileSync(file, 'utf8');
  return JSON.parse(raw);
}

function decryptPayload({ key, iv, ciphertext, authTag }) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function main() {
  const { keyFile, input, output } = parseArgs();

  if (!keyFile || !fs.existsSync(keyFile)) {
    console.error('ERR: private key file missing');
    process.exit(2);
  }

  if (!input || !fs.existsSync(input)) {
    console.error('ERR: input envelope missing');
    process.exit(2);
  }

  if (!output) {
    console.error('ERR: output path missing');
    process.exit(2);
  }

  console.log(`[decrypt] ⏳ Decrypting '${input}' → '${output}'…`);

  try {
    const passphrase = process.env.SFD_PQ_PRIV_PASSPHRASE;
    const privateKey = loadPrivateKey(keyFile, passphrase);

    const envelope = readJson(input);
    if (!envelope || envelope.format !== 'SFD-PQC-ENVELOPE-1') {
      throw new Error('Input is not a recognised SFD PQC envelope');
    }

    const kemCiphertext = Buffer.from(envelope.kem.ciphertext, 'base64');
    const key = decryptKey(privateKey, kemCiphertext);
    if (key.length !== 32) {
      throw new Error('Recovered key has invalid length');
    }

    const iv = Buffer.from(envelope.aead.iv, 'base64');
    const ciphertext = Buffer.from(envelope.aead.ciphertext, 'base64');
    const authTag = Buffer.from(envelope.aead.authTag, 'base64');
    const plaintext = decryptPayload({ key, iv, ciphertext, authTag });

    const tmp = `${output}.part`;
    fs.writeFileSync(tmp, plaintext);
    fs.renameSync(tmp, output);
    console.log(`[decrypt] ✅ OK → ${output}`);
  } catch (err) {
    console.error('[decrypt] ❌ Failed:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error('[decrypt] ❌ Unexpected error:', err.message);
    process.exit(1);
  }
}

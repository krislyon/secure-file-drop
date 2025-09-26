#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { encryptKey } = require('./lib/pqc/lwe');
const { loadPublicKey } = require('./lib/pqc/key_io');

function usage() {
  const script = path.basename(process.argv[1] || 'encrypt_file.js');
  console.log(`Usage: ${script} -r RECIP_PUB.json -i INPUT -o OUTPUT\n` +
    'Encrypt INPUT with AES-256-GCM and wrap the key using an LWE-based KEM.\n' +
    '\n' +
    'Options:\n' +
    '  -r, --recipient  Recipient public key JSON file\n' +
    '  -i, --input      Input file to encrypt\n' +
    '  -o, --output     Output envelope file (e.g., file.cms)\n' +
    '  -h, --help       Show this message');
}

function parseArgs() {
  const args = process.argv.slice(2);
  let recipient;
  let input;
  let output;

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    switch (arg) {
      case '-r':
      case '--recipient':
        recipient = args[++i];
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

  return { recipient, input, output };
}

function encryptPayload(plaintext) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { key, iv, ciphertext, authTag };
}

function buildEnvelope({ publicKey, kemCiphertext, iv, ciphertext, authTag }) {
  return {
    format: 'SFD-PQC-ENVELOPE-1',
    kem: {
      scheme: publicKey.scheme,
      params: publicKey.params,
      ciphertext: kemCiphertext.toString('base64'),
    },
    aead: {
      algorithm: 'AES-256-GCM',
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      authTag: authTag.toString('base64'),
    },
  };
}

function atomicWrite(file, data) {
  const tmp = `${file}.part`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

function main() {
  const { recipient, input, output } = parseArgs();

  if (!recipient || !fs.existsSync(recipient)) {
    console.error('ERR: recipient public key missing');
    process.exit(2);
  }

  if (!input || !fs.existsSync(input)) {
    console.error('ERR: input file missing');
    process.exit(2);
  }

  if (!output) {
    console.error('ERR: output path missing');
    process.exit(2);
  }

  console.log(`[encrypt] ⏳ Encrypting '${input}' → '${output}' (AES-256-GCM + LWE KEM)…`);

  try {
    const publicKey = loadPublicKey(recipient);

    const plaintext = fs.readFileSync(input);
    const { key, iv, ciphertext, authTag } = encryptPayload(plaintext);
    const kemCiphertext = encryptKey(publicKey, key);
    const envelope = buildEnvelope({ publicKey, kemCiphertext, iv, ciphertext, authTag });
    atomicWrite(output, `${JSON.stringify(envelope, null, 2)}\n`);
    console.log(`[encrypt] ✅ Wrote PQC envelope: ${output}`);
  } catch (err) {
    console.error('[encrypt] ❌ Encryption failed:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error('[encrypt] ❌ Unexpected error:', err.message);
    process.exit(1);
  }
}

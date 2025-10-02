#!/usr/bin/env node
'use strict';

/**
 * CMS (Cryptographic Message Syntax) encryptor backed by node-forge.
 *
 * This example mirrors the behaviour of encrypt_file.sh but relies on the
 * battle-tested node-forge library to assemble the PKCS#7 / CMS envelope
 * rather than manually crafting ASN.1 structures. The script supports a single
 * RSA recipient and uses AES-256 content encryption. node-forge automatically
 * negotiates the necessary key-wrapping details and produces a DER-encoded CMS
 * EnvelopedData structure that OpenSSL can decrypt.
 */

const fs = require('fs');
const path = require('path');

let forge;
try {
  forge = require('node-forge');
} catch (err) {
  if (err && err.code === 'MODULE_NOT_FOUND') {
    console.error('The "node-forge" package is required. Install it with "npm install" before running this script.');
    process.exit(1);
  }
  throw err;
}

function usage() {
  const script = path.basename(process.argv[1] || 'encrypt_file.js');
  console.log(`Usage: ${script} -r CERT_PEM -i INPUT -o OUTPUT\n` +
    'Encrypt INPUT into a CMS envelope using node-forge.\n' +
    '\n' +
    'Options:\n' +
    '  -r, --recipient  Recipient certificate (PEM, contains RSA public key)\n' +
    '  -i, --input      Input file to encrypt\n' +
    '  -o, --output     Output CMS file (e.g., file.cms)\n' +
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

function ensureReadableFile(label, filePath) {
  if (!filePath) {
    throw new Error(`Missing required ${label} path`);
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`${label} not found: ${filePath}`);
  }
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) {
    throw new Error(`${label} must be a regular file: ${filePath}`);
  }
}

function encryptWithForge(certificatePem, payloadBuffer) {
  let certificate;
  try {
    certificate = forge.pki.certificateFromPem(certificatePem);
  } catch (err) {
    throw new Error(`Failed to parse recipient certificate: ${err.message}`);
  }

  const payloadBytes = payloadBuffer.toString('binary');
  const algorithms = [
    {
      label: 'AES-256-GCM',
      options: { contentEncryptionAlgorithm: { name: 'aes256-GCM' } },
    },
    {
      label: 'AES-256-CBC',
      options: { contentEncryptionAlgorithm: 'aes256' },
    },
  ];

  let lastError;
  for (const { label, options } of algorithms) {
    const envelope = forge.pkcs7.createEnvelopedData();
    envelope.addRecipient(certificate);
    envelope.content = forge.util.createBuffer(payloadBytes, 'binary');

    try {
      envelope.encrypt(options);
      return { envelope, algorithm: label };
    } catch (err) {
      lastError = err;
    }
  }

  const errorMessage = lastError && lastError.message ? lastError.message : 'unknown error';
  throw new Error(`Encryption failed (node-forge): ${errorMessage}`);
}

function main() {
  const { recipient, input, output } = parseArgs();

  try {
    ensureReadableFile('recipient certificate', recipient);
    ensureReadableFile('input file', input);
    if (!output) {
      throw new Error('Missing required output path');
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    usage();
    process.exit(2);
  }

  const certPem = fs.readFileSync(recipient, 'utf8');
  const plaintext = fs.readFileSync(input);

  const { envelope, algorithm } = encryptWithForge(certPem, plaintext);
  const derBytes = forge.asn1.toDer(envelope.toAsn1()).getBytes();
  const derBuffer = Buffer.from(derBytes, 'binary');

  fs.writeFileSync(output, derBuffer);
  console.log(`[encrypt] ✅ Encrypted '${input}' → '${output}' using ${algorithm}.`);
}

if (require.main === module) {
  main();
}

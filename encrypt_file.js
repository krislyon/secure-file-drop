#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

function usage() {
  const script = path.basename(process.argv[1] || 'encrypt_file.js');
  console.log(`Usage: ${script} -r CERT_PEM -i INPUT -o OUTPUT\n` +
    'Encrypt INPUT into a CMS (DER) file using OpenSSL (AES-256-GCM).\n' +
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

async function runOpenssl(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'], ...options });
    let stderr = '';

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('error', (err) => {
      reject(new Error(`Failed to start openssl: ${err.message}`));
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        const message = stderr.trim() || `openssl exited with code ${code}`;
        reject(new Error(message));
      }
    });
  });
}

async function encrypt(recipient, input, output) {
  ensureReadableFile('recipient certificate', recipient);
  ensureReadableFile('input file', input);
  if (!output) {
    throw new Error('Missing required output path');
  }

  const tmpPath = `${output}.part`;
  console.log(`[encrypt] ⏳ Encrypting '${input}' → '${output}' (CMS, AES-256-GCM)…`);

  const args = [
    'cms', '-encrypt',
    '-binary', '-stream',
    '-aes-256-gcm',
    '-in', input,
    '-out', tmpPath,
    '-outform', 'DER',
    recipient
  ];

  try {
    await runOpenssl(args);
    fs.renameSync(tmpPath, output);
  } catch (err) {
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch (cleanupErr) {
      // Ignore cleanup errors.
    }
    throw err;
  }

  console.log(`[encrypt] ✅ Wrote CMS envelope: ${output}`);
}

async function main() {
  const { recipient, input, output } = parseArgs();

  try {
    await encrypt(recipient, input, output);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    usage();
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

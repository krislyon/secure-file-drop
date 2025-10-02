#!/usr/bin/env node
'use strict';

/**
 * CMS (Cryptographic Message Syntax) encryptor backed by PKI.js.
 *
 * This example mirrors the behaviour of encrypt_file.sh but relies on
 * well-maintained PKCS#7/CMS tooling from the PKI.js ecosystem instead of
 * hand-rolled ASN.1. A single RSA recipient is supported and the content is
 * wrapped with AES-256-GCM, matching the OpenSSL-based shell implementation.
 */

const fs = require('fs');
const path = require('path');

let cryptoDepsPromise;

async function loadCryptoDependencies() {
  if (!cryptoDepsPromise) {
    cryptoDepsPromise = (async () => {
      try {
        const [webcryptoModule, asn1Module, pkijsModule] = await Promise.all([
          import('@peculiar/webcrypto'),
          import('asn1js'),
          import('pkijs')
        ]);

        const CryptoCtor = webcryptoModule.Crypto || webcryptoModule.default;
        const asn1js = asn1Module.default || asn1Module;
        const pkijs = pkijsModule.default || pkijsModule;

        if (!CryptoCtor) {
          throw new Error('Failed to load @peculiar/webcrypto.');
        }

        const webcrypto = new CryptoCtor();
        const { setEngine, CryptoEngine } = pkijs;
        setEngine('nodeEngine', webcrypto, new CryptoEngine({
          name: 'nodeEngine',
          crypto: webcrypto,
          subtle: webcrypto.subtle
        }));

        return { asn1js, pkijs };
      } catch (err) {
        if (err && (err.code === 'ERR_MODULE_NOT_FOUND' || err.code === 'MODULE_NOT_FOUND')) {
          console.error('Missing required dependencies. Run "npm install" to install pkijs, asn1js, and @peculiar/webcrypto.');
          process.exit(1);
        }
        throw err;
      }
    })();
  }

  return cryptoDepsPromise;
}

function usage() {
  const script = path.basename(process.argv[1] || 'encrypt_file.js');
  console.log(`Usage: ${script} -r CERT_PEM -i INPUT -o OUTPUT\n` +
    'Encrypt INPUT into a CMS envelope using PKI.js (AES-256-GCM).\n' +
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

function pemToDer(pem) {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return Buffer.from(base64, 'base64');
}

function toArrayBuffer(buffer) {
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

async function encryptWithPkijs(certificatePem, payloadBuffer) {
  const { asn1js, pkijs } = await loadCryptoDependencies();

  const derCert = pemToDer(certificatePem);
  const asn1 = asn1js.fromBER(toArrayBuffer(derCert));
  if (asn1.offset === -1) {
    throw new Error('Failed to parse recipient certificate. Ensure it is a valid PEM-encoded X.509 certificate.');
  }

  const certificate = new pkijs.Certificate({ schema: asn1.result });
  const envelopedData = new pkijs.EnvelopedData();

  await envelopedData.addRecipientByCertificate(certificate, {});

  const messageArrayBuffer = toArrayBuffer(payloadBuffer);
  await envelopedData.encrypt({
    name: 'AES-GCM',
    length: 256
  }, messageArrayBuffer);

  const contentInfo = new pkijs.ContentInfo();
  contentInfo.contentType = '1.2.840.113549.1.7.3'; // EnvelopedData
  contentInfo.content = envelopedData.toSchema();

  const cmsDer = contentInfo.toSchema().toBER(false);
  return { buffer: Buffer.from(cmsDer), algorithm: 'AES-256-GCM' };
}

async function main() {
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

  const { buffer, algorithm } = await encryptWithPkijs(certPem, plaintext);
  fs.writeFileSync(output, buffer);
  console.log(`[encrypt] ✅ Encrypted '${input}' → '${output}' using ${algorithm}.`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
}

#!/usr/bin/env node
'use strict';

/**
 * Pure-JavaScript CMS (AuthenticatedEnvelopedData) encryptor.
 *
 * This script mirrors the behaviour of encrypt_file.sh but performs the CMS
 * assembly itself using Node's crypto primitives instead of invoking the
 * OpenSSL CLI. It supports a single RSA recipient and AES-256-GCM content
 * encryption, which matches the defaults used throughout the project.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  randomBytes,
  createCipheriv,
  publicEncrypt,
  X509Certificate,
  constants: { RSA_PKCS1_PADDING },
} = crypto;

const OIDS = {
  idSmimeCtAuthEnvelopedData: '1.2.840.113549.1.9.16.1.23',
  pkcs7Data: '1.2.840.113549.1.7.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  aes256Gcm: '2.16.840.1.101.3.4.1.46',
};

function usage() {
  const script = path.basename(process.argv[1] || 'encrypt_file.js');
  console.log(`Usage: ${script} -r CERT_PEM -i INPUT -o OUTPUT\n` +
    'Encrypt INPUT into a CMS AuthEnvelopedData structure using AES-256-GCM.\n' +
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

function readElement(buffer, offset = 0) {
  if (offset >= buffer.length) {
    throw new Error('ASN.1 parse error: truncated element');
  }

  const tagByte = buffer[offset];
  const tagClassIndex = tagByte >> 6;
  const tagClasses = ['universal', 'application', 'context', 'private'];
  const tagClass = tagClasses[tagClassIndex];
  const constructed = (tagByte & 0x20) !== 0;
  let tagNumber = tagByte & 0x1f;
  let cursor = offset + 1;

  if (tagNumber === 0x1f) {
    tagNumber = 0;
    let b;
    do {
      if (cursor >= buffer.length) {
        throw new Error('ASN.1 parse error: truncated long-form tag');
      }
      b = buffer[cursor];
      cursor += 1;
      tagNumber = (tagNumber << 7) | (b & 0x7f);
    } while ((b & 0x80) !== 0);
  }

  if (cursor >= buffer.length) {
    throw new Error('ASN.1 parse error: missing length');
  }

  const lenByte = buffer[cursor];
  cursor += 1;
  let length;

  if ((lenByte & 0x80) === 0) {
    length = lenByte;
  } else {
    const numBytes = lenByte & 0x7f;
    if (numBytes === 0) {
      throw new Error('ASN.1 parse error: indefinite length not supported');
    }
    if (cursor + numBytes > buffer.length) {
      throw new Error('ASN.1 parse error: truncated length');
    }
    length = 0;
    for (let i = 0; i < numBytes; i += 1) {
      length = (length << 8) | buffer[cursor + i];
    }
    cursor += numBytes;
  }

  const contentOffset = cursor;
  const end = contentOffset + length;
  if (end > buffer.length) {
    throw new Error('ASN.1 parse error: truncated content');
  }

  return {
    tagClass,
    constructed,
    tagNumber,
    headerLength: cursor - offset,
    contentOffset,
    contentLength: length,
    start: offset,
    end,
  };
}

function extractIssuerAndSerial(certDer) {
  const root = readElement(certDer, 0);
  if (root.tagClass !== 'universal' || root.tagNumber !== 16) {
    throw new Error('Unexpected certificate structure');
  }

  const tbs = readElement(certDer, root.contentOffset);
  let cursor = tbs.contentOffset;

  // Optional version field [0] EXPLICIT
  const maybeVersion = readElement(certDer, cursor);
  if (maybeVersion.tagClass === 'context' && maybeVersion.tagNumber === 0) {
    cursor = maybeVersion.end;
  }

  const serialElem = readElement(certDer, cursor);
  if (serialElem.tagClass !== 'universal' || serialElem.tagNumber !== 2) {
    throw new Error('Certificate serial number missing');
  }
  const serial = certDer.slice(serialElem.contentOffset, serialElem.end);
  cursor = serialElem.end;

  // Skip signature algorithm identifier
  const sigAlg = readElement(certDer, cursor);
  cursor = sigAlg.end;

  const issuerElem = readElement(certDer, cursor);
  if (issuerElem.tagClass !== 'universal' || issuerElem.tagNumber !== 16) {
    throw new Error('Certificate issuer missing');
  }
  const issuer = certDer.slice(issuerElem.start, issuerElem.end);

  return { issuer, serial }; // serial contains the INTEGER value bytes
}

function encodeLength(length) {
  if (length < 0x80) {
    return Buffer.from([length]);
  }
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeTLV(tag, value) {
  return Buffer.concat([Buffer.from([tag]), encodeLength(value.length), value]);
}

function trimIntegerBuffer(buf) {
  let offset = 0;
  while (offset < buf.length - 1 && buf[offset] === 0x00 && (buf[offset + 1] & 0x80) === 0) {
    offset += 1;
  }
  return buf.slice(offset);
}

function encodeInteger(value) {
  let buf;
  if (typeof value === 'number') {
    if (value === 0) {
      buf = Buffer.from([0]);
    } else {
      const bytes = [];
      let v = value;
      while (v > 0) {
        bytes.unshift(v & 0xff);
        v >>= 8;
      }
      buf = Buffer.from(bytes);
    }
  } else if (Buffer.isBuffer(value)) {
    buf = Buffer.from(value);
  } else {
    throw new TypeError('INTEGER must be a number or Buffer');
  }

  if (buf.length === 0) {
    buf = Buffer.from([0]);
  }

  buf = trimIntegerBuffer(buf);
  if ((buf[0] & 0x80) !== 0) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }

  return encodeTLV(0x02, buf);
}

function encodeNull() {
  return Buffer.from([0x05, 0x00]);
}

function encodeOctetString(value) {
  return encodeTLV(0x04, value);
}

function encodeOID(oid) {
  const parts = oid.split('.').map((n) => {
    const num = Number.parseInt(n, 10);
    if (!Number.isFinite(num) || num < 0) {
      throw new Error(`Invalid OID component: ${n}`);
    }
    return num;
  });

  if (parts.length < 2) {
    throw new Error('OID must have at least two components');
  }

  const first = 40 * parts[0] + parts[1];
  const bytes = [first];

  for (let i = 2; i < parts.length; i += 1) {
    let value = parts[i];
    if (value === 0) {
      bytes.push(0);
      continue;
    }
    const stack = [];
    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }
    stack[stack.length - 1] &= 0x7f;
    bytes.push(...stack);
  }

  return encodeTLV(0x06, Buffer.from(bytes));
}

function encodeSequence(elements) {
  return encodeTLV(0x30, Buffer.concat(elements));
}

function encodeSet(elements) {
  const sorted = elements.slice().sort(Buffer.compare);
  return encodeTLV(0x31, Buffer.concat(sorted));
}

function encodeContextExplicit(tagNumber, inner) {
  if (!Buffer.isBuffer(inner)) {
    throw new TypeError('Explicit context value must be a Buffer');
  }
  return encodeTLV(0xa0 + tagNumber, inner);
}

function encodeContextPrimitive(tagNumber, value) {
  return encodeTLV(0x80 + tagNumber, value);
}

function buildRecipientInfo({ issuer, serial, encryptedKey }) {
  const version = encodeInteger(0);
  const issuerAndSerial = encodeSequence([
    issuer,
    encodeInteger(serial),
  ]);
  const keyEncryptionAlgorithm = encodeSequence([
    encodeOID(OIDS.rsaEncryption),
    encodeNull(),
  ]);
  const encryptedKeyOctets = encodeOctetString(encryptedKey);

  return encodeSequence([
    version,
    issuerAndSerial,
    keyEncryptionAlgorithm,
    encryptedKeyOctets,
  ]);
}

function buildAuthenticatedEnvelopedData({ recipientInfo, iv, ciphertext, authTag }) {
  const version = encodeInteger(0);
  const recipientInfos = encodeSet([recipientInfo]);
  const gcmParameters = encodeSequence([
    encodeOctetString(iv),
    encodeInteger(16),
  ]);
  const contentEncryptionAlgorithm = encodeSequence([
    encodeOID(OIDS.aes256Gcm),
    gcmParameters,
  ]);
  const encryptedContentInfo = encodeSequence([
    encodeOID(OIDS.pkcs7Data),
    contentEncryptionAlgorithm,
    encodeContextPrimitive(0, ciphertext),
  ]);
  const mac = encodeOctetString(authTag);

  return encodeSequence([
    version,
    recipientInfos,
    encryptedContentInfo,
    mac,
  ]);
}

function buildContentInfo(authEnvelopedData) {
  return encodeSequence([
    encodeOID(OIDS.idSmimeCtAuthEnvelopedData),
    encodeContextExplicit(0, authEnvelopedData),
  ]);
}

function encryptPayload(plaintext) {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { key, iv, ciphertext, authTag };
}

function encryptContentEncryptionKey(cert, cek) {
  return publicEncrypt({
    key: cert.publicKey,
    padding: RSA_PKCS1_PADDING,
  }, cek);
}

function main() {
  const { recipient, input, output } = parseArgs();

  if (!recipient || !fs.existsSync(recipient)) {
    console.error('ERR: recipient cert missing');
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

  const tmp = `${output}.part`;

  console.log(`[encrypt] ⏳ Encrypting '${input}' → '${output}' (CMS, AES-256-GCM)…`);

  try {
    const pem = fs.readFileSync(recipient, 'utf8');
    const cert = new X509Certificate(pem);
    if (!cert.publicKey || cert.publicKey.asymmetricKeyType !== 'rsa') {
      throw new Error('Recipient certificate must contain an RSA public key');
    }

    const { issuer, serial } = extractIssuerAndSerial(cert.raw);
    const plaintext = fs.readFileSync(input);
    const { key, iv, ciphertext, authTag } = encryptPayload(plaintext);
    const encryptedKey = encryptContentEncryptionKey(cert, key);
    const recipientInfo = buildRecipientInfo({ issuer, serial, encryptedKey });
    const authEnv = buildAuthenticatedEnvelopedData({ recipientInfo, iv, ciphertext, authTag });
    const cms = buildContentInfo(authEnv);

    fs.writeFileSync(tmp, cms);
    fs.renameSync(tmp, output);
    console.log(`[encrypt] ✅ Wrote CMS envelope: ${output}`);
  } catch (err) {
    if (fs.existsSync(tmp)) {
      try {
        fs.rmSync(tmp);
      } catch (cleanupErr) {
        console.warn('[encrypt] ⚠️ Failed to remove temporary file:', cleanupErr.message);
      }
    }
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

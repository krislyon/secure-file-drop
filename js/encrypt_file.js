#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OID = {
  AUTH_ENVELOPED_DATA: '1.2.840.113549.1.9.16.1.23',
  ENVELOPED_DATA: '1.2.840.113549.1.7.3',
  DATA: '1.2.840.113549.1.7.1',
  RSA_ENCRYPTION: '1.2.840.113549.1.1.1',
  AES_256_GCM: '2.16.840.1.101.3.4.1.46',
  AES_256_CBC: '2.16.840.1.101.3.4.1.42'
};

const SUPPORTED_ALGORITHMS = new Set(['aes-256-gcm', 'aes-256-cbc']);

function usage() {
  const script = path.basename(process.argv[1] || __filename);
  console.log(
    `Usage: ${script} -r CERT_PEM -i INPUT -o OUTPUT\n` +
      'Encrypt INPUT into a CMS (DER) file with RSA key transport.\n' +
      '\n' +
      'Options:\n' +
      '  -r, --recipient  Recipient certificate (PEM, contains RSA public key)\n' +
      '  -i, --input      Input file to encrypt\n' +
      '  -o, --output     Output CMS file (e.g., file.cms)\n' +
      '  -a, --algorithm  Encryption algorithm (aes-256-gcm | aes-256-cbc, default: aes-256-gcm)\n' +
      '  -h, --help       Show this message'
  );
}

function parseArgs() {
  const args = process.argv.slice(2);
  let recipient;
  let input;
  let output;
  let algorithm = 'aes-256-gcm';

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
      case '-a':
      case '--algorithm': {
        const value = args[++i];
        if (!value) {
          console.error('Missing algorithm name');
          usage();
          process.exit(1);
        }
        const normalized = value.toLowerCase();
        if (!SUPPORTED_ALGORITHMS.has(normalized)) {
          console.error(`Unsupported algorithm: ${value}`);
          usage();
          process.exit(1);
        }
        algorithm = normalized;
        break;
      }
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

  return { recipient, input, output, algorithm };
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

function readASN1Element(buffer, offset) {
  if (offset >= buffer.length) {
    throw new Error('Unexpected end of ASN.1 data');
  }
  const tag = buffer[offset];
  if (offset + 1 >= buffer.length) {
    throw new Error('Malformed ASN.1 length');
  }
  const lengthByte = buffer[offset + 1];
  let length = 0;
  let headerLength = 2;

  if ((lengthByte & 0x80) === 0) {
    length = lengthByte;
  } else {
    const numBytes = lengthByte & 0x7f;
    if (numBytes === 0) {
      throw new Error('Indefinite lengths are not supported');
    }
    if (offset + 2 + numBytes > buffer.length) {
      throw new Error('Malformed ASN.1 length');
    }
    for (let i = 0; i < numBytes; i += 1) {
      length = (length << 8) | buffer[offset + 2 + i];
    }
    headerLength += numBytes;
  }

  const contentStart = offset + headerLength;
  const contentEnd = contentStart + length;
  if (contentEnd > buffer.length) {
    throw new Error('ASN.1 element overruns buffer');
  }

  return {
    tag,
    length,
    headerLength,
    contentStart,
    contentEnd,
    totalLength: headerLength + length
  };
}

function pemToDer(pem) {
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/i);
  if (!match) {
    throw new Error('Invalid certificate PEM');
  }
  const base64 = match[1].replace(/\s+/g, '');
  return Buffer.from(base64, 'base64');
}

function extractIssuerAndSerial(pemPath) {
  const pem = fs.readFileSync(pemPath, 'utf8');
  const der = pemToDer(pem);

  const certSeq = readASN1Element(der, 0);
  if (certSeq.tag !== 0x30) {
    throw new Error('Certificate is not a sequence');
  }

  const tbsOffset = certSeq.contentStart;
  const tbs = readASN1Element(der, tbsOffset);
  if (tbs.tag !== 0x30) {
    throw new Error('TBSCertificate is not a sequence');
  }

  let pos = tbs.contentStart;
  let element = readASN1Element(der, pos);

  if (element.tag === 0xa0) {
    pos += element.totalLength;
    element = readASN1Element(der, pos);
  }

  if (element.tag !== 0x02) {
    throw new Error('Expected serialNumber INTEGER');
  }
  const serial = der.slice(element.contentStart, element.contentEnd);
  pos += element.totalLength;

  element = readASN1Element(der, pos); // signature algorithm
  pos += element.totalLength;

  element = readASN1Element(der, pos); // issuer
  if (element.tag !== 0x30) {
    throw new Error('Expected issuer Name sequence');
  }
  const issuerDer = der.slice(pos, pos + element.totalLength);

  return { pem, issuerDer, serial };
}

function encodeLength(length) {
  if (length < 0x80) {
    return Buffer.from([length]);
  }
  const bytes = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeInteger(value) {
  let buf = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from([value]);
  if (buf.length === 0) {
    buf = Buffer.from([0]);
  }
  let index = 0;
  while (index < buf.length - 1 && buf[index] === 0x00 && (buf[index + 1] & 0x80) === 0) {
    index += 1;
  }
  buf = buf.slice(index);
  if (buf[0] & 0x80) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return Buffer.concat([Buffer.from([0x02]), encodeLength(buf.length), buf]);
}

function encodeOID(oid) {
  const parts = oid.split('.').map((part) => Number(part));
  if (parts.length < 2) {
    throw new Error(`Invalid OID: ${oid}`);
  }
  const firstByte = 40 * parts[0] + parts[1];
  const body = [firstByte];
  for (let i = 2; i < parts.length; i += 1) {
    body.push(...encodeBase128(parts[i]));
  }
  const content = Buffer.from(body);
  return Buffer.concat([Buffer.from([0x06]), encodeLength(content.length), content]);
}

function encodeBase128(value) {
  if (value === 0) {
    return [0];
  }
  const bytes = [];
  let remaining = value;
  while (remaining > 0) {
    bytes.unshift(remaining & 0x7f);
    remaining >>= 7;
  }
  for (let i = 0; i < bytes.length - 1; i += 1) {
    bytes[i] |= 0x80;
  }
  return bytes;
}

function encodeOctetString(buffer) {
  const content = Buffer.from(buffer);
  return Buffer.concat([Buffer.from([0x04]), encodeLength(content.length), content]);
}

function encodeNull() {
  return Buffer.from([0x05, 0x00]);
}

function encodeSequence(components) {
  const content = Buffer.concat(components);
  return Buffer.concat([Buffer.from([0x30]), encodeLength(content.length), content]);
}

function encodeSet(components) {
  const content = Buffer.concat(components);
  return Buffer.concat([Buffer.from([0x31]), encodeLength(content.length), content]);
}

function encodeExplicit(tagNumber, content) {
  const tag = 0xa0 + tagNumber;
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

function encodeImplicitOctetString(tagNumber, buffer) {
  const content = Buffer.from(buffer);
  return Buffer.concat([Buffer.from([0x80 | tagNumber]), encodeLength(content.length), content]);
}

function encodeGcmParameters(iv, tagLength) {
  const components = [encodeOctetString(iv)];
  if (typeof tagLength === 'number') {
    components.push(encodeInteger(tagLength));
  }
  return encodeSequence(components);
}

function encryptContent(plaintext, algorithm) {
  const cek = crypto.randomBytes(32);
  if (algorithm === 'aes-256-gcm') {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv, { authTagLength: 16 });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return { cek, iv, ciphertext, tag };
  }
  if (algorithm === 'aes-256-cbc') {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', cek, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { cek, iv, ciphertext };
  }
  throw new Error(`Unsupported algorithm: ${algorithm}`);
}

function buildCmsEnvelope(encryptionResult, certInfo, algorithm) {
  const encryptedKey = crypto.publicEncrypt(
    {
      key: certInfo.pem,
      padding: crypto.constants.RSA_PKCS1_PADDING
    },
    encryptionResult.cek
  );

  const recipientInfo = encodeSequence([
    encodeInteger(0),
    encodeSequence([
      certInfo.issuerDer,
      encodeInteger(certInfo.serial)
    ]),
    encodeSequence([
      encodeOID(OID.RSA_ENCRYPTION),
      encodeNull()
    ]),
    encodeOctetString(encryptedKey)
  ]);

  if (algorithm === 'aes-256-gcm') {
    const gcmParameters = encodeGcmParameters(encryptionResult.iv, 16);

    const authEncryptedContentInfo = encodeSequence([
      encodeOID(OID.DATA),
      encodeSequence([
        encodeOID(OID.AES_256_GCM),
        gcmParameters
      ]),
      encodeImplicitOctetString(0, encryptionResult.ciphertext)
    ]);

    const authEnvelopedData = encodeSequence([
      encodeInteger(0),
      encodeSet([recipientInfo]),
      authEncryptedContentInfo,
      encodeOctetString(encryptionResult.tag)
    ]);

    return encodeSequence([
      encodeOID(OID.AUTH_ENVELOPED_DATA),
      encodeExplicit(0, authEnvelopedData)
    ]);
  }

  if (algorithm === 'aes-256-cbc') {
    const encryptedContentInfo = encodeSequence([
      encodeOID(OID.DATA),
      encodeSequence([
        encodeOID(OID.AES_256_CBC),
        encodeOctetString(encryptionResult.iv)
      ]),
      encodeImplicitOctetString(0, encryptionResult.ciphertext)
    ]);

    const envelopedData = encodeSequence([
      encodeInteger(0),
      encodeSet([recipientInfo]),
      encryptedContentInfo
    ]);

    return encodeSequence([
      encodeOID(OID.ENVELOPED_DATA),
      encodeExplicit(0, envelopedData)
    ]);
  }

  throw new Error(`Unsupported algorithm: ${algorithm}`);
}

function encrypt(recipientPath, inputPath, outputPath, algorithm) {
  ensureReadableFile('recipient certificate', recipientPath);
  ensureReadableFile('input file', inputPath);
  if (!outputPath) {
    throw new Error('Missing required output path');
  }

  const certInfo = extractIssuerAndSerial(recipientPath);
  const plaintext = fs.readFileSync(inputPath);
  const encryptionResult = encryptContent(plaintext, algorithm);
  const cmsDer = buildCmsEnvelope(encryptionResult, certInfo, algorithm);

  const tmpPath = `${outputPath}.part`;
  fs.writeFileSync(tmpPath, cmsDer);
  fs.renameSync(tmpPath, outputPath);
}

function main() {
  const { recipient, input, output, algorithm } = parseArgs();

  try {
    console.log(`[encrypt] ⏳ Encrypting '${input}' → '${output}' (CMS, ${algorithm.toUpperCase()})…`);
    encrypt(recipient, input, output, algorithm);
    console.log(`[encrypt] ✅ Wrote CMS envelope: ${output}`);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    usage();
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

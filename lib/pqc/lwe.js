'use strict';

const crypto = require('crypto');

const PARAMS = {
  name: 'Regev-LWE-640',
  n: 640,
  q: 32768,
  eta: 4,
};

function shake128(seed, length) {
  const hash = crypto.createHash('shake128', { outputLength: length });
  hash.update(seed);
  return new Uint8Array(hash.digest());
}

function generateMatrix(seed, n, q) {
  const totalEntries = n * n;
  const bytesNeeded = totalEntries * 2;
  const stream = shake128(seed, bytesNeeded);
  const matrix = new Uint16Array(totalEntries);
  for (let i = 0; i < totalEntries; i += 1) {
    const lo = stream[2 * i];
    const hi = stream[2 * i + 1];
    matrix[i] = ((hi << 8) | lo) % q;
  }
  return matrix;
}

function popcnt4(x) {
  x &= 0x0f;
  x = (x & 0x5) + ((x >> 1) & 0x5);
  x = (x & 0x3) + ((x >> 2) & 0x3);
  return x;
}

function sampleBinaryVector(len) {
  const bytes = crypto.randomBytes(len);
  const vec = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) {
    vec[i] = bytes[i] & 1;
  }
  return vec;
}

function sampleErrorVector(len, eta) {
  const bytes = crypto.randomBytes(len);
  const vec = new Int8Array(len);
  for (let i = 0; i < len; i += 1) {
    const b = bytes[i];
    const a = popcnt4(b & 0x0f);
    const c = popcnt4(b >> 4);
    vec[i] = a - c;
    if (eta > 4) {
      const extra = eta - 4;
      let acc = 0;
      let count = extra;
      while (count > 0) {
        const rand = crypto.randomBytes(1)[0];
        const a2 = popcnt4(rand & 0x0f);
        const c2 = popcnt4(rand >> 4);
        acc += a2 - c2;
        count -= 1;
      }
      vec[i] += acc;
    }
  }
  return vec;
}

function sampleErrorScalar(eta) {
  const [v] = sampleErrorVector(1, eta);
  return v;
}

function modQ(x, q) {
  let r = x % q;
  if (r < 0) {
    r += q;
  }
  return r;
}

function matrixVectorMultiply(matrix, vector, n, q) {
  const result = new Uint16Array(n);
  for (let row = 0; row < n; row += 1) {
    let acc = 0;
    for (let col = 0; col < n; col += 1) {
      const a = matrix[row * n + col];
      const b = vector[col];
      acc += a * b;
    }
    result[row] = modQ(acc, q);
  }
  return result;
}

function dotProduct(vecA, vecB, q) {
  let acc = 0;
  for (let i = 0; i < vecA.length; i += 1) {
    acc += vecA[i] * vecB[i];
  }
  return modQ(acc, q);
}

function addError(vector, error, q) {
  const out = new Uint16Array(vector.length);
  for (let i = 0; i < vector.length; i += 1) {
    out[i] = modQ(vector[i] + error[i], q);
  }
  return out;
}

function bufferFromUint16Array(arr) {
  const buf = Buffer.alloc(arr.length * 2);
  for (let i = 0; i < arr.length; i += 1) {
    buf.writeUInt16LE(arr[i], i * 2);
  }
  return buf;
}

function uint16ArrayFromBuffer(buf) {
  if (buf.length % 2 !== 0) {
    throw new Error('Invalid buffer length for Uint16Array');
  }
  const arr = new Uint16Array(buf.length / 2);
  for (let i = 0; i < arr.length; i += 1) {
    arr[i] = buf.readUInt16LE(i * 2);
  }
  return arr;
}

function uint8ArrayFromBuffer(buf) {
  return new Uint8Array(buf);
}

function bufferFromUint8Array(arr) {
  return Buffer.from(arr);
}

function generateKeypair(params = PARAMS) {
  const { n, q, eta } = params;
  const seedA = crypto.randomBytes(32);
  const matrixA = generateMatrix(seedA, n, q);
  const s = sampleBinaryVector(n);
  const e = sampleErrorVector(n, eta);
  const b = new Uint16Array(n);
  for (let col = 0; col < n; col += 1) {
    let acc = e[col];
    for (let row = 0; row < n; row += 1) {
      acc += matrixA[row * n + col] * s[row];
    }
    b[col] = modQ(acc, q);
  }

  const publicKey = {
    format: 'SFD-PQ-PUB-1',
    scheme: params.name,
    params: { n, q, eta },
    seed: seedA.toString('base64'),
    b: bufferFromUint16Array(b).toString('base64'),
  };

  const privateKey = {
    format: 'SFD-PQ-PRIV-1',
    scheme: params.name,
    params: { n, q, eta },
    seed: seedA.toString('base64'),
    s: bufferFromUint8Array(s).toString('base64'),
  };

  return { publicKey, privateKey };
}

function serializeCiphertext({ params, bits, byteLength, vectorsU, scalarsV }) {
  const { n, q } = params;
  const perBit = n * 2 + 2;
  const totalLen = 4 + 1 + 2 + 2 + 2 + 2 + bits * perBit;
  const buf = Buffer.alloc(totalLen);
  let offset = 0;
  buf.write('SFDQ', offset, 'ascii');
  offset += 4;
  buf[offset] = 1; // version
  offset += 1;
  buf.writeUInt16LE(n, offset);
  offset += 2;
  buf.writeUInt16LE(q, offset);
  offset += 2;
  buf.writeUInt16LE(bits, offset);
  offset += 2;
  buf.writeUInt16LE(byteLength, offset);
  offset += 2;

  for (let i = 0; i < bits; i += 1) {
    const u = vectorsU[i];
    const v = scalarsV[i];
    for (let j = 0; j < n; j += 1) {
      buf.writeUInt16LE(u[j], offset);
      offset += 2;
    }
    buf.writeUInt16LE(v, offset);
    offset += 2;
  }

  return buf;
}

function deserializeCiphertext(buffer) {
  let offset = 0;
  if (buffer.length < 13) {
    throw new Error('Ciphertext too short');
  }
  const magic = buffer.toString('ascii', offset, offset + 4);
  if (magic !== 'SFDQ') {
    throw new Error('Invalid ciphertext magic');
  }
  offset += 4;
  const version = buffer[offset];
  offset += 1;
  if (version !== 1) {
    throw new Error(`Unsupported ciphertext version: ${version}`);
  }
  const n = buffer.readUInt16LE(offset);
  offset += 2;
  const q = buffer.readUInt16LE(offset);
  offset += 2;
  const bits = buffer.readUInt16LE(offset);
  offset += 2;
  const byteLength = buffer.readUInt16LE(offset);
  offset += 2;

  const vectorsU = new Array(bits);
  const scalarsV = new Uint16Array(bits);

  for (let i = 0; i < bits; i += 1) {
    const u = new Uint16Array(n);
    for (let j = 0; j < n; j += 1) {
      if (offset + 2 > buffer.length) {
        throw new Error('Ciphertext truncated (u)');
      }
      u[j] = buffer.readUInt16LE(offset);
      offset += 2;
    }
    if (offset + 2 > buffer.length) {
      throw new Error('Ciphertext truncated (v)');
    }
    const v = buffer.readUInt16LE(offset);
    offset += 2;
    vectorsU[i] = u;
    scalarsV[i] = v;
  }

  if (offset !== buffer.length) {
    throw new Error('Ciphertext has trailing data');
  }

  return {
    params: { n, q },
    bits,
    byteLength,
    vectorsU,
    scalarsV,
  };
}

function ensureParamsMatch(params, keyParams) {
  if (params.n !== keyParams.n || params.q !== keyParams.q) {
    throw new Error('Ciphertext parameters do not match key parameters');
  }
}

function bitsFromBuffer(buffer) {
  const bits = [];
  for (let byteIndex = 0; byteIndex < buffer.length; byteIndex += 1) {
    const byte = buffer[byteIndex];
    for (let bit = 0; bit < 8; bit += 1) {
      bits.push((byte >> bit) & 1);
    }
  }
  return bits;
}

function bufferFromBits(bits) {
  const bytes = Buffer.alloc(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i += 1) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = i % 8;
    bytes[byteIndex] |= bits[i] << bitIndex;
  }
  return bytes;
}

function encryptKey(publicKey, keyBuffer) {
  if (publicKey.format !== 'SFD-PQ-PUB-1') {
    throw new Error('Unsupported public key format');
  }
  const { params } = publicKey;
  const { n, q, eta } = params;
  const seedA = Buffer.from(publicKey.seed, 'base64');
  const matrixA = generateMatrix(seedA, n, q);
  const b = uint16ArrayFromBuffer(Buffer.from(publicKey.b, 'base64'));

  const keyBits = bitsFromBuffer(keyBuffer);
  const vectorsU = new Array(keyBits.length);
  const scalarsV = new Uint16Array(keyBits.length);

  for (let idx = 0; idx < keyBits.length; idx += 1) {
    const r = sampleBinaryVector(n);
    const e1 = sampleErrorVector(n, eta);
    const e2 = sampleErrorScalar(eta);
    const uBase = matrixVectorMultiply(matrixA, r, n, q);
    const u = addError(uBase, e1, q);
    let v = dotProduct(b, r, q);
    v = modQ(v + e2 + (keyBits[idx] ? Math.floor(q / 2) : 0), q);
    vectorsU[idx] = u;
    scalarsV[idx] = v;
  }

  const ciphertext = serializeCiphertext({
    params,
    bits: keyBits.length,
    byteLength: keyBuffer.length,
    vectorsU,
    scalarsV,
  });
  return ciphertext;
}

function decryptKey(privateKey, ciphertextBuffer) {
  if (privateKey.format !== 'SFD-PQ-PRIV-1') {
    throw new Error('Unsupported private key format');
  }
  const { params } = privateKey;
  const { n, q } = params;
  const seedA = Buffer.from(privateKey.seed, 'base64');
  const s = uint8ArrayFromBuffer(Buffer.from(privateKey.s, 'base64'));
  if (s.length !== n) {
    throw new Error('Private key vector length mismatch');
  }

  const parsed = deserializeCiphertext(ciphertextBuffer);
  ensureParamsMatch(parsed.params, params);
  const bits = new Array(parsed.bits);

  for (let idx = 0; idx < parsed.bits; idx += 1) {
    const u = parsed.vectorsU[idx];
    const v = parsed.scalarsV[idx];
    let inner = 0;
    for (let i = 0; i < n; i += 1) {
      inner += s[i] * u[i];
    }
    inner = modQ(inner, q);
    let diff = v - inner;
    diff = modQ(diff, q);
    const bit = (diff >= (q / 4) && diff <= ((3 * q) / 4)) ? 1 : 0;
    bits[idx] = bit;
  }

  const full = bufferFromBits(bits);
  const keyBuffer = full.subarray(0, parsed.byteLength);
  return keyBuffer;
}

module.exports = {
  PARAMS,
  generateKeypair,
  encryptKey,
  decryptKey,
  serializeCiphertext,
  deserializeCiphertext,
};

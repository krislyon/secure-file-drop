#!/usr/bin/env node
'use strict';

const { loadPrivateKey } = require('../lib/pqc/key_io');

function main() {
  const file = process.argv[2];
  if (!file) {
    console.error('Usage: validate_private_key.js <private_key.json>');
    process.exit(2);
  }
  const passphrase = process.env.SFD_PQ_PRIV_PASSPHRASE;
  loadPrivateKey(file, passphrase);
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

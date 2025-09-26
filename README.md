# Secure File Drop

Secure File Drop is a set of hardened-friendly helpers that let you accept files
protected with authenticated encryption while storing the wrapping keys using a
post-quantum secure asymmetric scheme. The toolkit covers the entire flow: key
generation, directory provisioning, unattended decryption, and client-side
encryption helpers.

## Post-Quantum by Default

The original version of Secure File Drop relied on CMS/RSA envelopes. The
project now uses a Learning-With-Errors (LWE) based public-key encryption
scheme inspired by Regev's construction. Each payload is protected with
AES-256-GCM and the symmetric key is wrapped with the lattice-based KEM. The
scheme uses 640-dimensional secret vectors, a modulus of 32768, and centered
binomial noise (η = 4), providing conservative quantum-resistant security while
remaining fully self-contained.

The wire format is JSON for ease of inspection and auditing. Every envelope
looks like this:

```json
{
  "format": "SFD-PQC-ENVELOPE-1",
  "kem": {
    "scheme": "Regev-LWE-640",
    "params": { "n": 640, "q": 32768, "eta": 4 },
    "ciphertext": "...base64..."
  },
  "aead": {
    "algorithm": "AES-256-GCM",
    "iv": "...",
    "ciphertext": "...",
    "authTag": "..."
  }
}
```

## Repository Layout

```text
.
├── decrypt_file.js      # Decrypt a PQC envelope to plaintext
├── decrypt_watch.sh     # Continuously decrypt new envelopes
├── encrypt_file.js      # Encrypt files with AES-256-GCM + PQC KEM
├── encrypt_file.sh      # Thin wrapper around encrypt_file.js
├── init_keys.sh         # Create an LWE key pair (passphrase protected)
├── init_layout.sh       # Provision secure inbox/outbox directories
├── lib/pqc/             # Post-quantum primitives and key I/O helpers
├── samples/             # Example payloads
└── tools/               # Utility scripts (key generation & validation)
```

## Prerequisites

* Linux or another POSIX environment with Bash ≥ 4
* Node.js 18+ (for the encryption/decryption utilities)
* Optional but recommended: [`inotify-tools`](https://github.com/inotify-tools/inotify-tools)
  so `decrypt_watch.sh` can react instantly; otherwise it falls back to polling
  every few seconds.

## Getting Started

1. **Generate the recipient keys**

   ```bash
   ./init_keys.sh keys "SFD PQC Recipient"
   ```

   The script prompts for a strong passphrase, stores the encrypted private key
   (`private_key_encrypted.json`) and matching public key (`public_key.json`) in
   the target directory. Keep the passphrase safe—it is required when
   decrypting files.

2. **Provision the secure file-drop layout**

   ```bash
   sudo ./init_layout.sh --root /secure --make-user --tmpfiles
   ```

   This creates `/secure/{inbox,outbox,processed,error,keys}` with restrictive
   permissions, optionally creates a dedicated system user, and installs a
   tmpfiles rule if requested.

3. **Start the decryption watcher**

   Place `public_key.json` (optional) and `private_key_encrypted.json` in
   `/secure/keys/`, then launch:

   ```bash
   PRIVKEY_JSON=/secure/keys/private_key_encrypted.json \
   ./decrypt_watch.sh
   ```

   The watcher validates the private key, prompts once for its passphrase (or
   honours `PASSIN_OPT` if provided), and continuously processes new `.cms`
   envelopes that appear in `/secure/inbox`. Successful decryptions are written
   atomically into `/secure/outbox` and the original envelopes are archived
   under `/secure/processed`. Failures move the envelope to `/secure/error` for
   inspection.

4. **Encrypt a file on the sending side**

   ```bash
   ./encrypt_file.sh \
     -r /path/to/public_key.json \
     -i secret.pdf \
     -o secret.pdf.cms
   ```

   The script produces an `SFD-PQC-ENVELOPE-1` JSON file using AES-256-GCM for
   the payload and the lattice-based KEM for key encapsulation. The resulting
   `.cms` file can be dropped into the inbox for decryption.

   Prefer JavaScript? Call the Node.js implementation directly:

   ```bash
   node encrypt_file.js \
     -r /path/to/public_key.json \
     -i secret.pdf \
     -o secret.pdf.cms
   ```

## Configuring `decrypt_watch.sh`

`decrypt_watch.sh` honours a handful of environment variables so it can fit
different deployment layouts. Defaults are shown below.

| Variable        | Default value                               | Purpose |
| --------------- | ------------------------------------------- | ------- |
| `WATCH_DIR`     | `/secure/inbox`                             | Location to monitor for incoming envelopes |
| `OUT_DIR`       | `/secure/outbox`                            | Where decrypted payloads are written |
| `PROCESSED_DIR` | `/secure/processed`                         | Archive for successfully processed envelopes |
| `ERROR_DIR`     | `/secure/error`                             | Holds envelopes that failed to decrypt |
| `PRIVKEY_JSON`  | `/secure/keys/private_key_encrypted.json`   | Encrypted private key JSON |
| `PASSIN_OPT`    | `ask`                                       | How to supply the private-key passphrase (`ask`, `env:VAR`, `pass:****`) |
| `POLL_SEC`      | `2`                                         | Poll interval (seconds) if `inotifywait` is unavailable |

Additional behaviour worth noting:

* When `PASSIN_OPT=ask` (the default) and a TTY is available, the script caches
  the passphrase in memory for the lifetime of the process so you are not
  prompted for every file.
* If `PASSIN_OPT` is set to `env:VAR` or `pass:****`, the passphrase is sourced
  non-interactively—useful for supervised services.
* Directory permissions are tightened on startup whenever possible, helping you
  detect misconfigurations early.

## Operating Tips

* Arrange for the watcher to run as a dedicated low-privilege user (e.g.
  `decryptd`) created via `init_layout.sh`.
* Back up the encrypted private key and its passphrase securely. Without them,
  encrypted files cannot be recovered.
* Monitor the `error/` directory for envelopes that could not be decrypted—this
  is a signal of incorrect keys, tampering, or passphrase issues.
* Consider rotating the recipient key pair periodically by re-running
  `init_keys.sh` and distributing the new `public_key.json` to senders.

## License

This project is distributed under the MIT license. See [LICENSE](LICENSE) if
provided by the repository owner.

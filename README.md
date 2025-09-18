# Secure File Drop

Secure File Drop is a set of hardening-friendly shell scripts that let you accept
files encrypted with CMS (Cryptographic Message Syntax) and decrypt them safely
on a dedicated host. It covers the entire flow: key generation, directory
provisioning, unattended decryption, and client-side encryption helpers.

## Why CMS?

CMS (the successor to PKCS#7) is widely supported, easy to automate with
OpenSSL, and allows encrypting large payloads without revealing their contents
or metadata. These scripts embrace CMS with AES-256-GCM envelopes so you can
exchange files without standing up a heavyweight service.

## Repository Layout

```text
.
├── encrypt_file.sh    # Encrypt files for the secure inbox
├── decrypt_watch.sh   # Continuously decrypt new CMS envelopes
├── init_keys.sh       # Create RSA keys and a self-signed certificate
├── init_layout.sh     # Provision secure inbox/outbox directories
└── README.md
```

## Prerequisites

* Linux or another POSIX environment with Bash ≥ 4
* [OpenSSL](https://www.openssl.org/) 1.1 or newer (for `openssl cms` and
  `openssl pkcs8`)
* Optional but recommended: [`inotify-tools`](https://github.com/inotify-tools/inotify-tools)
  so `decrypt_watch.sh` can react instantly; otherwise it falls back to polling
  every few seconds.

## Getting Started

1. **Generate the recipient keys**

   ```bash
   ./init_keys.sh keys "Offline CMS Recipient"
   ```

   The script prompts for a strong passphrase, stores the encrypted private key
   (`privkey_encrypted.pk8`), the matching public key, and a self-signed
   certificate in the target directory. Keep the passphrase safe—it is required
   when decrypting files.

2. **Provision the secure file-drop layout**

   ```bash
   sudo ./init_layout.sh --root /secure --make-user --tmpfiles
   ```

   This creates `/secure/{inbox,outbox,processed,error,keys}` with restrictive
   permissions, optionally creates a dedicated system user, and installs a
   tmpfiles rule if requested.

3. **Start the decryption watcher**

   Place the certificate and encrypted private key created earlier into
   `/secure/keys/`, then launch:

   ```bash
   CERT_PEM=/secure/keys/cert.pem \
   PRIVKEY_PK8=/secure/keys/privkey_encrypted.pk8 \
   ./decrypt_watch.sh
   ```

   The watcher validates the private key, prompts once for its passphrase (or
   uses `PASSIN_OPT` if provided), and continuously processes new `.cms` files
   that appear in `/secure/inbox`. Successful decryptions are written atomically
   into `/secure/outbox` and the original envelopes are archived under
   `/secure/processed`. Failures move the envelope to `/secure/error` for
   inspection.

4. **Encrypt a file on the sending side**

   ```bash
   ./encrypt_file.sh \
     -r /path/to/recipient_cert.pem \
     -i secret.pdf \
     -o secret.pdf.cms
   ```

   The script produces a DER-formatted CMS envelope using AES-256-GCM and the
   recipient's RSA certificate. The resulting `.cms` file can be dropped into
   the inbox for decryption.

## Configuring `decrypt_watch.sh`

`decrypt_watch.sh` honours a handful of environment variables so it can fit
different deployment layouts. Defaults are shown below.

| Variable        | Default value                     | Purpose |
| --------------- | --------------------------------- | ------- |
| `WATCH_DIR`     | `/secure/inbox`                   | Location to monitor for incoming `.cms` files |
| `OUT_DIR`       | `/secure/outbox`                  | Where decrypted payloads are written |
| `PROCESSED_DIR` | `/secure/processed`               | Archive for successfully processed envelopes |
| `ERROR_DIR`     | `/secure/error`                   | Holds envelopes that failed to decrypt |
| `CERT_PEM`      | `/secure/keys/cert.pem`           | Recipient certificate (PEM) |
| `PRIVKEY_PK8`   | `/secure/keys/privkey_encrypted.pk8` | Encrypted PKCS#8 private key |
| `PASSIN_OPT`    | `ask`                             | How to supply the private-key passphrase (`ask`, `env:VAR`, `file:/path`, …) |
| `POLL_SEC`      | `2`                               | Poll interval (seconds) if `inotifywait` is unavailable |

Additional behaviour worth noting:

* When `PASSIN_OPT=ask` (the default) and a TTY is available, the script caches
  the passphrase in memory for the lifetime of the process so you are not
  prompted for every file.
* If `PASSIN_OPT` is set to `env:VAR`, `file:/path`, or `fd:N`, OpenSSL follows
  its usual `-passin` semantics, allowing unattended operation.
* Directory permissions are tightened on startup whenever possible, helping you
  detect misconfigurations early.

## Operating Tips

* Arrange for the watcher to run as a dedicated low-privilege user (e.g.
  `decryptd`) created via `init_layout.sh`.
* Back up the encrypted private key and its passphrase securely. Without them,
  encrypted files cannot be recovered.
* Monitor the `error/` directory for envelopes that could not be decrypted—this
  is a signal of incorrect certificates, tampering, or passphrase issues.
* Consider rotating the recipient certificate periodically by re-running
  `init_keys.sh` and distributing the new `cert.pem` to senders.

## License

This project is distributed under the MIT license. See [LICENSE](LICENSE) if
provided by the repository owner.

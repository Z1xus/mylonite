# Security

## Reporting a vulnerability

Do not open a public issue. Report it privately through [GitHub security advisories](https://github.com/Z1xus/mylonite/security/advisories/new). Include the version, the steps to reproduce, and the impact.

Only the latest release gets fixes.

## Model

The server stores ciphertext only. It cannot read note content, file names, or paths.

- Vault data is encrypted on the device with XChaCha20-Poly1305. The keys come from a random vault secret through Argon2id and HKDF. The vault secret never leaves paired devices unencrypted.
- Blob ids are keyed BLAKE3 hashes, so the server cannot match files against known content.
- Each device has an Ed25519 key. It signs every API request and the WebSocket handshake. Revoked devices are rejected.
- A new device gets the vault secret through an X25519 exchange. Approve it only when the six-digit safety code matches on both devices.
- The admin API answers loopback connections only.

## Limits

- The server sees metadata: device ids, op count and timing, and blob and op sizes.
- Anyone with access to a paired device can read the vault. Local sync state is not encrypted at rest.
- On platforms without Obsidian SecretStorage, the device key and vault secret are stored in the plugin data file.
- If you lose every paired device, the vault cannot be recovered.
- Use TLS, directly or through a reverse proxy, for any server that is not on localhost.

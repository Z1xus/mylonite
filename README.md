# Mylonite

![Latest release](https://img.shields.io/github/v/release/z1xus/mylonite)
![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)
![Bun](https://img.shields.io/badge/runtime-bun-black.svg)
![Obsidian](https://img.shields.io/badge/obsidian-desktop%20%2B%20mobile-7c3aed.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Mylonite is a self-hosted sync server for Obsidian. Use it with the Mylonite plugin to pair devices and sync end-to-end encrypted vault data through your own storage.

<p align="center">
<img width="960" height="540" alt="Image" src="https://github.com/user-attachments/assets/83c73568-f482-4cb8-8103-48ea9a87cf7d" />
<sub> Synchronization showcase using a remote server hundreds of kilometers away. Vault data remains end-to-end encrypted throughout the sync process.</sub>
</p>
<br>

> [!NOTE]  
> Mylonite is still in early development, expect bugs and breaking changes.

## Server

Install the latest binary.

Debian/Ubuntu x86_64:

```bash
curl -fL -o /tmp/mylonite \
  https://github.com/z1xus/mylonite/releases/latest/download/mylonite-x86_64-unknown-linux-gnu
sudo install -m 0755 /tmp/mylonite /usr/local/bin/mylonite
mylonite --version
```

Other platforms: grab the matching binary from Releases and place it on your `PATH`.

Create the config and the first vault's pairing token:

```bash
mylonite init
```

Run the server:

```bash
mylonite serve
```

The default config lives at:

- Linux: `~/.config/mylonite/config.toml`
- macOS: `~/Library/Application Support/mylonite/config.toml`
- Windows: `%APPDATA%\mylonite\config.toml`

Keep `listen = "127.0.0.1:9821"` when a reverse proxy terminates TLS on the same host.  
Use `listen = "0.0.0.0:9821"` and set `public_url` to the reachable URL if the server should accept direct connections.

### Systemd

Drop this unit at `/etc/systemd/system/mylonite.service`, replacing `YOUR_USER` with the account that ran `mylonite init`:

```ini
[Unit]
Description=Mylonite sync server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mylonite serve
Restart=on-failure
User=YOUR_USER

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mylonite
sudo systemctl status mylonite
```

Windows: run `mylonite serve` with NSSM, WinSW, or your preferred service wrapper.

### Docker

```bash
docker run -p 9821:9821 \
  -v ./config.toml:/etc/mylonite/config.toml:ro \
  -v ./data:/var/lib/mylonite \
  ghcr.io/z1xus/mylonite:latest
```

## Plugin

[Install Mylonite](obsidian://show-plugin?id=mylonite) from the [Obsidian community plugin directory](https://community.obsidian.md/plugins/mylonite).

Beta install: install [BRAT](https://tfthacker.com/brat-quick-guide), then add `https://github.com/Z1xus/mylonite` as a beta plugin.

Manual install: download [mylonite-obsidian-plugin.zip](https://github.com/z1xus/mylonite/releases/latest/download/mylonite-obsidian-plugin.zip) from Releases and extract it into:

```text
<vault>/.obsidian/plugins/mylonite/
```

Enable Mylonite in Obsidian's community plugins list, then open its settings.

## Pairing

The first device must be paired with the pairing token. Every other device joins through a short-lived invite approved by an already-paired device.

### First device

1. Enter your server URL (and optionally your device label).
2. Paste the pairing token printed by `mylonite init`.
3. Click Pair.

### Additional devices

1. On an already-paired device, open Mylonite settings -> Add another device -> Create. Mylonite shows a QR code, an invite code, and the server URL.
2. On the new device:
* If the camera is available, scan the QR code. It will open an invite page on your Mylonite server.
* Otherwise, type the server URL and invite code manually or paste the invite code.
3. Compare the six-digit safety code on both devices, then click Approve on the already-paired device.

If you ever lose access to every paired device, the vault data is unrecoverable — the encryption key was generated on the first device and the server only holds ciphertext. Wipe the dead vault and start fresh:

```bash
mylonite vault delete <vault_id>
mylonite vault create "My Vault"
# pair the new device with the freshly printed token
```

## Develop

Requirements:

- Rust 1.85+
- Bun 1.2+

Run locally:

```bash
cargo run -p mylonite -- serve --config dev/config.toml
cargo run -p mylonite -- vault create "My Vault" --config dev/config.toml
```

Build the plugin:

```bash
cd plugin
bun install
bun run build
```

Run checks:

```bash
cargo fmt --check
cargo clippy -p mylonite --all-targets -- -D warnings
cargo test -p mylonite
cd plugin
bun run test
bun run build
```

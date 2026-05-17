# Mylonite

![Latest release](https://img.shields.io/github/v/release/z1xus/mylonite)
![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)
![Bun](https://img.shields.io/badge/runtime-bun-black.svg)
![Obsidian](https://img.shields.io/badge/obsidian-desktop%20%2B%20mobile-7c3aed.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Mylonite is a self-hosted sync server for Obsidian. Use it with the Mylonite plugin to pair devices and sync encrypted vault data through your own storage.

## Deploy

Install the latest server binary.

Debian/Ubuntu x86_64:

```bash
curl -fL -o /tmp/mylonite \
  https://github.com/z1xus/mylonite/releases/latest/download/mylonite-x86_64-unknown-linux-gnu
sudo install -m 0755 /tmp/mylonite /usr/local/bin/mylonite
mylonite --version
```

Other platforms: download the matching binary from Releases and place it somewhere on `PATH`.

Bootstrap config and the first pairing token:

```bash
mylonite init
```

Start the server:

```bash
mylonite serve
```

Default config locations:

- Linux: `~/.config/mylonite/config.toml`
- macOS: `~/Library/Application Support/mylonite/config.toml`
- Windows: `%APPDATA%\mylonite\config.toml`

Run `mylonite serve` under your service manager.

Systemd:

```bash
sudo useradd --system --create-home --home-dir /var/lib/mylonite --shell /usr/sbin/nologin mylonite
sudo -u mylonite -H /usr/local/bin/mylonite init
sudo nano /var/lib/mylonite/.config/mylonite/config.toml
sudo nano /etc/systemd/system/mylonite.service
```

When running as the `mylonite` user, the default config path is `/var/lib/mylonite/.config/mylonite/config.toml`. Keep `listen = "127.0.0.1:9821"` if a reverse proxy terminates TLS on the same host. Use `listen = "0.0.0.0:9821"` and set `public_url` to the reachable URL if the server should accept direct network connections.

```ini
[Unit]
Description=Mylonite sync server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mylonite serve
Restart=on-failure
User=mylonite
Group=mylonite
WorkingDirectory=/var/lib/mylonite

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mylonite
sudo systemctl status mylonite
```

Windows: run `mylonite serve` with NSSM, WinSW, or your preferred service wrapper.

## Docker

```bash
docker run -p 9821:9821 \
  -v ./config.toml:/etc/mylonite/config.toml:ro \
  -v ./data:/var/lib/mylonite \
  ghcr.io/z1xus/mylonite:latest
```

## Install Plugin

Preferred: install [BRAT](https://tfthacker.com/brat-quick-guide), then add `z1xus/mylonite` as a beta plugin. This is the easiest path on mobile.

Manual install: download [mylonite-obsidian-plugin.zip](https://github.com/z1xus/mylonite/releases/latest/download/mylonite-obsidian-plugin.zip) from Releases and extract it into:

```text
<vault>/.obsidian/plugins/mylonite/
```

Enable Mylonite in Obsidian, enter the server URL and pairing token, then click Pair.

## Pair More Devices

1. On the new device, open Mylonite settings and click **Request**.
2. Copy the request to an already paired device.
3. Paste it into **Authorize another device** and click **Authorize**.
4. Copy the response back to the new device and click **Complete**.

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

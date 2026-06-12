mod app;
mod cli;
mod config;
mod storage;

use std::{
    io::{self, Write},
    net::SocketAddr,
};

use anyhow::Context;
use clap::Parser;
use cli::{Cli, Command, DeviceCommand, VaultCommand};
use config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { config, no_vault } => handle_init(config, no_vault),
        Command::Serve { config } => handle_serve(config.as_deref()).await,
        Command::Vault { command } => handle_vault(command),
        Command::Device { command } => handle_device(command),
        Command::Stats { config } => handle_stats(config.as_deref()),
    }
}

async fn handle_serve(config_path: Option<&std::path::Path>) -> anyhow::Result<()> {
    let config = config::Config::load_or_default(config_path)?;
    config::init_tracing(&config.log)?;
    let storage = storage::Storage::open(&config.server.data_dir)?;
    print_listening(config.server.listen, &config.server.public_url);
    app::serve(
        config.server.listen,
        config.tls,
        &config.server.data_dir,
        config.limits,
        config.snapshots,
        storage,
    )
    .await
}

fn handle_vault(command: VaultCommand) -> anyhow::Result<()> {
    match command {
        VaultCommand::Create { name, config } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            let name = match name {
                Some(name) => name,
                None => prompt_text("vault name", "My Vault")?,
            };
            let vault = with_admin_or_storage(
                &config,
                |admin| admin.create_vault(&name),
                |storage| storage.create_vault(&name),
            )
            .context("create vault")?;
            print_vault(&vault);
        }
        VaultCommand::List { config } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            for vault in with_admin_or_storage(&config, AdminClient::list_vaults, |storage| {
                storage.list_vaults()
            })? {
                println!("{}\t{}\t{}", vault.id, vault.name, vault.created_at_unix);
            }
        }
        VaultCommand::Delete { vault, config, yes } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            let vault_id = resolve_vault_id(&config, vault)?;
            if !yes
                && !prompt_yes_no(
                    &format!(
                        "Delete vault {vault_id} and all of its devices, ops, blobs, and snapshots?"
                    ),
                    false,
                )?
            {
                print_status("Cancelled", "vault was not deleted");
                return Ok(());
            }
            with_admin_or_storage(
                &config,
                |admin| admin.delete_vault(&vault_id),
                |storage| storage.delete_vault(&vault_id),
            )?;
            print_status("Vault", &format!("deleted {vault_id}"));
        }
    }
    Ok(())
}

fn handle_device(command: DeviceCommand) -> anyhow::Result<()> {
    match command {
        DeviceCommand::List { vault, config } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            let vault = resolve_vault_id(&config, vault)?;
            for device in with_admin_or_storage(
                &config,
                |admin| admin.list_devices(&vault),
                |storage| storage.list_devices(&vault),
            )? {
                println!(
                    "{}\t{}\t{}\t{:?}",
                    device.device_id, device.label, device.created_at_unix, device.revoked_at_unix
                );
            }
        }
        DeviceCommand::Revoke {
            vault,
            device,
            config,
        } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            let vault = resolve_vault_id(&config, vault)?;
            let device = resolve_device_id(&config, &vault, device)?;
            with_admin_or_storage(
                &config,
                |admin| admin.revoke_device(&vault, &device),
                |storage| storage.revoke_device(&vault, &device),
            )?;
            println!("revoked device {device} in vault {vault}");
        }
    }
    Ok(())
}

fn handle_stats(config_path: Option<&std::path::Path>) -> anyhow::Result<()> {
    let config = config::Config::load_or_default(config_path)?;
    let stats = with_admin_or_storage(&config, AdminClient::stats, storage::Storage::stats)?;
    println!("vaults={}", stats.vault_count);
    println!("devices={}", stats.device_count);
    println!("active_devices={}", stats.active_device_count);
    println!("revoked_devices={}", stats.revoked_device_count);
    println!("pairing_tokens={}", stats.pairing_token_count);
    println!("active_pairing_tokens={}", stats.active_pairing_token_count);
    println!(
        "consumed_pairing_tokens={}",
        stats.consumed_pairing_token_count
    );
    println!(
        "expired_pairing_tokens={}",
        stats.expired_pairing_token_count
    );
    println!("ops={}", stats.op_count);
    println!("blobs={}", stats.blob_count);
    println!("snapshots={}", stats.snapshot_count);
    println!(
        "indexed_blob_size={}",
        format_bytes(stats.indexed_blob_bytes)
    );
    println!("database_size={}", format_bytes(stats.database_bytes));
    println!("blob_file_size={}", format_bytes(stats.blob_file_bytes));
    println!(
        "total_storage_size={}",
        format_bytes(stats.total_storage_bytes)
    );
    println!("indexed_blob_bytes={}", stats.indexed_blob_bytes);
    println!("database_bytes={}", stats.database_bytes);
    println!("blob_file_bytes={}", stats.blob_file_bytes);
    println!("total_storage_bytes={}", stats.total_storage_bytes);
    println!("data_dir={}", stats.data_dir);
    Ok(())
}

fn print_vault(vault: &storage::CreatedVault) {
    println!("vault_id={}", vault.id);
    println!("name={}", vault.name);
    println!("pairing_token={}", vault.pairing_token);
}

fn resolve_vault_id(config: &Config, supplied: Option<String>) -> anyhow::Result<String> {
    if let Some(vault_id) = supplied {
        return Ok(vault_id);
    }
    let vaults = with_admin_or_storage(config, AdminClient::list_vaults, |storage| {
        storage.list_vaults()
    })?;
    match vaults.len() {
        0 => anyhow::bail!("no vaults configured; run mylonite vault create"),
        1 => Ok(vaults[0].id.clone()),
        _ => {
            print_status("Vaults", "select one");
            for (index, vault) in vaults.iter().enumerate() {
                println!("  {}. {} {}", index + 1, vault.name, dim(&vault.id));
            }
            let index = prompt_index("vault", vaults.len())?;
            Ok(vaults[index].id.clone())
        }
    }
}

fn resolve_device_id(
    config: &Config,
    vault_id: &str,
    supplied: Option<String>,
) -> anyhow::Result<String> {
    if let Some(device_id) = supplied {
        return Ok(device_id);
    }
    let devices = with_admin_or_storage(
        config,
        |admin| admin.list_devices(vault_id),
        |storage| storage.list_devices(vault_id),
    )?;
    match devices.len() {
        0 => anyhow::bail!("no devices found in vault {vault_id}"),
        1 => Ok(devices[0].device_id.clone()),
        _ => {
            print_status("Devices", "select one");
            for (index, device) in devices.iter().enumerate() {
                let revoked = if device.revoked_at_unix.is_some() {
                    " revoked"
                } else {
                    ""
                };
                println!(
                    "  {}. {} {}{}",
                    index + 1,
                    device.label,
                    dim(&device.device_id),
                    dim(revoked)
                );
            }
            let index = prompt_index("device", devices.len())?;
            Ok(devices[index].device_id.clone())
        }
    }
}

fn handle_init(config_path: Option<std::path::PathBuf>, no_vault: bool) -> anyhow::Result<()> {
    let path = config_path.unwrap_or_else(config::default_config_path);
    if path.exists() {
        print_status("Config", &format!("using {}", path.display()));
    } else {
        config::write_default_config(&path)?;
        print_status("Config", &format!("created {}", path.display()));
    }
    let config = config::Config::load_or_default(Some(&path))?;
    let existing_vaults = with_admin_or_storage(&config, AdminClient::list_vaults, |storage| {
        storage.list_vaults()
    })?;
    if existing_vaults.is_empty()
        && !no_vault
        && prompt_yes_no("create the first vault now?", true)?
    {
        let name = prompt_text("vault name", "My Vault")?;
        let vault = with_admin_or_storage(
            &config,
            |admin| admin.create_vault(&name),
            |storage| storage.create_vault(&name),
        )
        .context("create vault")?;
        print_status("Vault", &format!("created {}", vault.name));
        print_kv("vault id", &vault.id);
        print_kv("pairing token", &vault.pairing_token);
    } else if !existing_vaults.is_empty() {
        print_status(
            "Vaults",
            &format!("{} already configured", existing_vaults.len()),
        );
    }
    print_status("Next", "run mylonite serve");
    Ok(())
}

fn prompt_yes_no(question: &str, default: bool) -> anyhow::Result<bool> {
    let suffix = if default { "Y/n" } else { "y/N" };
    print!("{} {question} [{suffix}] ", cyan("?"));
    io::stdout().flush().context("flush prompt")?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read prompt")?;
    let input = input.trim().to_ascii_lowercase();
    if input.is_empty() {
        return Ok(default);
    }
    Ok(matches!(input.as_str(), "y" | "yes"))
}

fn prompt_text(label: &str, default: &str) -> anyhow::Result<String> {
    print!("{} {label} [{default}] ", cyan("?"));
    io::stdout().flush().context("flush prompt")?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).context("read prompt")?;
    let input = input.trim();
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input.to_string())
    }
}

fn prompt_index(label: &str, len: usize) -> anyhow::Result<usize> {
    loop {
        print!("{} {label} [1-{len}] ", cyan("?"));
        io::stdout().flush().context("flush prompt")?;
        let mut input = String::new();
        io::stdin().read_line(&mut input).context("read prompt")?;
        let input = input.trim();
        if let Ok(value) = input.parse::<usize>()
            && (1..=len).contains(&value)
        {
            return Ok(value - 1);
        }
        eprintln!("enter a number from 1 to {len}");
    }
}

fn print_listening(listen: SocketAddr, public_url: &str) {
    let trimmed = public_url.trim_end_matches('/');
    let display = if trimmed.is_empty() {
        format!("http://{listen}")
    } else {
        trimmed.to_string()
    };
    print_status("Server", &format!("listening on {display}"));
}

fn print_status(label: &str, value: &str) {
    println!("{} {} {}", green("*"), bold(label), value);
}

fn print_kv(label: &str, value: &str) {
    println!("  {} {}", dim(&format!("{label}:")), value);
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut divisor = 1_u64;
    let mut unit = 0;
    while bytes / divisor >= 1024 && unit < UNITS.len() - 1 {
        divisor *= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        let mut whole = bytes / divisor;
        let remainder = bytes % divisor;
        let mut tenths = ((remainder * 10) + (divisor / 2)) / divisor;
        if tenths == 10 {
            whole += 1;
            tenths = 0;
        }
        if whole >= 10 || tenths == 0 {
            format!("{whole} {}", UNITS[unit])
        } else {
            format!("{whole}.{tenths} {}", UNITS[unit])
        }
    }
}

fn green(text: &str) -> String {
    color("32", text)
}

fn cyan(text: &str) -> String {
    color("36", text)
}

fn bold(text: &str) -> String {
    color("1", text)
}

fn dim(text: &str) -> String {
    color("2", text)
}

fn color(code: &str, text: &str) -> String {
    if std::env::var_os("NO_COLOR").is_some() {
        text.to_string()
    } else {
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

fn with_admin_or_storage<T>(
    config: &Config,
    admin_op: impl FnOnce(&AdminClient) -> anyhow::Result<T>,
    storage_op: impl FnOnce(&storage::Storage) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let admin = AdminClient::new(config.server.listen);
    match admin_op(&admin) {
        Ok(value) => Ok(value),
        Err(error) if is_admin_unavailable(&error) => {
            let storage = storage::Storage::open(&config.server.data_dir)?;
            storage_op(&storage)
        }
        Err(error) => Err(error),
    }
}

fn is_admin_unavailable(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut
            )
        })
}

struct AdminClient {
    base_url: String,
}

impl AdminClient {
    fn new(listen: SocketAddr) -> Self {
        let host = if listen.ip().is_unspecified() {
            "127.0.0.1".to_string()
        } else if listen.ip().is_ipv6() {
            format!("[{}]", listen.ip())
        } else {
            listen.ip().to_string()
        };
        Self {
            base_url: format!("http://{host}:{}", listen.port()),
        }
    }

    fn create_vault(&self, name: &str) -> anyhow::Result<storage::CreatedVault> {
        self.json_request(
            "POST",
            "/api/v1/admin/vaults",
            Some(&serde_json::json!({ "name": name })),
        )
    }

    fn list_vaults(&self) -> anyhow::Result<Vec<storage::CreatedVault>> {
        self.json_request("GET", "/api/v1/admin/vaults", None)
    }

    fn delete_vault(&self, vault_id: &str) -> anyhow::Result<()> {
        self.empty_request("DELETE", &format!("/api/v1/admin/vaults/{vault_id}"))
    }

    fn list_devices(&self, vault_id: &str) -> anyhow::Result<Vec<storage::DeviceRecord>> {
        self.json_request(
            "GET",
            &format!("/api/v1/admin/vaults/{vault_id}/devices"),
            None,
        )
    }

    fn revoke_device(&self, vault_id: &str, device_id: &str) -> anyhow::Result<()> {
        self.empty_request(
            "POST",
            &format!("/api/v1/admin/vaults/{vault_id}/devices/{device_id}/revoke"),
        )
    }

    fn stats(&self) -> anyhow::Result<storage::StorageStats> {
        self.json_request("GET", "/api/v1/admin/stats", None)
    }

    fn json_request<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> anyhow::Result<T> {
        let response = self.request(method, path, body)?;
        serde_json::from_slice(&response).context("decode admin response")
    }

    fn empty_request(&self, method: &str, path: &str) -> anyhow::Result<()> {
        self.request(method, path, None).map(|_| ())
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> anyhow::Result<Vec<u8>> {
        use std::{
            io::{Read, Write},
            net::TcpStream,
            time::Duration,
        };

        let body = match body {
            Some(value) => serde_json::to_vec(value).context("encode admin request")?,
            None => Vec::new(),
        };
        let url = format!("{}{path}", self.base_url);
        let without_scheme = url
            .strip_prefix("http://")
            .context("admin URL must use http")?;
        let (authority, _) = without_scheme
            .split_once('/')
            .context("admin URL must include path")?;
        let mut stream = TcpStream::connect(authority).with_context(|| format!("connect {url}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .context("set admin read timeout")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .context("set admin write timeout")?;
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .context("write admin request headers")?;
        stream
            .write_all(&body)
            .context("write admin request body")?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .context("read admin response")?;
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .context("admin response missing headers")?
            + 4;
        let headers = std::str::from_utf8(&response[..header_end])
            .context("admin response headers are not UTF-8")?;
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .context("admin response missing status")?;
        let body = response[header_end..].to_vec();
        if !(200..300).contains(&status) {
            let message = String::from_utf8_lossy(&body);
            anyhow::bail!("admin request failed with HTTP {status}: {message}");
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::format_bytes;

    #[test]
    fn format_bytes_uses_compact_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(10 * 1024), "10 KiB");
        assert_eq!(format_bytes(3_694_592), "3.5 MiB");
    }
}

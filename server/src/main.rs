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
            let storage = storage::Storage::open(&config.server.data_dir)?;
            let name = match name {
                Some(name) => name,
                None => prompt_text("vault name", "My Vault")?,
            };
            let vault = storage.create_vault(&name).context("create vault")?;
            print_vault(&vault);
        }
        VaultCommand::List { config } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            let storage = storage::Storage::open(&config.server.data_dir)?;
            for vault in storage.list_vaults()? {
                println!("{}\t{}\t{}", vault.id, vault.name, vault.created_at_unix);
            }
        }
        VaultCommand::Delete { vault, config, yes } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            let storage = storage::Storage::open(&config.server.data_dir)?;
            let vault_id = resolve_vault_id(&storage, vault)?;
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
            storage.delete_vault(&vault_id)?;
            print_status("Vault", &format!("deleted {vault_id}"));
        }
    }
    Ok(())
}

fn handle_device(command: DeviceCommand) -> anyhow::Result<()> {
    match command {
        DeviceCommand::List { vault, config } => {
            let config = config::Config::load_or_default(config.as_deref())?;
            let storage = storage::Storage::open(&config.server.data_dir)?;
            let vault = resolve_vault_id(&storage, vault)?;
            for device in storage.list_devices(&vault)? {
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
            let storage = storage::Storage::open(&config.server.data_dir)?;
            let vault = resolve_vault_id(&storage, vault)?;
            let device = resolve_device_id(&storage, &vault, device)?;
            storage.revoke_device(&vault, &device)?;
            println!("revoked device {device} in vault {vault}");
        }
    }
    Ok(())
}

fn handle_stats(config_path: Option<&std::path::Path>) -> anyhow::Result<()> {
    let config = config::Config::load_or_default(config_path)?;
    let storage = storage::Storage::open(&config.server.data_dir)?;
    let stats = storage.stats()?;
    println!("vaults={}", stats.vault_count);
    Ok(())
}

fn print_vault(vault: &storage::CreatedVault) {
    println!("vault_id={}", vault.id);
    println!("name={}", vault.name);
    println!("pairing_token={}", vault.pairing_token);
}

fn resolve_vault_id(
    storage: &storage::Storage,
    supplied: Option<String>,
) -> anyhow::Result<String> {
    if let Some(vault_id) = supplied {
        return Ok(vault_id);
    }
    let vaults = storage.list_vaults()?;
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
    storage: &storage::Storage,
    vault_id: &str,
    supplied: Option<String>,
) -> anyhow::Result<String> {
    if let Some(device_id) = supplied {
        return Ok(device_id);
    }
    let devices = storage.list_devices(vault_id)?;
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
    let storage = storage::Storage::open(&config.server.data_dir)?;
    let existing_vaults = storage.list_vaults()?;
    if existing_vaults.is_empty()
        && !no_vault
        && prompt_yes_no("create the first vault now?", true)?
    {
        let name = prompt_text("vault name", "My Vault")?;
        let vault = storage.create_vault(&name).context("create vault")?;
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
        if let Ok(value) = input.parse::<usize>() {
            if (1..=len).contains(&value) {
                return Ok(value - 1);
            }
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

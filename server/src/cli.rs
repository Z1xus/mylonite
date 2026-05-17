use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "mylonite", version, about = "Self-hosted Obsidian sync server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        no_vault: bool,
    },
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Stats {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    Create {
        name: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    List {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Delete {
        vault: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    List {
        vault: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Revoke {
        vault: Option<String>,
        device: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

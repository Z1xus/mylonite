use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub limits: LimitsConfig,
    pub snapshots: SnapshotConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub public_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub mode: String,
    pub acme_email: String,
    pub domains: Vec<String>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[expect(
    clippy::struct_field_names,
    reason = "field names match the public TOML schema"
)]
pub struct LimitsConfig {
    pub max_blob_size_mb: u64,
    pub max_vault_size_gb: u64,
    pub max_devices_per_vault: u32,
    pub max_ops_per_push: u32,
    #[serde(default = "default_max_json_body_kb")]
    pub max_json_body_kb: u64,
    #[serde(default = "default_max_op_ciphertext_kb")]
    pub max_op_ciphertext_kb: u64,
    #[serde(default = "default_max_snapshot_ciphertext_mb")]
    pub max_snapshot_ciphertext_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    pub ops_interval: u64,
    pub time_interval_hours: u64,
    pub tail_size_mb: u64,
    pub retain: u32,
    pub safety_tail_ops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub format: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen: "127.0.0.1:9821"
                    .parse()
                    .expect("valid default listen address"),
                data_dir: default_data_dir(),
                public_url: "http://127.0.0.1:9821".to_string(),
            },
            tls: TlsConfig {
                mode: "off".to_string(),
                acme_email: "you@example.com".to_string(),
                domains: vec!["sync.example.com".to_string()],
                cert: None,
                key: None,
            },
            limits: LimitsConfig {
                max_blob_size_mb: 256,
                max_vault_size_gb: 50,
                max_devices_per_vault: 16,
                max_ops_per_push: 512,
                max_json_body_kb: default_max_json_body_kb(),
                max_op_ciphertext_kb: default_max_op_ciphertext_kb(),
                max_snapshot_ciphertext_mb: default_max_snapshot_ciphertext_mb(),
            },
            snapshots: SnapshotConfig {
                ops_interval: 1000,
                time_interval_hours: 24,
                tail_size_mb: 16,
                retain: 3,
                safety_tail_ops: 100,
            },
            log: LogConfig {
                level: "info".to_string(),
                format: "compact".to_string(),
            },
        }
    }
}

fn default_max_json_body_kb() -> u64 {
    1024
}

fn default_max_op_ciphertext_kb() -> u64 {
    1024
}

fn default_max_snapshot_ciphertext_mb() -> u64 {
    256
}

impl Config {
    pub fn load_or_default(path: Option<&Path>) -> anyhow::Result<Self> {
        let path = path.map_or_else(default_config_path, Path::to_path_buf);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
    }
}

pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mylonite")
        .join("config.toml")
}

fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mylonite")
}

pub fn write_default_config(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let text = toml::to_string_pretty(&Config::default()).context("serialize default config")?;
    fs::write(path, text).with_context(|| format!("write {}", path.display()))
}

pub fn init_tracing(config: &LogConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.level).context("parse log filter")?;
    let builder = fmt().with_env_filter(filter);
    if config.format == "json" {
        builder
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))?;
    } else {
        builder
            .compact()
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize tracing: {error}"))?;
    }
    Ok(())
}

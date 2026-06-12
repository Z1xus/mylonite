use std::net::SocketAddr;
use std::{fs, path::Path};

use anyhow::{Context, bail};
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use tracing::warn;

use crate::config::TlsConfig;

pub enum ServerTls {
    Off,
    Enabled(RustlsConfig),
}

pub async fn load_server_config(config: &TlsConfig, data_dir: &Path) -> anyhow::Result<ServerTls> {
    match config.mode.as_str() {
        "off" => Ok(ServerTls::Off),
        "manual" => {
            install_rustls_provider();
            load_manual(config).await.map(ServerTls::Enabled)
        }
        "self-signed" => {
            install_rustls_provider();
            load_self_signed(config, data_dir)
                .await
                .map(ServerTls::Enabled)
        }
        mode => bail!("unsupported tls.mode {mode:?}; expected off, manual, or self-signed"),
    }
}

fn install_rustls_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        assert!(
            rustls::crypto::ring::default_provider()
                .install_default()
                .is_ok(),
            "install rustls ring crypto provider"
        );
    });
}

async fn load_manual(config: &TlsConfig) -> anyhow::Result<RustlsConfig> {
    let (cert, key) = configured_cert_key(config, "manual")?;
    RustlsConfig::from_pem_file(&cert, &key)
        .await
        .with_context(|| format!("load TLS cert {} and key {}", cert.display(), key.display()))
}

async fn load_self_signed(config: &TlsConfig, data_dir: &Path) -> anyhow::Result<RustlsConfig> {
    let cert = config
        .cert
        .clone()
        .unwrap_or_else(|| data_dir.join("tls").join("cert.pem"));
    let key = config
        .key
        .clone()
        .unwrap_or_else(|| data_dir.join("tls").join("key.pem"));

    if !cert.exists() || !key.exists() {
        generate_self_signed_cert(config, &cert, &key)?;
    }

    RustlsConfig::from_pem_file(&cert, &key)
        .await
        .with_context(|| format!("load TLS cert {} and key {}", cert.display(), key.display()))
}

fn configured_cert_key(
    config: &TlsConfig,
    mode: &str,
) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let Some(cert) = config.cert.clone() else {
        bail!("tls.mode {mode:?} requires tls.cert");
    };
    let Some(key) = config.key.clone() else {
        bail!("tls.mode {mode:?} requires tls.key");
    };
    Ok((cert, key))
}

fn generate_self_signed_cert(config: &TlsConfig, cert: &Path, key: &Path) -> anyhow::Result<()> {
    let names = if config.domains.is_empty() {
        vec!["localhost".to_string()]
    } else {
        config.domains.clone()
    };
    let certified_key = generate_simple_self_signed(names).context("generate self-signed cert")?;
    if let Some(parent) = cert.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if let Some(parent) = key.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(cert, certified_key.cert.pem())
        .with_context(|| format!("write {}", cert.display()))?;
    fs::write(key, certified_key.signing_key.serialize_pem())
        .with_context(|| format!("write {}", key.display()))?;
    Ok(())
}

pub async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "failed to install ctrl-c handler");
    }
}

pub async fn shutdown_server(handle: Handle<SocketAddr>) {
    shutdown_signal().await;
    handle.graceful_shutdown(None);
}

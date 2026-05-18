mod auth;
mod routes;
mod tls;
mod validation;
mod ws;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderName, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::{
    config::{LimitsConfig, SnapshotConfig, TlsConfig},
    storage::{EncryptedOpRecord, Storage},
};

#[derive(Debug, Clone)]
struct AppState {
    storage: Storage,
    max_blob_size_bytes: usize,
    max_vault_size_bytes: u64,
    max_devices_per_vault: usize,
    max_json_body_bytes: usize,
    max_op_json_body_bytes: usize,
    max_op_ciphertext_bytes: usize,
    max_ops_per_push: u64,
    max_snapshot_json_body_bytes: usize,
    max_snapshot_ciphertext_bytes: usize,
    snapshot_retain: usize,
    op_broadcast: broadcast::Sender<EncryptedOpRecord>,
    pairing_sessions: Arc<Mutex<HashMap<String, PairingSession>>>,
}

#[derive(Debug, Clone)]
struct PairingSession {
    vault_id: String,
    invite_code_hash: String,
    expires_at_unix: u64,
    request: Option<PairingSessionRequest>,
    grant: Option<PairingSessionGrant>,
}

#[derive(Debug, Clone)]
struct PairingSessionRequest {
    request_hash: String,
    label: String,
    verifying_key: String,
    x25519_public_key: String,
}

#[derive(Debug, Clone)]
struct PairingSessionGrant {
    x25519_public_key: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

pub async fn serve(
    listen: SocketAddr,
    tls: TlsConfig,
    data_dir: &Path,
    limits: LimitsConfig,
    snapshots: SnapshotConfig,
    storage: Storage,
) -> anyhow::Result<()> {
    let max_blob_size_bytes =
        usize::try_from(limits.max_blob_size_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX);
    let max_vault_size_bytes = limits.max_vault_size_gb.saturating_mul(1024 * 1024 * 1024);
    let max_json_body_bytes =
        usize::try_from(limits.max_json_body_kb.saturating_mul(1024)).unwrap_or(usize::MAX);
    let max_op_ciphertext_bytes =
        usize::try_from(limits.max_op_ciphertext_kb.saturating_mul(1024)).unwrap_or(usize::MAX);
    let max_snapshot_ciphertext_bytes = usize::try_from(
        limits
            .max_snapshot_ciphertext_mb
            .saturating_mul(1024 * 1024),
    )
    .unwrap_or(usize::MAX);
    let max_op_json_body_bytes = encrypted_json_body_limit(max_op_ciphertext_bytes);
    let max_snapshot_json_body_bytes = encrypted_json_body_limit(max_snapshot_ciphertext_bytes);
    let state = AppState {
        storage,
        max_blob_size_bytes,
        max_vault_size_bytes,
        max_devices_per_vault: usize::try_from(limits.max_devices_per_vault).unwrap_or(usize::MAX),
        max_json_body_bytes,
        max_op_json_body_bytes,
        max_op_ciphertext_bytes,
        max_ops_per_push: u64::from(limits.max_ops_per_push).max(1),
        max_snapshot_json_body_bytes,
        max_snapshot_ciphertext_bytes,
        snapshot_retain: usize::try_from(snapshots.retain).unwrap_or(usize::MAX),
        op_broadcast: broadcast::channel(1024).0,
        pairing_sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    let app = build_router(
        state,
        max_json_body_bytes,
        max_op_json_body_bytes,
        max_blob_size_bytes,
        max_snapshot_json_body_bytes,
    );

    match tls::load_server_config(&tls, data_dir).await? {
        tls::ServerTls::Off => {
            let listener = tokio::net::TcpListener::bind(listen).await?;
            info!(%listen, tls_mode = %tls.mode, "mylonite server listening");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(tls::shutdown_signal())
            .await?;
        }
        tls::ServerTls::Enabled(config) => {
            info!(%listen, tls_mode = %tls.mode, "mylonite server listening");
            let handle = axum_server::Handle::new();
            tokio::spawn(tls::shutdown_server(handle.clone()));
            axum_server::bind_rustls(listen, config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
    }
    Ok(())
}

fn build_router(
    state: AppState,
    max_json_body_bytes: usize,
    max_op_json_body_bytes: usize,
    max_blob_size_bytes: usize,
    max_snapshot_json_body_bytes: usize,
) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route("/pair", get(routes::pair_invite_page))
        .route(
            "/api/v1/admin/vaults",
            get(routes::admin_list_vaults)
                .post(routes::admin_create_vault)
                .layer(DefaultBodyLimit::max(max_json_body_bytes)),
        )
        .route(
            "/api/v1/admin/vaults/{vault_id}",
            delete(routes::admin_delete_vault),
        )
        .route(
            "/api/v1/admin/vaults/{vault_id}/devices",
            get(routes::admin_list_devices),
        )
        .route(
            "/api/v1/admin/vaults/{vault_id}/devices/{device_id}/revoke",
            post(routes::admin_revoke_device),
        )
        .route("/api/v1/admin/stats", get(routes::admin_stats))
        .route(
            "/api/v1/pair/first-device",
            post(routes::pair_first_device).layer(DefaultBodyLimit::max(max_json_body_bytes)),
        )
        .route(
            "/api/v1/pair/invites/request",
            post(routes::submit_pairing_session_request)
                .layer(DefaultBodyLimit::max(max_json_body_bytes)),
        )
        .route(
            "/api/v1/pair/sessions/{session_id}/grant",
            get(routes::get_pairing_session_grant),
        )
        .route(
            "/api/v1/vaults/{vault_id}/devices",
            get(routes::list_devices)
                .post(routes::register_device)
                .layer(DefaultBodyLimit::max(max_json_body_bytes)),
        )
        .route(
            "/api/v1/vaults/{vault_id}/pairing-sessions/{session_id}/grant",
            post(routes::put_pairing_session_grant)
                .layer(DefaultBodyLimit::max(max_json_body_bytes)),
        )
        .route(
            "/api/v1/vaults/{vault_id}/pairing-sessions",
            post(routes::open_pairing_session).layer(DefaultBodyLimit::max(max_json_body_bytes)),
        )
        .route(
            "/api/v1/vaults/{vault_id}/pairing-sessions/{session_id}",
            get(routes::get_pairing_session),
        )
        .route(
            "/api/v1/vaults/{vault_id}/devices/{device_id}",
            post(routes::revoke_device).layer(DefaultBodyLimit::max(max_json_body_bytes)),
        )
        .route(
            "/api/v1/vaults/{vault_id}/ops",
            get(routes::list_ops)
                .post(routes::append_op)
                .layer(DefaultBodyLimit::max(max_op_json_body_bytes)),
        )
        .route(
            "/api/v1/vaults/{vault_id}/blobs/{blob_id}",
            get(routes::get_blob)
                .put(routes::put_blob)
                .layer(DefaultBodyLimit::max(max_blob_size_bytes)),
        )
        .route(
            "/api/v1/vaults/{vault_id}/snapshots",
            get(routes::list_snapshots)
                .post(routes::put_snapshot)
                .layer(DefaultBodyLimit::max(max_snapshot_json_body_bytes)),
        )
        .route("/ws", get(ws::ws_handler))
        .layer(api_cors_layer())
        .with_state(state)
}

fn encrypted_json_body_limit(max_ciphertext_bytes: usize) -> usize {
    max_ciphertext_bytes
        .saturating_mul(2)
        .saturating_add(16 * 1024)
}

fn api_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("content-type"),
            HeaderName::from_static("x-mylonite-device-id"),
            HeaderName::from_static("x-mylonite-signature"),
        ])
}

#[derive(Debug)]
struct ApiError(anyhow::Error);

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self(error.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.0.to_string()).into_response()
    }
}

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::{ApiError, AppState, auth::verify_device_signature, validation};
use crate::storage::{
    BlobRecord, CreatedVault, DeviceRecord, EncryptedOpRecord, SnapshotRecord, StorageStats,
};

pub(super) async fn health(State(app_state): State<AppState>) -> impl IntoResponse {
    match app_state.storage.stats() {
        Ok(storage_stats) => format!("ok vaults={}\n", storage_stats.vault_count),
        Err(error) => format!("degraded error={error}\n"),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminCreateVaultRequest {
    name: String,
}

pub(super) async fn admin_create_vault(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
    body: Bytes,
) -> Result<Json<CreatedVault>, ApiError> {
    require_loopback_admin(peer)?;
    validate_json_body_len(&app_state, &body)?;
    let request: AdminCreateVaultRequest = serde_json::from_slice(&body)?;
    Ok(Json(app_state.storage.create_vault(&request.name)?))
}

pub(super) async fn admin_list_vaults(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
) -> Result<Json<Vec<CreatedVault>>, ApiError> {
    require_loopback_admin(peer)?;
    Ok(Json(app_state.storage.list_vaults()?))
}

pub(super) async fn admin_delete_vault(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_loopback_admin(peer)?;
    validation::validate_vault_id(&vault_id)?;
    app_state.storage.delete_vault(&vault_id)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn admin_list_devices(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<DeviceRecord>>, ApiError> {
    require_loopback_admin(peer)?;
    validation::validate_vault_id(&vault_id)?;
    Ok(Json(app_state.storage.list_devices(&vault_id)?))
}

pub(super) async fn admin_revoke_device(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
    Path((vault_id, device_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_loopback_admin(peer)?;
    validation::validate_vault_id(&vault_id)?;
    validation::validate_device_id(&device_id)?;
    app_state.storage.revoke_device(&vault_id, &device_id)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn admin_stats(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(app_state): State<AppState>,
) -> Result<Json<StorageStats>, ApiError> {
    require_loopback_admin(peer)?;
    Ok(Json(app_state.storage.stats()?))
}

#[derive(Debug, Deserialize)]
pub(super) struct PairFirstDeviceRequest {
    pub(super) token: String,
    pub(super) label: String,
    pub(super) verifying_key: String,
}

#[derive(Debug, Serialize)]
pub(super) struct PairFirstDeviceResponse {
    vault_id: String,
    device_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct RegisterDeviceRequest {
    pub(super) label: String,
    pub(super) verifying_key: String,
}

#[derive(Debug, Serialize)]
pub(super) struct RegisterDeviceResponse {
    device_id: String,
}

pub(super) async fn pair_first_device(
    State(app_state): State<AppState>,
    body: Bytes,
) -> Result<Json<PairFirstDeviceResponse>, ApiError> {
    validate_json_body_len(&app_state, &body)?;
    let request: PairFirstDeviceRequest = serde_json::from_slice(&body)?;
    validation::validate_pairing_request(&request)?;
    let device = app_state.storage.register_first_device(
        &request.token,
        &request.label,
        &request.verifying_key,
    )?;
    Ok(Json(PairFirstDeviceResponse {
        vault_id: device.vault_id,
        device_id: device.device_id,
    }))
}

pub(super) async fn list_devices(
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceRecord>>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "GET",
        &format!("/api/v1/vaults/{vault_id}/devices"),
        &[],
        &headers,
    )?;
    Ok(Json(app_state.storage.list_devices(&vault_id)?))
}

pub(super) async fn register_device(
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<RegisterDeviceResponse>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validate_json_body_len(&app_state, &body)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "POST",
        &format!("/api/v1/vaults/{vault_id}/devices"),
        &body,
        &headers,
    )?;
    let request: RegisterDeviceRequest = serde_json::from_slice(&body)?;
    validation::validate_register_device_request(&request)?;
    let device = app_state.storage.register_authorized_device(
        &vault_id,
        &request.label,
        &request.verifying_key,
        app_state.max_devices_per_vault,
    )?;
    Ok(Json(RegisterDeviceResponse {
        device_id: device.device_id,
    }))
}

pub(super) async fn revoke_device(
    State(app_state): State<AppState>,
    Path((vault_id, device_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validation::validate_device_id(&device_id)?;
    validate_json_body_len(&app_state, &body)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "POST",
        &format!("/api/v1/vaults/{vault_id}/devices/{device_id}"),
        &body,
        &headers,
    )?;
    app_state.storage.revoke_device(&vault_id, &device_id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub(super) struct OpsQuery {
    after: Option<u64>,
    limit: Option<u64>,
}

pub(super) async fn list_ops(
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<OpsQuery>,
) -> Result<Json<Vec<EncryptedOpRecord>>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    let after = query.after.unwrap_or(0);
    let signed_path = match query.limit {
        Some(limit) => format!("/api/v1/vaults/{vault_id}/ops?after={after}&limit={limit}"),
        None => format!("/api/v1/vaults/{vault_id}/ops?after={after}"),
    };
    verify_device_signature(&app_state, &vault_id, "GET", &signed_path, &[], &headers)?;
    let limit = query
        .limit
        .unwrap_or(app_state.max_ops_per_push)
        .min(app_state.max_ops_per_push);
    validation::validate_op_list_limit(limit)?;
    Ok(Json(
        app_state.storage.list_ops_after(&vault_id, after, limit)?,
    ))
}

#[derive(Debug, Deserialize)]
pub(super) struct AppendOpRequest {
    pub(super) client_op_id: String,
    pub(super) device_id: String,
    pub(super) lamport: u64,
    pub(super) kind: u8,
    pub(super) key_version: u32,
    pub(super) nonce_hex: String,
    pub(super) ciphertext_hex: String,
}

#[derive(Debug, Serialize)]
pub(super) struct AppendOpResponse {
    server_seq: u64,
}

#[derive(Debug, Deserialize)]
pub(super) struct PutSnapshotRequest {
    pub(super) snapshot_id: String,
    pub(super) device_id: String,
    pub(super) covers_through_seq: u64,
    pub(super) key_version: u32,
    pub(super) nonce_hex: String,
    pub(super) ciphertext_hex: String,
}

pub(super) async fn append_op(
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<AppendOpResponse>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validate_body_len(&body, app_state.max_op_json_body_bytes)?;
    let signed_device_id = verify_device_signature(
        &app_state,
        &vault_id,
        "POST",
        &format!("/api/v1/vaults/{vault_id}/ops"),
        &body,
        &headers,
    )?;
    let request: AppendOpRequest = serde_json::from_slice(&body)?;
    validation::validate_op_request(&request, app_state.max_op_ciphertext_bytes)?;
    validate_body_device_matches_signer(&request.device_id, &signed_device_id)?;
    let mut op = EncryptedOpRecord {
        vault_id: vault_id.clone(),
        server_seq: 0,
        client_op_id: request.client_op_id,
        device_id: request.device_id,
        lamport: request.lamport,
        kind: request.kind,
        key_version: request.key_version,
        nonce_hex: request.nonce_hex,
        ciphertext_hex: request.ciphertext_hex,
        accepted_at_unix: 0,
    };
    let append = app_state.storage.append_op(op.clone())?;
    op.server_seq = append.server_seq;
    if append.inserted {
        let _ = app_state.op_broadcast.send(op);
    }
    Ok(Json(AppendOpResponse {
        server_seq: append.server_seq,
    }))
}

pub(super) async fn put_blob(
    State(app_state): State<AppState>,
    Path((vault_id, blob_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<BlobRecord>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validation::validate_blob_id(&blob_id)?;
    if body.len() > app_state.max_blob_size_bytes {
        return Err(ApiError(anyhow::anyhow!(
            "blob exceeds configured size limit"
        )));
    }
    verify_device_signature(
        &app_state,
        &vault_id,
        "PUT",
        &format!("/api/v1/vaults/{vault_id}/blobs/{blob_id}"),
        &body,
        &headers,
    )?;
    Ok(Json(app_state.storage.put_blob_with_vault_limit(
        &vault_id,
        &blob_id,
        &body,
        app_state.max_vault_size_bytes,
    )?))
}

pub(super) async fn get_blob(
    State(app_state): State<AppState>,
    Path((vault_id, blob_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validation::validate_blob_id(&blob_id)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "GET",
        &format!("/api/v1/vaults/{vault_id}/blobs/{blob_id}"),
        &[],
        &headers,
    )?;
    match app_state.storage.get_blob(&vault_id, &blob_id)? {
        Some(bytes) => Ok((StatusCode::OK, bytes).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

pub(super) async fn list_snapshots(
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<SnapshotRecord>>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "GET",
        &format!("/api/v1/vaults/{vault_id}/snapshots"),
        &[],
        &headers,
    )?;
    Ok(Json(app_state.storage.list_snapshots(&vault_id)?))
}

pub(super) async fn put_snapshot(
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validate_body_len(&body, app_state.max_snapshot_json_body_bytes)?;
    let signed_device_id = verify_device_signature(
        &app_state,
        &vault_id,
        "POST",
        &format!("/api/v1/vaults/{vault_id}/snapshots"),
        &body,
        &headers,
    )?;
    let request: PutSnapshotRequest = serde_json::from_slice(&body)?;
    validation::validate_snapshot_request(&request, app_state.max_snapshot_ciphertext_bytes)?;
    validate_body_device_matches_signer(&request.device_id, &signed_device_id)?;
    app_state.storage.put_snapshot(SnapshotRecord {
        vault_id: vault_id.clone(),
        snapshot_id: request.snapshot_id,
        device_id: request.device_id,
        covers_through_seq: request.covers_through_seq,
        key_version: request.key_version,
        nonce_hex: request.nonce_hex,
        ciphertext_hex: request.ciphertext_hex,
        created_at_unix: 0,
    })?;
    app_state
        .storage
        .prune_snapshots(&vault_id, app_state.snapshot_retain)?;
    Ok(StatusCode::CREATED)
}

fn validate_json_body_len(app_state: &AppState, body: &Bytes) -> Result<(), ApiError> {
    validate_body_len(body, app_state.max_json_body_bytes)
}

fn validate_body_len(body: &Bytes, max_bytes: usize) -> Result<(), ApiError> {
    if body.len() > max_bytes {
        return Err(ApiError(anyhow::anyhow!(
            "request body exceeds configured JSON size limit"
        )));
    }
    Ok(())
}

fn validate_body_device_matches_signer(
    body_device_id: &str,
    signed_device_id: &str,
) -> Result<(), ApiError> {
    if body_device_id != signed_device_id {
        return Err(ApiError(anyhow::anyhow!(
            "request body device id does not match signing device"
        )));
    }
    Ok(())
}

fn require_loopback_admin(peer: SocketAddr) -> Result<(), ApiError> {
    if peer.ip().is_loopback() {
        return Ok(());
    }
    Err(ApiError(anyhow::anyhow!(
        "admin API is only available from loopback"
    )))
}

#[cfg(test)]
mod tests {
    use super::{require_loopback_admin, validate_body_device_matches_signer};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn body_device_id_must_match_signing_device() {
        assert!(validate_body_device_matches_signer("d111", "d111").is_ok());
        assert!(validate_body_device_matches_signer("d111", "d222").is_err());
    }

    #[test]
    fn admin_routes_require_loopback_peer() {
        assert!(
            require_loopback_admin(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12000)).is_ok()
        );
        assert!(
            require_loopback_admin(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                12000
            ))
            .is_err()
        );
    }
}

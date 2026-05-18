use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    ApiError, AppState, PairingSession, PairingSessionGrant, PairingSessionRequest,
    auth::verify_device_signature, validation,
};
use crate::storage::{
    BlobRecord, CreatedVault, DeviceRecord, EncryptedOpRecord, SnapshotRecord, StorageStats,
};

const PAIRING_SESSION_TTL_SECS: u64 = 10 * 60;
const MAX_PAIRING_SESSIONS: usize = 1024;

pub(super) async fn health(State(app_state): State<AppState>) -> impl IntoResponse {
    match app_state.storage.stats() {
        Ok(storage_stats) => format!("ok vaults={}\n", storage_stats.vault_count),
        Err(error) => format!("degraded error={error}\n"),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct PairInvitePageQuery {
    invite: Option<String>,
    code: Option<String>,
}

pub(super) async fn pair_invite_page(
    Query(query): Query<PairInvitePageQuery>,
) -> Result<Html<String>, ApiError> {
    let invite = query.invite.unwrap_or_default();
    if !invite.is_empty() {
        validate_pairing_invite_text(&invite)?;
    }
    let code = query.code.unwrap_or_default();
    if !code.is_empty() {
        validation::validate_invite_code(&code)?;
    }
    let escaped_invite = html_escape(&invite);
    let encoded_invite = percent_encode(&invite);
    let escaped_code = html_escape(&code);
    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mylonite device invite</title>
<style>
body {{ color: #1f2328; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; }}
main {{ margin: 0 auto; max-width: 680px; padding: 32px 20px; }}
h1 {{ font-size: 1.5rem; margin: 0 0 12px; }}
p {{ color: #4f5866; line-height: 1.5; }}
textarea {{ box-sizing: border-box; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; min-height: 120px; width: 100%; }}
.actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 20px 0; }}
a, button {{ background: #1f2328; border: 0; border-radius: 6px; color: #fff; cursor: pointer; font: inherit; padding: 10px 14px; text-decoration: none; }}
button.secondary {{ background: #e7e9ed; color: #1f2328; }}
</style>
</head>
<body>
<main>
<h1>Mylonite device invite</h1>
<p>Open this invite in Obsidian on the device you want to add. If that handoff is unavailable, copy the invite text or code and paste it in Mylonite settings.</p>
<div class="actions">
<a id="open" href="obsidian://mylonite-pair?invite={encoded_invite}">Open in Obsidian</a>
<button class="secondary" type="button" onclick="navigator.clipboard.writeText(document.querySelector('textarea').value)">Copy invite</button>
</div>
<textarea readonly>{escaped_invite}</textarea>
<p><strong>Invite code:</strong> <code id="code">{escaped_code}</code></p>
<script>
const code = document.getElementById("code").textContent;
const textarea = document.querySelector("textarea");
if (!textarea.value && code) {{
  const invite = "MYLONITE:" + btoa(JSON.stringify({{ version: 1, server_url: location.origin, invite_code: code }})).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  textarea.value = invite;
  document.getElementById("open").href = "obsidian://mylonite-pair?invite=" + encodeURIComponent(invite);
}}
</script>
</main>
</body>
</html>"#
    )))
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

#[derive(Debug, Deserialize)]
pub(super) struct OpenPairingSessionRequest {
    session_id: String,
    invite_code_hash: String,
}

#[derive(Debug, Serialize)]
pub(super) struct OpenPairingSessionResponse {
    session_id: String,
    expires_at_unix: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(super) struct PairingSessionRequestPayload {
    request_hash: String,
    label: String,
    verifying_key: String,
    x25519_public_key: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubmitPairingSessionRequest {
    invite_code: String,
    request: PairingSessionRequestPayload,
}

#[derive(Debug, Serialize)]
pub(super) struct SubmitPairingSessionResponse {
    session_id: String,
    expires_at_unix: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(super) struct PairingSessionGrantPayload {
    x25519_public_key: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct PutPairingSessionGrantRequest {
    request_hash: String,
    grant: PairingSessionGrantPayload,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum PairingSessionResponse {
    Waiting {
        expires_at_unix: u64,
    },
    Requested {
        expires_at_unix: u64,
        request: PairingSessionRequestPayload,
    },
    Granted {
        expires_at_unix: u64,
        grant: PairingSessionGrantPayload,
    },
    Expired,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum PairingSessionGrantResponse {
    Pending {
        expires_at_unix: u64,
    },
    Granted {
        expires_at_unix: u64,
        grant: PairingSessionGrantPayload,
    },
    Expired,
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

pub(super) async fn open_pairing_session(
    State(app_state): State<AppState>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<OpenPairingSessionResponse>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validate_json_body_len(&app_state, &body)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "POST",
        &format!("/api/v1/vaults/{vault_id}/pairing-sessions"),
        &body,
        &headers,
    )?;
    let request: OpenPairingSessionRequest = serde_json::from_slice(&body)?;
    validation::validate_pairing_session_id(&request.session_id)?;
    validation::validate_invite_code_hash(&request.invite_code_hash)?;

    let now = now_unix()?;
    let expires_at_unix = now.saturating_add(PAIRING_SESSION_TTL_SECS);
    let mut sessions = app_state
        .pairing_sessions
        .lock()
        .map_err(|_| ApiError(anyhow::anyhow!("pairing session state unavailable")))?;
    prune_pairing_sessions(&mut sessions, now);
    if sessions.len() >= MAX_PAIRING_SESSIONS {
        return Err(ApiError(anyhow::anyhow!(
            "too many active pairing sessions"
        )));
    }
    if sessions.contains_key(&request.session_id) {
        return Err(ApiError(anyhow::anyhow!("pairing session already exists")));
    }

    sessions.insert(
        request.session_id.clone(),
        PairingSession {
            vault_id,
            invite_code_hash: request.invite_code_hash,
            expires_at_unix,
            request: None,
            grant: None,
        },
    );
    Ok(Json(OpenPairingSessionResponse {
        session_id: request.session_id,
        expires_at_unix,
    }))
}

pub(super) async fn get_pairing_session(
    State(app_state): State<AppState>,
    Path((vault_id, session_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<PairingSessionResponse>, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validation::validate_pairing_session_id(&session_id)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "GET",
        &format!("/api/v1/vaults/{vault_id}/pairing-sessions/{session_id}"),
        &[],
        &headers,
    )?;

    let now = now_unix()?;
    let mut sessions = app_state
        .pairing_sessions
        .lock()
        .map_err(|_| ApiError(anyhow::anyhow!("pairing session state unavailable")))?;
    prune_pairing_sessions(&mut sessions, now);
    let Some(session) = sessions.get(&session_id) else {
        return Ok(Json(PairingSessionResponse::Expired));
    };
    if session.vault_id != vault_id {
        return Err(ApiError(anyhow::anyhow!("pairing session vault mismatch")));
    }
    if let Some(grant) = &session.grant {
        return Ok(Json(PairingSessionResponse::Granted {
            expires_at_unix: session.expires_at_unix,
            grant: PairingSessionGrantPayload {
                x25519_public_key: grant.x25519_public_key.clone(),
                nonce_hex: grant.nonce_hex.clone(),
                ciphertext_hex: grant.ciphertext_hex.clone(),
            },
        }));
    }
    if let Some(request) = &session.request {
        return Ok(Json(PairingSessionResponse::Requested {
            expires_at_unix: session.expires_at_unix,
            request: PairingSessionRequestPayload {
                request_hash: request.request_hash.clone(),
                label: request.label.clone(),
                verifying_key: request.verifying_key.clone(),
                x25519_public_key: request.x25519_public_key.clone(),
            },
        }));
    }
    Ok(Json(PairingSessionResponse::Waiting {
        expires_at_unix: session.expires_at_unix,
    }))
}

pub(super) async fn submit_pairing_session_request(
    State(app_state): State<AppState>,
    body: Bytes,
) -> Result<Json<SubmitPairingSessionResponse>, ApiError> {
    validate_json_body_len(&app_state, &body)?;
    let request: SubmitPairingSessionRequest = serde_json::from_slice(&body)?;
    validation::validate_invite_code(&request.invite_code)?;
    validate_pairing_session_request(&request.request)?;

    let now = now_unix()?;
    let mut sessions = app_state
        .pairing_sessions
        .lock()
        .map_err(|_| ApiError(anyhow::anyhow!("pairing session state unavailable")))?;
    prune_pairing_sessions(&mut sessions, now);
    let Some((session_id, session)) = sessions.iter_mut().find(|(session_id, session)| {
        session.invite_code_hash == invite_code_hash(session_id, &request.invite_code)
    }) else {
        return Err(ApiError(anyhow::anyhow!("invite code not found")));
    };
    if session.request.is_some() || session.grant.is_some() {
        return Err(ApiError(anyhow::anyhow!("pairing session already claimed")));
    }
    session.request = Some(PairingSessionRequest {
        request_hash: request.request.request_hash,
        label: request.request.label,
        verifying_key: request.request.verifying_key,
        x25519_public_key: request.request.x25519_public_key,
    });
    Ok(Json(SubmitPairingSessionResponse {
        session_id: session_id.clone(),
        expires_at_unix: session.expires_at_unix,
    }))
}

pub(super) async fn get_pairing_session_grant(
    State(app_state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<PairingSessionGrantResponse>, ApiError> {
    validation::validate_pairing_session_id(&session_id)?;
    let now = now_unix()?;
    let mut sessions = app_state
        .pairing_sessions
        .lock()
        .map_err(|_| ApiError(anyhow::anyhow!("pairing session state unavailable")))?;
    prune_pairing_sessions(&mut sessions, now);
    let Some(session) = sessions.get(&session_id) else {
        return Ok(Json(PairingSessionGrantResponse::Expired));
    };
    if let Some(grant) = &session.grant {
        return Ok(Json(PairingSessionGrantResponse::Granted {
            expires_at_unix: session.expires_at_unix,
            grant: PairingSessionGrantPayload {
                x25519_public_key: grant.x25519_public_key.clone(),
                nonce_hex: grant.nonce_hex.clone(),
                ciphertext_hex: grant.ciphertext_hex.clone(),
            },
        }));
    }
    Ok(Json(PairingSessionGrantResponse::Pending {
        expires_at_unix: session.expires_at_unix,
    }))
}

pub(super) async fn put_pairing_session_grant(
    State(app_state): State<AppState>,
    Path((vault_id, session_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    validation::validate_vault_id(&vault_id)?;
    validation::validate_pairing_session_id(&session_id)?;
    validate_json_body_len(&app_state, &body)?;
    verify_device_signature(
        &app_state,
        &vault_id,
        "POST",
        &format!("/api/v1/vaults/{vault_id}/pairing-sessions/{session_id}/grant"),
        &body,
        &headers,
    )?;
    let request: PutPairingSessionGrantRequest = serde_json::from_slice(&body)?;
    validation::validate_request_hash(&request.request_hash)?;
    validate_pairing_session_grant(&request.grant)?;

    let now = now_unix()?;
    let mut sessions = app_state
        .pairing_sessions
        .lock()
        .map_err(|_| ApiError(anyhow::anyhow!("pairing session state unavailable")))?;
    prune_pairing_sessions(&mut sessions, now);
    let Some(session) = sessions.get_mut(&session_id) else {
        return Err(ApiError(anyhow::anyhow!("pairing session expired")));
    };
    if session.vault_id != vault_id {
        return Err(ApiError(anyhow::anyhow!("pairing session vault mismatch")));
    }
    let Some(pending_request) = &session.request else {
        return Err(ApiError(anyhow::anyhow!("pairing session has no request")));
    };
    if pending_request.request_hash != request.request_hash {
        return Err(ApiError(anyhow::anyhow!("pairing request hash mismatch")));
    }
    if session.grant.is_some() {
        return Err(ApiError(anyhow::anyhow!("pairing session already granted")));
    }
    session.grant = Some(PairingSessionGrant {
        x25519_public_key: request.grant.x25519_public_key,
        nonce_hex: request.grant.nonce_hex,
        ciphertext_hex: request.grant.ciphertext_hex,
    });
    Ok(StatusCode::NO_CONTENT)
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

fn validate_pairing_session_grant(grant: &PairingSessionGrantPayload) -> Result<(), ApiError> {
    validation::validate_x25519_public_key(&grant.x25519_public_key)?;
    validation::validate_nonce_hex(&grant.nonce_hex)?;
    validation::validate_ciphertext_hex(&grant.ciphertext_hex)
}

fn validate_pairing_session_request(
    request: &PairingSessionRequestPayload,
) -> Result<(), ApiError> {
    validation::validate_request_hash(&request.request_hash)?;
    validate_device_label(&request.label)?;
    validation::validate_x25519_public_key(&request.x25519_public_key)?;
    validate_verifying_key(&request.verifying_key)
}

fn validate_device_label(label: &str) -> Result<(), ApiError> {
    if label.trim().is_empty() || label.len() > 128 {
        return Err(ApiError(anyhow::anyhow!(
            "device label must be 1..128 bytes"
        )));
    }
    Ok(())
}

fn validate_verifying_key(verifying_key: &str) -> Result<(), ApiError> {
    if verifying_key.len() != 64 || !validation::is_lower_hex(verifying_key) {
        return Err(ApiError(anyhow::anyhow!("invalid Ed25519 verifying key")));
    }
    Ok(())
}

fn invite_code_hash(session_id: &str, invite_code: &str) -> String {
    let material = format!("mylonite/pairing-invite-code/v1|{session_id}|{invite_code}");
    hex_encode(&Sha256::digest(material.as_bytes()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn prune_pairing_sessions(
    sessions: &mut std::collections::HashMap<String, PairingSession>,
    now: u64,
) {
    sessions.retain(|_, session| session.expires_at_unix >= now);
}

fn now_unix() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn validate_pairing_invite_text(invite: &str) -> Result<(), ApiError> {
    if invite.len() > 2048 || !(invite.starts_with("MYLONITE:") || invite.starts_with('{')) {
        return Err(ApiError(anyhow::anyhow!("invalid pairing invite")));
    }
    Ok(())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[usize::from(byte >> 4)]));
            out.push(char::from(b"0123456789ABCDEF"[usize::from(byte & 0x0f)]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        PairingSessionGrantPayload, PairingSessionRequestPayload, invite_code_hash, percent_encode,
        require_loopback_admin, validate_body_device_matches_signer, validate_pairing_invite_text,
        validate_pairing_session_grant, validate_pairing_session_request,
    };
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

    #[test]
    fn pairing_session_grant_requires_public_key_nonce_and_ciphertext_hex() {
        let valid = PairingSessionGrantPayload {
            x25519_public_key: "a".repeat(64),
            nonce_hex: "b".repeat(48),
            ciphertext_hex: "cc".to_string(),
        };
        assert!(validate_pairing_session_grant(&valid).is_ok());

        assert!(
            validate_pairing_session_grant(&PairingSessionGrantPayload {
                x25519_public_key: "A".repeat(64),
                ..valid.clone()
            })
            .is_err()
        );
        assert!(
            validate_pairing_session_grant(&PairingSessionGrantPayload {
                ciphertext_hex: "abc".to_string(),
                ..valid
            })
            .is_err()
        );
    }

    #[test]
    fn pairing_session_request_requires_device_keys_and_hash() {
        let valid = PairingSessionRequestPayload {
            request_hash: "a".repeat(64),
            label: "Phone".to_string(),
            verifying_key: "b".repeat(64),
            x25519_public_key: "c".repeat(64),
        };
        assert!(validate_pairing_session_request(&valid).is_ok());
        assert!(
            validate_pairing_session_request(&PairingSessionRequestPayload {
                label: " ".to_string(),
                ..valid.clone()
            })
            .is_err()
        );
        assert!(
            validate_pairing_session_request(&PairingSessionRequestPayload {
                x25519_public_key: "C".repeat(64),
                ..valid
            })
            .is_err()
        );
    }

    #[test]
    fn invite_code_hash_is_stable() {
        assert_eq!(
            invite_code_hash("psaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ABCD-2345-WXYZ"),
            invite_code_hash("psaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ABCD-2345-WXYZ")
        );
        assert_ne!(
            invite_code_hash("psaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ABCD-2345-WXYZ"),
            invite_code_hash("psaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ABCD-2345-WXY2")
        );
    }

    #[test]
    fn pairing_invite_page_helpers_reject_bad_invites_and_encode_urls() {
        assert!(validate_pairing_invite_text("MYLONITE:abc").is_ok());
        assert!(validate_pairing_invite_text("{\"version\":1}").is_ok());
        assert!(validate_pairing_invite_text("https://example.com").is_err());
        assert_eq!(percent_encode("MYLONITE:a+b"), "MYLONITE%3Aa%2Bb");
    }
}

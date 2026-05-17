use super::{
    ApiError,
    routes::{AppendOpRequest, PairFirstDeviceRequest, PutSnapshotRequest, RegisterDeviceRequest},
};
use mylonite_protocol::OpKind;

pub(super) fn validate_pairing_request(request: &PairFirstDeviceRequest) -> Result<(), ApiError> {
    validate_device_label(&request.label)?;
    validate_verifying_key(&request.verifying_key)?;
    if !request.token.starts_with('p')
        || request.token.len() != 49
        || !is_lower_hex(&request.token[1..])
    {
        return Err(ApiError(anyhow::anyhow!("invalid pairing token")));
    }
    Ok(())
}

pub(super) fn validate_register_device_request(
    request: &RegisterDeviceRequest,
) -> Result<(), ApiError> {
    validate_device_label(&request.label)?;
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
    if verifying_key.len() != 64 || !is_lower_hex(verifying_key) {
        return Err(ApiError(anyhow::anyhow!("invalid Ed25519 verifying key")));
    }
    Ok(())
}

pub(super) fn validate_op_request(
    request: &AppendOpRequest,
    max_ciphertext_bytes: usize,
) -> Result<(), ApiError> {
    validate_hex_field("client_op_id", &request.client_op_id, 64)?;
    validate_device_id(&request.device_id)?;
    if OpKind::try_from(request.kind).is_err() {
        return Err(ApiError(anyhow::anyhow!("invalid op kind")));
    }
    validate_key_version(request.key_version)?;
    validate_hex_field("nonce_hex", &request.nonce_hex, 48)?;
    if request.ciphertext_hex.is_empty() || !is_lower_hex(&request.ciphertext_hex) {
        return Err(ApiError(anyhow::anyhow!("invalid ciphertext hex")));
    }
    validate_hex_payload_size("ciphertext", &request.ciphertext_hex, max_ciphertext_bytes)?;
    Ok(())
}

pub(super) fn validate_snapshot_request(
    request: &PutSnapshotRequest,
    max_ciphertext_bytes: usize,
) -> Result<(), ApiError> {
    validate_snapshot_id(&request.snapshot_id)?;
    validate_device_id(&request.device_id)?;
    validate_key_version(request.key_version)?;
    validate_hex_field("nonce_hex", &request.nonce_hex, 48)?;
    if request.ciphertext_hex.is_empty() || !is_lower_hex(&request.ciphertext_hex) {
        return Err(ApiError(anyhow::anyhow!("invalid ciphertext hex")));
    }
    validate_hex_payload_size(
        "snapshot ciphertext",
        &request.ciphertext_hex,
        max_ciphertext_bytes,
    )?;
    Ok(())
}

pub(super) fn validate_opaque_id(name: &str, value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(ApiError(anyhow::anyhow!("invalid {name}")));
    }
    Ok(())
}

pub(super) fn validate_vault_id(vault_id: &str) -> Result<(), ApiError> {
    validate_opaque_id("vault id", vault_id)
}

pub(super) fn validate_blob_id(blob_id: &str) -> Result<(), ApiError> {
    validate_hex_field("blob id", blob_id, 64)
}

pub(super) fn validate_op_list_limit(limit: u64) -> Result<(), ApiError> {
    if limit == 0 {
        return Err(ApiError(anyhow::anyhow!(
            "op list limit must be at least 1"
        )));
    }
    Ok(())
}

fn validate_snapshot_id(snapshot_id: &str) -> Result<(), ApiError> {
    validate_hex_field("snapshot id", snapshot_id, 32)
}

pub(super) fn validate_device_id(device_id: &str) -> Result<(), ApiError> {
    if !device_id.starts_with('d') || device_id.len() != 33 || !is_lower_hex(&device_id[1..]) {
        return Err(ApiError(anyhow::anyhow!("invalid device id")));
    }
    Ok(())
}

fn validate_hex_field(name: &str, value: &str, len: usize) -> Result<(), ApiError> {
    if value.len() != len || !is_lower_hex(value) {
        return Err(ApiError(anyhow::anyhow!("invalid {name}")));
    }
    Ok(())
}

fn validate_hex_payload_size(name: &str, value: &str, max_bytes: usize) -> Result<(), ApiError> {
    if value.len() % 2 != 0 {
        return Err(ApiError(anyhow::anyhow!("invalid {name} hex length")));
    }
    if value.len() / 2 > max_bytes {
        return Err(ApiError(anyhow::anyhow!(
            "{name} exceeds configured size limit"
        )));
    }
    Ok(())
}

fn validate_key_version(key_version: u32) -> Result<(), ApiError> {
    if key_version != 1 {
        return Err(ApiError(anyhow::anyhow!("unsupported key version")));
    }
    Ok(())
}

pub(super) fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::super::routes::{AppendOpRequest, PutSnapshotRequest};
    use super::{
        validate_blob_id, validate_op_list_limit, validate_op_request, validate_snapshot_request,
    };
    use mylonite_protocol::OpKind;

    fn valid_op_request(ciphertext_hex: &str) -> AppendOpRequest {
        AppendOpRequest {
            client_op_id: "a".repeat(64),
            device_id: format!("d{}", "b".repeat(32)),
            lamport: 1,
            kind: OpKind::FileUpdate as u8,
            key_version: 1,
            nonce_hex: "c".repeat(48),
            ciphertext_hex: ciphertext_hex.to_string(),
        }
    }

    #[test]
    fn validate_op_request_rejects_odd_length_ciphertext_hex() {
        let request = valid_op_request("abc");

        assert!(validate_op_request(&request, 16).is_err());
    }

    #[test]
    fn validate_op_request_rejects_oversized_ciphertext() {
        let request = valid_op_request("aa");

        assert!(validate_op_request(&request, 0).is_err());
    }

    #[test]
    fn validate_op_request_rejects_unsupported_key_version() {
        let mut request = valid_op_request("aa");
        request.key_version = 2;

        assert!(validate_op_request(&request, 16).is_err());
    }

    #[test]
    fn validate_op_list_limit_rejects_zero() {
        assert!(validate_op_list_limit(1).is_ok());
        assert!(validate_op_list_limit(0).is_err());
    }

    #[test]
    fn validate_blob_id_requires_lowercase_32_byte_hex() {
        assert!(validate_blob_id(&"a".repeat(64)).is_ok());
        assert!(validate_blob_id("blob-a").is_err());
        assert!(validate_blob_id(&"A".repeat(64)).is_err());
        assert!(validate_blob_id(&"a".repeat(63)).is_err());
    }

    #[test]
    fn validate_snapshot_request_requires_generated_snapshot_id_shape() {
        let mut request = PutSnapshotRequest {
            snapshot_id: "a".repeat(32),
            device_id: format!("d{}", "b".repeat(32)),
            covers_through_seq: 1,
            key_version: 1,
            nonce_hex: "c".repeat(48),
            ciphertext_hex: "dd".to_string(),
        };

        assert!(validate_snapshot_request(&request, 16).is_ok());

        request.snapshot_id = "snapshot-a".to_string();
        assert!(validate_snapshot_request(&request, 16).is_err());
    }

    #[test]
    fn validate_snapshot_request_rejects_unsupported_key_version() {
        let mut request = PutSnapshotRequest {
            snapshot_id: "a".repeat(32),
            device_id: format!("d{}", "b".repeat(32)),
            covers_through_seq: 1,
            key_version: 2,
            nonce_hex: "c".repeat(48),
            ciphertext_hex: "dd".to_string(),
        };

        assert!(validate_snapshot_request(&request, 16).is_err());

        request.key_version = 1;
        assert!(validate_snapshot_request(&request, 16).is_ok());
    }
}

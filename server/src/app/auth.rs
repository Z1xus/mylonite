use axum::http::HeaderMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::{ApiError, AppState};
use crate::app::validation::is_lower_hex;

pub(super) fn verify_device_signature(
    app_state: &AppState,
    vault_id: &str,
    method: &str,
    path: &str,
    body: &[u8],
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    let device_id = header_str(headers, "x-mylonite-device-id")?;
    let signature_hex = header_str(headers, "x-mylonite-signature")?;
    let device = app_state.storage.get_active_device(vault_id, device_id)?;
    if device.device_id != device_id {
        return Err(ApiError(anyhow::anyhow!("device id mismatch")));
    }

    let key_bytes = hex_decode(&device.verifying_key)?;
    let signature_bytes = hex_decode(signature_hex)?;
    let verifying_key = VerifyingKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 verifying key length"))?,
    )?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 signature length"))?,
    );
    let payload = format!("{}\n{}\n{}", method.to_uppercase(), path, hex_encode(body));
    verifying_key.verify(payload.as_bytes(), &signature)?;
    Ok(device_id.to_string())
}

pub(super) fn verify_ws_challenge_signature(
    app_state: &AppState,
    vault_id: &str,
    device_id: &str,
    path: &str,
    challenge_hex: &str,
    signature_hex: &str,
) -> Result<(), ApiError> {
    let device = app_state.storage.get_active_device(vault_id, device_id)?;
    let key_bytes = hex_decode(&device.verifying_key)?;
    let signature_bytes = hex_decode(signature_hex)?;
    let verifying_key = VerifyingKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 verifying key length"))?,
    )?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 signature length"))?,
    );
    let payload = format!("WS\n{path}\n{challenge_hex}");
    verifying_key.verify(payload.as_bytes(), &signature)?;
    Ok(())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ApiError> {
    headers
        .get(name)
        .ok_or_else(|| ApiError(anyhow::anyhow!("missing {name} header")))?
        .to_str()
        .map_err(|_| ApiError(anyhow::anyhow!("invalid {name} header")))
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ApiError> {
    if value.len() % 2 != 0 || !is_lower_hex(value) {
        return Err(ApiError(anyhow::anyhow!("invalid hex")));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        out.push(u8::from_str_radix(&value[index..index + 2], 16)?);
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::{hex_encode, verify_device_signature, verify_ws_challenge_signature};
    use crate::{
        app::AppState,
        storage::{EncryptedOpRecord, Storage},
    };
    use axum::http::HeaderMap;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::broadcast;

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn signature_verification_accepts_valid_ed25519_signatures() {
        let (state, vault_id, device_id, signing_key) = signed_test_state();
        let body = br#"{"hello":"world"}"#;
        let headers = signed_headers(
            &device_id,
            &signing_key,
            "POST",
            &format!("/api/v1/vaults/{vault_id}/ops"),
            body,
        );

        let verified_device_id = verify_device_signature(
            &state,
            &vault_id,
            "POST",
            &format!("/api/v1/vaults/{vault_id}/ops"),
            body,
            &headers,
        )
        .expect("valid signature verifies");
        assert_eq!(verified_device_id, device_id);
    }

    #[test]
    fn signature_verification_rejects_invalid_ed25519_signatures() {
        let (state, vault_id, device_id, signing_key) = signed_test_state();
        let body = br#"{"hello":"world"}"#;
        let headers = signed_headers(
            &device_id,
            &signing_key,
            "POST",
            &format!("/api/v1/vaults/{vault_id}/ops"),
            b"different body",
        );

        assert!(
            verify_device_signature(
                &state,
                &vault_id,
                "POST",
                &format!("/api/v1/vaults/{vault_id}/ops"),
                body,
                &headers,
            )
            .is_err()
        );
    }

    #[test]
    fn websocket_challenge_verification_accepts_valid_signature() {
        let (state, vault_id, device_id, signing_key) = signed_test_state();
        let path = format!("/ws?vault_id={vault_id}&device_id={device_id}");
        let challenge_hex = "00112233445566778899aabbccddeeff";
        let payload = format!("WS\n{path}\n{challenge_hex}");
        let signature = signing_key.sign(payload.as_bytes());

        verify_ws_challenge_signature(
            &state,
            &vault_id,
            &device_id,
            &path,
            challenge_hex,
            &hex_encode(&signature.to_bytes()),
        )
        .expect("valid websocket challenge signature verifies");
    }

    #[test]
    fn websocket_challenge_verification_rejects_wrong_challenge() {
        let (state, vault_id, device_id, signing_key) = signed_test_state();
        let path = format!("/ws?vault_id={vault_id}&device_id={device_id}");
        let signature = signing_key.sign(format!("WS\n{path}\n0011").as_bytes());

        assert!(
            verify_ws_challenge_signature(
                &state,
                &vault_id,
                &device_id,
                &path,
                "2233",
                &hex_encode(&signature.to_bytes()),
            )
            .is_err()
        );
    }

    fn signed_test_state() -> (AppState, String, String, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let verifying_key_hex = hex_encode(&signing_key.verifying_key().to_bytes());
        let storage = Storage::open(&unique_temp_dir()).expect("open storage");
        let vault = storage.create_vault("test vault").expect("create vault");
        let device = storage
            .register_first_device(&vault.pairing_token, "laptop", &verifying_key_hex)
            .expect("register device");
        let state = AppState {
            storage,
            max_blob_size_bytes: 1024,
            max_vault_size_bytes: 1024 * 1024,
            max_devices_per_vault: 16,
            max_json_body_bytes: 1024,
            max_op_json_body_bytes: 4096,
            max_op_ciphertext_bytes: 1024,
            max_ops_per_push: 512,
            max_snapshot_json_body_bytes: 4096,
            max_snapshot_ciphertext_bytes: 1024,
            snapshot_retain: 2,
            op_broadcast: broadcast::channel::<EncryptedOpRecord>(16).0,
        };

        (state, vault.id, device.device_id, signing_key)
    }

    fn signed_headers(
        device_id: &str,
        signing_key: &SigningKey,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> HeaderMap {
        let payload = format!("{}\n{}\n{}", method.to_uppercase(), path, hex_encode(body));
        let signature = signing_key.sign(payload.as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-mylonite-device-id",
            device_id.parse().expect("device id header"),
        );
        headers.insert(
            "x-mylonite-signature",
            hex_encode(&signature.to_bytes())
                .parse()
                .expect("signature header"),
        );
        headers
    }

    fn unique_temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mylonite-app-test-{}-{}",
            std::process::id(),
            TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}

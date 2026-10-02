use axum::{
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
};
use futures_util::StreamExt;
use mylonite_protocol::{ClientMsgKind, Frame, ServerMsgKind};
use serde::Deserialize;
use serde::Serialize;
use tokio::time::{Duration, timeout};
use tracing::warn;

use super::{ApiError, AppState, auth::verify_ws_challenge_signature, validation};
use crate::util::random_hex;

#[derive(Debug, Deserialize)]
pub(super) struct WsQuery {
    vault_id: String,
    device_id: String,
}

#[derive(Debug, Serialize)]
struct WsChallenge {
    challenge_hex: String,
}

#[derive(Debug, Deserialize)]
struct WsHello {
    signature: String,
}

pub(super) async fn ws_handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, ApiError> {
    validation::validate_vault_id(&query.vault_id)?;
    validation::validate_device_id(&query.device_id)?;
    Ok(ws.on_upgrade(|socket| handle_socket(state, query.vault_id, query.device_id, socket)))
}

async fn handle_socket(state: AppState, vault_id: String, device_id: String, socket: WebSocket) {
    let mut socket = socket;
    if !authenticate_socket(&state, &vault_id, &device_id, &mut socket).await {
        return;
    }
    let mut op_receiver = state.op_broadcast.subscribe();

    loop {
        tokio::select! {
            op = op_receiver.recv() => match op {
                Ok(op) => {
                    if op.vault_id != vault_id {
                        continue;
                    }
                    let Ok(payload) = serde_json::to_vec(&op) else {
                        continue;
                    };
                    let Ok(encoded) = Frame::new(ServerMsgKind::OpBroadcast as u8, 0, payload).encode() else {
                        continue;
                    };
                    if socket.send(Message::Binary(encoded.into())).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    // closing makes the client reconnect and catch up from its cursor
                    warn!(skipped, "websocket op broadcast receiver lagged");
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
            message = socket.next() => match message {
                Some(Ok(Message::Binary(bytes))) => match Frame::decode(&bytes) {
                    Ok(frame) if frame.kind == ClientMsgKind::Ping as u8 => {
                        let Ok(encoded) = Frame::new(ServerMsgKind::Pong as u8, 0, Vec::new()).encode() else {
                            continue;
                        };
                        if socket.send(Message::Binary(encoded.into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(frame) if frame.kind == ClientMsgKind::OpPush as u8 => {
                        if let Err(error) = append_pushed_op(&state, &vault_id, &device_id, &frame.payload).await {
                            warn!(?error, "websocket op push rejected");
                        }
                    }
                    Ok(_) => {
                        warn!("unsupported websocket client message");
                    }
                    Err(error) => warn!(%error, "invalid websocket frame"),
                },
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    warn!(%error, "websocket error");
                    break;
                }
            }
        }
    }
}

async fn append_pushed_op(
    state: &AppState,
    vault_id: &str,
    authenticated_device_id: &str,
    payload: &[u8],
) -> Result<(), ApiError> {
    if payload.len() > state.max_op_json_body_bytes {
        return Err(ApiError::payload_too_large(anyhow::anyhow!(
            "request body exceeds configured JSON size limit"
        )));
    }
    let request: super::routes::AppendOpRequest = serde_json::from_slice(payload)?;
    let format = request.format;
    super::routes::append_ops(
        state,
        vault_id,
        authenticated_device_id,
        format,
        vec![request],
    )
    .await?;
    Ok(())
}

async fn authenticate_socket(
    state: &AppState,
    vault_id: &str,
    device_id: &str,
    socket: &mut WebSocket,
) -> bool {
    let path = format!("/ws?vault_id={vault_id}&device_id={device_id}");
    let challenge_hex = random_hex(16);
    let Ok(challenge_payload) = serde_json::to_vec(&WsChallenge {
        challenge_hex: challenge_hex.clone(),
    }) else {
        return false;
    };
    let Ok(challenge_frame) =
        Frame::new(ServerMsgKind::HelloChallenge as u8, 0, challenge_payload).encode()
    else {
        return false;
    };
    if socket
        .send(Message::Binary(challenge_frame.into()))
        .await
        .is_err()
    {
        return false;
    }

    let Ok(Some(Ok(Message::Binary(bytes)))) =
        timeout(Duration::from_secs(15), socket.next()).await
    else {
        return false;
    };
    let Ok(frame) = Frame::decode(&bytes) else {
        return false;
    };
    if frame.kind != ClientMsgKind::Hello as u8 {
        return false;
    }
    let Ok(hello) = serde_json::from_slice::<WsHello>(&frame.payload) else {
        return false;
    };
    if verify_ws_challenge_signature(
        state,
        vault_id,
        device_id,
        &path,
        &challenge_hex,
        &hello.signature,
    )
    .await
    .is_err()
    {
        return false;
    }

    let Ok(ack_frame) = Frame::new(ServerMsgKind::HelloAck as u8, 0, Vec::new()).encode() else {
        return false;
    };
    socket.send(Message::Binary(ack_frame.into())).await.is_ok()
}

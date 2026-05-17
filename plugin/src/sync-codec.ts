import { VaultKeys, decryptPayload, encryptPayload, keyedBlobId, randomHex } from "./crypto";
import { PendingEncryptedOp } from "./sync-types";

export function encodeEncryptedOp(
  keys: VaultKeys,
  vaultId: string,
  deviceId: string,
  lamport: number,
  kind: number,
  payloadObject: object,
): PendingEncryptedOp {
  const clientOpId = randomHex(32);
  const payload = new TextEncoder().encode(JSON.stringify(payloadObject));
  const aad = new TextEncoder().encode([
    "mylonite-op-v1",
    vaultId,
    clientOpId,
    deviceId,
    String(lamport),
    String(kind),
    "1",
  ].join("|"));
  const encrypted = encryptPayload(keys.opKey, payload, aad);
  return {
    client_op_id: clientOpId,
    device_id: deviceId,
    lamport,
    kind,
    key_version: 1,
    nonce_hex: encrypted.nonceHex,
    ciphertext_hex: encrypted.ciphertextHex,
  };
}

export function decodeEncryptedOpPayload(keys: VaultKeys, vaultId: string, op: PendingEncryptedOp): unknown {
  const aad = new TextEncoder().encode([
    "mylonite-op-v1",
    vaultId,
    op.client_op_id,
    op.device_id,
    String(op.lamport),
    String(op.kind),
    String(op.key_version),
  ].join("|"));
  const plaintext = decryptPayload(keys.opKey, op.nonce_hex, op.ciphertext_hex, aad);
  return JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
}

export function encryptBlob(keys: VaultKeys, vaultId: string, plaintext: Uint8Array): { blobId: string; envelope: Uint8Array } {
  const blobId = keyedBlobId(keys.blobIdKey, vaultId, plaintext);
  const aad = new TextEncoder().encode(`mylonite-blob-v1|${vaultId}|${blobId}`);
  const encrypted = encryptPayload(keys.blobKey, plaintext, aad);
  return { blobId, envelope: new TextEncoder().encode(JSON.stringify(encrypted)) };
}

export function decryptBlobEnvelope(keys: VaultKeys, vaultId: string, blobId: string, envelope: Uint8Array): Uint8Array {
  const encrypted = JSON.parse(new TextDecoder().decode(envelope)) as { nonceHex: string; ciphertextHex: string };
  const aad = new TextEncoder().encode(`mylonite-blob-v1|${vaultId}|${blobId}`);
  return decryptPayload(keys.blobKey, encrypted.nonceHex, encrypted.ciphertextHex, aad);
}

export function encryptSnapshot(keys: VaultKeys, vaultId: string, snapshotId: string, coversThroughSeq: number, payload: object): { nonceHex: string; ciphertextHex: string } {
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const aad = new TextEncoder().encode(`mylonite-snapshot-v1|${vaultId}|${snapshotId}|${coversThroughSeq}`);
  return encryptPayload(keys.snapshotKey, plaintext, aad);
}

export function decryptSnapshot<T>(keys: VaultKeys, vaultId: string, snapshotId: string, coversThroughSeq: number, nonceHex: string, ciphertextHex: string): T {
  const aad = new TextEncoder().encode(`mylonite-snapshot-v1|${vaultId}|${snapshotId}|${coversThroughSeq}`);
  const plaintext = decryptPayload(keys.snapshotKey, nonceHex, ciphertextHex, aad);
  return JSON.parse(new TextDecoder().decode(plaintext)) as T;
}

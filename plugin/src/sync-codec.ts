import { VaultKeys, decryptPayload, encryptPayload, keyedBlobId } from "./crypto";

export interface EncryptedOp {
  client_op_id: string;
  device_id: string;
  lamport: number;
  kind: number;
  key_version: number;
  nonce_hex: string;
  ciphertext_hex: string;
}

// the server only checks the kind range, so v3 ops reuse the update kind
const OPAQUE_OP_KIND = 2;
// version byte, 12 byte AES-GCM nonce, ciphertext. v1 envelopes are JSON and start with "{"
const BLOB_ENVELOPE_V2 = 2;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function encryptOp(keys: VaultKeys, vaultId: string, deviceId: string, opId: string, payload: object): EncryptedOp {
  const op = { client_op_id: opId, device_id: deviceId, lamport: 0, kind: OPAQUE_OP_KIND, key_version: 1 };
  const encrypted = encryptPayload(keys.opKey, encoder.encode(JSON.stringify(payload)), opAad(vaultId, op));
  return { ...op, nonce_hex: encrypted.nonceHex, ciphertext_hex: encrypted.ciphertextHex };
}

export function decryptOp(keys: VaultKeys, vaultId: string, op: EncryptedOp): unknown {
  const plaintext = decryptPayload(keys.opKey, op.nonce_hex, op.ciphertext_hex, opAad(vaultId, op));
  return JSON.parse(decoder.decode(plaintext)) as unknown;
}

function opAad(vaultId: string, op: Pick<EncryptedOp, "client_op_id" | "device_id" | "lamport" | "kind" | "key_version">): Uint8Array {
  return encoder.encode(["mylonite-op-v1", vaultId, op.client_op_id, op.device_id, op.lamport, op.kind, op.key_version].join("|"));
}

export function blobIdOf(keys: VaultKeys, vaultId: string, plaintext: Uint8Array): Promise<string> {
  return keyedBlobId(keys.blobIdKey, vaultId, plaintext);
}

export async function encryptBlob(keys: VaultKeys, vaultId: string, plaintext: Uint8Array): Promise<{ blobId: string; envelope: Uint8Array }> {
  const blobId = await blobIdOf(keys, vaultId, plaintext);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: blobAad(vaultId, blobId) as BufferSource },
    await blobCryptoKey(keys),
    plaintext as BufferSource,
  ));
  const envelope = new Uint8Array(1 + nonce.byteLength + ciphertext.byteLength);
  envelope[0] = BLOB_ENVELOPE_V2;
  envelope.set(nonce, 1);
  envelope.set(ciphertext, 1 + nonce.byteLength);
  return { blobId, envelope };
}

export async function decryptBlob(keys: VaultKeys, vaultId: string, blobId: string, envelope: Uint8Array): Promise<Uint8Array> {
  const aad = blobAad(vaultId, blobId);
  if (envelope[0] === BLOB_ENVELOPE_V2) {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: envelope.subarray(1, 13) as BufferSource, additionalData: aad as BufferSource },
      await blobCryptoKey(keys),
      envelope.subarray(13) as BufferSource,
    ));
  }
  const legacy = JSON.parse(decoder.decode(envelope)) as { nonceHex: string; ciphertextHex: string };
  return decryptPayload(keys.blobKey, legacy.nonceHex, legacy.ciphertextHex, aad);
}

const blobCryptoKeys = new WeakMap<Uint8Array, Promise<CryptoKey>>();

function blobCryptoKey(keys: VaultKeys): Promise<CryptoKey> {
  let key = blobCryptoKeys.get(keys.blobKey);
  if (!key) {
    key = crypto.subtle.importKey("raw", keys.blobKey as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
    blobCryptoKeys.set(keys.blobKey, key);
  }
  return key;
}

function blobAad(vaultId: string, blobId: string): Uint8Array {
  return encoder.encode(`mylonite-blob-v1|${vaultId}|${blobId}`);
}

export function encryptSnapshot(keys: VaultKeys, vaultId: string, snapshotId: string, coversThroughSeq: number, payload: object): { nonceHex: string; ciphertextHex: string } {
  const plaintext = encoder.encode(JSON.stringify(payload));
  return encryptPayload(keys.snapshotKey, plaintext, snapshotAad(vaultId, snapshotId, coversThroughSeq));
}

export function decryptSnapshot(keys: VaultKeys, vaultId: string, snapshotId: string, coversThroughSeq: number, nonceHex: string, ciphertextHex: string): unknown {
  const plaintext = decryptPayload(keys.snapshotKey, nonceHex, ciphertextHex, snapshotAad(vaultId, snapshotId, coversThroughSeq));
  return JSON.parse(decoder.decode(plaintext)) as unknown;
}

function snapshotAad(vaultId: string, snapshotId: string, coversThroughSeq: number): Uint8Array {
  return encoder.encode(`mylonite-snapshot-v1|${vaultId}|${snapshotId}|${coversThroughSeq}`);
}


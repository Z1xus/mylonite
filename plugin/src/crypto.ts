import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { idle } from "./idle";

const textEncoder = new TextEncoder();

export interface DeviceKeypair {
  privateKeyHex: string;
  publicKeyHex: string;
}

export interface VaultKeys {
  opKey: Uint8Array;
  blobKey: Uint8Array;
  blobIdKey: Uint8Array;
  snapshotKey: Uint8Array;
}

export interface EncryptedPayload {
  nonceHex: string;
  ciphertextHex: string;
}

export interface X25519Keypair {
  privateKeyHex: string;
  publicKeyHex: string;
}

export function generateDeviceKeypair(): DeviceKeypair {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
  };
}

export async function signRequest(privateKeyHex: string, method: string, path: string, body: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body as BufferSource));
  const payload = textEncoder.encode(`${method.toUpperCase()}\n${path}\n${bytesToHex(digest)}`);
  return bytesToHex(ed25519.sign(payload, hexToBytes(privateKeyHex)));
}

export function signWebSocketChallenge(privateKeyHex: string, path: string, challengeHex: string): string {
  const payload = textEncoder.encode(`WS\n${path}\n${challengeHex}`);
  return bytesToHex(ed25519.sign(payload, hexToBytes(privateKeyHex)));
}

export function generateX25519Keypair(): X25519Keypair {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
  };
}

export function encryptDevicePairingSecret(privateKeyHex: string, peerPublicKeyHex: string, plaintext: Uint8Array): EncryptedPayload {
  const key = pairingSecretKey(privateKeyHex, peerPublicKeyHex);
  return encryptPayload(key, plaintext, textEncoder.encode("mylonite/device-pairing/v1"));
}

export function decryptDevicePairingSecret(privateKeyHex: string, peerPublicKeyHex: string, payload: EncryptedPayload): Uint8Array {
  const key = pairingSecretKey(privateKeyHex, peerPublicKeyHex);
  return decryptPayload(key, payload.nonceHex, payload.ciphertextHex, textEncoder.encode("mylonite/device-pairing/v1"));
}

export async function deriveVaultKeys(passphrase: string, saltHex: string): Promise<VaultKeys> {
  const salt = hexToBytes(saltHex);
  const passphraseBytes = textEncoder.encode(passphrase);
  const masterKey = await argon2idAsync(passphraseBytes, salt, {
    t: 3,
    m: 64 * 1024,
    p: 1,
    dkLen: 32,
  });
  return {
    opKey: hkdf(sha256, masterKey, undefined, textEncoder.encode("mylonite/op/v1"), 32),
    blobKey: hkdf(sha256, masterKey, undefined, textEncoder.encode("mylonite/blob/v1"), 32),
    blobIdKey: hkdf(sha256, masterKey, undefined, textEncoder.encode("mylonite/blob-id/v1"), 32),
    snapshotKey: hkdf(sha256, masterKey, undefined, textEncoder.encode("mylonite/snapshot/v1"), 32),
  };
}

const HASH_CHUNK = 4 * 1024 * 1024;

export async function keyedBlobId(blobIdKey: Uint8Array, vaultId: string, plaintext: Uint8Array): Promise<string> {
  const hasher = blake3.create({ key: blobIdKey });
  hasher.update(textEncoder.encode(`mylonite-blob-id-v1|${vaultId}|`));
  for (let offset = 0; offset < plaintext.byteLength; offset += HASH_CHUNK) {
    hasher.update(plaintext.subarray(offset, offset + HASH_CHUNK));
    if (offset + HASH_CHUNK < plaintext.byteLength) {
      await idle();
    }
  }
  return bytesToHex(hasher.digest());
}

export function encryptPayload(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): EncryptedPayload {
  const nonce = new Uint8Array(24);
  crypto.getRandomValues(nonce);
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return { nonceHex: bytesToHex(nonce), ciphertextHex: bytesToHex(ciphertext) };
}

export function decryptPayload(key: Uint8Array, nonceHex: string, ciphertextHex: string, aad: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, hexToBytes(nonceHex), aad).decrypt(hexToBytes(ciphertextHex));
}

export function randomHex(byteLen: number): string {
  const bytes = new Uint8Array(byteLen);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function pairingSecretKey(privateKeyHex: string, peerPublicKeyHex: string): Uint8Array {
  const shared = x25519.getSharedSecret(hexToBytes(privateKeyHex), hexToBytes(peerPublicKeyHex));
  return hkdf(sha256, shared, undefined, textEncoder.encode("mylonite/device-pairing-key/v1"), 32);
}

const HEX_PAIRS = new Uint16Array(256);
for (let byte = 0; byte < 256; byte += 1) {
  const pair = byte.toString(16).padStart(2, "0");
  HEX_PAIRS[byte] = pair.charCodeAt(0) | (pair.charCodeAt(1) << 8);
}
const latin1 = new TextDecoder("latin1");
const NIBBLES = new Int8Array(128).fill(-1);
for (let value = 0; value < 16; value += 1) {
  NIBBLES[value.toString(16).charCodeAt(0)] = value;
}

export function bytesToHex(bytes: Uint8Array): string {
  const out = new Uint16Array(bytes.length);
  for (let index = 0; index < bytes.length; index += 1) {
    out[index] = HEX_PAIRS[bytes[index]];
  }
  return latin1.decode(out);
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    const high = NIBBLES[hex.charCodeAt(index * 2)] ?? -1;
    const low = NIBBLES[hex.charCodeAt(index * 2 + 1)] ?? -1;
    if (high < 0 || low < 0) {
      throw new Error("invalid hex");
    }
    out[index] = (high << 4) | low;
  }
  return out;
}

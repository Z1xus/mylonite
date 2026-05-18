import { sha256 } from "@noble/hashes/sha2.js";

import { bytesToHex, hexToBytes } from "./crypto";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const INVITE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export interface DevicePairingInvitePayload {
  version: number;
  server_url: string;
  invite_code: string;
}

export interface DevicePairingRequestPayload {
  version: number;
  request_hash: string;
  label: string;
  verifying_key: string;
  x25519_public_key: string;
}

export interface DevicePairingResponsePayload {
  version: number;
  x25519_public_key: string;
  nonce_hex: string;
  ciphertext_hex: string;
}

export interface DevicePairingSecretPayload {
  version: number;
  vault_id: string;
  vault_salt_hex: string;
  passphrase: string;
  device_id: string;
  request_hash: string;
  last_server_seq: number;
}

export function createDevicePairingInvitePayload(serverUrl: string): DevicePairingInvitePayload {
  const invite = {
    version: 1,
    server_url: normalizeServerUrl(serverUrl),
    invite_code: randomInviteCode(),
  };
  validateDevicePairingInvite(invite);
  return invite;
}

export function createDevicePairingRequestPayload(
  inviteCode: string,
  label: string,
  verifyingKey: string,
  x25519PublicKey: string,
): DevicePairingRequestPayload {
  const request = {
    version: 1,
    request_hash: devicePairingRequestHash(inviteCode, label, verifyingKey, x25519PublicKey),
    label,
    verifying_key: verifyingKey,
    x25519_public_key: x25519PublicKey,
  };
  validateDevicePairingRequest(request, inviteCode);
  return request;
}

export function devicePairingInviteText(invite: DevicePairingInvitePayload): string {
  validateDevicePairingInvite(invite);
  return `MYLONITE:${base64UrlEncode(textEncoder.encode(JSON.stringify(invite)))}`;
}

export function devicePairingInviteUrl(invite: DevicePairingInvitePayload): string {
  validateDevicePairingInvite(invite);
  return `${invite.server_url}/p/${encodeURIComponent(invite.invite_code.replace(/-/g, ""))}`;
}

export function devicePairingInviteQrUrl(invite: DevicePairingInvitePayload): string {
  validateDevicePairingInvite(invite);
  return `${invite.server_url.toUpperCase()}/P/${encodeURIComponent(invite.invite_code.replace(/-/g, ""))}`;
}

export function parseDevicePairingInviteInput(value: string): DevicePairingInvitePayload {
  const trimmed = value.trim();
  const urlInvite = inviteFromUrl(trimmed);
  if (urlInvite) {
    return parseDevicePairingInviteInput(urlInvite);
  }
  const raw = trimmed.startsWith("MYLONITE:") ? trimmed.slice("MYLONITE:".length) : trimmed;
  let decoded = raw;
  if (!raw.startsWith("{")) {
    decoded = textDecoder.decode(base64UrlDecode(raw));
  }
  const payload = JSON.parse(decoded) as DevicePairingInvitePayload;
  validateDevicePairingInvite(payload);
  return payload;
}

export function pairingSafetyCode(requestHash: string): string {
  if (!isHex(requestHash, 64)) {
    throw new Error("invalid request hash");
  }
  const bytes = hexToBytes(requestHash);
  const value = (
    ((bytes[0] << 24) >>> 0)
    + (bytes[1] << 16)
    + (bytes[2] << 8)
    + bytes[3]
  ) % 1_000_000;
  const padded = value.toString().padStart(6, "0");
  return `${padded.slice(0, 3)} ${padded.slice(3)}`;
}

export function inviteCodeHash(sessionId: string, inviteCode: string): string {
  if (!validPairingSessionId(sessionId) || !validInviteCode(inviteCode)) {
    throw new Error("invalid invite");
  }
  const material = textEncoder.encode(`mylonite/pairing-invite-code/v1|${sessionId}|${inviteCode}`);
  return bytesToHex(sha256(material));
}

export function validateDevicePairingInvite(payload: DevicePairingInvitePayload): void {
  if (
    payload.version !== 1
    || !validServerUrl(payload.server_url)
    || !validInviteCode(payload.invite_code)
  ) {
    throw new Error("invalid device pairing invite");
  }
}

export function validateDevicePairingRequest(payload: DevicePairingRequestPayload, inviteCode: string): void {
  if (
    payload.version !== 1
    || !validInviteCode(inviteCode)
    || !isHex(payload.request_hash, 64)
    || !validDeviceLabel(payload.label)
    || !isHex(payload.verifying_key, 64)
    || !isHex(payload.x25519_public_key, 64)
    || payload.request_hash !== devicePairingRequestHash(inviteCode, payload.label, payload.verifying_key, payload.x25519_public_key)
  ) {
    throw new Error("invalid device pairing request");
  }
}

export function validatePairingRequestShape(payload: DevicePairingRequestPayload): void {
  if (
    payload.version !== 1
    || !isHex(payload.request_hash, 64)
    || !validDeviceLabel(payload.label)
    || !isHex(payload.verifying_key, 64)
    || !isHex(payload.x25519_public_key, 64)
  ) {
    throw new Error("invalid device pairing request");
  }
}

export function validateDevicePairingResponse(payload: DevicePairingResponsePayload): void {
  if (payload.version !== 1 || !isHex(payload.x25519_public_key, 64) || !isHex(payload.nonce_hex, 48) || !isHex(payload.ciphertext_hex)) {
    throw new Error("invalid device pairing response");
  }
}

export function validateDevicePairingSecret(payload: DevicePairingSecretPayload, expectedRequestHash: string): void {
  if (
    payload.version !== 1
    || !validOpaqueId(payload.vault_id)
    || !isHex(payload.vault_salt_hex, 32)
    || typeof payload.passphrase !== "string"
    || payload.passphrase.length === 0
    || !validDeviceId(payload.device_id)
    || !isHex(payload.request_hash, 64)
    || payload.request_hash !== expectedRequestHash
    || !Number.isSafeInteger(payload.last_server_seq)
    || payload.last_server_seq < 0
  ) {
    throw new Error("invalid device pairing secret");
  }
}

export function normalizeServerUrl(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

export function normalizeInviteCode(value: string): string {
  const compact = value.trim().toUpperCase().replace(/[^A-Z2-9]/g, "");
  return [compact.slice(0, 4), compact.slice(4, 8), compact.slice(8, 12)]
    .filter((part) => part.length > 0)
    .join("-");
}

function randomInviteCode(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  const chars = Array.from(bytes, (byte) => INVITE_ALPHABET[byte % INVITE_ALPHABET.length]);
  return `${chars.slice(0, 4).join("")}-${chars.slice(4, 8).join("")}-${chars.slice(8, 12).join("")}`;
}

function devicePairingRequestHash(inviteCode: string, label: string, verifyingKey: string, x25519PublicKey: string): string {
  const canonical = JSON.stringify({
    version: 1,
    invite_code: normalizeInviteCode(inviteCode),
    label,
    verifying_key: verifyingKey,
    x25519_public_key: x25519PublicKey,
  });
  const material = textEncoder.encode(`mylonite/device-pairing-request/v1|${canonical}`);
  return bytesToHex(sha256(material));
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    out[index] = binary.charCodeAt(index);
  }
  return out;
}

function inviteFromUrl(value: string): string | null {
  try {
    const url = new URL(value);
    const invite = url.searchParams.get("invite");
    if (invite) {
      return invite;
    }
    const pathCode = url.pathname.match(/^\/[pP]\/([A-Za-z2-9-]+)$/)?.[1] ?? null;
    const code = pathCode ?? url.searchParams.get("c") ?? url.searchParams.get("code");
    if (code) {
      return JSON.stringify({
        version: 1,
        server_url: url.origin,
        invite_code: normalizeInviteCode(code),
      });
    }
    return null;
  } catch {
    return null;
  }
}

function validServerUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function validPairingSessionId(value: string): boolean {
  return typeof value === "string" && /^ps[0-9a-f]{32}$/.test(value);
}

function validInviteCode(value: string): boolean {
  return typeof value === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value);
}

function validOpaqueId(value: string): boolean {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && /^[A-Za-z0-9_-]+$/.test(value);
}

function validDeviceId(value: string): boolean {
  return typeof value === "string" && /^d[0-9a-f]{32}$/.test(value);
}

function validDeviceLabel(value: string): boolean {
  return typeof value === "string" && value.trim().length > 0 && textEncoder.encode(value).length <= 128;
}

function isHex(value: string, len?: number): boolean {
  return typeof value === "string" && (len === undefined || value.length === len) && /^[0-9a-f]+$/.test(value);
}

import { requestUrl } from "obsidian";

import { signRequest, signWebSocketChallenge } from "./crypto";
import { OpKind } from "./protocol";

export interface PairFirstDeviceResponse {
  vault_id: string;
  device_id: string;
}

export interface OpenPairingSessionResponse {
  session_id: string;
  expires_at_unix: number;
}

export interface SubmitPairingSessionResponse {
  session_id: string;
  expires_at_unix: number;
}

export interface PairingGrantPayload {
  x25519_public_key: string;
  nonce_hex: string;
  ciphertext_hex: string;
}

export interface PairingRequestPayload {
  request_hash: string;
  label: string;
  verifying_key: string;
  x25519_public_key: string;
}

export type PairingSessionResponse =
  | { status: "waiting"; expires_at_unix: number }
  | { status: "requested"; expires_at_unix: number; request: PairingRequestPayload }
  | { status: "granted"; expires_at_unix: number; grant: PairingGrantPayload }
  | { status: "expired" };

export type PairingSessionGrantResponse =
  | { status: "pending"; expires_at_unix: number }
  | { status: "granted"; expires_at_unix: number; grant: PairingGrantPayload }
  | { status: "expired" };

export interface EncryptedOpRecord {
  vault_id: string;
  server_seq: number;
  client_op_id: string;
  device_id: string;
  lamport: number;
  kind: number;
  key_version: number;
  nonce_hex: string;
  ciphertext_hex: string;
  accepted_at_unix: number;
}

export interface AppendOpRequest {
  client_op_id: string;
  device_id: string;
  lamport: number;
  kind: number;
  key_version: number;
  nonce_hex: string;
  ciphertext_hex: string;
}

export interface AppendOpResponse {
  server_seq: number;
}

export interface DeviceAuth {
  deviceId: string;
  privateKeyHex: string;
}

export interface DeviceRecord {
  vault_id: string;
  device_id: string;
  label: string;
  verifying_key: string;
  created_at_unix: number;
  revoked_at_unix: number | null;
  last_seen_at_unix: number | null;
}

export interface RegisterDeviceResponse {
  device_id: string;
}

export interface SnapshotRecord {
  vault_id: string;
  snapshot_id: string;
  device_id: string;
  covers_through_seq: number;
  key_version: number;
  nonce_hex: string;
  ciphertext_hex: string;
  created_at_unix: number;
}

export interface PutSnapshotRequest {
  snapshot_id: string;
  device_id: string;
  covers_through_seq: number;
  key_version: number;
  nonce_hex: string;
  ciphertext_hex: string;
}

type ApiRequestInit = {
  method?: string;
  headers?: Record<string, string>;
  body?: string | ArrayBuffer | Uint8Array;
};

type ApiResponse = {
  status: number;
  arrayBuffer(): Promise<ArrayBuffer>;
  json(): Promise<unknown>;
  text(): Promise<string>;
};

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

const RETRIABLE_CLIENT_STATUSES = new Set([401, 403, 408, 425, 429]);

export function isPermanentApiRejection(error: unknown): boolean {
  return error instanceof ApiError && error.status >= 400 && error.status < 500 && !RETRIABLE_CLIENT_STATUSES.has(error.status);
}

export class MyloniteApiClient {
  constructor(private readonly serverUrl: string, private readonly auth?: DeviceAuth) {}

  websocketUrl(vaultId: string): string {
    if (!this.auth) {
      throw new Error("device authentication is required");
    }
    validateOpaqueId("vault id", vaultId);
    const path = this.websocketPath(vaultId);
    const base = this.serverUrl.replace(/\/$/, "").replace(/^http:/, "ws:").replace(/^https:/, "wss:");
    return `${base}${path}`;
  }

  websocketHello(vaultId: string, challengeHex: string): { signature: string } {
    if (!this.auth) {
      throw new Error("device authentication is required");
    }
    validateOpaqueId("vault id", vaultId);
    return { signature: signWebSocketChallenge(this.auth.privateKeyHex, this.websocketPath(vaultId), challengeHex) };
  }

  private websocketPath(vaultId: string): string {
    if (!this.auth) {
      throw new Error("device authentication is required");
    }
    validateOpaqueId("vault id", vaultId);
    validateDeviceId(this.auth.deviceId);
    return `/ws?vault_id=${encodeURIComponent(vaultId)}&device_id=${encodeURIComponent(this.auth.deviceId)}`;
  }

  async pairFirstDevice(token: string, label: string, verifyingKey: string): Promise<PairFirstDeviceResponse> {
    validatePairingToken(token);
    validateDeviceLabel(label);
    validateVerifyingKey(verifyingKey);
    return this.requestJson("/api/v1/pair/first-device", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, label, verifying_key: verifyingKey }),
    });
  }

  async openPairingSession(vaultId: string, sessionId: string, inviteCodeHash: string): Promise<OpenPairingSessionResponse> {
    validateOpaqueId("vault id", vaultId);
    validatePairingSessionId(sessionId);
    validateInviteCodeHash(inviteCodeHash);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/pairing-sessions`;
    const body = new TextEncoder().encode(JSON.stringify({ session_id: sessionId, invite_code_hash: inviteCodeHash }));
    return this.requestJson(path, {
      method: "POST",
      headers: this.signedHeaders("POST", path, body, { "content-type": "application/json" }),
      body,
    });
  }

  async getPairingSession(vaultId: string, sessionId: string): Promise<PairingSessionResponse> {
    validateOpaqueId("vault id", vaultId);
    validatePairingSessionId(sessionId);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/pairing-sessions/${encodeURIComponent(sessionId)}`;
    const response = await this.requestJson<PairingSessionResponse>(path, {
      headers: this.signedHeaders("GET", path, new Uint8Array()),
    });
    validatePairingSessionResponse(response);
    return response;
  }

  async submitPairingSessionRequest(inviteCode: string, request: PairingRequestPayload): Promise<SubmitPairingSessionResponse> {
    validateInviteCode(inviteCode);
    validatePairingRequestPayload(request);
    const path = "/api/v1/pair/invites/request";
    const response = await this.requestJson<SubmitPairingSessionResponse>(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ invite_code: inviteCode, request }),
    });
    validatePairingSessionId(response.session_id);
    validateSequence("expires at", response.expires_at_unix, 0);
    return response;
  }

  async getPairingSessionGrant(sessionId: string): Promise<PairingSessionGrantResponse> {
    validatePairingSessionId(sessionId);
    const response = await this.requestJson<PairingSessionGrantResponse>(`/api/v1/pair/sessions/${encodeURIComponent(sessionId)}/grant`);
    validatePairingSessionGrantResponse(response);
    return response;
  }

  async listOps(vaultId: string, after: number, limit?: number): Promise<EncryptedOpRecord[]> {
    validateOpaqueId("vault id", vaultId);
    validateSequence("after", after);
    if (limit !== undefined) {
      validateSequence("limit", limit, 1);
    }
    const limitQuery = limit === undefined ? "" : `&limit=${limit}`;
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/ops?after=${after}${limitQuery}`;
    return this.requestJson(path, {
      headers: this.signedHeaders("GET", path, new Uint8Array()),
    });
  }

  async appendOp(vaultId: string, op: AppendOpRequest): Promise<AppendOpResponse> {
    validateOpaqueId("vault id", vaultId);
    validateAppendOpRequest(op);
    this.validateAuthenticatedDevice(op.device_id);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/ops`;
    const body = new TextEncoder().encode(JSON.stringify(op));
    return this.requestJson(path, {
      method: "POST",
      headers: this.signedHeaders("POST", path, body, { "content-type": "application/json" }),
      body,
    });
  }

  async putBlob(vaultId: string, blobId: string, ciphertext: Uint8Array): Promise<void> {
    validateOpaqueId("vault id", vaultId);
    validateBlobId(blobId);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/blobs/${encodeURIComponent(blobId)}`;
    const body = new Uint8Array(ciphertext).buffer;
    await this.request(path, {
      method: "PUT",
      headers: this.signedHeaders("PUT", path, ciphertext),
      body,
    });
  }

  async getBlob(vaultId: string, blobId: string): Promise<Uint8Array | null> {
    validateOpaqueId("vault id", vaultId);
    validateBlobId(blobId);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/blobs/${encodeURIComponent(blobId)}`;
    const response = await this.request(path, {
      headers: this.signedHeaders("GET", path, new Uint8Array()),
    });
    if (response.status === 404) {
      return null;
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  async putSnapshot(vaultId: string, snapshot: PutSnapshotRequest): Promise<void> {
    validateOpaqueId("vault id", vaultId);
    validatePutSnapshotRequest(snapshot);
    this.validateAuthenticatedDevice(snapshot.device_id);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/snapshots`;
    const body = new TextEncoder().encode(JSON.stringify(snapshot));
    await this.request(path, {
      method: "POST",
      headers: this.signedHeaders("POST", path, body, { "content-type": "application/json" }),
      body,
    });
  }

  async listSnapshots(vaultId: string): Promise<SnapshotRecord[]> {
    validateOpaqueId("vault id", vaultId);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/snapshots`;
    return this.requestJson(path, {
      headers: this.signedHeaders("GET", path, new Uint8Array()),
    });
  }

  async listDevices(vaultId: string): Promise<DeviceRecord[]> {
    validateOpaqueId("vault id", vaultId);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/devices`;
    return this.requestJson(path, {
      headers: this.signedHeaders("GET", path, new Uint8Array()),
    });
  }

  async registerDevice(vaultId: string, label: string, verifyingKey: string): Promise<RegisterDeviceResponse> {
    validateOpaqueId("vault id", vaultId);
    validateDeviceLabel(label);
    validateVerifyingKey(verifyingKey);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/devices`;
    const body = new TextEncoder().encode(JSON.stringify({ label, verifying_key: verifyingKey }));
    return this.requestJson(path, {
      method: "POST",
      headers: this.signedHeaders("POST", path, body, { "content-type": "application/json" }),
      body,
    });
  }

  async putPairingSessionGrant(vaultId: string, sessionId: string, requestHash: string, grant: PairingGrantPayload): Promise<void> {
    validateOpaqueId("vault id", vaultId);
    validatePairingSessionId(sessionId);
    validateRequestHash(requestHash);
    validatePairingGrantPayload(grant);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/pairing-sessions/${encodeURIComponent(sessionId)}/grant`;
    const body = new TextEncoder().encode(JSON.stringify({ request_hash: requestHash, grant }));
    await this.request(path, {
      method: "POST",
      headers: this.signedHeaders("POST", path, body, { "content-type": "application/json" }),
      body,
    });
  }

  async revokeDevice(vaultId: string, deviceId: string): Promise<void> {
    validateOpaqueId("vault id", vaultId);
    validateDeviceId(deviceId);
    const path = `/api/v1/vaults/${encodeURIComponent(vaultId)}/devices/${encodeURIComponent(deviceId)}`;
    await this.request(path, {
      method: "POST",
      headers: this.signedHeaders("POST", path, new Uint8Array()),
    });
  }

  private async requestJson<T>(path: string, init?: ApiRequestInit): Promise<T> {
    const response = await this.request(path, init);
    return response.json() as Promise<T>;
  }

  private async request(path: string, init?: ApiRequestInit): Promise<ApiResponse> {
    const response = await requestUrl({
      url: `${this.serverUrl.replace(/\/$/, "")}${path}`,
      method: init?.method,
      headers: init?.headers,
      body: toRequestUrlBody(init?.body),
      throw: false,
    });
    if (response.status < 200 || (response.status >= 300 && response.status !== 404)) {
      throw new ApiError(response.status, response.text);
    }
    return {
      status: response.status,
      arrayBuffer: () => Promise.resolve(response.arrayBuffer),
      json: () => Promise.resolve(response.json as unknown),
      text: () => Promise.resolve(response.text),
    };
  }

  private signedHeaders(method: string, path: string, body: Uint8Array, headers: Record<string, string> = {}): Record<string, string> {
    if (!this.auth) {
      throw new Error("device authentication is required");
    }
    validateDeviceId(this.auth.deviceId);
    return {
      ...headers,
      "x-mylonite-device-id": this.auth.deviceId,
      "x-mylonite-signature": signRequest(this.auth.privateKeyHex, method, path, body),
    };
  }

  private validateAuthenticatedDevice(deviceId: string): void {
    if (!this.auth) {
      throw new Error("device authentication is required");
    }
    validateDeviceId(this.auth.deviceId);
    validateDeviceId(deviceId);
    if (deviceId !== this.auth.deviceId) {
      throw new Error("request device id does not match authenticated device");
    }
  }
}

function validateOpaqueId(name: string, value: string): void {
  if (value.length === 0 || value.length > 128 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
}

function validateSequence(name: string, value: number, minimum = 0): void {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`invalid ${name}`);
  }
}

function validateDeviceId(value: string): void {
  if (!/^d[0-9a-f]{32}$/.test(value)) {
    throw new Error("invalid device id");
  }
}

function validateDeviceLabel(value: string): void {
  if (typeof value !== "string" || value.trim().length === 0 || new TextEncoder().encode(value).length > 128) {
    throw new Error("invalid device label");
  }
}

function validatePairingToken(value: string): void {
  if (!/^p[0-9a-f]{48}$/.test(value)) {
    throw new Error("invalid pairing token");
  }
}

function toRequestUrlBody(body: ApiRequestInit["body"]): string | ArrayBuffer | undefined {
  if (body instanceof Uint8Array) {
    const copy = new Uint8Array(body.byteLength);
    copy.set(body);
    return copy.buffer;
  }
  return body;
}

function validatePairingSessionId(value: string): void {
  if (!/^ps[0-9a-f]{32}$/.test(value)) {
    throw new Error("invalid pairing session id");
  }
}

function validateRequestHash(value: string): void {
  validateHexField("request hash", value, 64);
}

function validateInviteCodeHash(value: string): void {
  validateHexField("invite code hash", value, 64);
}

function validateInviteCode(value: string): void {
  if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value)) {
    throw new Error("invalid invite code");
  }
}

function validateVerifyingKey(value: string): void {
  validateHexField("Ed25519 verifying key", value, 64);
}

function validateX25519PublicKey(value: string): void {
  validateHexField("X25519 public key", value, 64);
}

function validateBlobId(value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("invalid blob id");
  }
}

function validateSnapshotId(value: string): void {
  if (!/^[0-9a-f]{32}$/.test(value)) {
    throw new Error("invalid snapshot id");
  }
}

function validateAppendOpRequest(op: AppendOpRequest): void {
  validateHexField("client op id", op.client_op_id, 64);
  validateDeviceId(op.device_id);
  validateSequence("lamport", op.lamport, 0);
  if (!Number.isSafeInteger(op.kind) || op.kind < OpKind.FileCreate || op.kind > OpKind.FileCopy) {
    throw new Error("invalid op kind");
  }
  validateKeyVersion(op.key_version);
  validateHexField("nonce", op.nonce_hex, 48);
  validateHexPayload("ciphertext", op.ciphertext_hex);
}

function validatePutSnapshotRequest(snapshot: PutSnapshotRequest): void {
  validateSnapshotId(snapshot.snapshot_id);
  validateDeviceId(snapshot.device_id);
  validateSequence("covers through seq", snapshot.covers_through_seq, 0);
  validateKeyVersion(snapshot.key_version);
  validateHexField("nonce", snapshot.nonce_hex, 48);
  validateHexPayload("ciphertext", snapshot.ciphertext_hex);
}

function validatePairingSessionGrantResponse(response: PairingSessionGrantResponse): void {
  if (response.status === "expired") {
    return;
  }
  if (response.status === "pending") {
    validateSequence("expires at", response.expires_at_unix, 0);
    return;
  }
  if (response.status === "granted") {
    validateSequence("expires at", response.expires_at_unix, 0);
    validatePairingGrantPayload(response.grant);
    return;
  }
  throw new Error("invalid pairing session grant response");
}

function validatePairingSessionResponse(response: PairingSessionResponse): void {
  if (response.status === "expired") {
    return;
  }
  if (response.status === "waiting") {
    validateSequence("expires at", response.expires_at_unix, 0);
    return;
  }
  if (response.status === "requested") {
    validateSequence("expires at", response.expires_at_unix, 0);
    validatePairingRequestPayload(response.request);
    return;
  }
  if (response.status === "granted") {
    validateSequence("expires at", response.expires_at_unix, 0);
    validatePairingGrantPayload(response.grant);
    return;
  }
  throw new Error("invalid pairing session response");
}

function validatePairingRequestPayload(request: PairingRequestPayload): void {
  validateRequestHash(request.request_hash);
  validateDeviceLabel(request.label);
  validateVerifyingKey(request.verifying_key);
  validateX25519PublicKey(request.x25519_public_key);
}

function validatePairingGrantPayload(grant: PairingGrantPayload): void {
  validateX25519PublicKey(grant.x25519_public_key);
  validateHexField("nonce", grant.nonce_hex, 48);
  validateHexPayload("ciphertext", grant.ciphertext_hex);
}

function validateKeyVersion(value: number): void {
  if (value !== 1) {
    throw new Error("unsupported key version");
  }
}

function validateHexField(name: string, value: string, length: number): void {
  if (typeof value !== "string" || value.length !== length || /[^0-9a-f]/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
}

function validateHexPayload(name: string, value: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || /[^0-9a-f]/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
}

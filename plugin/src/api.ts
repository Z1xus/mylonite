import { requestUrl } from "obsidian";

import { signRequest, signWebSocketChallenge } from "./crypto";
import { EncryptedOp } from "./sync-codec";

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

export interface EncryptedOpRecord extends EncryptedOp {
  vault_id: string;
  server_seq: number;
  accepted_at_unix: number;
}

export interface VaultInfo {
  format: number;
  head_seq: number;
  upgrade_seq: number;
  upgrade_base: number;
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

export interface DeviceAuth {
  deviceId: string;
  privateKeyHex: string;
}

export const OP_FORMAT = 3;

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

interface Response {
  status: number;
  json: unknown;
  bytes: Uint8Array;
}

const encoder = new TextEncoder();

export class MyloniteApiClient {
  private readonly base: string;

  constructor(serverUrl: string, private readonly auth?: DeviceAuth) {
    this.base = serverUrl.replace(/\/+$/, "");
  }

  websocketUrl(vaultId: string): string {
    return `${this.base.replace(/^http/, "ws")}${this.websocketPath(vaultId)}`;
  }

  websocketHello(vaultId: string, challengeHex: string): { signature: string } {
    return { signature: signWebSocketChallenge(this.requireAuth().privateKeyHex, this.websocketPath(vaultId), challengeHex) };
  }

  async pairFirstDevice(token: string, label: string, verifyingKey: string): Promise<{ vault_id: string; device_id: string }> {
    return (await this.send("POST", "/api/v1/pair/first-device", { token, label, verifying_key: verifyingKey }, false)).json as { vault_id: string; device_id: string };
  }

  async submitPairingSessionRequest(inviteCode: string, request: PairingRequestPayload): Promise<{ session_id: string }> {
    return (await this.send("POST", "/api/v1/pair/invites/request", { invite_code: inviteCode, request }, false)).json as { session_id: string };
  }

  async getPairingSessionGrant(sessionId: string): Promise<PairingSessionGrantResponse> {
    return (await this.send("GET", `/api/v1/pair/sessions/${encode(sessionId)}/grant`, undefined, false)).json as PairingSessionGrantResponse;
  }

  async openPairingSession(vaultId: string, sessionId: string, inviteCodeHash: string): Promise<void> {
    await this.send("POST", `${vault(vaultId)}/pairing-sessions`, { session_id: sessionId, invite_code_hash: inviteCodeHash });
  }

  async getPairingSession(vaultId: string, sessionId: string): Promise<PairingSessionResponse> {
    return (await this.send("GET", `${vault(vaultId)}/pairing-sessions/${encode(sessionId)}`)).json as PairingSessionResponse;
  }

  async putPairingSessionGrant(vaultId: string, sessionId: string, requestHash: string, grant: PairingGrantPayload): Promise<void> {
    await this.send("POST", `${vault(vaultId)}/pairing-sessions/${encode(sessionId)}/grant`, { request_hash: requestHash, grant });
  }

  async registerDevice(vaultId: string, label: string, verifyingKey: string): Promise<{ device_id: string }> {
    return (await this.send("POST", `${vault(vaultId)}/devices`, { label, verifying_key: verifyingKey })).json as { device_id: string };
  }

  async vaultInfo(vaultId: string): Promise<VaultInfo | null> {
    const response = await this.send("GET", vault(vaultId));
    return response.status === 404 ? null : response.json as VaultInfo;
  }

  async upgradeVault(vaultId: string, base: number): Promise<VaultInfo> {
    return (await this.send("POST", `${vault(vaultId)}/upgrade`, { base })).json as VaultInfo;
  }

  async listOps(vaultId: string, after: number, limit: number): Promise<EncryptedOpRecord[]> {
    return (await this.send("GET", `${vault(vaultId)}/ops?after=${after}&limit=${limit}`)).json as EncryptedOpRecord[];
  }

  async appendOps(vaultId: string, ops: EncryptedOp[]): Promise<number[]> {
    return ((await this.send("POST", `${vault(vaultId)}/ops/batch`, { format: OP_FORMAT, ops })).json as { server_seqs: number[] }).server_seqs;
  }

  async missingBlobs(vaultId: string, blobIds: string[]): Promise<Set<string>> {
    return new Set(((await this.send("POST", `${vault(vaultId)}/blobs/missing`, { blob_ids: blobIds })).json as { missing: string[] }).missing);
  }

  async putBlob(vaultId: string, blobId: string, envelope: Uint8Array): Promise<void> {
    await this.send("PUT", `${vault(vaultId)}/blobs/${encode(blobId)}`, envelope);
  }

  async getBlob(vaultId: string, blobId: string): Promise<Uint8Array | null> {
    const response = await this.send("GET", `${vault(vaultId)}/blobs/${encode(blobId)}`);
    return response.status === 404 ? null : response.bytes;
  }

  async latestSnapshot(vaultId: string): Promise<SnapshotRecord | null> {
    const response = await this.send("GET", `${vault(vaultId)}/snapshots/latest`);
    return response.status === 404 ? null : response.json as SnapshotRecord;
  }

  async putSnapshot(vaultId: string, snapshot: Omit<SnapshotRecord, "vault_id" | "created_at_unix">): Promise<void> {
    await this.send("POST", `${vault(vaultId)}/snapshots`, snapshot);
  }

  private websocketPath(vaultId: string): string {
    return `/ws?vault_id=${encode(vaultId)}&device_id=${encode(this.requireAuth().deviceId)}`;
  }

  private requireAuth(): DeviceAuth {
    if (!this.auth) {
      throw new Error("device authentication is required");
    }
    return this.auth;
  }

  private async send(method: string, path: string, body?: object | Uint8Array, signed = true): Promise<Response> {
    const bytes = body instanceof Uint8Array ? body : body === undefined ? new Uint8Array() : encoder.encode(JSON.stringify(body));
    const headers: Record<string, string> = body !== undefined && !(body instanceof Uint8Array) ? { "content-type": "application/json" } : {};
    if (signed) {
      const auth = this.requireAuth();
      headers["x-mylonite-device-id"] = auth.deviceId;
      headers["x-mylonite-body-sha256"] = "1";
      headers["x-mylonite-signature"] = await signRequest(auth.privateKeyHex, method, path, bytes);
    }
    const response = await requestUrl({
      url: `${this.base}${path}`,
      method,
      headers,
      body: body === undefined ? undefined : bytes.slice().buffer,
      throw: false,
    });
    if (response.status !== 404 && (response.status < 200 || response.status >= 300)) {
      throw new ApiError(response.status, response.text);
    }
    return {
      status: response.status,
      get json(): unknown {
        return response.json as unknown;
      },
      get bytes(): Uint8Array {
        return new Uint8Array(response.arrayBuffer);
      },
    };
  }
}

function encode(value: string): string {
  return encodeURIComponent(value);
}

function vault(vaultId: string): string {
  return `/api/v1/vaults/${encode(vaultId)}`;
}

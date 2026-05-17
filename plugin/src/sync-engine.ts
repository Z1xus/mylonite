import { Notice, Plugin, TFile, normalizePath } from "obsidian";
import * as Y from "yjs";

import { EncryptedOpRecord, MyloniteApiClient, SnapshotRecord } from "./api";
import { VaultKeys } from "./crypto";
import { ClientMsgKind, ServerMsgKind, decodeFrame, encodeFrame } from "./protocol";
import { createEncryptedSnapshot, restoreEncryptedSnapshot } from "./snapshot-service";
import { decodeEncryptedOpPayload, decryptBlobEnvelope, encodeEncryptedOp, encryptBlob } from "./sync-codec";
import { PendingEncryptedOp, RemoteBlobRef, RemotePayload, RemoteYjsUpdate, SnapshotBinaryEntry } from "./sync-types";
import { applyBinaryUpsert, applyFileDelete, applyFileRename, applyMarkdownUpsert, normalizeVaultPath } from "./vault-adapter";
import { MyloniteSettings } from "./settings";
import {
  applyMarkdownUpdate,
  encodeMarkdownDeleteUpdate,
  encodeMarkdownRenameUpdate,
  encodeMarkdownUpsertUpdate,
  getMarkdownText,
} from "./yjs-markdown";

const OP_PAGE_SIZE = 512;

export interface SyncEngineHost extends Plugin {
  settings: MyloniteSettings;
  createApiClient(): MyloniteApiClient;
  debug(message: string): void;
  loadVaultKeys(): Promise<VaultKeys>;
  saveSettings(): Promise<void>;
  updateStatus(state: string): void;
}

export class SyncEngine {
  private readonly suppressedPaths = new Set<string>();
  private readonly locallyDirtyPaths = new Set<string>();
  private readonly pendingOpPaths = new Map<string, string[]>();
  private readonly modifyTimers = new Map<string, number>();
  private readonly ydoc = new Y.Doc();
  private readonly ytree = this.ydoc.getMap<Y.Map<unknown>>("tree");
  private socket: WebSocket | null = null;
  private started = false;

  constructor(private readonly host: SyncEngineHost) {}

  start(): void {
    if (!this.started) {
      this.registerVaultEvents();
      this.host.registerInterval(window.setInterval(() => {
        void this.catchUp().catch((error) => {
          this.host.updateStatus("catch-up error");
          this.host.debug(`poll failed: ${String(error)}`);
        });
      }, 15_000));
      this.host.debug(`initial visible files: ${this.host.app.vault.getFiles().length}`);
      this.started = true;
    }
    this.connectWebSocket();
    void this.catchUp().catch((error) => {
      this.host.updateStatus("catch-up error");
      this.host.debug(`catch-up failed: ${String(error)}`);
    });
  }

  close(): void {
    this.socket?.close();
    this.socket = null;
  }

  async catchUp(): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      return;
    }
    await this.flushPendingOps();
    let appliedCount = 0;
    for (;;) {
      const ops = await this.host.createApiClient().listOps(this.host.settings.vaultId, this.host.settings.lastServerSeq, OP_PAGE_SIZE);
      if (ops.length === 0) {
        break;
      }
      if (ops.length === OP_PAGE_SIZE && await this.restoreSnapshotForCatchUp()) {
        continue;
      }
      for (const op of ops) {
        await this.applyRemoteOp(op);
        this.host.settings.lastServerSeq = Math.max(this.host.settings.lastServerSeq, op.server_seq);
        this.host.settings.lamport = Math.max(this.host.settings.lamport, op.lamport);
        appliedCount += 1;
      }
    }
    if (appliedCount > 0) {
      await this.host.saveSettings();
      this.host.updateStatus(`caught up ${appliedCount} ops`);
    }
  }

  async createSnapshot(): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      new Notice("Pair Mylonite before creating a snapshot.");
      return;
    }
    const keys = await this.host.loadVaultKeys();
    const encrypted = await createEncryptedSnapshot(
      this.host.app.vault,
      keys,
      this.host.settings.vaultId,
      this.host.settings.lastServerSeq,
      async (blobId, envelope) => this.host.createApiClient().putBlob(this.host.settings.vaultId, blobId, envelope),
    );
    await this.host.createApiClient().putSnapshot(this.host.settings.vaultId, {
      snapshot_id: encrypted.snapshotId,
      device_id: this.host.settings.deviceId,
      covers_through_seq: this.host.settings.lastServerSeq,
      key_version: 1,
      nonce_hex: encrypted.nonceHex,
      ciphertext_hex: encrypted.ciphertextHex,
    });
    this.host.updateStatus("snapshot uploaded");
    new Notice("Mylonite snapshot uploaded.");
  }

  async restoreLatestSnapshot(): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      new Notice("Pair Mylonite before restoring a snapshot.");
      return;
    }
    const snapshots = await this.host.createApiClient().listSnapshots(this.host.settings.vaultId);
    const latest = snapshots.at(-1);
    if (!latest) {
      new Notice("No Mylonite snapshots are available.");
      return;
    }
    validateSnapshotRecord(latest, this.host.settings.vaultId);
    const deleteMissing = window.confirm(
      "Delete local files that are absent from the latest Mylonite snapshot? Choose Cancel to only overwrite/create files from the snapshot.",
    );
    await this.restoreSnapshot(latest, deleteMissing);
    this.host.settings.lastServerSeq = Math.max(this.host.settings.lastServerSeq, latest.covers_through_seq);
    await this.host.saveSettings();
    this.host.updateStatus("snapshot restored");
    new Notice("Mylonite snapshot restored.");
  }

  private registerVaultEvents(): void {
    this.host.registerEvent(this.host.app.vault.on("create", (file) => this.host.debug(`create ${normalizePath(file.path)}`)));
    this.host.registerEvent(this.host.app.vault.on("modify", (file) => {
      this.host.debug(`modify ${normalizePath(file.path)}`);
      if (file instanceof TFile) {
        if (file.extension === "md") {
          this.scheduleMarkdownUpdate(file);
        } else {
          void this.pushBinaryUpdate(file).catch((error) => {
            this.host.updateStatus("sync error");
            this.host.debug(`binary push failed: ${String(error)}`);
          });
        }
      }
    }));
    this.host.registerEvent(this.host.app.vault.on("delete", (file) => {
      this.host.debug(`delete ${normalizePath(file.path)}`);
      void this.pushFileDelete(file.path, file instanceof TFile && file.extension === "md").catch((error) => {
        this.host.updateStatus("sync error");
        this.host.debug(`delete push failed: ${String(error)}`);
      });
    }));
    this.host.registerEvent(this.host.app.vault.on("rename", (file, oldPath) => {
      this.host.debug(`rename ${normalizePath(oldPath)} -> ${normalizePath(file.path)}`);
      if (file instanceof TFile) {
        void this.pushFileRename(oldPath, file).catch((error) => {
          this.host.updateStatus("sync error");
          this.host.debug(`rename push failed: ${String(error)}`);
        });
      }
    }));
  }

  private async pushMarkdownUpdate(file: TFile): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId || file.extension !== "md") {
      return;
    }
    const normalizedPath = normalizeVaultPath(file.path);
    if (this.suppressedPaths.delete(normalizedPath)) {
      this.locallyDirtyPaths.delete(normalizedPath);
      this.host.debug(`suppressed remote echo ${normalizedPath}`);
      return;
    }
    this.locallyDirtyPaths.add(normalizedPath);
    const content = await this.host.app.vault.read(file);
    const updateHex = this.updateMarkdownYjs(normalizedPath, content);
    await this.pushEncryptedOp(5, [normalizedPath], {
      kind: "yjs-update",
      updateHex,
      changedPaths: [normalizedPath],
    });
    this.host.updateStatus("synced local change");
  }

  private async pushBinaryUpdate(file: TFile): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId || file.extension === "md") {
      return;
    }
    const normalizedPath = normalizeVaultPath(file.path);
    if (this.suppressedPaths.delete(normalizedPath)) {
      this.host.debug(`suppressed remote binary echo ${normalizedPath}`);
      return;
    }
    this.locallyDirtyPaths.add(normalizedPath);
    const keys = await this.host.loadVaultKeys();
    const plaintext = new Uint8Array(await this.host.app.vault.readBinary(file));
    const { blobId, envelope } = encryptBlob(keys, this.host.settings.vaultId, plaintext);
    await this.host.createApiClient().putBlob(this.host.settings.vaultId, blobId, envelope);
    await this.pushEncryptedOp(4, [normalizedPath], {
      kind: "blob-ref",
      path: normalizedPath,
      blobId,
      size: plaintext.byteLength,
    });
    this.host.updateStatus("synced binary change");
  }

  private async pushFileDelete(path: string, isMarkdown: boolean): Promise<void> {
    const normalizedPath = normalizeVaultPath(path);
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      return;
    }
    const pendingModify = this.modifyTimers.get(normalizedPath);
    if (pendingModify !== undefined) {
      window.clearTimeout(pendingModify);
      this.modifyTimers.delete(normalizedPath);
    }
    if (this.suppressedPaths.delete(normalizedPath)) {
      this.host.debug(`suppressed remote delete echo ${normalizedPath}`);
      return;
    }
    this.locallyDirtyPaths.add(normalizedPath);
    if (isMarkdown) {
      const updateHex = this.deleteMarkdownYjs(normalizedPath);
      await this.pushEncryptedOp(5, [normalizedPath], {
        kind: "yjs-update",
        updateHex,
        changedPaths: [normalizedPath],
      });
      this.host.updateStatus("synced local delete");
      return;
    }
    await this.pushEncryptedOp(2, [normalizedPath], { kind: "file-delete", path: normalizedPath });
    this.host.updateStatus("synced local delete");
  }

  private async pushFileRename(oldPath: string, file: TFile): Promise<void> {
    const normalizedOldPath = normalizeVaultPath(oldPath);
    const normalizedNewPath = normalizeVaultPath(file.path);
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      return;
    }
    for (const path of [normalizedOldPath, normalizedNewPath]) {
      const pendingModify = this.modifyTimers.get(path);
      if (pendingModify !== undefined) {
        window.clearTimeout(pendingModify);
        this.modifyTimers.delete(path);
      }
    }
    if (this.suppressedPaths.delete(normalizedNewPath) || this.suppressedPaths.delete(normalizedOldPath)) {
      this.host.debug(`suppressed remote rename echo ${normalizedOldPath} -> ${normalizedNewPath}`);
      return;
    }
    this.locallyDirtyPaths.add(normalizedOldPath);
    this.locallyDirtyPaths.add(normalizedNewPath);
    if (file.extension === "md") {
      const content = await this.host.app.vault.read(file);
      const updateHex = this.renameMarkdownYjs(normalizedOldPath, normalizedNewPath, content);
      await this.pushEncryptedOp(5, [normalizedOldPath, normalizedNewPath], {
        kind: "yjs-update",
        updateHex,
        changedPaths: [normalizedOldPath, normalizedNewPath],
      });
      this.host.updateStatus("synced local rename");
      return;
    }
    await this.pushEncryptedOp(3, [normalizedOldPath, normalizedNewPath], {
      kind: "file-rename",
      oldPath: normalizedOldPath,
      newPath: normalizedNewPath,
    });
    this.host.updateStatus("synced local rename");
  }

  private async pushEncryptedOp(kind: number, changedPaths: string[], payloadObject: object): Promise<void> {
    const keys = await this.host.loadVaultKeys();
    const lamport = this.host.settings.lamport + 1;
    const op = encodeEncryptedOp(keys, this.host.settings.vaultId, this.host.settings.deviceId, lamport, kind, payloadObject);
    const normalizedChangedPaths = changedPaths.map((path) => normalizeVaultPath(path));
    this.pendingOpPaths.set(op.client_op_id, normalizedChangedPaths);
    try {
      await this.host.createApiClient().appendOp(this.host.settings.vaultId, op);
      this.clearDirtyPathsForOp(op.client_op_id);
    } catch (error) {
      this.host.settings.pendingOps.push(op);
      this.host.debug(`queued op ${op.client_op_id}: ${String(error)}`);
      this.host.updateStatus("queued offline change");
    }
    this.host.settings.lamport = lamport;
    await this.host.saveSettings();
  }

  private async flushPendingOps(): Promise<void> {
    if (this.host.settings.pendingOps.length === 0 || !this.host.settings.vaultId) {
      return;
    }
    const client = this.host.createApiClient();
    const remaining: PendingEncryptedOp[] = [];
    for (const [index, op] of this.host.settings.pendingOps.entries()) {
      try {
        await client.appendOp(this.host.settings.vaultId, op);
        this.clearDirtyPathsForOp(op.client_op_id);
      } catch (error) {
        remaining.push(...retainUnflushedPendingOps(this.host.settings.pendingOps, index));
        this.host.debug(`pending op flush stopped: ${String(error)}`);
        break;
      }
    }
    if (remaining.length !== this.host.settings.pendingOps.length) {
      this.host.settings.pendingOps = remaining;
      await this.host.saveSettings();
    }
  }

  private connectWebSocket(): void {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId || this.socket) {
      return;
    }
    try {
      const socket = new WebSocket(this.host.createApiClient().websocketUrl(this.host.settings.vaultId));
      socket.binaryType = "arraybuffer";
      socket.onopen = () => this.host.updateStatus("authenticating live sync");
      socket.onmessage = (event: MessageEvent<ArrayBuffer>) => {
        void this.handleSocketMessage(event.data).catch((error) => {
          this.host.updateStatus("live sync error");
          this.host.debug(`websocket apply failed: ${String(error)}`);
        });
      };
      socket.onclose = () => {
        this.socket = null;
        this.host.updateStatus("offline polling");
      };
      socket.onerror = () => this.host.updateStatus("live sync error");
      this.socket = socket;
    } catch (error) {
      this.host.debug(`websocket connect failed: ${String(error)}`);
    }
  }

  private async handleSocketMessage(data: ArrayBuffer): Promise<void> {
    const frame = decodeFrame(new Uint8Array(data));
    if (frame.kind === ServerMsgKind.HelloChallenge) {
      this.sendWebSocketHello(frame.payload);
      return;
    }
    if (frame.kind === ServerMsgKind.HelloAck) {
      this.host.updateStatus("live");
      return;
    }
    if (frame.kind !== ServerMsgKind.OpBroadcast) {
      return;
    }
    const op = JSON.parse(new TextDecoder().decode(frame.payload)) as unknown;
    validateRemoteOpRecord(op);
    if (op.server_seq <= this.host.settings.lastServerSeq) {
      return;
    }
    await this.applyRemoteOp(op);
    this.host.settings.lastServerSeq = Math.max(this.host.settings.lastServerSeq, op.server_seq);
    this.host.settings.lamport = Math.max(this.host.settings.lamport, op.lamport);
    await this.host.saveSettings();
  }

  private sendWebSocketHello(payload: Uint8Array): void {
    if (!this.socket || !this.host.settings.vaultId) {
      return;
    }
    const challengeHex = parseWebSocketChallenge(payload);
    const hello = this.host.createApiClient().websocketHello(this.host.settings.vaultId, challengeHex);
    const helloPayload = new TextEncoder().encode(JSON.stringify(hello));
    const frame = encodeFrame({ kind: ClientMsgKind.Hello, flags: 0, payload: helloPayload });
    const bytes = new Uint8Array(frame.byteLength);
    bytes.set(frame);
    this.socket.send(bytes.buffer);
  }

  private scheduleMarkdownUpdate(file: TFile): void {
    const path = normalizeVaultPath(file.path);
    this.locallyDirtyPaths.add(path);
    const existing = this.modifyTimers.get(path);
    if (existing !== undefined) {
      window.clearTimeout(existing);
    }
    const timer = window.setTimeout(() => {
      this.modifyTimers.delete(path);
      void this.pushMarkdownUpdate(file).catch((error) => {
        this.host.updateStatus("sync error");
        this.host.debug(`push failed: ${String(error)}`);
      });
    }, 750);
    this.modifyTimers.set(path, timer);
  }

  private async applyRemoteOp(op: EncryptedOpRecord): Promise<void> {
    validateRemoteOpRecord(op);
    if (op.device_id === this.host.settings.deviceId) {
      return;
    }
    const keys = await this.host.loadVaultKeys();
    const payload = decodeEncryptedOpPayload(keys, this.host.settings.vaultId, op) as RemotePayload;
    validateRemotePayload(payload);
    this.reportRemoteRace(remotePayloadPaths(payload));
    if (payload.kind === "markdown-upsert") {
      await applyMarkdownUpsert(this.host.app.vault, this.suppressedPaths, payload.path, payload.content);
    } else if (payload.kind === "yjs-update") {
      await this.applyYjsUpdate(payload);
    } else if (payload.kind === "blob-ref") {
      await this.applyBlobRef(payload);
    } else if (payload.kind === "file-delete") {
      await applyFileDelete(this.host.app.vault, this.suppressedPaths, payload.path);
    } else if (payload.kind === "file-rename") {
      await applyFileRename(this.host.app.vault, this.suppressedPaths, payload.oldPath, payload.newPath);
    }
  }

  private reportRemoteRace(remotePaths: string[]): void {
    const races = racedPaths(remotePaths, this.locallyDirtyPaths);
    if (races.length === 0) {
      return;
    }
    const summary = races.slice(0, 3).join(", ");
    this.host.updateStatus(`remote change raced local edit: ${summary}`);
    this.host.debug(`remote op raced local dirty paths: ${races.join(", ")}`);
    new Notice(`Mylonite applied a remote change that raced a local edit: ${summary}`);
  }

  private clearDirtyPathsForOp(clientOpId: string): void {
    const paths = this.pendingOpPaths.get(clientOpId) ?? [];
    for (const path of paths) {
      this.locallyDirtyPaths.delete(path);
    }
    this.pendingOpPaths.delete(clientOpId);
  }

  private updateMarkdownYjs(path: string, content: string): string {
    return encodeMarkdownUpsertUpdate(this.ydoc, this.ytree, path, content);
  }

  private deleteMarkdownYjs(path: string): string {
    return encodeMarkdownDeleteUpdate(this.ydoc, this.ytree, path);
  }

  private renameMarkdownYjs(oldPath: string, newPath: string, content: string): string {
    return encodeMarkdownRenameUpdate(this.ydoc, this.ytree, oldPath, newPath, content);
  }

  private async applyYjsUpdate(payload: RemoteYjsUpdate): Promise<void> {
    applyMarkdownUpdate(this.ydoc, payload.updateHex);
    for (const path of payload.changedPaths) {
      const normalizedPath = normalizeVaultPath(path);
      const text = getMarkdownText(this.ytree, normalizedPath);
      if (text) {
        await applyMarkdownUpsert(this.host.app.vault, this.suppressedPaths, normalizedPath, text.toString());
      } else {
        await applyFileDelete(this.host.app.vault, this.suppressedPaths, normalizedPath);
      }
    }
  }

  private async applyBlobRef(payload: RemoteBlobRef): Promise<void> {
    const keys = await this.host.loadVaultKeys();
    const blobBytes = await this.host.createApiClient().getBlob(this.host.settings.vaultId, payload.blobId);
    if (!blobBytes) {
      throw new Error(`missing blob ${payload.blobId}`);
    }
    const plaintext = decryptBlobEnvelope(keys, this.host.settings.vaultId, payload.blobId, blobBytes);
    await applyBinaryUpsert(this.host.app.vault, this.suppressedPaths, payload.path, plaintext);
  }

  private async restoreSnapshot(snapshot: SnapshotRecord, deleteMissing: boolean): Promise<void> {
    const keys = await this.host.loadVaultKeys();
    await restoreEncryptedSnapshot(
      this.host.app.vault,
      this.suppressedPaths,
      keys,
      this.host.settings.vaultId,
      snapshot,
      (entry) => this.loadSnapshotBinary(entry),
      deleteMissing,
    );
  }

  private async restoreSnapshotForCatchUp(): Promise<boolean> {
    const snapshots = await this.host.createApiClient().listSnapshots(this.host.settings.vaultId);
    const latest = snapshots.at(-1);
    if (!latest) {
      return false;
    }
    validateSnapshotRecord(latest, this.host.settings.vaultId);
    if (latest.covers_through_seq <= this.host.settings.lastServerSeq) {
      return false;
    }
    await this.restoreSnapshot(latest, false);
    this.host.settings.lastServerSeq = latest.covers_through_seq;
    await this.host.saveSettings();
    this.host.updateStatus(`restored snapshot through seq ${latest.covers_through_seq}`);
    return true;
  }

  private async loadSnapshotBinary(entry: SnapshotBinaryEntry): Promise<Uint8Array> {
    const keys = await this.host.loadVaultKeys();
    const blobBytes = await this.host.createApiClient().getBlob(this.host.settings.vaultId, entry.blobId);
    if (!blobBytes) {
      throw new Error(`missing blob ${entry.blobId}`);
    }
    return decryptBlobEnvelope(keys, this.host.settings.vaultId, entry.blobId, blobBytes);
  }
}

export function retainUnflushedPendingOps(pendingOps: PendingEncryptedOp[], firstFailedIndex: number): PendingEncryptedOp[] {
  return pendingOps.slice(firstFailedIndex);
}

export function racedPaths(remotePaths: string[], localPaths: ReadonlySet<string>): string[] {
  return remotePaths.map((path) => normalizeVaultPath(path)).filter((path) => localPaths.has(path));
}

export function validateRemotePayload(payload: unknown): asserts payload is RemotePayload {
  if (!isRecord(payload) || typeof payload.kind !== "string") {
    throw new Error("invalid remote payload");
  }
  if (payload.kind === "markdown-upsert") {
    normalizeVaultPath(payload.path);
    if (typeof payload.content !== "string") {
      throw new Error("invalid markdown payload content");
    }
    return;
  }
  if (payload.kind === "yjs-update") {
    if (typeof payload.updateHex !== "string" || payload.updateHex.length === 0 || payload.updateHex.length % 2 !== 0 || /[^0-9a-f]/.test(payload.updateHex)) {
      throw new Error("invalid yjs update payload");
    }
    if (!Array.isArray(payload.changedPaths) || payload.changedPaths.length === 0 || payload.changedPaths.length > 1024) {
      throw new Error("invalid yjs changed paths");
    }
    for (const path of payload.changedPaths) {
      normalizeVaultPath(path);
    }
    return;
  }
  if (payload.kind === "blob-ref") {
    normalizeVaultPath(payload.path);
    if (typeof payload.blobId !== "string" || !/^[0-9a-f]{64}$/.test(payload.blobId)) {
      throw new Error("invalid blob-ref payload blob id");
    }
    if (typeof payload.size !== "number" || !Number.isSafeInteger(payload.size) || payload.size < 0) {
      throw new Error("invalid blob-ref payload size");
    }
    return;
  }
  if (payload.kind === "file-delete") {
    normalizeVaultPath(payload.path);
    return;
  }
  if (payload.kind === "file-rename") {
    normalizeVaultPath(payload.oldPath);
    normalizeVaultPath(payload.newPath);
    return;
  }
  throw new Error("unsupported remote payload kind");
}

export function parseWebSocketChallenge(payload: Uint8Array): string {
  const challenge = JSON.parse(new TextDecoder().decode(payload)) as unknown;
  if (!isRecord(challenge) || typeof challenge.challenge_hex !== "string" || !/^[0-9a-f]{32}$/.test(challenge.challenge_hex)) {
    throw new Error("invalid websocket challenge");
  }
  return challenge.challenge_hex;
}

export function validateRemoteOpRecord(op: unknown): asserts op is EncryptedOpRecord {
  if (!isRecord(op)) {
    throw new Error("invalid encrypted op record");
  }
  validateOpaqueId("op vault id", op.vault_id);
  validateHexField("op client id", op.client_op_id, 64);
  validateDeviceId(op.device_id);
  validateSequence("op server seq", op.server_seq, 1);
  validateSequence("op lamport", op.lamport, 0);
  if (typeof op.kind !== "number" || !Number.isSafeInteger(op.kind) || op.kind < 1 || op.kind > 7) {
    throw new Error("invalid op kind");
  }
  if (op.key_version !== 1) {
    throw new Error("unsupported op key version");
  }
  validateHexField("op nonce", op.nonce_hex, 48);
  validateHexPayload("op ciphertext", op.ciphertext_hex);
  validateSequence("op accepted time", op.accepted_at_unix, 0);
}

export function validateSnapshotRecord(snapshot: unknown, expectedVaultId?: string): asserts snapshot is SnapshotRecord {
  if (!isRecord(snapshot)) {
    throw new Error("invalid snapshot record");
  }
  validateOpaqueId("snapshot vault id", snapshot.vault_id);
  if (expectedVaultId !== undefined && snapshot.vault_id !== expectedVaultId) {
    throw new Error("snapshot vault id mismatch");
  }
  validateHexField("snapshot id", snapshot.snapshot_id, 32);
  validateDeviceId(snapshot.device_id);
  validateSequence("snapshot covers seq", snapshot.covers_through_seq, 0);
  if (snapshot.key_version !== 1) {
    throw new Error("unsupported snapshot key version");
  }
  validateHexField("snapshot nonce", snapshot.nonce_hex, 48);
  validateHexPayload("snapshot ciphertext", snapshot.ciphertext_hex);
  validateSequence("snapshot created time", snapshot.created_at_unix, 0);
}

function remotePayloadPaths(payload: RemotePayload): string[] {
  if (payload.kind === "file-rename") {
    return [payload.oldPath, payload.newPath];
  }
  if (payload.kind === "yjs-update") {
    return payload.changedPaths;
  }
  return [payload.path];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function validateOpaqueId(name: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
}

function validateSequence(name: string, value: unknown, minimum: number): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`invalid ${name}`);
  }
}

function validateDeviceId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^d[0-9a-f]{32}$/.test(value)) {
    throw new Error("invalid op device id");
  }
}

function validateHexField(name: string, value: unknown, length: number): asserts value is string {
  if (typeof value !== "string" || value.length !== length || /[^0-9a-f]/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
}

function validateHexPayload(name: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || /[^0-9a-f]/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
}

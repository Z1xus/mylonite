import { Notice, Plugin, TFile, normalizePath } from "obsidian";
import * as Y from "yjs";

import { EncryptedOpRecord, MyloniteApiClient, SnapshotRecord } from "./api";
import { VaultKeys } from "./crypto";
import { ClientMsgKind, OpKind, ServerMsgKind, decodeFrame, encodeFrame } from "./protocol";
import { createEncryptedSnapshot, restoreEncryptedSnapshot } from "./snapshot-service";
import { decodeEncryptedOpPayload, decryptBlobEnvelope, encodeEncryptedOp, encryptBlob } from "./sync-codec";
import { PendingEncryptedOp, RemotePayload, RemoteV2Payload, SnapshotBinaryEntry } from "./sync-types";
import {
  applyBinaryUpsertWithCollision,
  applyFileDelete,
  applyFileRenameWithCollision,
  applyMarkdownUpsertWithCollision,
  normalizeVaultPath,
} from "./vault-adapter";
import { MyloniteSettings } from "./settings";
import { decideRemoteV2Apply } from "./conflict-policy";
import { LocalEventClassifier } from "./local-event-classifier";
import { VaultStateIndex } from "./state-index";
import { FileKind, SyncJournalEntry } from "./sync-state";
import {
  applyMarkdownUpdate,
  encodeMarkdownDeleteUpdate,
  encodeMarkdownRenameUpdate,
  encodeMarkdownUpsertUpdate,
  getMarkdownText,
} from "./yjs-markdown";

const OP_PAGE_SIZE = 512;
export const MARKDOWN_DEBOUNCE_MS = 75;
export const OFFLINE_POLL_INTERVAL_MS = 15_000;
export const LIVE_POLL_INTERVAL_MS = 60_000;
export const WEBSOCKET_RECONNECT_DELAYS_MS = [1_000, 2_000, 5_000, 15_000] as const;

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
  private readonly locallyDirtyFileIds = new Set<string>();
  private readonly pendingOpPaths = new Map<string, string[]>();
  private readonly pendingOpFileIds = new Map<string, string[]>();
  private stateIndex: VaultStateIndex;
  private classifier: LocalEventClassifier;
  private readonly modifyTimers = new Map<string, { file: TFile; timer: number }>();
  private readonly ydoc = new Y.Doc();
  private readonly ytree = this.ydoc.getMap<Y.Map<unknown>>("tree");
  private socket: WebSocket | null = null;
  private reconnectTimer: number | null = null;
  private reconnectAttempt = 0;
  private socketLive = false;
  private manuallyClosed = false;
  private lastPeriodicCatchUpAt = 0;
  private started = false;

  constructor(private readonly host: SyncEngineHost) {
    if (!this.host.settings.durableSyncState) {
      this.host.settings.durableSyncState = {
        version: 1,
        index: { version: 1, files: [], tombstones: [] },
        journal: [],
      };
    }
    this.stateIndex = VaultStateIndex.fromSnapshot(this.host.settings.durableSyncState?.index);
    this.classifier = new LocalEventClassifier(this.stateIndex);
  }

  start(): void {
    this.manuallyClosed = false;
    if (!this.started) {
      this.registerVaultEvents();
      this.host.registerInterval(window.setInterval(() => {
        if (!this.shouldRunPeriodicCatchUp(Date.now())) {
          return;
        }
        void this.catchUp().catch((error) => {
          this.host.updateStatus("catch-up error");
          this.host.debug(`poll failed: ${String(error)}`);
        });
      }, OFFLINE_POLL_INTERVAL_MS));
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
    this.manuallyClosed = true;
    this.flushScheduledMarkdownUpdates();
    this.clearReconnectTimer();
    this.socketLive = false;
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
      this.host.updateStatus(`synced ${appliedCount} changes`);
    }
  }

  async createSnapshot(): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      new Notice("Device is not paired. Pair it before creating a snapshot.");
      return;
    }
    const keys = await this.host.loadVaultKeys();
    const encrypted = await createEncryptedSnapshot(
      this.host.app.vault,
      keys,
      this.host.settings.vaultId,
      this.host.settings.lastServerSeq,
      async (blobId, envelope) => this.host.createApiClient().putBlob(this.host.settings.vaultId, blobId, envelope),
      this.stateIndex.toSnapshot(),
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
    new Notice("Snapshot uploaded.");
  }

  async restoreLatestSnapshot(): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      new Notice("Device is not paired. Pair it before restoring a snapshot.");
      return;
    }
    const snapshots = await this.host.createApiClient().listSnapshots(this.host.settings.vaultId);
    const latest = snapshots.at(-1);
    if (!latest) {
      new Notice("No snapshots found. Create a snapshot on another device first.");
      return;
    }
    validateSnapshotRecord(latest, this.host.settings.vaultId);
    const deleteMissing = window.confirm(
      "Delete files missing from the snapshot? This removes local files that are not in the latest snapshot.",
    );
    await this.restoreSnapshot(latest, deleteMissing);
    this.host.settings.lastServerSeq = Math.max(this.host.settings.lastServerSeq, latest.covers_through_seq);
    await this.host.saveSettings();
    this.host.updateStatus("snapshot restored");
    new Notice("Snapshot restored.");
  }

  private registerVaultEvents(): void {
    this.host.registerEvent(this.host.app.vault.on("create", (file) => {
      this.host.debug(`create ${normalizePath(file.path)}`);
      if (file instanceof TFile) {
        void this.pushFileCreate(file).catch((error) => {
          this.host.updateStatus("sync error");
          this.host.debug(`create push failed: ${String(error)}`);
        });
      }
    }));
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
    const transition = this.classifier.classifyModify({ path: normalizedPath, kind: "markdown", content });
    this.queueTransition(transition);
    const updateHex = this.updateMarkdownYjs(normalizedPath, content);
    await this.pushEncryptedOp(OpKind.FileUpdate, [normalizedPath], {
      version: 2,
      kind: "file-update",
      fileId: transition.fileId,
      path: normalizedPath,
      fileKind: "markdown",
      contentUpdate: updateHex,
      changedPaths: [normalizedPath],
      baseHash: transition.baseHash,
      contentHash: transition.contentHash,
    }, [transition.fileId], transition.transitionId);
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
    const transition = this.classifier.classifyModify({ path: normalizedPath, kind: "binary", content: plaintext });
    this.queueTransition(transition);
    const { blobId, envelope } = encryptBlob(keys, this.host.settings.vaultId, plaintext);
    await this.host.createApiClient().putBlob(this.host.settings.vaultId, blobId, envelope);
    await this.pushEncryptedOp(OpKind.FileUpdate, [normalizedPath], {
      version: 2,
      kind: "file-update",
      fileId: transition.fileId,
      path: normalizedPath,
      fileKind: "binary",
      blobId,
      size: plaintext.byteLength,
      baseHash: transition.baseHash,
      contentHash: transition.contentHash,
    }, [transition.fileId], transition.transitionId);
    this.host.updateStatus("synced binary change");
  }

  private async pushFileDelete(path: string, isMarkdown: boolean): Promise<void> {
    const normalizedPath = normalizeVaultPath(path);
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      return;
    }
    this.clearScheduledMarkdownUpdate(normalizedPath);
    if (this.suppressedPaths.delete(normalizedPath)) {
      this.host.debug(`suppressed remote delete echo ${normalizedPath}`);
      return;
    }
    this.locallyDirtyPaths.add(normalizedPath);
    const transition = this.classifier.classifyDelete(normalizedPath, isMarkdown ? "markdown" : "binary");
    this.queueTransition(transition);
    if (isMarkdown) {
      const updateHex = this.deleteMarkdownYjs(normalizedPath);
      await this.pushEncryptedOp(OpKind.FileDelete, [normalizedPath], {
        version: 2,
        kind: "file-delete",
        fileId: transition.fileId,
        path: normalizedPath,
        tombstoneId: transition.tombstoneId,
        updateHex,
        changedPaths: [normalizedPath],
      }, [transition.fileId], transition.transitionId);
      this.host.updateStatus("synced local delete");
      return;
    }
    await this.pushEncryptedOp(OpKind.FileDelete, [normalizedPath], {
      version: 2,
      kind: "file-delete",
      fileId: transition.fileId,
      path: normalizedPath,
      tombstoneId: transition.tombstoneId,
    }, [transition.fileId], transition.transitionId);
    this.host.updateStatus("synced local delete");
  }

  private async pushFileRename(oldPath: string, file: TFile): Promise<void> {
    const normalizedOldPath = normalizeVaultPath(oldPath);
    const normalizedNewPath = normalizeVaultPath(file.path);
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      return;
    }
    for (const path of [normalizedOldPath, normalizedNewPath]) {
      this.clearScheduledMarkdownUpdate(path);
    }
    if (this.suppressedPaths.delete(normalizedNewPath) || this.suppressedPaths.delete(normalizedOldPath)) {
      this.host.debug(`suppressed remote rename echo ${normalizedOldPath} -> ${normalizedNewPath}`);
      return;
    }
    this.locallyDirtyPaths.add(normalizedOldPath);
    this.locallyDirtyPaths.add(normalizedNewPath);
    if (file.extension === "md") {
      const content = await this.host.app.vault.read(file);
      const transition = this.classifier.classifyRename(normalizedOldPath, { path: normalizedNewPath, kind: "markdown", content });
      this.queueTransition(transition);
      const updateHex = this.renameMarkdownYjs(normalizedOldPath, normalizedNewPath, content);
      await this.pushEncryptedOp(OpKind.FileRename, [normalizedOldPath, normalizedNewPath], {
        version: 2,
        kind: "file-rename",
        fileId: transition.fileId,
        oldPath: normalizedOldPath,
        newPath: normalizedNewPath,
        path: normalizedNewPath,
        updateHex,
        changedPaths: [normalizedOldPath, normalizedNewPath],
      }, [transition.fileId], transition.transitionId);
      this.host.updateStatus("synced local rename");
      return;
    }
    const bytes = new Uint8Array(await this.host.app.vault.readBinary(file));
    const transition = this.classifier.classifyRename(normalizedOldPath, { path: normalizedNewPath, kind: "binary", content: bytes });
    this.queueTransition(transition);
    await this.pushEncryptedOp(OpKind.FileRename, [normalizedOldPath, normalizedNewPath], {
      version: 2,
      kind: "file-rename",
      fileId: transition.fileId,
      oldPath: normalizedOldPath,
      newPath: normalizedNewPath,
      path: normalizedNewPath,
    }, [transition.fileId], transition.transitionId);
    this.host.updateStatus("synced local rename");
  }

  private async pushEncryptedOp(kind: number, changedPaths: string[], payloadObject: object, changedFileIds: string[] = [], transitionId?: string): Promise<void> {
    const keys = await this.host.loadVaultKeys();
    const lamport = this.host.settings.lamport + 1;
    const op = encodeEncryptedOp(keys, this.host.settings.vaultId, this.host.settings.deviceId, lamport, kind, payloadObject);
    const normalizedChangedPaths = changedPaths.map((path) => normalizeVaultPath(path));
    this.pendingOpPaths.set(op.client_op_id, normalizedChangedPaths);
    this.pendingOpFileIds.set(op.client_op_id, changedFileIds);
    this.attachOpToTransition(transitionId, op.client_op_id);
    try {
      if (this.canPushOpOverWebSocket()) {
        this.queuePendingOp(op);
        this.sendWebSocketOpPush(op);
      } else {
        await this.host.createApiClient().appendOp(this.host.settings.vaultId, op);
        this.clearDirtyPathsForOp(op.client_op_id);
        this.acknowledgeTransition(transitionId);
      }
    } catch (error) {
      this.host.settings.pendingOps.push(op);
      this.host.debug(`queued op ${op.client_op_id}: ${String(error)}`);
      this.host.updateStatus("queued offline");
    }
    this.host.settings.lamport = lamport;
    this.persistSyncState();
    await this.host.saveSettings();
  }

  private async pushFileCreate(file: TFile): Promise<void> {
    if (!this.host.settings.vaultId || !this.host.settings.deviceId) {
      return;
    }
    const normalizedPath = normalizeVaultPath(file.path);
    if (this.suppressedPaths.delete(normalizedPath)) {
      this.host.debug(`suppressed remote create echo ${normalizedPath}`);
      return;
    }
    if (file.extension === "md") {
      const content = await this.host.app.vault.read(file);
      const transition = this.classifier.classifyCreate({ path: normalizedPath, kind: "markdown", content });
      this.queueTransition(transition);
      const updateHex = this.updateMarkdownYjs(normalizedPath, content);
      await this.pushEncryptedOp(transition.kind === "file-copy" ? OpKind.FileCopy : OpKind.FileCreate, [normalizedPath], {
        version: 2,
        kind: transition.kind,
        fileId: transition.fileId,
        sourceFileId: transition.sourceFileId,
        newFileId: transition.fileId,
        path: normalizedPath,
        fileKind: "markdown",
        content,
        updateHex,
        contentHash: transition.contentHash,
      }, [transition.fileId], transition.transitionId);
      return;
    }
    const keys = await this.host.loadVaultKeys();
    const plaintext = new Uint8Array(await this.host.app.vault.readBinary(file));
    const transition = this.classifier.classifyCreate({ path: normalizedPath, kind: "binary", content: plaintext });
    this.queueTransition(transition);
    const { blobId, envelope } = encryptBlob(keys, this.host.settings.vaultId, plaintext);
    await this.host.createApiClient().putBlob(this.host.settings.vaultId, blobId, envelope);
    await this.pushEncryptedOp(transition.kind === "file-copy" ? OpKind.FileCopy : OpKind.FileCreate, [normalizedPath], {
      version: 2,
      kind: transition.kind,
      fileId: transition.fileId,
      sourceFileId: transition.sourceFileId,
      newFileId: transition.fileId,
      path: normalizedPath,
      fileKind: "binary",
      blobId,
      size: plaintext.byteLength,
      contentHash: transition.contentHash,
    }, [transition.fileId], transition.transitionId);
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
        this.acknowledgeTransitionByClientOp(op.client_op_id);
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
    if (this.manuallyClosed || !this.host.settings.vaultId || !this.host.settings.deviceId || this.socket) {
      return;
    }
    this.clearReconnectTimer();
    try {
      const socket = new WebSocket(this.host.createApiClient().websocketUrl(this.host.settings.vaultId));
      socket.binaryType = "arraybuffer";
      socket.onopen = () => this.host.updateStatus("authenticating");
      socket.onmessage = (event: MessageEvent<ArrayBuffer>) => {
        void this.handleSocketMessage(event.data).catch((error) => {
          this.host.updateStatus("live sync error");
          this.host.debug(`websocket apply failed: ${String(error)}`);
        });
      };
      socket.onclose = () => {
        this.socketLive = false;
        this.socket = null;
        this.host.updateStatus("offline");
        this.scheduleWebSocketReconnect();
      };
      socket.onerror = () => {
        this.socketLive = false;
        this.host.updateStatus("live sync error");
        socket.close();
      };
      this.socket = socket;
    } catch (error) {
      this.host.debug(`websocket connect failed: ${String(error)}`);
      this.scheduleWebSocketReconnect();
    }
  }

  private async handleSocketMessage(data: ArrayBuffer): Promise<void> {
    const frame = decodeFrame(new Uint8Array(data));
    if (frame.kind === ServerMsgKind.HelloChallenge) {
      this.sendWebSocketHello(frame.payload);
      return;
    }
    if (frame.kind === ServerMsgKind.HelloAck) {
      this.reconnectAttempt = 0;
      this.socketLive = true;
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
    if (op.server_seq > this.host.settings.lastServerSeq + 1) {
      await this.catchUp();
      return;
    }
    await this.applyRemoteOp(op);
    this.host.settings.lastServerSeq = Math.max(this.host.settings.lastServerSeq, op.server_seq);
    this.host.settings.lamport = Math.max(this.host.settings.lamport, op.lamport);
    this.clearDirtyPathsForOp(op.client_op_id);
    this.removePendingOp(op.client_op_id);
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

  private canPushOpOverWebSocket(): boolean {
    return this.socketLive && this.socket?.readyState === WebSocket.OPEN;
  }

  private sendWebSocketOpPush(op: PendingEncryptedOp): void {
    if (!this.socket) {
      throw new Error("websocket is not connected");
    }
    const payload = new TextEncoder().encode(JSON.stringify(op));
    const frame = encodeFrame({ kind: ClientMsgKind.OpPush, flags: 0, payload });
    const bytes = new Uint8Array(frame.byteLength);
    bytes.set(frame);
    this.socket.send(bytes.buffer);
  }

  private scheduleMarkdownUpdate(file: TFile): void {
    const path = normalizeVaultPath(file.path);
    this.locallyDirtyPaths.add(path);
    const existing = this.modifyTimers.get(path);
    if (existing !== undefined) {
      window.clearTimeout(existing.timer);
    }
    const timer = window.setTimeout(() => {
      this.modifyTimers.delete(path);
      void this.pushMarkdownUpdate(file).catch((error) => {
        this.host.updateStatus("sync error");
        this.host.debug(`push failed: ${String(error)}`);
      });
    }, MARKDOWN_DEBOUNCE_MS);
    this.modifyTimers.set(path, { file, timer });
  }

  private clearScheduledMarkdownUpdate(path: string): void {
    const pendingModify = this.modifyTimers.get(path);
    if (pendingModify === undefined) {
      return;
    }
    window.clearTimeout(pendingModify.timer);
    this.modifyTimers.delete(path);
  }

  private flushScheduledMarkdownUpdates(): void {
    const pending = Array.from(this.modifyTimers.entries());
    this.modifyTimers.clear();
    for (const [, { file, timer }] of pending) {
      window.clearTimeout(timer);
      void this.pushMarkdownUpdate(file).catch((error) => {
        this.host.updateStatus("sync error");
        this.host.debug(`flush before close failed: ${String(error)}`);
      });
    }
  }

  private shouldRunPeriodicCatchUp(now: number): boolean {
    const interval = this.socketLive ? LIVE_POLL_INTERVAL_MS : OFFLINE_POLL_INTERVAL_MS;
    if (now - this.lastPeriodicCatchUpAt < interval) {
      return false;
    }
    this.lastPeriodicCatchUpAt = now;
    return true;
  }

  private scheduleWebSocketReconnect(): void {
    if (this.manuallyClosed || !this.started || !this.host.settings.vaultId || !this.host.settings.deviceId || this.reconnectTimer !== null) {
      return;
    }
    const delay = webSocketReconnectDelay(this.reconnectAttempt);
    this.reconnectAttempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connectWebSocket();
    }, delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer === null) {
      return;
    }
    window.clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
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
    await this.applyRemoteV2Payload(payload, op.server_seq);
    this.persistSyncState();
  }

  private reportRemoteRace(remotePaths: string[]): void {
    const races = racedPaths(remotePaths, this.locallyDirtyPaths);
    if (races.length === 0) {
      return;
    }
    const summary = races.slice(0, 3).join(", ");
    this.host.updateStatus(`edit conflict: ${summary}`);
    this.host.debug(`remote op raced local dirty paths: ${races.join(", ")}`);
    new Notice(`Remote edit overlapped a local edit. Check ${summary}.`);
  }

  private clearDirtyPathsForOp(clientOpId: string): void {
    const paths = this.pendingOpPaths.get(clientOpId) ?? [];
    for (const path of paths) {
      this.locallyDirtyPaths.delete(path);
    }
    const fileIds = this.pendingOpFileIds.get(clientOpId) ?? [];
    for (const fileId of fileIds) {
      this.locallyDirtyFileIds.delete(fileId);
    }
    this.pendingOpPaths.delete(clientOpId);
    this.pendingOpFileIds.delete(clientOpId);
  }

  private queuePendingOp(op: PendingEncryptedOp): void {
    if (this.host.settings.pendingOps.some((pending) => pending.client_op_id === op.client_op_id)) {
      return;
    }
    this.host.settings.pendingOps.push(op);
  }

  private queueTransition(entry: SyncJournalEntry): void {
    this.locallyDirtyFileIds.add(entry.fileId);
    const journal = this.host.settings.durableSyncState.journal;
    if (!journal.some((existing) => existing.transitionId === entry.transitionId)) {
      journal.push({ ...entry, status: "queued" });
    }
    this.persistSyncState();
  }

  private attachOpToTransition(transitionId: string | undefined, clientOpId: string): void {
    if (!transitionId) {
      return;
    }
    const journal = this.host.settings.durableSyncState.journal;
    const entry = journal.find((candidate) => candidate.transitionId === transitionId);
    if (entry) {
      entry.clientOpId = clientOpId;
      entry.status = "queued";
    }
    this.persistSyncState();
  }

  private acknowledgeTransition(transitionId: string | undefined): void {
    if (!transitionId) {
      return;
    }
    const entry = this.host.settings.durableSyncState.journal.find((candidate) => candidate.transitionId === transitionId);
    if (entry) {
      entry.status = "acknowledged";
    }
  }

  private acknowledgeTransitionByClientOp(clientOpId: string): void {
    const entry = this.host.settings.durableSyncState.journal.find((candidate) => candidate.clientOpId === clientOpId);
    if (entry) {
      entry.status = "acknowledged";
    }
  }

  private persistSyncState(): void {
    this.host.settings.durableSyncState.index = this.stateIndex.toSnapshot();
    this.host.settings.durableSyncState.journal = this.host.settings.durableSyncState.journal.slice(-2048);
  }

  private removePendingOp(clientOpId: string): void {
    this.host.settings.pendingOps = this.host.settings.pendingOps.filter((op) => op.client_op_id !== clientOpId);
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

  private async applyRemoteV2Payload(payload: RemoteV2Payload, serverSeq: number): Promise<void> {
    const decision = decideRemoteV2Apply(this.stateIndex, payload, this.locallyDirtyFileIds);
    if (decision.action === "prompt") {
      this.host.updateStatus("conflict needs input");
      new Notice(`Mylonite needs input: ${decision.reason}. Keeping local work for now.`);
      return;
    }
    if (decision.action === "noop") {
      return;
    }
    if (payload.kind === "file-rename") {
      const targetPath = decision.action === "conflict-path" ? decision.path : payload.newPath;
      const result = await applyFileRenameWithCollision(this.host.app.vault, this.suppressedPaths, payload.oldPath, targetPath, payload.fileId);
      const finalPath = result.status === "missing-local-file" ? targetPath : result.path;
      const current = this.stateIndex.byFileId(payload.fileId);
      this.stateIndex.upsertFile({
        fileId: payload.fileId,
        path: finalPath,
        kind: current?.kind ?? "markdown",
        contentHash: current?.contentHash ?? "",
        tombstone: false,
        lastLocalSeq: current?.lastLocalSeq ?? 0,
        lastRemoteSeq: serverSeq,
        updatedAtMs: Date.now(),
      });
      return;
    }
    if (payload.kind === "file-delete") {
      await applyFileDelete(this.host.app.vault, this.suppressedPaths, payload.path);
      this.stateIndex.deleteFile(payload.fileId, payload.path, Date.now(), payload.tombstoneId);
      return;
    }
    if (payload.kind === "file-create" || payload.kind === "file-copy") {
      const fileId = payload.kind === "file-copy" ? payload.newFileId : payload.fileId;
      const path = decision.action === "conflict-path" ? decision.path : payload.path;
      await this.applyRemoteV2Content({ ...payload, fileId, path }, false, serverSeq);
      return;
    }
    await this.applyRemoteV2Content(payload, true, serverSeq);
  }

  private async applyRemoteV2Content(payload: RemoteV2Payload & { path: string; fileId: string }, allowOverwrite: boolean, serverSeq: number): Promise<void> {
    if ((payload.kind === "file-create" || payload.kind === "file-copy") && payload.fileKind === "markdown") {
      const content = payload.content ?? "";
      const result = await applyMarkdownUpsertWithCollision(this.host.app.vault, this.suppressedPaths, payload.path, content, payload.fileId, allowOverwrite);
      this.recordRemoteFile(payload.fileId, result.path, "markdown", payload.contentHash, serverSeq);
      return;
    }
    if (payload.kind === "file-update" && payload.fileKind === "markdown") {
      if (payload.contentUpdate) {
        applyMarkdownUpdate(this.ydoc, payload.contentUpdate);
        const text = getMarkdownText(this.ytree, normalizeVaultPath(payload.path));
        const content = text?.toString() ?? "";
        const result = await applyMarkdownUpsertWithCollision(this.host.app.vault, this.suppressedPaths, payload.path, content, payload.fileId, allowOverwrite);
        this.recordRemoteFile(payload.fileId, result.path, "markdown", payload.contentHash, serverSeq);
      }
      return;
    }
    if ((payload.kind === "file-create" || payload.kind === "file-copy" || payload.kind === "file-update") && payload.fileKind === "binary") {
      if (!payload.blobId) {
        throw new Error("missing v2 binary blob id");
      }
      const keys = await this.host.loadVaultKeys();
      const blobBytes = await this.host.createApiClient().getBlob(this.host.settings.vaultId, payload.blobId);
      if (!blobBytes) {
        throw new Error(`missing blob ${payload.blobId}`);
      }
      const plaintext = decryptBlobEnvelope(keys, this.host.settings.vaultId, payload.blobId, blobBytes);
      const result = await applyBinaryUpsertWithCollision(this.host.app.vault, this.suppressedPaths, payload.path, plaintext, payload.fileId, allowOverwrite);
      this.recordRemoteFile(payload.fileId, result.path, "binary", payload.contentHash, serverSeq);
    }
  }

  private recordRemoteFile(fileId: string, path: string, kind: FileKind, contentHash: string, serverSeq: number): void {
    const current = this.stateIndex.byFileId(fileId);
    this.stateIndex.upsertFile({
      fileId,
      path,
      kind,
      contentHash,
      tombstone: false,
      lastLocalSeq: current?.lastLocalSeq ?? 0,
      lastRemoteSeq: serverSeq,
      updatedAtMs: Date.now(),
    });
  }

  private async restoreSnapshot(snapshot: SnapshotRecord, deleteMissing: boolean): Promise<void> {
    const keys = await this.host.loadVaultKeys();
    const payload = await restoreEncryptedSnapshot(
      this.host.app.vault,
      this.suppressedPaths,
      keys,
      this.host.settings.vaultId,
      snapshot,
      (entry) => this.loadSnapshotBinary(entry),
      deleteMissing,
    );
    if (payload.state) {
      this.host.settings.durableSyncState.index = payload.state;
      this.stateIndex = VaultStateIndex.fromSnapshot(payload.state);
      this.classifier = new LocalEventClassifier(this.stateIndex);
    }
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
    this.host.updateStatus("snapshot restored");
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

export function webSocketReconnectDelay(attempt: number): number {
  return WEBSOCKET_RECONNECT_DELAYS_MS[Math.min(attempt, WEBSOCKET_RECONNECT_DELAYS_MS.length - 1)];
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
  if (payload.version !== 2) {
    throw new Error("unsupported remote payload version");
  }
  validateRemoteV2Payload(payload as unknown as RemoteV2Payload);
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
  if (typeof op.kind !== "number" || !Number.isSafeInteger(op.kind) || op.kind < OpKind.FileCreate || op.kind > OpKind.FileCopy) {
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
  return [payload.path];
}

function validateRemoteV2Payload(payload: RemoteV2Payload): void {
  validateFileId(payload.fileId);
  normalizeVaultPath(payload.path);
  if (payload.kind === "file-create" || payload.kind === "file-update" || payload.kind === "file-copy") {
    validateFileKind(payload.fileKind);
    validateContentHash(payload.contentHash);
    if (payload.fileKind === "markdown") {
      if (payload.kind !== "file-update" && payload.content !== undefined && typeof payload.content !== "string") {
        throw new Error("invalid v2 markdown content");
      }
      if (payload.kind === "file-update" && payload.contentUpdate !== undefined) {
        validateHexPayload("v2 content update", payload.contentUpdate);
      }
    }
    if (payload.fileKind === "binary") {
      if (typeof payload.blobId !== "string" || !/^[0-9a-f]{64}$/.test(payload.blobId)) {
        throw new Error("invalid v2 blob id");
      }
      if (typeof payload.size !== "number" || !Number.isSafeInteger(payload.size) || payload.size < 0) {
        throw new Error("invalid v2 binary size");
      }
    }
  }
  if (payload.kind === "file-rename") {
    normalizeVaultPath(payload.oldPath);
    normalizeVaultPath(payload.newPath);
  }
  if (payload.kind === "file-delete") {
    if (typeof payload.tombstoneId !== "string" || !/^t[0-9a-f]{32}$/.test(payload.tombstoneId)) {
      throw new Error("invalid v2 tombstone id");
    }
  }
  if (payload.kind === "file-copy") {
    validateFileId(payload.sourceFileId);
    validateFileId(payload.newFileId);
  }
}

function validateFileKind(value: unknown): asserts value is FileKind {
  if (value !== "markdown" && value !== "binary") {
    throw new Error("invalid v2 file kind");
  }
}

function validateFileId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^f[0-9a-f]{32}$/.test(value)) {
    throw new Error("invalid v2 file id");
  }
}

function validateContentHash(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 || /[^0-9a-f]/.test(value)) {
    throw new Error("invalid v2 content hash");
  }
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

import { Notice, Plugin, TAbstractFile, TFile } from "obsidian";

import { ApiError, EncryptedOpRecord, MyloniteApiClient } from "./api";
import { VaultKeys, randomHex } from "./crypto";
import { LegacyState, isLegacyClean, legacyOpPaths } from "./migrate";
import { RemoteOp, parseWire, toBase64, toWire } from "./ops";
import { Replica } from "./replica";
import { MyloniteSettings } from "./settings";
import { LiveSocket } from "./socket";
import { SyncStore, deleteIdbStore, openIdbStore } from "./store";
import { blobIdOf, decryptBlob, decryptOp, decryptSnapshot, encryptBlob, encryptOp, encryptSnapshot } from "./sync-codec";
import { LegacyHint, OutboxEntry, SyncOp } from "./sync-types";
import { ObsidianVaultIO } from "./vault-io";

const PAGE_SIZE = 512;
const BATCH_OPS = 128;
const BATCH_BYTES = 1_000_000;
/** Text edits larger than this travel as a blob, so ops stay small. */
const INLINE_UPDATE_BYTES = 256 * 1024;
const LOCAL_DEBOUNCE_MS = 300;
const TICK_MS = 15_000;
const LIVE_POLL_MS = 60_000;
const RETRY_DELAYS_MS = [2_000, 5_000, 15_000, 30_000, 60_000];

export interface SyncEngineHost extends Plugin {
  settings: MyloniteSettings;
  createApiClient(): MyloniteApiClient;
  loadVaultKeys(): Promise<VaultKeys>;
  /** Old sync state from data.json, returned once. */
  takeLegacyState(): LegacyState | null;
  /** Called after the old sync state is safely in the new store. */
  retireLegacyState(): Promise<void>;
  updateStatus(state: string): void;
  debug(message: string): void;
}

interface Session {
  store: SyncStore;
  replica: Replica;
  socket: LiveSocket;
  cursor: number | undefined;
  legacy: LegacyState | undefined;
  hints: Record<string, LegacyHint>;
  pushedSeq: number;
}

class ServerTooOldError extends Error {}

export class SyncEngine {
  private session: Session | null = null;
  private chain: Promise<unknown> = Promise.resolve();
  private readonly pendingPaths = new Set<string>();
  private readonly pendingRenames: Array<[string, string]> = [];
  private localTimer: number | null = null;
  private retryTimer: number | null = null;
  private retryAttempt = 0;
  private lastSyncAt = 0;
  private live = false;
  private registered = false;
  private notices: string[] = [];

  constructor(private readonly host: SyncEngineHost) {}

  private get settings(): MyloniteSettings {
    return this.host.settings;
  }

  private get paired(): boolean {
    return Boolean(this.settings.vaultId && this.settings.deviceId);
  }

  start(): void {
    if (!this.paired || this.session) {
      return;
    }
    this.register();
    void this.run("start", async () => {
      if (!this.session && this.paired) {
        await this.open();
        await this.syncOnce();
      }
    });
  }

  async close(): Promise<void> {
    const session = this.session;
    this.session = null;
    this.clearTimers();
    session?.socket.stop();
    await this.chain.catch(() => undefined);
    session?.store.close();
    this.live = false;
  }

  /** Stops syncing and deletes the local sync state of this device. */
  async destroy(): Promise<void> {
    const name = this.storeName();
    await this.close();
    if (name) {
      await deleteIdbStore(name);
    }
  }

  /** Rebuilds the local sync state from the server. Local files are kept. */
  async resync(): Promise<void> {
    await this.run("flush before resync", async () => {
      if (this.session) {
        await this.flush(this.session);
      }
    }).catch(() => undefined);
    await this.destroy();
    this.start();
  }

  async syncNow(): Promise<void> {
    if (!this.session) {
      this.start();
    }
    await this.run("sync now", async () => this.syncOnce(), true);
  }

  /** Uploads a snapshot so new devices start from it instead of replaying the log. */
  async createSnapshot(): Promise<void> {
    await this.run("snapshot", async () => {
      const session = this.requireSession();
      await this.syncOnce();
      if (session.cursor === undefined || session.replica.outbox.length > 0 || session.cursor < session.pushedSeq) {
        throw new Error("changes are still waiting to sync");
      }
      const keys = await this.host.loadVaultKeys();
      const files = (await session.replica.canonicalFiles()).map(({ record, state }) => ({
        id: record.id,
        path: record.cpath,
        kind: record.kind,
        init: record.initHash,
        device: record.initDevice,
        hash: record.hash,
        size: record.size,
        state: state ? toBase64(state) : undefined,
      }));
      const snapshotId = randomHex(16);
      const encrypted = encryptSnapshot(keys, this.settings.vaultId, snapshotId, session.cursor, { version: 3, files });
      await this.host.createApiClient().putSnapshot(this.settings.vaultId, {
        snapshot_id: snapshotId,
        device_id: this.settings.deviceId,
        covers_through_seq: session.cursor,
        key_version: 1,
        nonce_hex: encrypted.nonceHex,
        ciphertext_hex: encrypted.ciphertextHex,
      });
    }, true);
  }

  statusSummary(): string {
    if (!this.paired) {
      return "This device is not paired.";
    }
    const session = this.session;
    if (!session) {
      return "Sync is stopped.";
    }
    const waiting = session.replica.outbox.length;
    return [
      `${session.replica.fileCount} files tracked`,
      `${waiting} ${waiting === 1 ? "change" : "changes"} waiting`,
      `server position ${session.cursor ?? 0}`,
      this.live ? "live" : "not connected",
    ].join(", ");
  }

  // ---- lifecycle ----

  private register(): void {
    if (this.registered) {
      return;
    }
    this.registered = true;
    const { vault } = this.host.app;
    const mark = (file: TAbstractFile) => {
      if (file instanceof TFile) {
        this.markLocal(file.path);
      }
    };
    this.host.registerEvent(vault.on("create", mark));
    this.host.registerEvent(vault.on("modify", mark));
    this.host.registerEvent(vault.on("delete", (file) => this.markLocal(file.path)));
    this.host.registerEvent(vault.on("rename", (file, oldPath) => {
      if (file instanceof TFile) {
        this.pendingRenames.push([oldPath, file.path]);
        this.scheduleLocal();
      }
    }));
    this.host.registerInterval(window.setInterval(() => {
      if (this.session && (!this.live || Date.now() - this.lastSyncAt > LIVE_POLL_MS)) {
        void this.run("poll", async () => this.syncOnce()).catch(() => undefined);
      }
    }, TICK_MS));
  }

  private async open(): Promise<void> {
    const name = this.storeName();
    if (!name) {
      return;
    }
    const store = await openIdbStore(name);
    const snapshot = await store.load();
    let clientId = snapshot.meta.get("clientId");
    if (typeof clientId !== "number") {
      clientId = (crypto.getRandomValues(new Uint32Array(1))[0] % 0x7fffffff) + 1;
    }
    const io = new ObsidianVaultIO(this.host.app);
    this.blobKeys = await this.host.loadVaultKeys();
    const session: Session = {
      store,
      replica: null as unknown as Replica,
      socket: null as unknown as LiveSocket,
      cursor: numberOrUndefined(snapshot.meta.get("cursor")),
      legacy: snapshot.meta.get("legacy") as LegacyState | undefined,
      hints: (snapshot.meta.get("hints") as Record<string, LegacyHint> | undefined) ?? {},
      pushedSeq: 0,
    };
    session.replica = new Replica({
      io,
      deviceId: this.settings.deviceId,
      store,
      clientId: clientId as number,
      blobId: (bytes) => this.blobId(bytes),
      fetchBlob: async (blobId) => this.fetchBlob(blobId),
      legacyClean: (path, content, stat) => isLegacyClean(session.hints, path, content, stat),
      notify: (message) => this.notices.push(message),
    }, snapshot.files, snapshot.outbox);
    session.replica.setMeta("clientId", clientId);

    const legacy = this.host.takeLegacyState();
    if (legacy && session.cursor === undefined && !session.legacy) {
      session.legacy = legacy;
      session.replica.setMeta("legacy", legacy);
    }
    await session.replica.commit();
    if (legacy) {
      await this.host.retireLegacyState();
    }

    session.socket = new LiveSocket({
      url: () => this.host.createApiClient().websocketUrl(this.settings.vaultId),
      hello: (challenge) => this.host.createApiClient().websocketHello(this.settings.vaultId, challenge),
      onRecord: (record) => void this.run("live op", async () => this.applyLive(record)).catch(() => undefined),
      onLive: (live) => {
        this.live = live;
        if (live) {
          void this.run("reconnect", async () => this.syncOnce()).catch(() => undefined);
        }
        this.showStatus();
      },
      debug: (message) => this.host.debug(message),
    });
    this.session = session;
    session.socket.start();
  }

  private storeName(): string | null {
    return this.paired ? `mylonite-${this.settings.vaultId}-${this.settings.deviceId}` : null;
  }

  private requireSession(): Session {
    if (!this.session) {
      throw new Error("sync is not running");
    }
    return this.session;
  }

  // ---- the sync loop ----

  /** Runs tasks one at a time, so local scans and remote ops never interleave. */
  private run<T>(label: string, task: () => Promise<T>, rethrow = false): Promise<T | undefined> {
    const result = this.chain.then(task).then(
      (value) => {
        this.retryAttempt = 0;
        this.showNotices();
        this.showStatus();
        return value;
      },
      (error: unknown) => {
        this.showNotices();
        this.handleError(label, error);
        if (rethrow) {
          throw error;
        }
        return undefined;
      },
    );
    this.chain = result.catch(() => undefined);
    return result;
  }

  private async syncOnce(): Promise<void> {
    const session = this.session;
    if (!session) {
      return;
    }
    this.host.updateStatus("Syncing…");
    if (session.cursor === undefined) {
      await this.bootstrap(session);
    }
    await this.catchUp(session);
    await this.drainLocal(session);
    await this.flush(session);
    this.lastSyncAt = Date.now();
  }

  /** First start with an empty store: pick the starting point and adopt files already on disk. */
  private async bootstrap(session: Session): Promise<void> {
    const client = this.host.createApiClient();
    const vaultId = this.settings.vaultId;
    let info = await client.vaultInfo(vaultId);
    if (!info) {
      throw new ServerTooOldError();
    }
    if (info.format < 3) {
      info = await client.upgradeVault(vaultId, session.legacy?.cursor ?? 0);
    }
    if (session.legacy) {
      session.hints = { ...session.legacy.hints };
      await this.forgetUnseenLegacyEdits(session, info.upgrade_base, info.upgrade_seq);
      session.replica.setMeta("hints", session.hints);
    }
    let cursor = info.upgrade_seq;
    const snapshot = await client.latestSnapshot(vaultId);
    if (snapshot && snapshot.covers_through_seq >= cursor && await this.applySnapshot(session, snapshot)) {
      cursor = snapshot.covers_through_seq;
    }
    session.cursor = cursor;
    session.replica.setMeta("cursor", cursor);
    session.replica.setMeta("legacy", null);
    await session.replica.commit();
    await this.catchUp(session);
    await session.replica.scanAll();
    session.hints = {};
    session.replica.setMeta("hints", null);
    await session.replica.commit();
  }

  /**
   * Edits this device sent with the old plugin after the upgrading device's
   * position never reached the new format. Those files are treated as changed here.
   */
  private async forgetUnseenLegacyEdits(session: Session, after: number, through: number): Promise<void> {
    const keys = await this.host.loadVaultKeys();
    const client = this.host.createApiClient();
    let cursor = after;
    while (cursor < through) {
      const records = await client.listOps(this.settings.vaultId, cursor, PAGE_SIZE);
      if (records.length === 0) {
        break;
      }
      for (const record of records) {
        if (record.server_seq > through) {
          return;
        }
        if (record.device_id === this.settings.deviceId) {
          try {
            for (const path of legacyOpPaths(decryptOp(keys, this.settings.vaultId, record))) {
              delete session.hints[path];
            }
          } catch (error) {
            this.host.debug(`skipped unreadable legacy op ${record.server_seq}: ${String(error)}`);
          }
        }
        cursor = record.server_seq;
      }
    }
  }

  private async applySnapshot(session: Session, snapshot: { snapshot_id: string; covers_through_seq: number; nonce_hex: string; ciphertext_hex: string }): Promise<boolean> {
    const keys = await this.host.loadVaultKeys();
    const payload = decryptSnapshot(keys, this.settings.vaultId, snapshot.snapshot_id, snapshot.covers_through_seq, snapshot.nonce_hex, snapshot.ciphertext_hex) as { version?: unknown; files?: unknown };
    if (payload.version !== 3 || !Array.isArray(payload.files)) {
      return false;
    }
    for (const file of payload.files as Array<Record<string, unknown>>) {
      const wire = file.kind === "text"
        ? { v: 3, t: "text", id: file.id, path: file.path, hash: file.init, u: file.state }
        : { v: 3, t: "blob", id: file.id, path: file.path, blob: file.hash, size: file.size };
      const op = parseWire(wire);
      if (op && !("ref" in op)) {
        await session.replica.apply(op, "", typeof file.device === "string" ? file.device : "");
      }
    }
    await session.replica.commit();
    return true;
  }

  private async catchUp(session: Session): Promise<void> {
    const client = this.host.createApiClient();
    for (;;) {
      const records = await client.listOps(this.settings.vaultId, session.cursor ?? 0, PAGE_SIZE);
      for (const record of records) {
        await this.applyRecord(session, record);
      }
      session.replica.setMeta("cursor", session.cursor);
      await session.replica.commit();
      if (records.length < PAGE_SIZE) {
        return;
      }
    }
  }

  private async applyLive(record: unknown): Promise<void> {
    const session = this.session;
    const seq = (record as { server_seq?: unknown } | null)?.server_seq;
    if (!session || session.cursor === undefined || typeof seq !== "number") {
      return;
    }
    if (seq === session.cursor + 1) {
      await this.applyRecord(session, record as EncryptedOpRecord);
      session.replica.setMeta("cursor", session.cursor);
      await session.replica.commit();
      await this.drainLocal(session);
    } else if (seq > session.cursor + 1) {
      await this.catchUp(session);
    }
  }

  private async applyRecord(session: Session, record: EncryptedOpRecord): Promise<void> {
    if (session.cursor !== undefined && record.server_seq <= session.cursor) {
      return;
    }
    const op = await this.decodeRecord(record);
    if (op) {
      await session.replica.apply(op, record.client_op_id, record.device_id);
    }
    session.cursor = record.server_seq;
  }

  private async decodeRecord(record: EncryptedOpRecord): Promise<SyncOp | null> {
    let remote: RemoteOp | null;
    try {
      remote = parseWire(decryptOp(await this.host.loadVaultKeys(), this.settings.vaultId, record));
    } catch (error) {
      this.host.debug(`skipped unreadable op ${record.server_seq}: ${String(error)}`);
      return null;
    }
    if (!remote || !("ref" in remote)) {
      return remote;
    }
    const update = await this.fetchBlob(remote.ref);
    if (!update) {
      this.host.debug(`skipped op ${record.server_seq}: its update is missing on the server`);
      return null;
    }
    const { ref: _ref, ...rest } = remote;
    return { ...rest, update };
  }

  private markLocal(path: string): void {
    this.pendingPaths.add(path);
    this.scheduleLocal();
  }

  private scheduleLocal(): void {
    if (this.localTimer !== null) {
      window.clearTimeout(this.localTimer);
    }
    this.localTimer = window.setTimeout(() => {
      this.localTimer = null;
      void this.run("local changes", async () => {
        const session = this.session;
        if (session && session.cursor !== undefined) {
          await this.drainLocal(session);
          await this.flush(session);
        }
      });
    }, LOCAL_DEBOUNCE_MS);
  }

  private async drainLocal(session: Session): Promise<void> {
    if (session.cursor === undefined) {
      return;
    }
    const renames = this.pendingRenames.splice(0);
    const paths = new Set([...this.pendingPaths, ...session.replica.dirty]);
    this.pendingPaths.clear();
    session.replica.dirty.clear();
    for (const [from, to] of renames) {
      await session.replica.rename(from, to);
      paths.delete(from);
      paths.delete(to);
    }
    for (const path of paths) {
      await session.replica.scan(path);
    }
    await session.replica.commit();
  }

  /** Sends queued ops in order, in batches. Blobs are uploaded before the ops that use them. */
  private async flush(session: Session): Promise<void> {
    const client = this.host.createApiClient();
    const keys = await this.host.loadVaultKeys();
    const { replica } = session;
    while (replica.outbox.length > 0) {
      const ready: OutboxEntry[] = [];
      const uploads = new Map<string, Uint8Array>();
      let bytes = 0;
      for (const entry of [...replica.outbox]) {
        if (ready.length >= BATCH_OPS || bytes >= BATCH_BYTES) {
          break;
        }
        let current = entry;
        if (entry.op.t === "blob") {
          const resolved = await replica.resolveBlob(entry);
          if (!resolved) {
            continue;
          }
          current = resolved.entry;
          uploads.set((current.op as { blob: string }).blob, resolved.bytes);
          bytes += resolved.bytes.byteLength;
        } else if (entry.op.t === "text") {
          bytes += entry.op.update.byteLength;
        }
        ready.push(current);
      }
      await replica.commit();
      if (ready.length === 0) {
        continue;
      }
      await this.uploadBlobs(client, keys, uploads, ready, replica);
      const encrypted = [];
      for (const entry of ready) {
        if (replica.outbox.some((candidate) => candidate.opId === entry.opId)) {
          encrypted.push(encryptOp(keys, this.settings.vaultId, this.settings.deviceId, entry.opId, await this.wire(client, keys, entry.op)));
        }
      }
      if (encrypted.length === 0) {
        continue;
      }
      const seqs = await client.appendOps(this.settings.vaultId, encrypted);
      session.pushedSeq = Math.max(session.pushedSeq, ...seqs);
      replica.ack(new Set(encrypted.map((op) => op.client_op_id)));
      await replica.commit();
    }
  }

  private async uploadBlobs(client: MyloniteApiClient, keys: VaultKeys, uploads: Map<string, Uint8Array>, ready: OutboxEntry[], replica: Replica): Promise<void> {
    if (uploads.size === 0) {
      return;
    }
    const missing = await client.missingBlobs(this.settings.vaultId, [...uploads.keys()]);
    for (const [blobId, plaintext] of uploads) {
      if (!missing.has(blobId)) {
        continue;
      }
      try {
        await client.putBlob(this.settings.vaultId, blobId, encryptBlob(keys, this.settings.vaultId, plaintext).envelope);
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 413) {
          throw error;
        }
        // too large for this server: skip the file instead of blocking all sync
        const skipped = ready.filter((entry) => entry.op.t === "blob" && entry.op.blob === blobId).map((entry) => entry.opId);
        replica.ack(new Set(skipped));
        this.notices.push("A file is larger than the server allows, so it was not synced.");
      }
    }
  }

  private async wire(client: MyloniteApiClient, keys: VaultKeys, op: SyncOp): Promise<Record<string, unknown>> {
    if (op.t !== "text" || op.update.byteLength <= INLINE_UPDATE_BYTES) {
      return toWire(op);
    }
    const { blobId, envelope } = encryptBlob(keys, this.settings.vaultId, op.update);
    await client.putBlob(this.settings.vaultId, blobId, envelope);
    return toWire(op, blobId);
  }

  private blobKeys: VaultKeys | null = null;

  private blobId(bytes: Uint8Array): string {
    if (!this.blobKeys) {
      throw new Error("vault keys are not loaded");
    }
    return blobIdOf(this.blobKeys, this.settings.vaultId, bytes);
  }

  private async fetchBlob(blobId: string): Promise<Uint8Array | null> {
    const envelope = await this.host.createApiClient().getBlob(this.settings.vaultId, blobId);
    return envelope ? decryptBlob(await this.host.loadVaultKeys(), this.settings.vaultId, blobId, envelope) : null;
  }

  // ---- status ----

  private handleError(label: string, error: unknown): void {
    this.host.debug(`${label} failed: ${String(error)}`);
    if (error instanceof ServerTooOldError) {
      this.host.updateStatus("Server update needed");
      return;
    }
    const waiting = this.session?.replica.outbox.length ?? 0;
    this.host.updateStatus(waiting > 0 ? `Not synced, ${waiting} waiting` : "Not synced");
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    if (this.retryTimer !== null || !this.session) {
      return;
    }
    const delay = RETRY_DELAYS_MS[Math.min(this.retryAttempt, RETRY_DELAYS_MS.length - 1)];
    this.retryAttempt += 1;
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = null;
      void this.run("retry", async () => this.syncOnce());
    }, delay);
  }

  private showStatus(): void {
    const session = this.session;
    if (!session) {
      return;
    }
    const waiting = session.replica.outbox.length;
    if (waiting > 0) {
      this.host.updateStatus(`${waiting} waiting`);
    } else {
      this.host.updateStatus(this.live ? "Synced" : "Synced, not live");
    }
  }

  private showNotices(): void {
    const notices = this.notices.splice(0);
    if (notices.length === 1) {
      new Notice(`Mylonite: ${notices[0]}`);
    } else if (notices.length > 1) {
      new Notice(`Mylonite: kept both versions of ${notices.length} files. Look for files with "conflict" in the name.`);
    }
  }

  private clearTimers(): void {
    for (const timer of [this.localTimer, this.retryTimer]) {
      if (timer !== null) {
        window.clearTimeout(timer);
      }
    }
    this.localTimer = null;
    this.retryTimer = null;
  }
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

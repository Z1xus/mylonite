import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Notice, TFile } from "obsidian";
import * as Y from "yjs";
import {
  MARKDOWN_DEBOUNCE_MS,
  SyncEngine,
  parseWebSocketChallenge,
  racedPaths,
  retainUnflushedPendingOps,
  validateRemoteOpRecord,
  validateRemotePayload,
  validateSnapshotRecord,
  webSocketReconnectDelay,
} from "./sync-engine";
import { PendingEncryptedOp } from "./sync-types";
import { ServerMsgKind, encodeFrame } from "./protocol";
import { encodeMarkdownRenameUpdate, encodeMarkdownUpsertUpdate, hexToBytes } from "./yjs-markdown";
import { VaultKeys } from "./crypto";
import { encryptBlob } from "./sync-codec";

const keys: VaultKeys = {
  opKey: new Uint8Array(32).fill(1),
  blobKey: new Uint8Array(32).fill(2),
  blobIdKey: new Uint8Array(32).fill(3),
  snapshotKey: new Uint8Array(32).fill(4),
};

function noticeMessages(): string[] {
  return (Notice as unknown as { messages: string[] }).messages;
}

describe("pending op queue", () => {
  it("keeps the failed op and later queued ops after a flush failure", () => {
    const ops = [testOp("op-a"), testOp("op-b"), testOp("op-c")];

    expect(retainUnflushedPendingOps(ops, 1).map((op) => op.client_op_id)).toEqual(["op-b", "op-c"]);
  });
});

describe("sync race detection", () => {
  it("returns normalized paths touched by both local and remote changes", () => {
    const localPaths = new Set(["Notes/a.md", "assets/image.png"]);

    expect(racedPaths(["Notes\\a.md", "other.md"], localPaths)).toEqual(["Notes/a.md"]);
  });
});

describe("markdown debounce", () => {
  beforeEach(() => {
    vi.stubGlobal("window", globalThis);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("pushes one markdown update after the debounce delay and resets on repeated edits", () => {
    vi.useFakeTimers();
    const engine = new SyncEngine(testHost());
    const pushMarkdownUpdate = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { pushMarkdownUpdate: typeof pushMarkdownUpdate }).pushMarkdownUpdate = pushMarkdownUpdate;
    const file = testFile("Notes/a.md", "md");

    callPrivate(engine, "scheduleMarkdownUpdate", file);
    vi.advanceTimersByTime(MARKDOWN_DEBOUNCE_MS - 1);
    callPrivate(engine, "scheduleMarkdownUpdate", file);
    vi.advanceTimersByTime(MARKDOWN_DEBOUNCE_MS - 1);

    expect(pushMarkdownUpdate).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);

    expect(pushMarkdownUpdate).toHaveBeenCalledTimes(1);
    expect(pushMarkdownUpdate).toHaveBeenCalledWith(file);
  });

  it("flushes scheduled markdown updates when the engine closes", () => {
    vi.useFakeTimers();
    const engine = new SyncEngine(testHost());
    const pushMarkdownUpdate = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { pushMarkdownUpdate: typeof pushMarkdownUpdate }).pushMarkdownUpdate = pushMarkdownUpdate;
    const file = testFile("Notes/a.md", "md");

    callPrivate(engine, "scheduleMarkdownUpdate", file);
    engine.close();
    vi.runAllTimers();

    expect(pushMarkdownUpdate).toHaveBeenCalledTimes(1);
    expect(pushMarkdownUpdate).toHaveBeenCalledWith(file);
  });

  it("can close without flushing scheduled markdown updates", () => {
    vi.useFakeTimers();
    const engine = new SyncEngine(testHost());
    const pushMarkdownUpdate = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { pushMarkdownUpdate: typeof pushMarkdownUpdate }).pushMarkdownUpdate = pushMarkdownUpdate;
    const file = testFile("Notes/a.md", "md");

    callPrivate(engine, "scheduleMarkdownUpdate", file);
    engine.close({ flushScheduledUpdates: false });
    vi.runAllTimers();

    expect(pushMarkdownUpdate).not.toHaveBeenCalled();
  });

  it("flushes pending markdown updates sequentially", async () => {
    const engine = new SyncEngine(testHost());
    let releaseFirst: () => void = () => undefined;
    const firstPush = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const pushMarkdownUpdate = vi
      .fn()
      .mockReturnValueOnce(firstPush)
      .mockResolvedValue(undefined);
    (engine as unknown as { pushMarkdownUpdate: typeof pushMarkdownUpdate }).pushMarkdownUpdate = pushMarkdownUpdate;
    const first = testFile("Notes/a.md", "md");
    const second = testFile("Notes/b.md", "md");

    callPrivate(engine, "scheduleMarkdownUpdate", first);
    callPrivate(engine, "scheduleMarkdownUpdate", second);
    const flush = callPrivate<Promise<void>>(engine, "flushScheduledMarkdownUpdates");
    await Promise.resolve();

    expect(pushMarkdownUpdate).toHaveBeenCalledTimes(1);
    expect(pushMarkdownUpdate).toHaveBeenCalledWith(first);

    releaseFirst();
    await flush;

    expect(pushMarkdownUpdate).toHaveBeenCalledTimes(2);
    expect(pushMarkdownUpdate).toHaveBeenNthCalledWith(2, second);
  });
});

describe("websocket reconnect", () => {
  beforeEach(() => {
    vi.stubGlobal("window", globalThis);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("uses bounded reconnect delays", () => {
    expect([0, 1, 2, 3, 4, 99].map(webSocketReconnectDelay)).toEqual([1_000, 2_000, 5_000, 15_000, 15_000, 15_000]);
  });

  it("reconnects after socket close while started", () => {
    vi.useFakeTimers();
    const sockets: MockWebSocket[] = [];
    vi.stubGlobal("WebSocket", class extends MockWebSocket {
      constructor(url: string) {
        super(url);
        sockets.push(this);
      }
    });
    const engine = new SyncEngine(testHost());

    engine.start();
    expect(sockets).toHaveLength(1);

    sockets[0].onclose?.({} as CloseEvent);
    vi.advanceTimersByTime(999);
    expect(sockets).toHaveLength(1);

    vi.advanceTimersByTime(1);
    expect(sockets).toHaveLength(2);
  });

  it("does not reconnect after explicit close", () => {
    vi.useFakeTimers();
    const sockets: MockWebSocket[] = [];
    vi.stubGlobal("WebSocket", class extends MockWebSocket {
      constructor(url: string) {
        super(url);
        sockets.push(this);
      }
    });
    const engine = new SyncEngine(testHost());

    engine.start();
    engine.close();
    vi.advanceTimersByTime(15_000);

    expect(sockets).toHaveLength(1);
  });
});

describe("websocket gap repair", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("runs catch-up instead of directly applying a broadcast when a sequence gap is detected", async () => {
    const host = testHost();
    host.settings.lastServerSeq = 3;
    const engine = new SyncEngine(host);
    const catchUpInner = vi.fn().mockResolvedValue(undefined);
    const applyRemoteOp = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { catchUpInner: typeof catchUpInner; applyRemoteOp: typeof applyRemoteOp }).catchUpInner = catchUpInner;
    (engine as unknown as { applyRemoteOp: typeof applyRemoteOp }).applyRemoteOp = applyRemoteOp;

    await callPrivate(engine, "handleSocketMessage", opBroadcast({ server_seq: 5 }));

    expect(catchUpInner).toHaveBeenCalledTimes(1);
    expect(applyRemoteOp).not.toHaveBeenCalled();
    expect(host.settings.lastServerSeq).toBe(3);
  });

  it("applies the next contiguous live broadcast directly", async () => {
    const host = testHost();
    host.settings.lastServerSeq = 3;
    host.settings.pendingOps = [testOp("a".repeat(64))];
    const engine = new SyncEngine(host);
    const catchUp = vi.fn().mockResolvedValue(undefined);
    const applyRemoteOp = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { catchUp: typeof catchUp; applyRemoteOp: typeof applyRemoteOp }).catchUp = catchUp;
    (engine as unknown as { applyRemoteOp: typeof applyRemoteOp }).applyRemoteOp = applyRemoteOp;

    await callPrivate(engine, "handleSocketMessage", opBroadcast({ server_seq: 4, lamport: 8 }));

    expect(catchUp).not.toHaveBeenCalled();
    expect(applyRemoteOp).toHaveBeenCalledTimes(1);
    expect(host.settings.lastServerSeq).toBe(4);
    expect(host.settings.lamport).toBe(8);
    expect(host.settings.pendingOps).toEqual([]);
  });

  it("does not apply a websocket broadcast already covered by an active catch-up", async () => {
    const host = testHost();
    const listOpsResult = deferred<unknown[]>();
    const op = testBroadcastOp();
    const listOps = vi.fn()
      .mockReturnValueOnce(listOpsResult.promise)
      .mockResolvedValue([]);
    host.createApiClient = () => ({
      websocketUrl: () => "wss://example.test/ws",
      listOps,
      putBlob: vi.fn().mockResolvedValue(undefined),
      appendOp: vi.fn().mockResolvedValue(undefined),
    }) as never;
    const engine = new SyncEngine(host);
    const applyRemoteOp = vi.fn(async () => undefined);
    (engine as unknown as { applyRemoteOp: typeof applyRemoteOp }).applyRemoteOp = applyRemoteOp;

    const catchUp = engine.catchUp();
    await Promise.resolve();
    const socketApply = callPrivate<Promise<void>>(engine, "handleSocketMessage", opBroadcast(op));
    await Promise.resolve();

    listOpsResult.resolve([op]);
    await catchUp;
    await socketApply;

    expect(applyRemoteOp).toHaveBeenCalledTimes(1);
    expect(host.settings.lastServerSeq).toBe(op.server_seq);
  });
});

describe("sync task scheduling", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("coalesces concurrent catch-up requests into one remote op walk", async () => {
    const host = testHost();
    const listOpsResult = deferred<unknown[]>();
    const listOps = vi.fn().mockReturnValue(listOpsResult.promise);
    host.createApiClient = () => ({
      websocketUrl: () => "wss://example.test/ws",
      listOps,
      putBlob: vi.fn().mockResolvedValue(undefined),
      appendOp: vi.fn().mockResolvedValue(undefined),
    }) as never;
    const engine = new SyncEngine(host);

    const first = engine.catchUp();
    await Promise.resolve();
    const second = engine.catchUp();
    await Promise.resolve();

    expect(listOps).toHaveBeenCalledTimes(1);

    listOpsResult.resolve([]);
    await Promise.all([first, second]);
  });

  it("queues snapshots behind an in-flight catch-up", async () => {
    const host = testHost();
    const listOpsResult = deferred<unknown[]>();
    host.createApiClient = () => ({
      websocketUrl: () => "wss://example.test/ws",
      listOps: vi.fn().mockReturnValue(listOpsResult.promise),
      putBlob: vi.fn().mockResolvedValue(undefined),
      appendOp: vi.fn().mockResolvedValue(undefined),
    }) as never;
    const engine = new SyncEngine(host);
    const createSnapshotInner = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { createSnapshotInner: typeof createSnapshotInner }).createSnapshotInner = createSnapshotInner;

    const catchUp = engine.catchUp();
    await Promise.resolve();
    const snapshot = engine.createSnapshot();
    await Promise.resolve();

    expect(createSnapshotInner).not.toHaveBeenCalled();

    listOpsResult.resolve([]);
    await catchUp;
    await snapshot;

    expect(createSnapshotInner).toHaveBeenCalledTimes(1);
  });
});

describe("remote payload validation", () => {
  it("accepts well-formed v2 remote payloads", () => {
    expect(() => validateRemotePayload(v2Payload({ kind: "file-create", fileKind: "markdown", updateHex: "00ff" }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "markdown", updateHex: "00ff" }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "binary", blobId: "a".repeat(64), size: 12 }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-delete", fileKind: "markdown", updateHex: "00ff", tombstoneId: "t" + "b".repeat(32) }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-rename", fileKind: "markdown", updateHex: "00ff", oldPath: "Notes/a.md", newPath: "Notes/b.md" }))).not.toThrow();
  });

  it("rejects unsafe vault paths before applying remote writes", () => {
    expect(() => validateRemotePayload(v2Payload({ path: "../outside.md", kind: "file-delete", tombstoneId: "t" + "b".repeat(32) }))).toThrow("invalid vault path");
    expect(() => validateRemotePayload(v2Payload({ path: "/absolute.md", kind: "file-create", fileKind: "markdown", updateHex: "00ff" }))).toThrow("invalid vault path");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-rename", oldPath: "Notes/a.md", newPath: "Notes/../b.md" }))).toThrow("invalid vault path");
  });

  it("rejects legacy and malformed v2 payloads", () => {
    expect(() => validateRemotePayload({ kind: "file-update", path: "Notes/a.md" })).toThrow("unsupported remote payload version");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "markdown", updateHex: "abc" }))).toThrow("invalid v2 update");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "binary", blobId: "blob-a", size: 1 }))).toThrow("invalid v2 blob id");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "binary", blobId: "a".repeat(64), size: -1 }))).toThrow("invalid v2 binary size");
  });
});

describe("v2 markdown application", () => {
  beforeEach(() => {
    noticeMessages().length = 0;
  });

  it("applies text updates after an empty create on a receiver", async () => {
    const path = "Notes/a.md";
    const fileId = "f" + "a".repeat(32);
    const localDoc = new Y.Doc();
    const localTree = localDoc.getMap<Y.Map<unknown>>("tree");
    const createUpdate = encodeMarkdownUpsertUpdate(localDoc, localTree, path, "");
    const editUpdate = encodeMarkdownUpsertUpdate(localDoc, localTree, path, "hello");
    const vault = new MemoryVault();
    const engine = new SyncEngine(testHost(vault));

    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-create",
      fileId,
      path,
      fileKind: "markdown",
      updateHex: createUpdate,
      contentHash: "00",
    }), 1);
    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-update",
      fileId,
      path,
      fileKind: "markdown",
      updateHex: editUpdate,
      contentHash: "01",
    }), 2);

    expect(vault.readText(path)).toBe("hello");
  });

  it("materializes a remote markdown rename when the old local file is missing", async () => {
    const oldPath = "Notes/a.md";
    const newPath = "Moved/a.md";
    const fileId = "f" + "a".repeat(32);
    const localDoc = new Y.Doc();
    const localTree = localDoc.getMap<Y.Map<unknown>>("tree");
    const renameUpdate = encodeMarkdownRenameUpdate(localDoc, localTree, oldPath, newPath, "hello after move");
    const vault = new MemoryVault();
    const engine = new SyncEngine(testHost(vault));

    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-rename",
      fileId,
      path: newPath,
      oldPath,
      newPath,
      fileKind: "markdown",
      updateHex: renameUpdate,
      contentHash: "abcd",
    }), 4);

    expect(vault.readText(newPath)).toBe("hello after move");
  });

  it("writes conflicted markdown content from the remote op path, not the generated conflict path", async () => {
    const path = "Notes/a.md";
    const remoteFileId = "f" + "a".repeat(32);
    const localFileId = "f" + "b".repeat(32);
    const localDoc = new Y.Doc();
    const localTree = localDoc.getMap<Y.Map<unknown>>("tree");
    const updateHex = encodeMarkdownUpsertUpdate(localDoc, localTree, path, "remote content");
    const vault = new MemoryVault([[path, "local content"]]);
    const host = testHost(vault);
    host.settings.durableSyncState.index.files = [{
      fileId: localFileId,
      path,
      kind: "markdown",
      contentHash: "local",
      tombstone: false,
      lastLocalSeq: 0,
      lastRemoteSeq: 0,
      updatedAtMs: 1,
    }];
    const engine = new SyncEngine(host);

    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-update",
      fileId: remoteFileId,
      path,
      fileKind: "markdown",
      updateHex,
      contentHash: "abcd",
    }), 5);

    expect(vault.readText(path)).toBe("local content");
    expect(vault.readText("Notes/a conflict-faaaaaaa.md")).toBe("remote content");
    expect(noticeMessages().filter((message) => message.startsWith("Mylonite kept both versions"))).toHaveLength(1);
  });
});

describe("v2 binary rename application", () => {
  beforeEach(() => {
    noticeMessages().length = 0;
  });

  it("materializes a remote binary rename when the old local file is missing", async () => {
    const oldPath = "assets/a.png";
    const newPath = "images/a.png";
    const fileId = "f" + "a".repeat(32);
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const encrypted = encryptBlob(keys, "vault-a", bytes);
    const vault = new MemoryVault();
    const host = testHost(vault);
    host.loadVaultKeys = vi.fn().mockResolvedValue(keys);
    host.createApiClient = () => ({
      websocketUrl: () => "wss://example.test/ws",
      listOps: vi.fn().mockResolvedValue([]),
      getBlob: vi.fn().mockResolvedValue(encrypted.envelope),
    }) as never;
    const engine = new SyncEngine(host);

    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-rename",
      fileId,
      path: newPath,
      oldPath,
      newPath,
      fileKind: "binary",
      contentHash: "abcd",
      blobId: encrypted.blobId,
      size: bytes.byteLength,
    }), 6);

    expect(Array.from(vault.readBinaryBytes(newPath) ?? [])).toEqual([1, 2, 3, 4]);
  });
});

describe("binary outbox", () => {
  it("queues a binary rename op behind its blob when blob upload fails", async () => {
    const oldPath = "assets/a.png";
    const newPath = "images/a.png";
    const vault = new MemoryVault();
    vault.binaries.set(newPath, new Uint8Array([1, 2, 3]));
    const host = testHost(vault);
    const putBlob = vi.fn().mockRejectedValue(new Error("offline"));
    const appendOp = vi.fn().mockResolvedValue(undefined);
    host.loadVaultKeys = vi.fn().mockResolvedValue(keys);
    host.createApiClient = () => ({
      websocketUrl: () => "wss://example.test/ws",
      listOps: vi.fn().mockResolvedValue([]),
      putBlob,
      appendOp,
    }) as never;
    const engine = new SyncEngine(host);

    await callPrivate(engine, "pushFileRename", oldPath, testFile(newPath, "png"));

    expect(host.settings.pendingBlobs).toHaveLength(1);
    expect(host.settings.pendingOps).toHaveLength(1);
    expect(appendOp).not.toHaveBeenCalled();
  });
});

describe("durable local dirty state", () => {
  beforeEach(() => {
    noticeMessages().length = 0;
  });

  it("rehydrates queued local changes before remote conflict decisions", async () => {
    const path = "assets/a.png";
    const fileId = "f" + "a".repeat(32);
    const host = testHost(new MemoryVault());
    host.settings.durableSyncState.journal = [{
      transitionId: "x" + "1".repeat(32),
      status: "queued",
      kind: "file-update",
      fileId,
      path,
      fileKind: "binary",
      contentHash: "abcd",
      observedAtMs: 1,
      affectedPaths: [path],
    }];
    const engine = new SyncEngine(host);

    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-delete",
      fileId,
      path,
      fileKind: "binary",
      tombstoneId: "t" + "b".repeat(32),
    }), 7);
    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-delete",
      fileId,
      path,
      fileKind: "binary",
      tombstoneId: "t" + "b".repeat(32),
    }), 8);

    expect(host.updateStatus).toHaveBeenCalledWith("conflict needs input");
    expect(noticeMessages().filter((message) => message.startsWith("Mylonite needs input"))).toHaveLength(1);
  });

  it("keeps local markdown and writes remote markdown to a conflict path while local work is unconfirmed", async () => {
    const path = "Notes/a.md";
    const fileId = "f" + "a".repeat(32);
    const localDoc = new Y.Doc();
    const localTree = localDoc.getMap<Y.Map<unknown>>("tree");
    const updateHex = encodeMarkdownUpsertUpdate(localDoc, localTree, path, "remote text");
    const vault = new MemoryVault([[path, "local text"]]);
    const host = testHost(vault);
    host.settings.durableSyncState.index.files = [{
      fileId,
      path,
      kind: "markdown",
      contentHash: "local",
      tombstone: false,
      lastLocalSeq: 0,
      lastRemoteSeq: 0,
      updatedAtMs: 1,
    }];
    host.settings.durableSyncState.journal = [{
      transitionId: "x" + "1".repeat(32),
      status: "queued",
      kind: "file-update",
      fileId,
      path,
      fileKind: "markdown",
      contentHash: "local2",
      observedAtMs: 2,
      affectedPaths: [path],
    }];
    const engine = new SyncEngine(host);

    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-update",
      fileId,
      path,
      fileKind: "markdown",
      updateHex,
      contentHash: "remote",
    }), 9);

    expect(vault.readText(path)).toBe("local text");
    expect(vault.readText("Notes/a conflict-faaaaaaa.md")).toBe("remote text");
    expect(noticeMessages().filter((message) => message.startsWith("Mylonite kept both versions"))).toHaveLength(1);
  });

  it("rehydrates pending recovery entries before remote markdown conflict decisions", async () => {
    const path = "Notes/a.md";
    const fileId = "f" + "a".repeat(32);
    const clientOpId = "c".repeat(64);
    const localDoc = new Y.Doc();
    const localTree = localDoc.getMap<Y.Map<unknown>>("tree");
    const updateHex = encodeMarkdownUpsertUpdate(localDoc, localTree, path, "remote text");
    const vault = new MemoryVault([[path, "local text"]]);
    const host = testHost(vault);
    host.settings.pendingOps = [testOp(clientOpId)];
    host.settings.recoveryLog = [{
      recoveryId: "r" + "1".repeat(32),
      path,
      fileId,
      contentHash: "local2",
      beforeContent: "local",
      afterContent: "local text",
      observedAtMs: 2,
      clientOpId,
    }];
    host.settings.durableSyncState.index.files = [{
      fileId,
      path,
      kind: "markdown",
      contentHash: "local",
      tombstone: false,
      lastLocalSeq: 0,
      lastRemoteSeq: 0,
      updatedAtMs: 1,
    }];
    const engine = new SyncEngine(host);

    await callPrivate(engine, "applyRemoteV2Payload", v2Payload({
      kind: "file-update",
      fileId,
      path,
      fileKind: "markdown",
      updateHex,
      contentHash: "remote",
    }), 10);

    expect(vault.readText(path)).toBe("local text");
    expect(vault.readText("Notes/a conflict-faaaaaaa.md")).toBe("remote text");
  });
});

describe("markdown recovery log", () => {
  beforeEach(() => {
    vi.stubGlobal("window", globalThis);
    noticeMessages().length = 0;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("records recovery data when a markdown update is queued", async () => {
    const path = "Notes/a.md";
    const vault = new MemoryVault([[path, "local text"]]);
    const host = testHost(vault);
    host.loadVaultKeys = vi.fn().mockResolvedValue(keys);
    const engine = new SyncEngine(host);

    await callPrivate(engine, "pushMarkdownUpdate", testFile(path, "md"));

    expect(host.settings.recoveryLog).toHaveLength(1);
    expect(host.settings.recoveryLog[0]).toMatchObject({
      path,
      beforeContent: "",
      afterContent: "local text",
    });
    expect(host.settings.recoveryLog[0].clientOpId).toMatch(/^[0-9a-f]{64}$/);
  });

  it("syncNow flushes scheduled markdown updates before catch-up", async () => {
    vi.useFakeTimers();
    const engine = new SyncEngine(testHost());
    const pushMarkdownUpdate = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { pushMarkdownUpdate: typeof pushMarkdownUpdate }).pushMarkdownUpdate = pushMarkdownUpdate;
    const file = testFile("Notes/a.md", "md");

    callPrivate(engine, "scheduleMarkdownUpdate", file);
    const sync = engine.syncNow();
    await Promise.resolve();
    await vi.runAllTimersAsync();
    await sync;

    expect(pushMarkdownUpdate).toHaveBeenCalledTimes(1);
    expect(pushMarkdownUpdate).toHaveBeenCalledWith(file);
  });

  it("restores the newest recovery entry and queues it as a normal markdown update", async () => {
    const path = "Notes/a.md";
    const fileId = "f" + "a".repeat(32);
    const vault = new MemoryVault([[path, "bad text"]]);
    const host = testHost(vault);
    host.loadVaultKeys = vi.fn().mockResolvedValue(keys);
    host.settings.recoveryLog = [{
      recoveryId: "r" + "1".repeat(32),
      path,
      fileId,
      contentHash: "good",
      beforeContent: "start",
      afterContent: "good text",
      observedAtMs: 2,
      clientOpId: "c".repeat(64),
    }];
    host.settings.durableSyncState.index.files = [{
      fileId,
      path,
      kind: "markdown",
      contentHash: "bad",
      tombstone: false,
      lastLocalSeq: 0,
      lastRemoteSeq: 0,
      updatedAtMs: 1,
    }];
    const engine = new SyncEngine(host);

    await expect(engine.restoreLatestRecoveryForPath(path)).resolves.toBe(true);

    expect(vault.readText(path)).toBe("good text");
    expect(host.settings.recoveryLog.at(-1)?.afterContent).toBe("good text");
    expect(host.settings.durableSyncState.journal.at(-1)?.status).toBe("queued");
  });

  it("reports detailed sync status", () => {
    const host = testHost();
    host.settings.lastServerSeq = 12;
    host.settings.pendingBlobs = [{ blobId: "a".repeat(64), envelopeHex: "00" }];
    host.settings.pendingOps = [testOp("b".repeat(64))];
    host.settings.recoveryLog = [{
      recoveryId: "r" + "1".repeat(32),
      path: "Notes/a.md",
      fileId: "f" + "a".repeat(32),
      contentHash: "abcd",
      beforeContent: "",
      afterContent: "text",
      observedAtMs: 1,
      clientOpId: "b".repeat(64),
    }];
    host.settings.durableSyncState.journal = [{
      transitionId: "x" + "1".repeat(32),
      status: "queued",
      kind: "file-update",
      fileId: "f" + "a".repeat(32),
      path: "Notes/a.md",
      fileKind: "markdown",
      contentHash: "abcd",
      observedAtMs: 1,
      affectedPaths: ["Notes/a.md"],
    }];
    const engine = new SyncEngine(host);

    expect(engine.syncStatusSummary()).toContain("server seq 12");
    expect(engine.syncStatusSummary()).toContain("1 pending blobs");
    expect(engine.syncStatusSummary()).toContain("1 pending ops");
    expect(engine.syncStatusSummary()).toContain("1 queued local changes");
    expect(engine.syncStatusSummary()).toContain("1 recovery records");
  });
});

describe("markdown state updates", () => {
  it("can bootstrap a receiver even if earlier updates were not applied", () => {
    const path = "Notes/a.md";
    const localDoc = new Y.Doc();
    const localTree = localDoc.getMap<Y.Map<unknown>>("tree");
    encodeMarkdownUpsertUpdate(localDoc, localTree, path, "");
    const editUpdate = encodeMarkdownUpsertUpdate(localDoc, localTree, path, "hello");
    const remoteDoc = new Y.Doc();
    const remoteTree = remoteDoc.getMap<Y.Map<unknown>>("tree");

    Y.applyUpdate(remoteDoc, hexToBytes(editUpdate));

    const text = remoteTree.get(path)?.get("content");
    expect(text instanceof Y.Text ? text.toString() : "").toBe("hello");
  });
});

describe("websocket input validation", () => {
  it("parses only well-formed challenge payloads", () => {
    const payload = new TextEncoder().encode(JSON.stringify({ challenge_hex: "a".repeat(32) }));

    expect(parseWebSocketChallenge(payload)).toBe("a".repeat(32));
    expect(() => parseWebSocketChallenge(new TextEncoder().encode(JSON.stringify({ challenge_hex: "A".repeat(32) })))).toThrow("invalid websocket challenge");
    expect(() => parseWebSocketChallenge(new TextEncoder().encode(JSON.stringify({ challenge_hex: "a".repeat(31) })))).toThrow("invalid websocket challenge");
  });

  it("validates encrypted op broadcast records before applying them", () => {
    const op = testBroadcastOp();

    expect(() => validateRemoteOpRecord(op)).not.toThrow();
    expect(() => validateRemoteOpRecord({ ...op, server_seq: 0 })).toThrow("invalid op server seq");
    expect(() => validateRemoteOpRecord({ ...op, key_version: 2 })).toThrow("unsupported op key version");
    expect(() => validateRemoteOpRecord({ ...op, ciphertext_hex: "abc" })).toThrow("invalid op ciphertext");
    expect(() => validateRemoteOpRecord({ ...op, vault_id: "../vault" })).toThrow("invalid op vault id");
  });
});

describe("snapshot record validation", () => {
  it("accepts well-formed snapshot records for the expected vault", () => {
    expect(() => validateSnapshotRecord(testSnapshot(), "vault-a")).not.toThrow();
  });

  it("rejects malformed or wrong-vault snapshot records before restore", () => {
    const snapshot = testSnapshot();

    expect(() => validateSnapshotRecord({ ...snapshot, vault_id: "../vault" }, "vault-a")).toThrow("invalid snapshot vault id");
    expect(() => validateSnapshotRecord({ ...snapshot, vault_id: "vault-b" }, "vault-a")).toThrow("snapshot vault id mismatch");
    expect(() => validateSnapshotRecord({ ...snapshot, snapshot_id: "snapshot-a" }, "vault-a")).toThrow("invalid snapshot id");
    expect(() => validateSnapshotRecord({ ...snapshot, key_version: 2 }, "vault-a")).toThrow("unsupported snapshot key version");
    expect(() => validateSnapshotRecord({ ...snapshot, ciphertext_hex: "abc" }, "vault-a")).toThrow("invalid snapshot ciphertext");
  });
});

function testOp(clientOpId: string): PendingEncryptedOp {
  return {
    client_op_id: clientOpId,
    device_id: "d" + "1".repeat(32),
    lamport: 1,
    kind: 1,
    key_version: 1,
    nonce_hex: "00".repeat(24),
    ciphertext_hex: "11".repeat(32),
  };
}

function testBroadcastOp() {
  return {
    vault_id: "vault-a",
    server_seq: 1,
    client_op_id: "a".repeat(64),
    device_id: "d" + "1".repeat(32),
    lamport: 1,
    kind: 5,
    key_version: 1,
    nonce_hex: "00".repeat(24),
    ciphertext_hex: "11".repeat(32),
    accepted_at_unix: 123,
  };
}

function testSnapshot() {
  return {
    vault_id: "vault-a",
    snapshot_id: "a".repeat(32),
    device_id: "d" + "1".repeat(32),
    covers_through_seq: 10,
    key_version: 1,
    nonce_hex: "00".repeat(24),
    ciphertext_hex: "11".repeat(32),
    created_at_unix: 123,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

function v2Payload(overrides: Record<string, unknown>) {
  return {
    version: 2,
    kind: "file-update",
    fileId: "f" + "a".repeat(32),
    path: "Notes/a.md",
    fileKind: "markdown",
    updateHex: "00ff",
    contentHash: "abcd",
    ...overrides,
  };
}

function testHost(vault: MemoryVault | null = null) {
  return {
    app: {
      vault: vault ?? {
        getFiles: () => [],
        on: vi.fn(),
      },
      fileManager: {
        trashFile: async (file: TFile) => {
          await (vault as MemoryVault | null)?.delete(file);
        },
      },
    },
    settings: {
      serverUrl: "https://example.test",
      vaultId: "vault-a",
      deviceId: "d" + "1".repeat(32),
      lastServerSeq: 0,
      lamport: 0,
      pendingBlobs: [],
      pendingOps: [],
      recoveryLog: [],
      durableSyncState: {
        version: 1,
        index: { version: 1, files: [], tombstones: [] },
        journal: [],
      },
      debugLogging: false,
    },
    createApiClient: () => ({
      websocketUrl: () => "wss://example.test/ws",
      listOps: vi.fn().mockResolvedValue([]),
      putBlob: vi.fn().mockResolvedValue(undefined),
      appendOp: vi.fn().mockResolvedValue(undefined),
    }),
    debug: vi.fn(),
    loadVaultKeys: vi.fn(),
    registerEvent: vi.fn(),
    registerInterval: vi.fn(),
    saveSettings: vi.fn().mockResolvedValue(undefined),
    updateStatus: vi.fn(),
  } as unknown as ConstructorParameters<typeof SyncEngine>[0];
}

class MemoryVault {
  readonly files = new Map<string, string>();
  readonly binaries = new Map<string, Uint8Array>();

  constructor(initialFiles: [string, string][] = []) {
    for (const [path, content] of initialFiles) {
      this.files.set(path, content);
    }
  }

  getFiles(): TFile[] {
    return [...this.files.keys(), ...this.binaries.keys()].map((path) => testFile(path, path.split(".").pop() ?? ""));
  }

  on(): void {}

  getFileByPath(path: string): TFile | null {
    return this.files.has(path) || this.binaries.has(path) ? testFile(path, path.split(".").pop() ?? "") : null;
  }

  getFolderByPath(): object | null {
    return {};
  }

  async create(path: string, content: string): Promise<void> {
    this.files.set(path, content);
  }

  async modify(file: TFile, content: string): Promise<void> {
    this.files.set(file.path, content);
  }

  async read(file: TFile): Promise<string> {
    return this.files.get(file.path) ?? "";
  }

  async delete(file: TFile): Promise<void> {
    this.files.delete(file.path);
    this.binaries.delete(file.path);
  }

  async rename(file: TFile, newPath: string): Promise<void> {
    if (this.binaries.has(file.path)) {
      const content = this.binaries.get(file.path) ?? new Uint8Array();
      this.binaries.delete(file.path);
      this.binaries.set(newPath, content);
      return;
    }
    const content = this.files.get(file.path) ?? "";
    this.files.delete(file.path);
    this.files.set(newPath, content);
  }

  async createBinary(path: string, content: ArrayBuffer): Promise<void> {
    this.binaries.set(path, new Uint8Array(content));
  }

  async modifyBinary(file: TFile, content: ArrayBuffer): Promise<void> {
    this.binaries.set(file.path, new Uint8Array(content));
  }

  async readBinary(file: TFile): Promise<ArrayBuffer> {
    const bytes = this.binaries.get(file.path) ?? new Uint8Array();
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  }

  async createFolder(): Promise<void> {}

  readText(path: string): string | undefined {
    return this.files.get(path);
  }

  readBinaryBytes(path: string): Uint8Array | undefined {
    return this.binaries.get(path);
  }
}

function testFile(path: string, extension: string): TFile {
  const file = Object.create(TFile.prototype) as TFile & { path: string; extension: string };
  file.path = path;
  file.extension = extension;
  return file;
}

function callPrivate<T>(target: unknown, name: string, ...args: unknown[]): T {
  return (target as Record<string, (...args: unknown[]) => T>)[name](...args);
}

function opBroadcast(overrides: Partial<ReturnType<typeof testBroadcastOp>> = {}): ArrayBuffer {
  const op = { ...testBroadcastOp(), ...overrides };
  const encoded = encodeFrame({
    kind: ServerMsgKind.OpBroadcast,
    flags: 0,
    payload: new TextEncoder().encode(JSON.stringify(op)),
  });
  return encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength) as ArrayBuffer;
}

class MockWebSocket {
  binaryType: BinaryType = "blob";
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent<ArrayBuffer>) => void) | null = null;
  onopen: ((event: Event) => void) | null = null;

  constructor(readonly url: string) {}

  close(): void {
    this.onclose?.({} as CloseEvent);
  }

  send(): void {}
}

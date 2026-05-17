import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TFile } from "obsidian";
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
    const catchUp = vi.fn().mockResolvedValue(undefined);
    const applyRemoteOp = vi.fn().mockResolvedValue(undefined);
    (engine as unknown as { catchUp: typeof catchUp; applyRemoteOp: typeof applyRemoteOp }).catchUp = catchUp;
    (engine as unknown as { applyRemoteOp: typeof applyRemoteOp }).applyRemoteOp = applyRemoteOp;

    await callPrivate(engine, "handleSocketMessage", opBroadcast({ server_seq: 5 }));

    expect(catchUp).toHaveBeenCalledTimes(1);
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
});

describe("remote payload validation", () => {
  it("accepts well-formed v2 remote payloads", () => {
    expect(() => validateRemotePayload(v2Payload({ kind: "file-create", fileKind: "markdown", content: "hello" }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "markdown", contentUpdate: "00ff" }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "binary", blobId: "a".repeat(64), size: 12 }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-delete", tombstoneId: "t" + "b".repeat(32) }))).not.toThrow();
    expect(() => validateRemotePayload(v2Payload({ kind: "file-rename", oldPath: "Notes/a.md", newPath: "Notes/b.md" }))).not.toThrow();
  });

  it("rejects unsafe vault paths before applying remote writes", () => {
    expect(() => validateRemotePayload(v2Payload({ path: "../outside.md", kind: "file-delete", tombstoneId: "t" + "b".repeat(32) }))).toThrow("invalid vault path");
    expect(() => validateRemotePayload(v2Payload({ path: "/absolute.md", kind: "file-create", fileKind: "markdown", content: "hello" }))).toThrow("invalid vault path");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-rename", oldPath: "Notes/a.md", newPath: "Notes/../b.md" }))).toThrow("invalid vault path");
  });

  it("rejects legacy and malformed v2 payloads", () => {
    expect(() => validateRemotePayload({ kind: "file-update", path: "Notes/a.md" })).toThrow("unsupported remote payload version");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "markdown", contentUpdate: "abc" }))).toThrow("invalid v2 content update");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "binary", blobId: "blob-a", size: 1 }))).toThrow("invalid v2 blob id");
    expect(() => validateRemotePayload(v2Payload({ kind: "file-update", fileKind: "binary", blobId: "a".repeat(64), size: -1 }))).toThrow("invalid v2 binary size");
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

function v2Payload(overrides: Record<string, unknown>) {
  return {
    version: 2,
    kind: "file-update",
    fileId: "f" + "a".repeat(32),
    path: "Notes/a.md",
    fileKind: "markdown",
    contentHash: "abcd",
    ...overrides,
  };
}

function testHost() {
  return {
    app: {
      vault: {
        getFiles: () => [],
        on: vi.fn(),
      },
    },
    settings: {
      serverUrl: "https://example.test",
      vaultId: "vault-a",
      deviceId: "d" + "1".repeat(32),
      lastServerSeq: 0,
      lamport: 0,
      pendingOps: [],
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
    }),
    debug: vi.fn(),
    loadVaultKeys: vi.fn(),
    registerEvent: vi.fn(),
    registerInterval: vi.fn(),
    saveSettings: vi.fn().mockResolvedValue(undefined),
    updateStatus: vi.fn(),
  } as unknown as ConstructorParameters<typeof SyncEngine>[0];
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

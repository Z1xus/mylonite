import { describe, expect, it } from "vitest";
import {
  parseWebSocketChallenge,
  racedPaths,
  retainUnflushedPendingOps,
  validateRemoteOpRecord,
  validateRemotePayload,
  validateSnapshotRecord,
} from "./sync-engine";
import { PendingEncryptedOp } from "./sync-types";

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

describe("remote payload validation", () => {
  it("accepts well-formed remote payloads", () => {
    expect(() => validateRemotePayload({ kind: "markdown-upsert", path: "Notes/a.md", content: "hello" })).not.toThrow();
    expect(() => validateRemotePayload({ kind: "yjs-update", updateHex: "00ff", changedPaths: ["Notes/a.md"] })).not.toThrow();
    expect(() => validateRemotePayload({ kind: "blob-ref", path: "assets/a.png", blobId: "a".repeat(64), size: 12 })).not.toThrow();
    expect(() => validateRemotePayload({ kind: "file-delete", path: "Notes/a.md" })).not.toThrow();
    expect(() => validateRemotePayload({ kind: "file-rename", oldPath: "Notes/a.md", newPath: "Notes/b.md" })).not.toThrow();
  });

  it("rejects unsafe vault paths before applying remote writes", () => {
    expect(() => validateRemotePayload({ kind: "file-delete", path: "../outside.md" })).toThrow("invalid vault path");
    expect(() => validateRemotePayload({ kind: "markdown-upsert", path: "/absolute.md", content: "hello" })).toThrow("invalid vault path");
    expect(() => validateRemotePayload({ kind: "file-rename", oldPath: "Notes/a.md", newPath: "Notes/../b.md" })).toThrow("invalid vault path");
  });

  it("rejects malformed yjs and blob-ref payloads", () => {
    expect(() => validateRemotePayload({ kind: "yjs-update", updateHex: "abc", changedPaths: ["Notes/a.md"] })).toThrow("invalid yjs update payload");
    expect(() => validateRemotePayload({ kind: "yjs-update", updateHex: "00", changedPaths: [] })).toThrow("invalid yjs changed paths");
    expect(() => validateRemotePayload({ kind: "blob-ref", path: "assets/a.png", blobId: "blob-a", size: 1 })).toThrow("invalid blob-ref payload blob id");
    expect(() => validateRemotePayload({ kind: "blob-ref", path: "assets/a.png", blobId: "a".repeat(64), size: -1 })).toThrow("invalid blob-ref payload size");
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

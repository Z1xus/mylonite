import { describe, expect, it } from "vitest";

import { SnapshotRecord } from "./api";
import { VaultKeys } from "./crypto";
import { decryptSnapshot, encryptSnapshot } from "./sync-codec";
import { createEncryptedSnapshot, restoreEncryptedSnapshot, validateSnapshotPayload } from "./snapshot-service";
import { SnapshotPayload } from "./sync-types";

const keys: VaultKeys = {
  opKey: new Uint8Array(32).fill(1),
  blobKey: new Uint8Array(32).fill(2),
  blobIdKey: new Uint8Array(32).fill(3),
  snapshotKey: new Uint8Array(32).fill(4),
};

interface FakeFile {
  path: string;
  extension: string;
  content: string;
}

function fakeVault(initialFiles: FakeFile[]) {
  const files = new Map(initialFiles.map((file) => [file.path, { ...file }]));
  return {
    files,
    fileManager: {
      trashFile: async (file: FakeFile) => {
        files.delete(file.path);
      },
    },
    vault: {
      getFiles: () => [...files.values()],
      getFileByPath: (path: string) => files.get(path) ?? null,
      getFolderByPath: () => ({}),
      read: async (file: FakeFile) => file.content,
      modify: async (file: FakeFile, content: string) => {
        file.content = content;
      },
      create: async (path: string, content: string) => {
        files.set(path, { path, extension: path.split(".").at(-1) ?? "", content });
      },
    },
  };
}

function snapshotRecord(payload: SnapshotPayload): SnapshotRecord {
  const encrypted = encryptSnapshot(keys, "vault-a", "snapshot-a", 7, payload);
  return {
    vault_id: "vault-a",
    snapshot_id: "snapshot-a",
    device_id: "device-a",
    covers_through_seq: 7,
    key_version: 1,
    nonce_hex: encrypted.nonceHex,
    ciphertext_hex: encrypted.ciphertextHex,
    created_at_unix: 1,
  };
}

describe("snapshot restore", () => {
  it("keeps local files absent from the snapshot by default", async () => {
    const { files, fileManager, vault } = fakeVault([
      { path: "keep.md", extension: "md", content: "old" },
      { path: "local-only.md", extension: "md", content: "local" },
    ]);
    const snapshot = snapshotRecord({
      version: 1,
      entries: [{ kind: "markdown", path: "keep.md", content: "new" }],
    });

    await restoreEncryptedSnapshot(vault as never, fileManager as never, new Set(), keys, "vault-a", snapshot, async () => new Uint8Array());

    expect(files.get("keep.md")?.content).toBe("new");
    expect(files.has("local-only.md")).toBe(true);
  });

  it("deletes local files absent from the snapshot when requested", async () => {
    const { files, fileManager, vault } = fakeVault([
      { path: "keep.md", extension: "md", content: "old" },
      { path: "local-only.md", extension: "md", content: "local" },
    ]);
    const snapshot = snapshotRecord({
      version: 1,
      entries: [{ kind: "markdown", path: "keep.md", content: "new" }],
    });

    await restoreEncryptedSnapshot(vault as never, fileManager as never, new Set(), keys, "vault-a", snapshot, async () => new Uint8Array(), true);

    expect(files.get("keep.md")?.content).toBe("new");
    expect(files.has("local-only.md")).toBe(false);
  });

  it("rejects binary snapshot entries whose decrypted blob size differs from metadata", async () => {
    const { fileManager, vault } = fakeVault([]);
    const snapshot = snapshotRecord({
      version: 1,
      entries: [{ kind: "binary", path: "assets/a.bin", blobId: "a".repeat(64), size: 4 }],
    });

    await expect(restoreEncryptedSnapshot(
      vault as never,
      fileManager as never,
      new Set(),
      keys,
      "vault-a",
      snapshot,
      async () => new Uint8Array([1, 2, 3]),
    )).rejects.toThrow("snapshot binary size mismatch");
  });

  it("validates decrypted snapshot payloads before restore writes", () => {
    expect(() => validateSnapshotPayload({
      version: 1,
      entries: [
        { kind: "markdown", path: "notes/a.md", content: "hello" },
        { kind: "binary", path: "assets/a.png", blobId: "a".repeat(64), size: 12 },
      ],
    })).not.toThrow();

    expect(() => validateSnapshotPayload({
      version: 2,
      entries: [],
    })).toThrow("invalid snapshot payload");
    expect(() => validateSnapshotPayload({
      version: 1,
      entries: [{ kind: "markdown", path: "../outside.md", content: "bad" }],
    })).toThrow("invalid snapshot path");
    expect(() => validateSnapshotPayload({
      version: 1,
      entries: [{ kind: "binary", path: "assets/a.png", blobId: "blob-a", size: 1 }],
    })).toThrow("invalid snapshot binary blob id");
    expect(() => validateSnapshotPayload({
      version: 1,
      entries: [{ kind: "binary", path: "assets/a.png", blobId: "a".repeat(64), size: -1 }],
    })).toThrow("invalid snapshot binary size");
  });
});

describe("snapshot creation", () => {
  it("stores an authoritative state index for snapshot entries", async () => {
    const { vault } = fakeVault([
      { path: "notes/a.md", extension: "md", content: "hello" },
    ]);

    const encrypted = await createEncryptedSnapshot(
      vault as never,
      keys,
      "vault-a",
      12,
      async () => undefined,
      { version: 1, files: [], tombstones: [] },
    );
    const payload = decryptSnapshot<SnapshotPayload>(
      keys,
      "vault-a",
      encrypted.snapshotId,
      12,
      encrypted.nonceHex,
      encrypted.ciphertextHex,
    );

    expect(payload.state?.files).toHaveLength(1);
    expect(payload.state?.files[0]?.path).toBe("notes/a.md");
    expect(payload.state?.files[0]?.fileId).toBe(payload.entries[0]?.fileId);
  });
});

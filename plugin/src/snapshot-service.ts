import { TFile, Vault } from "obsidian";

import { SnapshotRecord } from "./api";
import { VaultKeys, randomHex } from "./crypto";
import { decryptSnapshot, encryptBlob, encryptSnapshot } from "./sync-codec";
import { SnapshotBinaryEntry, SnapshotEntry, SnapshotPayload } from "./sync-types";
import { applyBinaryUpsert, applyMarkdownUpsert, normalizeVaultPath } from "./vault-adapter";
import { VaultStateIndex } from "./state-index";
import { hashBytes, hashText, newFileId, VaultStateSnapshot } from "./sync-state";

export interface EncryptedSnapshotUpload {
  snapshotId: string;
  nonceHex: string;
  ciphertextHex: string;
}

export async function createEncryptedSnapshot(
  vault: Vault,
  keys: VaultKeys,
  vaultId: string,
  coversThroughSeq: number,
  putBlob: (blobId: string, bytes: Uint8Array) => Promise<void>,
  state?: VaultStateSnapshot,
): Promise<EncryptedSnapshotUpload> {
  const entries: SnapshotEntry[] = [];
  const index = VaultStateIndex.fromSnapshot(state);
  for (const file of vault.getFiles()) {
    const path = normalizeVaultPath(file.path, "invalid snapshot path");
    if (file.extension === "md") {
      const content = await vault.read(file);
      const contentHash = hashText(content);
      const fileId = index.byPath(path)?.fileId ?? newFileId();
      entries.push({ kind: "markdown", path, fileId, contentHash, content });
      continue;
    }
    const bytes = new Uint8Array(await vault.readBinary(file as TFile));
    const { blobId, envelope } = encryptBlob(keys, vaultId, bytes);
    await putBlob(blobId, envelope);
    entries.push({ kind: "binary", path, fileId: index.byPath(path)?.fileId ?? newFileId(), contentHash: hashBytes(bytes), blobId, size: bytes.byteLength });
  }

  const snapshotId = randomHex(16);
  const encrypted = encryptSnapshot(keys, vaultId, snapshotId, coversThroughSeq, {
    version: 1,
    entries,
    state: state ?? { version: 1, files: [], tombstones: [] },
  });
  return {
    snapshotId,
    nonceHex: encrypted.nonceHex,
    ciphertextHex: encrypted.ciphertextHex,
  };
}

export async function restoreEncryptedSnapshot(
  vault: Vault,
  suppressedPaths: Set<string>,
  keys: VaultKeys,
  vaultId: string,
  snapshot: SnapshotRecord,
  loadBlob: (entry: SnapshotBinaryEntry) => Promise<Uint8Array>,
  deleteMissing = false,
): Promise<SnapshotPayload> {
  const payload = decryptSnapshot<SnapshotPayload>(
    keys,
    vaultId,
    snapshot.snapshot_id,
    snapshot.covers_through_seq,
    snapshot.nonce_hex,
    snapshot.ciphertext_hex,
  );
  validateSnapshotPayload(payload);
  const snapshotPaths = new Set(payload.entries.map((entry) => normalizeVaultPath(entry.path, "invalid snapshot path")));
  for (const entry of payload.entries) {
    if (entry.kind === "markdown") {
      await applyMarkdownUpsert(vault, suppressedPaths, entry.path, entry.content);
    } else {
      const bytes = await loadBlob(entry);
      if (bytes.byteLength !== entry.size) {
        throw new Error("snapshot binary size mismatch");
      }
      await applyBinaryUpsert(vault, suppressedPaths, entry.path, bytes);
    }
  }
  if (!deleteMissing) {
    return payload;
  }
  for (const file of vault.getFiles()) {
    const path = normalizeVaultPath(file.path, "invalid snapshot path");
    if (!snapshotPaths.has(path)) {
      suppressedPaths.add(path);
      await vault.delete(file);
    }
  }
  return payload;
}

export function validateSnapshotPayload(payload: unknown): asserts payload is SnapshotPayload {
  if (!isRecord(payload) || payload.version !== 1 || !Array.isArray(payload.entries) || payload.entries.length > 100_000) {
    throw new Error("invalid snapshot payload");
  }
  for (const entry of payload.entries) {
    if (!isRecord(entry) || typeof entry.kind !== "string") {
      throw new Error("invalid snapshot entry");
    }
    normalizeVaultPath(entry.path, "invalid snapshot path");
    if (entry.kind === "markdown") {
      if (typeof entry.content !== "string") {
        throw new Error("invalid snapshot markdown content");
      }
      continue;
    }
    if (entry.kind === "binary") {
      if (typeof entry.blobId !== "string" || !/^[0-9a-f]{64}$/.test(entry.blobId)) {
        throw new Error("invalid snapshot binary blob id");
      }
      if (typeof entry.size !== "number" || !Number.isSafeInteger(entry.size) || entry.size < 0) {
        throw new Error("invalid snapshot binary size");
      }
      continue;
    }
    throw new Error("unsupported snapshot entry kind");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

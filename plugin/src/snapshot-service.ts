import { FileManager, TFile, Vault } from "obsidian";

import { SnapshotRecord } from "./api";
import { VaultKeys, randomHex } from "./crypto";
import { decryptSnapshot, encryptBlob, encryptSnapshot } from "./sync-codec";
import { SnapshotBinaryEntry, SnapshotEntry, SnapshotPayload } from "./sync-types";
import { applyBinaryUpsert, applyMarkdownUpsert, normalizeVaultPath } from "./vault-adapter";
import { VaultStateIndex } from "./state-index";
import { hashBytes, hashText, newFileId, VaultStateSnapshot } from "./sync-state";
import { yieldToObsidian } from "./ui-yield";

const SLOW_SNAPSHOT_FILE_MS = 50;
const SNAPSHOT_FILES_PER_UI_YIELD = 4;

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
  debug?: (message: string) => void,
): Promise<EncryptedSnapshotUpload> {
  const entries: SnapshotEntry[] = [];
  const index = VaultStateIndex.fromSnapshot(state);
  const snapshotIndex = new VaultStateIndex();
  const now = Date.now();
  const files = vault.getFiles();
  for (const [fileIndex, file] of files.entries()) {
    if (fileIndex > 0 && fileIndex % SNAPSHOT_FILES_PER_UI_YIELD === 0) {
      await yieldToObsidian();
    }
    const started = performance.now();
    const path = normalizeVaultPath(file.path, "invalid snapshot path");
    if (file.extension === "md") {
      const content = await vault.read(file);
      const contentHash = hashText(content);
      const previous = index.byPath(path);
      const fileId = previous?.fileId ?? newFileId();
      entries.push({ kind: "markdown", path, fileId, contentHash, content });
      snapshotIndex.upsertFile({
        fileId,
        path,
        kind: "markdown",
        contentHash,
        tombstone: false,
        lastLocalSeq: previous?.lastLocalSeq ?? 0,
        lastRemoteSeq: Math.max(previous?.lastRemoteSeq ?? 0, coversThroughSeq),
        updatedAtMs: previous?.updatedAtMs ?? now,
      });
      logSlowSnapshotFile("snapshot read markdown", path, started, debug);
      continue;
    }
    if (!(file instanceof TFile)) {
      continue;
    }
    const bytes = new Uint8Array(await vault.readBinary(file));
    await yieldToObsidian();
    const { blobId, envelope } = encryptBlob(keys, vaultId, bytes);
    await putBlob(blobId, envelope);
    const previous = index.byPath(path);
    const fileId = previous?.fileId ?? newFileId();
    const contentHash = hashBytes(bytes);
    entries.push({ kind: "binary", path, fileId, contentHash, blobId, size: bytes.byteLength });
    snapshotIndex.upsertFile({
      fileId,
      path,
      kind: "binary",
      contentHash,
      blobId,
      size: bytes.byteLength,
      tombstone: false,
      lastLocalSeq: previous?.lastLocalSeq ?? 0,
      lastRemoteSeq: Math.max(previous?.lastRemoteSeq ?? 0, coversThroughSeq),
      updatedAtMs: previous?.updatedAtMs ?? now,
    });
    logSlowSnapshotFile("snapshot read binary", path, started, debug);
  }
  const snapshotState = snapshotIndex.toSnapshot();

  const snapshotId = randomHex(16);
  await yieldToObsidian();
  const encrypted = encryptSnapshot(keys, vaultId, snapshotId, coversThroughSeq, {
    version: 1,
    entries,
    state: { ...snapshotState, tombstones: state?.tombstones ?? [] },
  });
  return {
    snapshotId,
    nonceHex: encrypted.nonceHex,
    ciphertextHex: encrypted.ciphertextHex,
  };
}

export async function restoreEncryptedSnapshot(
  vault: Vault,
  fileManager: FileManager,
  suppressedPaths: Set<string>,
  keys: VaultKeys,
  vaultId: string,
  snapshot: SnapshotRecord,
  loadBlob: (entry: SnapshotBinaryEntry) => Promise<Uint8Array>,
  deleteMissing = false,
  debug?: (message: string) => void,
  skipPaths: ReadonlySet<string> = new Set(),
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
  for (const [entryIndex, entry] of payload.entries.entries()) {
    if (entryIndex > 0 && entryIndex % SNAPSHOT_FILES_PER_UI_YIELD === 0) {
      await yieldToObsidian();
    }
    const started = performance.now();
    if (skipPaths.has(normalizeVaultPath(entry.path, "invalid snapshot path"))) {
      continue;
    }
    if (entry.kind === "markdown") {
      await applyMarkdownUpsert(vault, suppressedPaths, entry.path, entry.content);
      logSlowSnapshotFile("snapshot restore markdown", entry.path, started, debug);
    } else {
      const bytes = await loadBlob(entry);
      if (bytes.byteLength !== entry.size) {
        throw new Error("snapshot binary size mismatch");
      }
      await applyBinaryUpsert(vault, suppressedPaths, entry.path, bytes);
      logSlowSnapshotFile("snapshot restore binary", entry.path, started, debug);
    }
  }
  if (!deleteMissing) {
    return payload;
  }
  const files = vault.getFiles();
  for (const [fileIndex, file] of files.entries()) {
    if (fileIndex > 0 && fileIndex % SNAPSHOT_FILES_PER_UI_YIELD === 0) {
      await yieldToObsidian();
    }
    const path = normalizeVaultPath(file.path, "invalid snapshot path");
    if (!snapshotPaths.has(path) && !skipPaths.has(path)) {
      suppressedPaths.add(path);
      await fileManager.trashFile(file);
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

function logSlowSnapshotFile(label: string, path: string, started: number, debug?: (message: string) => void): void {
  const elapsedMs = performance.now() - started;
  if (elapsedMs >= SLOW_SNAPSHOT_FILE_MS && debug) {
    debug(`slow sync span ${label} ${path}: ${elapsedMs.toFixed(1)}ms`);
  }
}

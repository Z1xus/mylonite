import { normalizeVaultPath } from "./vault-adapter";
import {
  FileKind,
  VaultFileState,
  VaultStateSnapshot,
  VaultTombstone,
  emptyVaultStateSnapshot,
  newTombstoneId,
} from "./sync-state";

const MAX_TOMBSTONES = 4096;

export class VaultStateIndex {
  private readonly filesById = new Map<string, VaultFileState>();
  private readonly fileIdsByPath = new Map<string, string>();
  private tombstones: VaultTombstone[] = [];

  static fromSnapshot(snapshot: VaultStateSnapshot | undefined): VaultStateIndex {
    const index = new VaultStateIndex();
    if (!snapshot || snapshot.version !== 1) {
      return index;
    }
    for (const file of snapshot.files) {
      if (isValidFileState(file)) {
        index.upsertFile(file);
      }
    }
    index.tombstones = snapshot.tombstones.filter(isValidTombstone).slice(-MAX_TOMBSTONES);
    return index;
  }

  toSnapshot(): VaultStateSnapshot {
    return {
      version: 1,
      files: Array.from(this.filesById.values()).map((file) => ({ ...file })),
      tombstones: this.tombstones.map((tombstone) => ({ ...tombstone })),
    };
  }

  ensureFile(path: string, kind: FileKind, contentHash: string, fileId: string, now = Date.now()): VaultFileState {
    const normalizedPath = normalizeVaultPath(path);
    const existingId = this.fileIdsByPath.get(normalizedPath);
    if (existingId) {
      const existing = this.filesById.get(existingId);
      if (existing) {
        const updated = { ...existing, kind, contentHash, tombstone: false, updatedAtMs: now };
        this.upsertFile(updated);
        return updated;
      }
    }
    const file: VaultFileState = {
      fileId,
      path: normalizedPath,
      kind,
      contentHash,
      tombstone: false,
      lastLocalSeq: 0,
      lastRemoteSeq: 0,
      updatedAtMs: now,
    };
    this.upsertFile(file);
    return file;
  }

  upsertFile(file: VaultFileState): void {
    const path = normalizeVaultPath(file.path);
    const previous = this.filesById.get(file.fileId);
    if (previous && previous.path !== path) {
      this.fileIdsByPath.delete(previous.path);
    }
    const occupant = this.fileIdsByPath.get(path);
    if (occupant && occupant !== file.fileId) {
      this.filesById.delete(occupant);
    }
    const normalized = { ...file, path, tombstone: false };
    this.filesById.set(normalized.fileId, normalized);
    this.fileIdsByPath.set(path, normalized.fileId);
  }

  renameFile(fileId: string, oldPath: string, newPath: string, now = Date.now()): VaultFileState | null {
    const file = this.filesById.get(fileId) ?? this.byPath(oldPath);
    if (!file) {
      return null;
    }
    const normalizedNewPath = normalizeVaultPath(newPath);
    this.fileIdsByPath.delete(file.path);
    const renamed = { ...file, path: normalizedNewPath, updatedAtMs: now, tombstone: false };
    this.upsertFile(renamed);
    return renamed;
  }

  deleteFile(fileId: string, path: string, now = Date.now(), tombstoneId = newTombstoneId()): VaultTombstone {
    const file = this.filesById.get(fileId) ?? this.byPath(path);
    const normalizedPath = normalizeVaultPath(file?.path ?? path);
    if (file) {
      this.filesById.delete(file.fileId);
      this.fileIdsByPath.delete(file.path);
    }
    const tombstone = { fileId, path: normalizedPath, tombstoneId, deletedAtMs: now };
    this.tombstones.push(tombstone);
    this.tombstones = this.tombstones.slice(-MAX_TOMBSTONES);
    return tombstone;
  }

  byFileId(fileId: string): VaultFileState | undefined {
    return this.filesById.get(fileId);
  }

  byPath(path: string): VaultFileState | undefined {
    const fileId = this.fileIdsByPath.get(normalizeVaultPath(path));
    return fileId ? this.filesById.get(fileId) : undefined;
  }

  findCurrentByHash(contentHash: string, kind?: FileKind): VaultFileState | undefined {
    return Array.from(this.filesById.values()).find((file) => file.contentHash === contentHash && (kind === undefined || file.kind === kind));
  }

  latestTombstoneForPath(path: string): VaultTombstone | undefined {
    const normalizedPath = normalizeVaultPath(path);
    return [...this.tombstones].reverse().find((tombstone) => tombstone.path === normalizedPath);
  }
}

function isValidFileState(value: VaultFileState): boolean {
  return typeof value.fileId === "string"
    && typeof value.path === "string"
    && (value.kind === "markdown" || value.kind === "binary")
    && typeof value.contentHash === "string"
    && !value.tombstone;
}

function isValidTombstone(value: VaultTombstone): boolean {
  return typeof value.fileId === "string" && typeof value.path === "string" && typeof value.tombstoneId === "string";
}

export function defaultStateIndex(): VaultStateIndex {
  return VaultStateIndex.fromSnapshot(emptyVaultStateSnapshot());
}

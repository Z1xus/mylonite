import { VaultStateIndex } from "./state-index";
import {
  FileKind,
  SyncJournalEntry,
  hashBytes,
  hashText,
  newFileId,
  newTombstoneId,
  newTransitionId,
} from "./sync-state";
import { normalizeVaultPath } from "./vault-adapter";

export interface FileObservation {
  path: string;
  kind: FileKind;
  content: string | Uint8Array;
  blobId?: string;
  size?: number;
  mtimeMs?: number;
}

export class LocalEventClassifier {
  constructor(private readonly index: VaultStateIndex) {}

  classifyCreate(observation: FileObservation, now = Date.now()): SyncJournalEntry {
    const path = normalizeVaultPath(observation.path);
    const contentHash = observationHash(observation);
    const copiedFrom = this.index.findCurrentByHash(contentHash, observation.kind);
    const fileId = newFileId();
    const file = this.index.ensureFile(path, observation.kind, contentHash, fileId, now);
    this.index.upsertFile(withObservedContentRef(file, observation));
    return baseEntry({
      kind: copiedFrom ? "file-copy" : "file-create",
      fileId,
      sourceFileId: copiedFrom?.fileId,
      path,
      fileKind: observation.kind,
      contentHash,
      observedAtMs: now,
      affectedPaths: [path],
    });
  }

  classifyModify(observation: FileObservation, now = Date.now()): SyncJournalEntry {
    const path = normalizeVaultPath(observation.path);
    const contentHash = observationHash(observation);
    const existing = this.index.byPath(path) ?? this.index.ensureFile(path, observation.kind, contentHash, newFileId(), now);
    const updated = withObservedContentRef({ ...existing, kind: observation.kind, contentHash, updatedAtMs: now }, observation);
    this.index.upsertFile(updated);
    return baseEntry({
      kind: "file-update",
      fileId: updated.fileId,
      path,
      fileKind: observation.kind,
      contentHash,
      baseHash: existing.contentHash,
      observedAtMs: now,
      affectedPaths: [path],
    });
  }

  classifyRename(oldPath: string, observation: FileObservation, now = Date.now()): SyncJournalEntry {
    const normalizedOldPath = normalizeVaultPath(oldPath);
    const normalizedNewPath = normalizeVaultPath(observation.path);
    const contentHash = observationHash(observation);
    const existing = this.index.byPath(normalizedOldPath)
      ?? this.index.findCurrentByHash(contentHash, observation.kind)
      ?? this.index.ensureFile(normalizedNewPath, observation.kind, contentHash, newFileId(), now);
    this.index.renameFile(existing.fileId, normalizedOldPath, normalizedNewPath, now);
    const current = this.index.byFileId(existing.fileId);
    if (current) {
      this.index.upsertFile(withObservedContentRef({ ...current, contentHash, kind: observation.kind, updatedAtMs: now }, observation));
    }
    return baseEntry({
      kind: "file-rename",
      fileId: existing.fileId,
      path: normalizedNewPath,
      oldPath: normalizedOldPath,
      newPath: normalizedNewPath,
      fileKind: observation.kind,
      contentHash,
      observedAtMs: now,
      affectedPaths: [normalizedOldPath, normalizedNewPath],
    });
  }

  classifyDelete(path: string, kind: FileKind, now = Date.now()): SyncJournalEntry {
    const normalizedPath = normalizeVaultPath(path);
    const existing = this.index.byPath(normalizedPath);
    const tombstoneId = newTombstoneId();
    const fileId = existing?.fileId ?? this.index.latestTombstoneForPath(normalizedPath)?.fileId ?? newFileId();
    const contentHash = existing?.contentHash ?? "";
    this.index.deleteFile(fileId, normalizedPath, now, tombstoneId);
    return baseEntry({
      kind: "file-delete",
      fileId,
      path: normalizedPath,
      fileKind: kind,
      contentHash,
      tombstoneId,
      observedAtMs: now,
      affectedPaths: [normalizedPath],
    });
  }
}

function observationHash(observation: FileObservation): string {
  return typeof observation.content === "string" ? hashText(observation.content) : hashBytes(observation.content);
}

function withObservedContentRef<T extends { kind: FileKind; blobId?: string; size?: number; mtimeMs?: number }>(file: T, observation: FileObservation): T {
  if (observation.kind !== "binary") {
    return { ...file, blobId: undefined, size: undefined, mtimeMs: observation.mtimeMs };
  }
  return {
    ...file,
    blobId: observation.blobId,
    size: observation.size,
    mtimeMs: observation.mtimeMs,
  };
}

function baseEntry(entry: Omit<SyncJournalEntry, "transitionId" | "status">): SyncJournalEntry {
  return {
    ...entry,
    transitionId: newTransitionId(),
    status: "classified",
  };
}

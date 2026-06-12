import { VaultStateIndex } from "./state-index";
import { RemoteV2Payload } from "./sync-types";
import { conflictPath, normalizeVaultPath } from "./vault-adapter";

export type ConflictDecision =
  | { action: "apply"; path: string }
  | { action: "conflict-path"; path: string; reason: string }
  | { action: "skip-local-wins"; reason: string };

export function decideRemoteV2Apply(index: VaultStateIndex, payload: RemoteV2Payload, localDirtyFileIds: ReadonlySet<string>): ConflictDecision {
  if (payload.kind === "file-delete") {
    if (localDirtyFileIds.has(payload.fileId)) {
      return { action: "skip-local-wins", reason: "remote delete overlaps local edits" };
    }
    return { action: "apply", path: index.byFileId(payload.fileId)?.path ?? normalizeVaultPath(payload.path) };
  }
  if (payload.kind === "file-rename") {
    const targetPath = normalizeVaultPath(payload.newPath);
    const occupant = index.byPath(targetPath);
    if (!occupant || occupant.fileId === payload.fileId) {
      return { action: "apply", path: targetPath };
    }
    if (localDirtyFileIds.has(occupant.fileId) || localDirtyFileIds.has(payload.fileId)) {
      return { action: "conflict-path", path: conflictPath(targetPath, payload.fileId), reason: "remote rename target is occupied" };
    }
    return { action: "apply", path: targetPath };
  }
  const fileId = payload.kind === "file-copy" ? payload.newFileId : payload.fileId;
  const targetPath = payload.kind === "file-update"
    ? index.byFileId(fileId)?.path ?? normalizeVaultPath(payload.path)
    : normalizeVaultPath(payload.path);
  const occupant = index.byPath(targetPath);
  if (occupant && occupant.fileId !== fileId) {
    if (occupant.kind === payload.fileKind && occupant.contentHash === payload.contentHash && !localDirtyFileIds.has(occupant.fileId)) {
      return { action: "apply", path: targetPath };
    }
    return { action: "conflict-path", path: conflictPath(targetPath, fileId), reason: "remote path is occupied by another file" };
  }
  if (payload.kind === "file-update" && payload.fileKind === "binary" && localDirtyFileIds.has(fileId)) {
    return { action: "skip-local-wins", reason: "remote binary update overlaps local edits" };
  }
  return { action: "apply", path: targetPath };
}

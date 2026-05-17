import { VaultStateIndex } from "./state-index";
import { RemoteV2Payload } from "./sync-types";
import { normalizeVaultPath } from "./vault-adapter";

export type ConflictDecision =
  | { action: "apply" }
  | { action: "noop" }
  | { action: "conflict-path"; path: string; reason: string }
  | { action: "prompt"; reason: string };

export function decideRemoteV2Apply(index: VaultStateIndex, payload: RemoteV2Payload, localDirtyFileIds: ReadonlySet<string>): ConflictDecision {
  if (payload.kind === "file-delete" && localDirtyFileIds.has(payload.fileId)) {
    return { action: "prompt", reason: "remote delete overlaps local edits" };
  }
  if (payload.kind === "file-rename") {
    const occupant = index.byPath(payload.newPath);
    if (!occupant || occupant.fileId === payload.fileId) {
      return { action: "apply" };
    }
    if (localDirtyFileIds.has(occupant.fileId) || localDirtyFileIds.has(payload.fileId)) {
      return { action: "conflict-path", path: conflictPath(payload.newPath, payload.fileId), reason: "remote rename target is occupied" };
    }
    return { action: "apply" };
  }
  const occupant = index.byPath(payload.path);
  if (occupant && occupant.fileId !== payload.fileId) {
    return { action: "conflict-path", path: conflictPath(payload.path, payload.fileId), reason: "remote path is occupied by another file" };
  }
  if (payload.kind === "file-update" && localDirtyFileIds.has(payload.fileId) && payload.fileKind === "binary") {
    return { action: "prompt", reason: "remote binary update overlaps local edits" };
  }
  return { action: "apply" };
}

export function conflictPath(path: string, suffix: string): string {
  const normalized = normalizeVaultPath(path);
  const dot = normalized.lastIndexOf(".");
  const tag = ` conflict-${suffix.slice(0, 8)}`;
  if (dot <= normalized.lastIndexOf("/")) {
    return `${normalized}${tag}`;
  }
  return `${normalized.slice(0, dot)}${tag}${normalized.slice(dot)}`;
}

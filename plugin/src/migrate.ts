import { bytesToHex } from "./crypto";
import { LegacyHint } from "./sync-types";
import { FileStat } from "./vault-io";

/** Sync state kept in data.json by plugin 0.1.x. */
export const LEGACY_SETTING_KEYS = ["lamport", "lastServerSeq", "pendingBlobs", "pendingOps", "durableSyncState"] as const;

export interface LegacyState {
  /** Last op the old plugin applied. */
  cursor: number;
  /** Files the old plugin knew as synced, by path. */
  hints: Record<string, LegacyHint>;
}

const SETTLED = new Set(["acknowledged", "applied", "superseded"]);
const encoder = new TextEncoder();

/**
 * Reads the old sync state. Files with changes that never reached the server
 * get no hint, so they are never replaced during the upgrade.
 */
export function readLegacyState(stored: Record<string, unknown>): LegacyState | null {
  const durable = stored.durableSyncState as { index?: { files?: unknown[] }; journal?: unknown[] } | undefined;
  const cursor = stored.lastServerSeq;
  if (!durable && typeof cursor !== "number") {
    return null;
  }
  const hints: Record<string, LegacyHint> = {};
  for (const file of durable?.index?.files ?? []) {
    const value = file as { path?: unknown; contentHash?: unknown; blobId?: unknown; size?: unknown; mtimeMs?: unknown };
    if (typeof value.path === "string" && typeof value.contentHash === "string") {
      hints[value.path] = {
        hash: value.contentHash,
        blobId: typeof value.blobId === "string" ? value.blobId : undefined,
        size: typeof value.size === "number" ? value.size : undefined,
        mtime: typeof value.mtimeMs === "number" ? value.mtimeMs : undefined,
      };
    }
  }
  for (const entry of durable?.journal ?? []) {
    const value = entry as { status?: unknown; affectedPaths?: unknown };
    if (!SETTLED.has(String(value.status)) && Array.isArray(value.affectedPaths)) {
      for (const path of value.affectedPaths) {
        delete hints[String(path)];
      }
    }
  }
  return { cursor: typeof cursor === "number" && Number.isSafeInteger(cursor) ? cursor : 0, hints };
}

/** Paths named by an old op payload. */
export function legacyOpPaths(payload: unknown): string[] {
  const value = payload as { path?: unknown; oldPath?: unknown; newPath?: unknown } | null;
  return [value?.path, value?.oldPath, value?.newPath].filter((path): path is string => typeof path === "string");
}

export function isLegacyClean(hints: Record<string, LegacyHint>, path: string, content: string | Uint8Array, stat: FileStat): boolean {
  const hint = hints[path];
  if (!hint) {
    return false;
  }
  if (typeof content !== "string" && hint.mtime === stat.mtime && hint.size === stat.size) {
    return true;
  }
  return legacyHash(typeof content === "string" ? encoder.encode(content) : content) === hint.hash;
}

/** The content hash of plugin 0.1.x. */
function legacyHash(bytes: Uint8Array): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (const byte of bytes) {
    h1 ^= byte;
    h1 = Math.imul(h1, 0x01000193);
    h2 = Math.imul(h2 ^ byte, 0x85ebca6b);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setUint32(0, h1 >>> 0);
  new DataView(out.buffer).setUint32(4, h2 >>> 0);
  return bytesToHex(out);
}

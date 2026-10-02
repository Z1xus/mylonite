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
    const value = entry as { status?: unknown };
    if (!SETTLED.has(String(value.status))) {
      markLegacyEdit(hints, entry);
    }
  }
  return { cursor: typeof cursor === "number" && Number.isSafeInteger(cursor) ? cursor : 0, hints };
}

/**
 * Records a local edit that other devices may not have. An update keeps the
 * version it started from, so a matching remote version still counts as its
 * ancestor. Other changes drop the hint.
 */
export function markLegacyEdit(hints: Record<string, LegacyHint>, change: unknown): void {
  const value = change as { kind?: unknown; path?: unknown; oldPath?: unknown; newPath?: unknown; affectedPaths?: unknown; baseHash?: unknown } | null;
  const paths = [value?.path, value?.oldPath, value?.newPath, ...(Array.isArray(value?.affectedPaths) ? value.affectedPaths : [])]
    .filter((path): path is string => typeof path === "string");
  for (const path of new Set(paths)) {
    if (hints[path]?.dirty) {
      continue;
    }
    if (value?.kind === "file-update" && typeof value.baseHash === "string") {
      hints[path] = { hash: value.baseHash, dirty: true };
    } else {
      delete hints[path];
    }
  }
}

/** The local content is the version the old plugin synced, with no local edits since. */
export function isLegacyClean(hints: Record<string, LegacyHint>, path: string, content: string | Uint8Array, stat: FileStat): boolean {
  const hint = hints[path];
  if (!hint || hint.dirty) {
    return false;
  }
  if (typeof content !== "string" && hint.mtime === stat.mtime && hint.size === stat.size) {
    return true;
  }
  return legacyHash(toBytes(content)) === hint.hash;
}

/** The incoming content is the version the local copy grew from, so the local copy is newer. */
export function isLegacyAncestor(hints: Record<string, LegacyHint>, path: string, content: string | Uint8Array): boolean {
  const hint = hints[path];
  return hint !== undefined && legacyHash(toBytes(content)) === hint.hash;
}

function toBytes(content: string | Uint8Array): Uint8Array {
  return typeof content === "string" ? encoder.encode(content) : content;
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

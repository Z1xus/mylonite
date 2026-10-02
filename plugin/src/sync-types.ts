export type FileKind = "text" | "blob";

export interface FileRecord {
  id: string;
  /** Path on this device. Differs from `cpath` while a local move is pending. */
  path: string;
  /** Path the server log gives this file. Unset until the creating op is in the log. */
  cpath?: string;
  kind: FileKind;
  /** Last content synced with the disk: a text hash or a blob id. */
  hash: string;
  size: number;
  mtime: number;
  /** Content hash of the op that created the file, as recorded in the log. */
  initHash?: string;
  /** Device that sent the create op. */
  initDevice?: string;
  /** Content hash of this device's create op while it waits for the log. */
  pendingInitHash?: string;
  /** The text doc has remote edits that are not yet written to disk. */
  ahead?: boolean;
  /** Deleted here. Kept until the delete op is in the log, so path decisions match other devices. */
  deleted?: boolean;
}

/**
 * Sync ops, version 3. A `path` on a text or blob op marks the op that creates the file.
 * Server order decides paths and binary content, text content merges.
 */
export type SyncOp =
  | { v: 3; t: "text"; id: string; path?: string; hash?: string; update: Uint8Array }
  | { v: 3; t: "blob"; id: string; path?: string; blob?: string; size?: number }
  | { v: 3; t: "move"; id: string; path: string }
  | { v: 3; t: "delete"; id: string };

export interface OutboxEntry {
  key: number;
  opId: string;
  op: SyncOp;
}

/** What the v2 plugin knew was synced, used once to resolve differences after the upgrade. */
export interface LegacyHint {
  hash: string;
  blobId?: string;
  size?: number;
  mtime?: number;
}

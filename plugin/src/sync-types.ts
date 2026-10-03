export type FileKind = "text" | "blob";

export interface FileRecord {
  id: string;
  path: string;
  cpath?: string;
  kind: FileKind;
  hash: string;
  size: number;
  mtime: number;
  initHash?: string;
  initDevice?: string;
  pendingInitHash?: string;
  ahead?: boolean;
  sentHash?: string;
  deleted?: boolean;
}

export type SyncOp =
  | { v: 4; t: "text"; id: string; path?: string; hash?: string; update: Uint8Array }
  | { v: 4; t: "blob"; id: string; path?: string; blob?: string; size?: number }
  | { v: 4; t: "move"; id: string; path: string }
  | { v: 4; t: "delete"; id: string };

export interface OutboxEntry {
  key: number;
  opId: string;
  op: SyncOp;
}

export interface LegacyHint {
  hash: string;
  dirty?: boolean;
  blobId?: string;
  size?: number;
  mtime?: number;
}

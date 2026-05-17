import { SyncJournalEntry, VaultStateSnapshot } from "./sync-state";

export interface PendingEncryptedOp {
  client_op_id: string;
  device_id: string;
  lamport: number;
  kind: number;
  key_version: number;
  nonce_hex: string;
  ciphertext_hex: string;
}

export type RemotePayload = RemoteV2Payload;

export type RemoteV2Payload =
  | RemoteV2FileCreate
  | RemoteV2FileUpdate
  | RemoteV2FileRename
  | RemoteV2FileDelete
  | RemoteV2FileCopy;

export interface RemoteV2Base {
  version: 2;
  fileId: string;
  path: string;
}

export interface RemoteV2FileCreate extends RemoteV2Base {
  kind: "file-create";
  fileKind: "markdown" | "binary";
  content?: string;
  updateHex?: string;
  blobId?: string;
  size?: number;
  contentHash: string;
}

export interface RemoteV2FileUpdate extends RemoteV2Base {
  kind: "file-update";
  fileKind: "markdown" | "binary";
  contentUpdate?: string;
  blobId?: string;
  size?: number;
  baseHash?: string;
  contentHash: string;
}

export interface RemoteV2FileRename extends RemoteV2Base {
  kind: "file-rename";
  oldPath: string;
  newPath: string;
}

export interface RemoteV2FileDelete extends RemoteV2Base {
  kind: "file-delete";
  tombstoneId: string;
}

export interface RemoteV2FileCopy extends RemoteV2Base {
  kind: "file-copy";
  sourceFileId: string;
  newFileId: string;
  fileKind: "markdown" | "binary";
  content?: string;
  updateHex?: string;
  blobId?: string;
  size?: number;
  contentHash: string;
}

export type SnapshotEntry = SnapshotMarkdownEntry | SnapshotBinaryEntry;

export interface SnapshotPayload {
  version: number;
  entries: SnapshotEntry[];
  state?: VaultStateSnapshot;
}

export interface SnapshotMarkdownEntry {
  kind: "markdown";
  path: string;
  fileId?: string;
  contentHash?: string;
  content: string;
}

export interface SnapshotBinaryEntry {
  kind: "binary";
  path: string;
  fileId?: string;
  contentHash?: string;
  blobId: string;
  size: number;
}

export interface DurableSyncState {
  version: 1;
  index: VaultStateSnapshot;
  journal: SyncJournalEntry[];
}

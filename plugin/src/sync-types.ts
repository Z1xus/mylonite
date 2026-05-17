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
  fileKind: "markdown" | "binary";
}

export interface RemoteV2MarkdownBase extends RemoteV2Base {
  fileKind: "markdown";
  updateHex: string;
}

export interface RemoteV2BinaryBase extends RemoteV2Base {
  fileKind: "binary";
}

export type RemoteV2FileCreate = RemoteV2MarkdownFileCreate | RemoteV2BinaryFileCreate;

export interface RemoteV2MarkdownFileCreate extends RemoteV2MarkdownBase {
  kind: "file-create";
  contentHash: string;
}

export interface RemoteV2BinaryFileCreate extends RemoteV2BinaryBase {
  kind: "file-create";
  blobId: string;
  size: number;
  contentHash: string;
}

export type RemoteV2FileUpdate = RemoteV2MarkdownFileUpdate | RemoteV2BinaryFileUpdate;

export interface RemoteV2MarkdownFileUpdate extends RemoteV2MarkdownBase {
  kind: "file-update";
  baseHash?: string;
  contentHash: string;
}

export interface RemoteV2BinaryFileUpdate extends RemoteV2BinaryBase {
  kind: "file-update";
  blobId: string;
  size: number;
  baseHash?: string;
  contentHash: string;
}

export type RemoteV2FileRename = RemoteV2MarkdownFileRename | RemoteV2BinaryFileRename;

export interface RemoteV2MarkdownFileRename extends RemoteV2MarkdownBase {
  kind: "file-rename";
  oldPath: string;
  newPath: string;
  contentHash?: string;
}

export interface RemoteV2BinaryFileRename extends RemoteV2BinaryBase {
  kind: "file-rename";
  oldPath: string;
  newPath: string;
  contentHash?: string;
}

export type RemoteV2FileDelete = RemoteV2MarkdownFileDelete | RemoteV2BinaryFileDelete;

export interface RemoteV2MarkdownFileDelete extends RemoteV2MarkdownBase {
  kind: "file-delete";
  tombstoneId: string;
}

export interface RemoteV2BinaryFileDelete extends RemoteV2BinaryBase {
  kind: "file-delete";
  tombstoneId: string;
}

export type RemoteV2FileCopy = RemoteV2MarkdownFileCopy | RemoteV2BinaryFileCopy;

export interface RemoteV2MarkdownFileCopy extends RemoteV2MarkdownBase {
  kind: "file-copy";
  sourceFileId: string;
  newFileId: string;
  contentHash: string;
}

export interface RemoteV2BinaryFileCopy extends RemoteV2BinaryBase {
  kind: "file-copy";
  sourceFileId: string;
  newFileId: string;
  blobId: string;
  size: number;
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

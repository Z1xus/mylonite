export interface PendingEncryptedOp {
  client_op_id: string;
  device_id: string;
  lamport: number;
  kind: number;
  key_version: number;
  nonce_hex: string;
  ciphertext_hex: string;
}

export type RemotePayload = RemoteMarkdownUpsert | RemoteYjsUpdate | RemoteBlobRef | RemoteFileDelete | RemoteFileRename;

export interface RemoteMarkdownUpsert {
  kind: "markdown-upsert";
  path: string;
  content: string;
}

export interface RemoteYjsUpdate {
  kind: "yjs-update";
  updateHex: string;
  changedPaths: string[];
}

export interface RemoteBlobRef {
  kind: "blob-ref";
  path: string;
  blobId: string;
  nonceHex: string;
  size: number;
}

export interface RemoteFileDelete {
  kind: "file-delete";
  path: string;
}

export interface RemoteFileRename {
  kind: "file-rename";
  oldPath: string;
  newPath: string;
}

export type SnapshotEntry = SnapshotMarkdownEntry | SnapshotBinaryEntry;

export interface SnapshotPayload {
  version: number;
  entries: SnapshotEntry[];
}

export interface SnapshotMarkdownEntry {
  kind: "markdown";
  path: string;
  content: string;
}

export interface SnapshotBinaryEntry {
  kind: "binary";
  path: string;
  blobId: string;
  size: number;
}

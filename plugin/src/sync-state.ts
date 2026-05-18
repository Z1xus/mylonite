import { bytesToHex, randomHex } from "./crypto";

export type FileKind = "markdown" | "binary";
export type SyncTransitionStatus = "observed" | "classified" | "queued" | "acknowledged" | "applied";
export type SyncTransitionKind = "file-create" | "file-update" | "file-rename" | "file-delete" | "file-copy";

export interface VaultFileState {
  fileId: string;
  path: string;
  kind: FileKind;
  contentHash: string;
  blobId?: string;
  size?: number;
  tombstone: boolean;
  lastLocalSeq: number;
  lastRemoteSeq: number;
  updatedAtMs: number;
}

export interface VaultTombstone {
  fileId: string;
  path: string;
  tombstoneId: string;
  deletedAtMs: number;
}

export interface VaultStateSnapshot {
  version: 1;
  files: VaultFileState[];
  tombstones: VaultTombstone[];
}

export interface SyncJournalEntry {
  transitionId: string;
  clientOpId?: string;
  status: SyncTransitionStatus;
  kind: SyncTransitionKind;
  fileId: string;
  sourceFileId?: string;
  path: string;
  oldPath?: string;
  newPath?: string;
  fileKind: FileKind;
  contentHash: string;
  baseHash?: string;
  tombstoneId?: string;
  observedAtMs: number;
  affectedPaths: string[];
}

export function newFileId(): string {
  return `f${randomHex(16)}`;
}

export function newTombstoneId(): string {
  return `t${randomHex(16)}`;
}

export function newTransitionId(): string {
  return `x${randomHex(16)}`;
}

export function hashText(value: string): string {
  return hashBytes(new TextEncoder().encode(value));
}

export function hashBytes(bytes: Uint8Array): string {
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

export function emptyVaultStateSnapshot(): VaultStateSnapshot {
  return { version: 1, files: [], tombstones: [] };
}

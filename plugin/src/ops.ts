import { randomHex } from "./crypto";
import { SyncOp } from "./sync-types";
import { isValidVaultPath } from "./vault-io";

export type TextRefOp = { v: 4; t: "text"; id: string; path?: string; hash?: string; ref: string };
export type RemoteOp = SyncOp | TextRefOp;

export function newFileId(): string {
  return `f${randomHex(16)}`;
}

export function newOpId(): string {
  return randomHex(32);
}

export function toWire(op: SyncOp, ref?: string): Record<string, unknown> {
  if (op.t !== "text") {
    return op;
  }
  const { update, ...rest } = op;
  return ref ? { ...rest, ref } : { ...rest, u: toBase64(update) };
}

export function parseWire(value: unknown): RemoteOp | null {
  if (!isRecord(value) || value.v !== 4 || !isFileId(value.id)) {
    return null;
  }
  const id = value.id;
  const path = value.path;
  if (path !== undefined && !isValidVaultPath(path)) {
    return null;
  }
  switch (value.t) {
    case "text": {
      const hash = value.hash;
      if (path !== undefined && !isHex(hash, 32)) {
        return null;
      }
      const base = { v: 4, t: "text", id, ...(path === undefined ? {} : { path, hash: hash as string }) } as const;
      if (typeof value.u === "string") {
        const update = fromBase64(value.u);
        return update ? { ...base, update } : null;
      }
      return isHex(value.ref, 64) ? { ...base, ref: value.ref } : null;
    }
    case "blob":
      if (!isHex(value.blob, 64) || !isSize(value.size)) {
        return null;
      }
      return { v: 4, t: "blob", id, blob: value.blob, size: value.size, ...(path === undefined ? {} : { path }) };
    case "move":
      return path === undefined ? null : { v: 4, t: "move", id, path };
    case "delete":
      return { v: 4, t: "delete", id };
    default:
      return null;
  }
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array | null {
  try {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      out[index] = binary.charCodeAt(index);
    }
    return out;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isFileId(value: unknown): value is string {
  return typeof value === "string" && /^f[0-9a-f]{32}$/.test(value);
}

function isHex(value: unknown, length: number): value is string {
  return typeof value === "string" && value.length === length && /^[0-9a-f]+$/.test(value);
}

function isSize(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

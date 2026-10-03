import { blake3 } from "@noble/hashes/blake3.js";
import { LoroDoc } from "loro-crdt/web";
import init from "loro-crdt/web/loro_wasm.js";

import { bytesToHex } from "./crypto";

export type TextDoc = LoroDoc;

const TEXT_KEY = "t";
const LINE_DIFF_CHARS = 64 * 1024;
const encoder = new TextEncoder();

export async function initText(wasm: BufferSource | WebAssembly.Module): Promise<void> {
  await init({ module_or_path: wasm });
}

export function openDoc(peerId: number, state?: Uint8Array): TextDoc {
  const doc = new LoroDoc();
  if (state) {
    doc.import(state);
  }
  doc.setPeerId(peerId);
  return doc;
}

export function textOf(doc: TextDoc): string {
  return doc.getText(TEXT_KEY).toString();
}

export function encodeDoc(doc: TextDoc): Uint8Array {
  return doc.export({ mode: "snapshot" });
}

export function applyUpdate(doc: TextDoc, update: Uint8Array): void {
  doc.import(update);
}

export function setText(doc: TextDoc, next: string): Uint8Array | null {
  const text = doc.getText(TEXT_KEY);
  if (text.toString() === next) {
    return null;
  }
  const before = doc.oplogVersion();
  if (next.length > LINE_DIFF_CHARS) {
    text.updateByLine(next);
  } else {
    text.update(next);
  }
  doc.commit();
  return doc.export({ mode: "update", from: before });
}

export function hashText(value: string): string {
  return hashBytes(encoder.encode(value));
}

export function hashBytes(bytes: Uint8Array): string {
  return bytesToHex(blake3(bytes, { dkLen: 16 }));
}

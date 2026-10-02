import { blake3 } from "@noble/hashes/blake3.js";
import { simpleDiffString } from "lib0/diff";
import { diffAuto } from "lib0/diff/patience";
import * as Y from "yjs";

import { bytesToHex } from "./crypto";

const TEXT_KEY = "t";
const encoder = new TextEncoder();

/** Opens a note document. Each store uses one stable client id, so edits stay compact. */
export function openDoc(clientId: number, state?: Uint8Array): Y.Doc {
  const doc = new Y.Doc();
  if (state) {
    Y.applyUpdate(doc, state);
  }
  // set after loading: the saved state already holds this client's edits
  doc.clientID = clientId;
  return doc;
}

export function textOf(doc: Y.Doc): string {
  return doc.getText(TEXT_KEY).toString();
}

export function encodeDoc(doc: Y.Doc): Uint8Array {
  return Y.encodeStateAsUpdate(doc);
}

export function applyUpdate(doc: Y.Doc, update: Uint8Array): void {
  Y.applyUpdate(doc, update);
}

export function mergeUpdates(updates: Uint8Array[]): Uint8Array {
  return Y.mergeUpdates(updates);
}

/**
 * Turns `next` into minimal text edits on the document, so concurrent edits on
 * other devices merge instead of being replaced. Returns the new edits, or
 * null when the text is unchanged.
 */
export function setText(doc: Y.Doc, next: string): Uint8Array | null {
  const text = doc.getText(TEXT_KEY);
  const previous = text.toString();
  if (previous === next) {
    return null;
  }
  const before = Y.encodeStateVector(doc);
  doc.transact(() => {
    for (const change of diffAuto(previous, next).reverse()) {
      if (change.remove.length > 0) {
        text.delete(change.index, change.remove.length);
      }
      if (change.insert.length > 0) {
        text.insert(change.index, change.insert);
      }
    }
    const current = text.toString();
    if (current !== next) {
      const fix = simpleDiffString(current, next);
      text.delete(fix.index, fix.remove);
      text.insert(fix.index, fix.insert);
    }
  });
  return Y.encodeStateAsUpdate(doc, before);
}

export function hashText(value: string): string {
  return hashBytes(encoder.encode(value));
}

export function hashBytes(bytes: Uint8Array): string {
  return bytesToHex(blake3(bytes, { dkLen: 16 }));
}

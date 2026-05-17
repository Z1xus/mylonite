import * as Y from "yjs";

export type MarkdownEntry = Y.Map<unknown>;
export type MarkdownTree = Y.Map<MarkdownEntry>;

const CONTENT_KEY = "content";
const KIND_KEY = "kind";
const PATH_KEY = "path";
const UPDATED_AT_KEY = "updatedAtMs";
const RENAMED_FROM_KEY = "renamedFrom";

export function getMarkdownText(tree: MarkdownTree, path: string): Y.Text | null {
  const entry = tree.get(path);
  const text = entry?.get(CONTENT_KEY);
  return text instanceof Y.Text ? text : null;
}

export function encodeMarkdownUpsertUpdate(doc: Y.Doc, tree: MarkdownTree, path: string, content: string): string {
  const beforeState = Y.encodeStateVector(doc);
  doc.transact(() => {
    const entry = ensureMarkdownEntry(tree, path);
    const text = ensureMarkdownContent(entry);
    entry.set(UPDATED_AT_KEY, Date.now());
    text.delete(0, text.length);
    text.insert(0, content);
  }, "local-vault");
  return bytesToHex(Y.encodeStateAsUpdate(doc, beforeState));
}

export function encodeMarkdownDeleteUpdate(doc: Y.Doc, tree: MarkdownTree, path: string): string {
  const beforeState = Y.encodeStateVector(doc);
  doc.transact(() => {
    tree.delete(path);
  }, "local-vault");
  return bytesToHex(Y.encodeStateAsUpdate(doc, beforeState));
}

export function encodeMarkdownRenameUpdate(doc: Y.Doc, tree: MarkdownTree, oldPath: string, newPath: string, content: string): string {
  const beforeState = Y.encodeStateVector(doc);
  doc.transact(() => {
    tree.delete(oldPath);
    const entry = ensureMarkdownEntry(tree, newPath);
    entry.set(RENAMED_FROM_KEY, oldPath);
    entry.set(UPDATED_AT_KEY, Date.now());
    const text = ensureMarkdownContent(entry);
    text.delete(0, text.length);
    text.insert(0, content);
  }, "local-vault");
  return bytesToHex(Y.encodeStateAsUpdate(doc, beforeState));
}

function ensureMarkdownEntry(tree: MarkdownTree, path: string): MarkdownEntry {
  let entry = tree.get(path);
  if (!entry) {
    entry = new Y.Map<unknown>();
    entry.set(CONTENT_KEY, new Y.Text());
    tree.set(path, entry);
  }
  entry.set(KIND_KEY, "markdown");
  entry.set(PATH_KEY, path);
  return entry;
}

function ensureMarkdownContent(entry: MarkdownEntry): Y.Text {
  const existing = entry.get(CONTENT_KEY);
  if (existing instanceof Y.Text) {
    return existing;
  }
  const text = new Y.Text();
  entry.set(CONTENT_KEY, text);
  return text;
}

export function applyMarkdownUpdate(doc: Y.Doc, updateHex: string): void {
  Y.applyUpdate(doc, hexToBytes(updateHex), "remote-server");
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/.test(hex)) {
    throw new Error("invalid yjs update hex");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

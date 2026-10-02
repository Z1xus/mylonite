import * as Y from "yjs";

import { newFileId, newOpId } from "./ops";
import { StoreTx, SyncStore } from "./store";
import { FileKind, FileRecord, OutboxEntry, SyncOp } from "./sync-types";
import { applyUpdate, encodeDoc, hashText, mergeUpdates, openDoc, setText, textOf } from "./text";
import { FileStat, VaultIO, conflictPath, kindOf } from "./vault-io";

const DOC_CACHE_SIZE = 32;
const SCAN_BATCH = 64;

export interface ReplicaDeps {
  io: VaultIO;
  deviceId: string;
  store: SyncStore;
  clientId: number;
  blobId(bytes: Uint8Array): string;
  fetchBlob(blobId: string): Promise<Uint8Array | null>;
  legacyClean(path: string, content: string | Uint8Array, stat: FileStat): boolean;
  legacyAncestor(path: string, content: string | Uint8Array): boolean;
  notify(message: string): void;
}

export class Replica {
  readonly outbox: OutboxEntry[];
  readonly dirty = new Set<string>();
  private readonly files = new Map<string, FileRecord>();
  private readonly byPath = new Map<string, string>();
  private readonly byCpath = new Map<string, string>();
  private readonly docs = new Map<string, Y.Doc>();
  private nextKey: number;
  private tx = new StoreTx();

  constructor(private readonly deps: ReplicaDeps, files: FileRecord[], outbox: OutboxEntry[]) {
    for (const record of files) {
      this.index(record);
    }
    this.outbox = outbox;
    this.nextKey = (outbox.at(-1)?.key ?? 0) + 1;
  }

  get fileCount(): number {
    return this.files.size;
  }

  setMeta(key: string, value: unknown): void {
    this.tx.meta.set(key, value);
  }

  async commit(): Promise<void> {
    const tx = this.tx;
    this.tx = new StoreTx();
    await this.deps.store.commit(tx);
  }

  async canonicalFiles(): Promise<Array<{ record: FileRecord; state?: Uint8Array }>> {
    const out: Array<{ record: FileRecord; state?: Uint8Array }> = [];
    for (const record of this.files.values()) {
      if (record.cpath !== undefined && !record.deleted) {
        out.push({ record, state: record.kind === "text" ? encodeDoc(await this.doc(record.id)) : undefined });
      }
    }
    return out;
  }

  ack(opIds: ReadonlySet<string>): void {
    this.removeEntries((entry) => opIds.has(entry.opId));
  }

  replaceEntry(entry: OutboxEntry): void {
    const index = this.outbox.findIndex((candidate) => candidate.key === entry.key);
    if (index >= 0) {
      this.outbox[index] = entry;
      this.tx.outbox.set(entry.key, entry);
    }
  }

  async scan(path: string): Promise<void> {
    const { io } = this.deps;
    const stat = io.stat(path);
    let record = this.recordAt(path);
    if (!stat) {
      if (record) {
        this.deleteLocal(record.id);
      }
      return;
    }
    const kind = kindOf(path);
    if (record && record.kind !== kind) {
      this.deleteLocal(record.id);
      record = undefined;
    }
    if (record && !record.ahead && stat.mtime === record.mtime && stat.size === record.size) {
      return;
    }
    if (kind === "blob") {
      this.scanBlob(record, stat);
      return;
    }
    const content = await io.readText(path);
    if (!record) {
      const doc = openDoc(this.deps.clientId);
      setText(doc, content);
      const id = newFileId();
      const hash = hashText(content);
      this.cacheDoc(id, doc);
      this.saveDoc(id, doc);
      this.put({ id, path, kind, hash, size: stat.size, mtime: stat.mtime, pendingInitHash: hash });
      this.enqueue({ v: 3, t: "text", id, path, hash, update: encodeDoc(doc) });
      return;
    }
    const doc = await this.doc(record.id);
    if (record.ahead && hashText(content) === record.hash) {
      await this.writeAhead(record, doc, content);
      return;
    }
    this.ingest(record, doc, content, stat);
  }

  async rename(from: string, to: string): Promise<void> {
    const record = this.recordAt(from);
    if (record && !this.recordAt(to) && kindOf(to) === record.kind && this.deps.io.stat(to)) {
      this.put({ ...record, path: to });
      this.enqueue({ v: 3, t: "move", id: record.id, path: to });
      await this.scan(to);
      return;
    }
    await this.scan(from);
    await this.scan(to);
  }

  async scanAll(): Promise<void> {
    const { io } = this.deps;
    const stats = io.list();
    const onDisk = new Set(stats.map((stat) => stat.path));
    const missing = [...this.files.values()].filter((record) => !record.deleted && !onDisk.has(record.path));
    if (missing.length > 0) {
      await this.matchRenames(missing, stats.filter((stat) => !this.byPath.has(stat.path)));
    }
    for (const record of [...this.files.values()]) {
      if (!record.deleted && !onDisk.has(record.path)) {
        await this.scan(record.path);
      }
    }
    for (const [index, stat] of stats.entries()) {
      await this.scan(stat.path);
      if (index % SCAN_BATCH === SCAN_BATCH - 1) {
        await this.commit();
        await idle();
      }
    }
  }

  private async matchRenames(missing: FileRecord[], untracked: FileStat[]): Promise<void> {
    const { io } = this.deps;
    for (const stat of untracked) {
      const kind = kindOf(stat.path);
      const candidates = missing.filter((record) => record.kind === kind && (kind === "text" || record.size === stat.size));
      if (candidates.length === 0) {
        continue;
      }
      const hash = kind === "text" ? hashText(await io.readText(stat.path)) : this.deps.blobId(await io.readBytes(stat.path));
      const matches = candidates.filter((record) => record.hash === hash);
      if (matches.length !== 1) {
        continue;
      }
      const record = matches[0];
      missing.splice(missing.indexOf(record), 1);
      this.put({ ...record, path: stat.path });
      this.enqueue({ v: 3, t: "move", id: record.id, path: stat.path });
    }
  }

  private scanBlob(record: FileRecord | undefined, stat: FileStat): void {
    if (!record) {
      const id = newFileId();
      this.put({ id, path: stat.path, kind: "blob", hash: "", size: stat.size, mtime: stat.mtime });
      this.enqueue({ v: 3, t: "blob", id, path: stat.path });
      return;
    }
    this.put({ ...record, size: stat.size, mtime: stat.mtime });
    if (!this.outbox.some((entry) => entry.op.id === record.id && entry.op.t === "blob" && entry.op.blob === undefined)) {
      this.enqueue({ v: 3, t: "blob", id: record.id });
    }
  }

  async resolveBlob(entry: OutboxEntry): Promise<{ entry: OutboxEntry; bytes: Uint8Array } | null> {
    const op = entry.op;
    const record = this.files.get(op.id);
    if (op.t !== "blob" || !record) {
      this.removeEntries((candidate) => candidate.key === entry.key);
      return null;
    }
    const stat = this.deps.io.stat(record.path);
    if (!stat) {
      this.removeEntries((candidate) => candidate.key === entry.key);
      if (op.path !== undefined) {
        this.remove(record.id);
      }
      return null;
    }
    const bytes = await this.deps.io.readBytes(record.path);
    const blob = this.deps.blobId(bytes);
    if (op.blob === blob) {
      return { entry, bytes };
    }
    if (op.path === undefined && op.blob === undefined && blob === record.hash) {
      this.removeEntries((candidate) => candidate.key === entry.key);
      return null;
    }
    const resolved: OutboxEntry = { key: entry.key, opId: newOpId(), op: { ...op, blob, size: bytes.byteLength } };
    this.replaceEntry(resolved);
    this.put({
      ...record,
      hash: blob,
      sentHash: blob,
      size: stat.size,
      mtime: stat.mtime,
      pendingInitHash: op.path === undefined ? record.pendingInitHash : blob,
    });
    return { entry: resolved, bytes };
  }

  async apply(op: SyncOp, opId: string, author: string): Promise<void> {
    this.removeEntries((entry) => entry.opId === opId);
    const ghost = this.files.get(op.id);
    if (ghost?.deleted) {
      this.applyToGhost(ghost, op, author);
      return;
    }
    switch (op.t) {
      case "text":
        await this.applyText(op, author);
        return;
      case "blob":
        await this.applyBlob(op, author);
        return;
      case "move":
        await this.applyMove(op.id, op.path);
        return;
      case "delete":
        await this.applyDelete(op.id);
        return;
    }
  }

  private async applyText(op: Extract<SyncOp, { t: "text" }>, author: string): Promise<void> {
    let record = this.files.get(op.id);
    if (!record) {
      if (op.path !== undefined && op.hash !== undefined) {
        await this.createText(op.id, op.path, { kind: "text", hash: op.hash, author }, op.update);
      }
      return;
    }
    if (record.kind !== "text") {
      return;
    }
    if (op.path !== undefined && record.cpath === undefined) {
      const confirmed = await this.confirmCreate(record, op.path, { kind: "text", hash: op.hash ?? "", author });
      if (!confirmed) {
        return;
      }
      record = confirmed;
    }
    await this.applyTextUpdate(record, op.update);
  }

  private async createText(id: string, path: string, created: Creation, update: Uint8Array): Promise<void> {
    const target = this.claim(id, path, created);
    if (target === null) {
      return;
    }
    const initHash = created.hash;
    const doc = openDoc(this.deps.clientId, update);
    const text = textOf(doc);
    const room = await this.makeRoom(target, {
      id,
      content: text,
      matches: async (at) => await this.deps.io.readText(at) === text,
    });
    if (room === "write") {
      await this.deps.io.writeText(target, text);
    }
    this.cacheDoc(id, doc);
    this.saveDoc(id, doc);
    const record = this.put({ id, path: target, cpath: target, kind: "text", hash: hashText(text), initHash, initDevice: created.author, ...this.statOf(target) });
    if (room === "keep") {
      const stat = this.deps.io.stat(target);
      if (stat) {
        this.ingest(record, doc, await this.deps.io.readText(target), stat);
      }
    }
  }

  private async applyTextUpdate(record: FileRecord, update: Uint8Array): Promise<void> {
    const { io } = this.deps;
    const doc = await this.doc(record.id);
    const stat = io.stat(record.path);
    let disk: string | undefined;
    if (stat && (record.ahead || stat.mtime !== record.mtime || stat.size !== record.size)) {
      disk = await io.readText(record.path);
      if (record.ahead && hashText(disk) === record.hash) {
        disk = textOf(doc);
        await this.writeAhead(record, doc, disk);
        record = this.files.get(record.id) ?? record;
      } else {
        record = this.ingest(record, doc, disk, stat);
      }
    }
    const before = textOf(doc);
    applyUpdate(doc, update);
    this.saveDoc(record.id, doc);
    if (!stat || textOf(doc) === before) {
      return;
    }
    this.put({ ...record, ahead: true });
    await this.commit();
    await this.writeAhead({ ...record, ahead: true }, doc, disk ?? before);
  }

  private async writeAhead(record: FileRecord, doc: Y.Doc, expected: string): Promise<void> {
    const text = textOf(doc);
    const written = await this.deps.io.processText(record.path, (current) => (current === expected || hashText(current) === record.hash ? text : current));
    if (written !== text) {
      this.put({ ...record, ahead: false, mtime: 0 });
      this.dirty.add(record.path);
      return;
    }
    this.put({ ...record, ahead: false, hash: hashText(text), ...this.statOf(record.path) });
  }

  private ingest(record: FileRecord, doc: Y.Doc, content: string, stat: FileStat): FileRecord {
    const update = setText(doc, content);
    if (update) {
      this.saveDoc(record.id, doc);
      this.enqueueText(record.id, update);
    }
    return this.put({ ...record, ahead: false, hash: hashText(content), size: stat.size, mtime: stat.mtime });
  }

  private async applyBlob(op: Extract<SyncOp, { t: "blob" }>, author: string): Promise<void> {
    const { io } = this.deps;
    if (op.blob === undefined || op.size === undefined) {
      return;
    }
    let record = this.files.get(op.id);
    if (!record) {
      if (op.path !== undefined) {
        await this.createBlob(op.id, op.path, { kind: "blob", hash: op.blob, author });
      }
      return;
    }
    if (record.kind !== "blob") {
      return;
    }
    if (op.path !== undefined && record.cpath === undefined) {
      const confirmed = await this.confirmCreate(record, op.path, { kind: "blob", hash: op.blob, author });
      if (!confirmed) {
        return;
      }
      record = confirmed;
    }
    if (author === this.deps.deviceId && record.sentHash !== undefined) {
      if (op.blob === record.sentHash) {
        this.put({ ...record, sentHash: undefined });
      }
      return;
    }
    if (op.blob === record.hash) {
      return;
    }
    const stat = io.stat(record.path);
    const ours = record.sentHash !== undefined || this.outbox.some((entry) => entry.op.id === record.id && entry.op.t === "blob" && entry.op.blob !== undefined);
    const unsent = !ours && stat !== null && await this.diskDiffers(record, stat);
    const bytes = await this.deps.fetchBlob(op.blob);
    if (!bytes || !stat) {
      this.put({ ...record, hash: op.blob, mtime: 0 });
      return;
    }
    if (ours || unsent) {
      const aside = this.freePath(conflictPath(record.path, op.blob));
      await io.writeBytes(aside, bytes);
      this.dirty.add(aside);
      this.deps.notify(`kept both versions of "${record.path}".`);
      if (unsent) {
        this.put({ ...record, hash: op.blob, mtime: 0 });
        this.dirty.add(record.path);
      }
      return;
    }
    await io.writeBytes(record.path, bytes);
    this.put({ ...record, hash: op.blob, ...this.statOf(record.path) });
  }

  private async createBlob(id: string, path: string, created: Creation): Promise<void> {
    const blob = created.hash;
    const target = this.claim(id, path, created);
    if (target === null) {
      return;
    }
    const bytes = await this.deps.fetchBlob(blob);
    if (!bytes) {
      return;
    }
    const room = await this.makeRoom(target, {
      id,
      content: bytes,
      matches: async (at) => this.deps.blobId(await this.deps.io.readBytes(at)) === blob,
    });
    if (room === "write") {
      await this.deps.io.writeBytes(target, bytes);
    }
    this.put({ id, path: target, cpath: target, kind: "blob", hash: blob, initHash: blob, initDevice: created.author, ...(room === "keep" ? { size: 0, mtime: 0 } : this.statOf(target)) });
    if (room === "keep") {
      this.dirty.add(target);
    }
  }

  private async applyMove(id: string, path: string): Promise<void> {
    const record = this.files.get(id);
    if (!record || record.cpath === undefined) {
      return;
    }
    const target = this.claim(id, path);
    if (target !== null) {
      await this.followLog(this.put({ ...record, cpath: target }));
    }
  }

  private async applyDelete(id: string): Promise<void> {
    const record = this.files.get(id);
    if (!record) {
      return;
    }
    const stat = this.deps.io.stat(record.path);
    const changedHere = this.outbox.some((entry) => entry.op.id === id)
      || (stat !== null && await this.diskDiffers(record, stat));
    this.remove(id);
    if (!stat) {
      return;
    }
    if (changedHere) {
      this.dirty.add(record.path);
      this.deps.notify(`kept "${record.path}". It changed here after another device deleted it.`);
      return;
    }
    await this.deps.io.trash(record.path);
  }

  private applyToGhost(ghost: FileRecord, op: SyncOp, author: string): void {
    if (op.t === "delete") {
      this.remove(ghost.id);
      return;
    }
    if (op.t === "move" && ghost.cpath !== undefined) {
      this.put({ ...ghost, cpath: this.claim(ghost.id, op.path) ?? op.path });
      return;
    }
    if (op.t === "move" || op.path === undefined || ghost.cpath !== undefined) {
      return;
    }
    const created = creationOf(op, author);
    const target = created ? this.claim(ghost.id, op.path, created) : null;
    if (target !== null && created) {
      this.put({ ...ghost, cpath: target, initHash: created.hash, initDevice: author });
    }
  }

  private async confirmCreate(record: FileRecord, path: string, created: Creation): Promise<FileRecord | null> {
    const target = this.claim(record.id, path, created);
    if (target === null) {
      await this.mergeInto(record, this.byCpath.get(path));
      return null;
    }
    const confirmed = this.put({ ...record, cpath: target, initHash: created.hash, initDevice: created.author, pendingInitHash: undefined });
    return await this.followLog(confirmed);
  }

  private async mergeInto(record: FileRecord, holderId: string | undefined): Promise<void> {
    const { io } = this.deps;
    const holder = holderId === undefined ? undefined : this.files.get(holderId);
    this.remove(record.id);
    const stat = io.stat(record.path);
    if (!stat) {
      return;
    }
    const same = holder !== undefined && !holder.deleted && io.stat(holder.path) !== null && (record.kind === "text"
      ? await io.readText(record.path) === await io.readText(holder.path)
      : this.deps.blobId(await io.readBytes(record.path)) === holder.hash);
    if (same) {
      await io.trash(record.path);
    } else {
      this.dirty.add(record.path);
    }
  }

  private async followLog(record: FileRecord): Promise<FileRecord> {
    const target = record.cpath;
    if (target === undefined || record.path === target || this.outbox.some((entry) => entry.op.id === record.id && entry.op.t === "move")) {
      return record;
    }
    const { io } = this.deps;
    await this.makeRoom(target, { id: record.id, matches: async () => false });
    if (!io.stat(record.path)) {
      this.dirty.add(target);
      return this.put({ ...record, path: target, mtime: 0 });
    }
    if (io.stat(target)) {
      await io.trash(target);
    }
    return await this.moveRecord(this.files.get(record.id) ?? record, target);
  }

  private async moveRecord(record: FileRecord, to: string): Promise<FileRecord> {
    const before = this.deps.io.stat(record.path);
    const inSync = before !== null && before.mtime === record.mtime && before.size === record.size;
    if (before) {
      await this.deps.io.move(record.path, to);
    }
    this.dirty.add(to);
    return this.put({ ...record, path: to, ...(inSync ? this.statOf(to) : { mtime: 0 }) });
  }

  private claim(id: string, path: string, created?: Creation): string | null {
    let target = path;
    for (;;) {
      const holderId = this.byCpath.get(target);
      if (holderId === undefined || holderId === id) {
        return target;
      }
      const holder = this.files.get(holderId);
      if (created && target === path && holder?.kind === created.kind && holder.initHash === created.hash && holder.initDevice !== created.author) {
        return null;
      }
      target = conflictPath(target, id);
    }
  }

  private async makeRoom(
    target: string,
    incoming: { id: string; content?: string | Uint8Array; matches(path: string): Promise<boolean> },
  ): Promise<"same" | "keep" | "write"> {
    const { io } = this.deps;
    const occupant = this.recordAt(target);
    if (occupant && occupant.id !== incoming.id) {
      const aside = this.freePath(conflictPath(target, occupant.id));
      await this.moveRecord(occupant, aside);
      return "write";
    }
    const stat = io.stat(target);
    if (!stat || occupant) {
      return "write";
    }
    if (await incoming.matches(target)) {
      return "same";
    }
    const content = kindOf(target) === "text" ? await io.readText(target) : await io.readBytes(target);
    if (this.deps.legacyClean(target, content, stat)) {
      return "write";
    }
    if (incoming.content !== undefined && this.deps.legacyAncestor(target, incoming.content)) {
      return "keep";
    }
    await this.moveAside(target);
    return "write";
  }

  private async moveAside(path: string): Promise<void> {
    const aside = this.freePath(conflictPath(path, newFileId()));
    await this.deps.io.move(path, aside);
    this.dirty.add(aside);
    this.deps.notify(`kept both versions of "${path}".`);
  }

  private async diskDiffers(record: FileRecord, stat: FileStat): Promise<boolean> {
    if (stat.mtime === record.mtime && stat.size === record.size && !record.ahead) {
      return false;
    }
    const { io } = this.deps;
    const hash = record.kind === "text" ? hashText(await io.readText(record.path)) : this.deps.blobId(await io.readBytes(record.path));
    return hash !== record.hash;
  }

  private freePath(path: string): string {
    let candidate = path;
    while (this.deps.io.stat(candidate) || this.byPath.has(candidate)) {
      candidate = conflictPath(candidate, newFileId());
    }
    return candidate;
  }

  private recordAt(path: string): FileRecord | undefined {
    const id = this.byPath.get(path);
    return id === undefined ? undefined : this.files.get(id);
  }

  private statOf(path: string): { size: number; mtime: number } {
    const stat = this.deps.io.stat(path);
    return { size: stat?.size ?? 0, mtime: stat?.mtime ?? 0 };
  }

  private put(record: FileRecord): FileRecord {
    this.index(record);
    this.tx.files.set(record.id, record);
    return record;
  }

  private index(record: FileRecord): void {
    const previous = this.files.get(record.id);
    if (previous) {
      this.unindex(previous);
    }
    this.files.set(record.id, record);
    if (!record.deleted) {
      this.byPath.set(record.path, record.id);
    }
    if (record.cpath !== undefined) {
      this.byCpath.set(record.cpath, record.id);
    }
  }

  private unindex(record: FileRecord): void {
    if (this.byPath.get(record.path) === record.id) {
      this.byPath.delete(record.path);
    }
    if (record.cpath !== undefined && this.byCpath.get(record.cpath) === record.id) {
      this.byCpath.delete(record.cpath);
    }
  }

  private deleteLocal(id: string): void {
    const record = this.files.get(id);
    this.remove(id);
    if (record) {
      this.put({ ...record, deleted: true, path: "", ahead: false });
    }
    this.enqueue({ v: 3, t: "delete", id });
  }

  private remove(id: string): void {
    const record = this.files.get(id);
    if (record) {
      this.unindex(record);
    }
    this.files.delete(id);
    this.docs.delete(id);
    this.tx.files.set(id, null);
    this.tx.docs.set(id, null);
    this.removeEntries((entry) => entry.op.id === id);
  }

  private async doc(id: string): Promise<Y.Doc> {
    const cached = this.docs.get(id);
    if (cached) {
      this.docs.delete(id);
      this.docs.set(id, cached);
      return cached;
    }
    const pending = this.tx.docs.get(id);
    const state = pending === undefined ? await this.deps.store.getDoc(id) : pending ?? undefined;
    const doc = openDoc(this.deps.clientId, state);
    this.cacheDoc(id, doc);
    return doc;
  }

  private cacheDoc(id: string, doc: Y.Doc): void {
    this.docs.set(id, doc);
    for (const [oldest, oldDoc] of this.docs) {
      if (this.docs.size <= DOC_CACHE_SIZE) {
        break;
      }
      this.docs.delete(oldest);
      oldDoc.destroy();
    }
  }

  private saveDoc(id: string, doc: Y.Doc): void {
    this.tx.docs.set(id, encodeDoc(doc));
  }

  private enqueue(op: SyncOp): void {
    const entry: OutboxEntry = { key: this.nextKey, opId: newOpId(), op };
    this.nextKey += 1;
    this.outbox.push(entry);
    this.tx.outbox.set(entry.key, entry);
  }

  private enqueueText(id: string, update: Uint8Array): void {
    let last: OutboxEntry | undefined;
    for (const entry of this.outbox) {
      if (entry.op.id === id) {
        last = entry;
      }
    }
    if (last && last.op.t === "text" && last.op.path === undefined) {
      this.replaceEntry({ key: last.key, opId: newOpId(), op: { ...last.op, update: mergeUpdates([last.op.update, update]) } });
      return;
    }
    this.enqueue({ v: 3, t: "text", id, update });
  }

  private removeEntries(match: (entry: OutboxEntry) => boolean): void {
    for (let index = this.outbox.length - 1; index >= 0; index -= 1) {
      const entry = this.outbox[index];
      if (match(entry)) {
        this.outbox.splice(index, 1);
        this.tx.outbox.set(entry.key, null);
      }
    }
  }
}

interface Creation {
  kind: FileKind;
  hash: string;
  author: string;
}

function creationOf(op: SyncOp, author: string): Creation | undefined {
  if (op.t === "text" && op.hash !== undefined) {
    return { kind: "text", hash: op.hash, author };
  }
  if (op.t === "blob" && op.blob !== undefined) {
    return { kind: "blob", hash: op.blob, author };
  }
  return undefined;
}

function idle(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

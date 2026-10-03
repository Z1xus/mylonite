import { FileRecord, OutboxEntry } from "./sync-types";

const STORES = ["files", "docs", "outbox", "meta"] as const;
type StoreName = typeof STORES[number];

export interface StoreSnapshot {
  files: FileRecord[];
  outbox: OutboxEntry[];
  meta: Map<string, unknown>;
}

export class StoreTx {
  readonly files = new Map<string, FileRecord | null>();
  readonly docs = new Map<string, Uint8Array | null>();
  readonly outbox = new Map<number, OutboxEntry | null>();
  readonly meta = new Map<string, unknown>();

  get empty(): boolean {
    return this.files.size + this.docs.size + this.outbox.size + this.meta.size === 0;
  }
}

export interface SyncStore {
  load(): Promise<StoreSnapshot>;
  getDoc(id: string): Promise<Uint8Array | undefined>;
  commit(tx: StoreTx): Promise<void>;
  close(): void;
}

export async function openIdbStore(name: string): Promise<SyncStore> {
  const open = indexedDB.open(name, 1);
  open.onupgradeneeded = () => {
    for (const store of STORES) {
      open.result.createObjectStore(store);
    }
  };
  const db = await request(open);
  return new IdbStore(db);
}

export async function deleteIdbStore(name: string): Promise<void> {
  await request(indexedDB.deleteDatabase(name));
}

class IdbStore implements SyncStore {
  constructor(private readonly db: IDBDatabase) {}

  async load(): Promise<StoreSnapshot> {
    const tx = this.db.transaction(["files", "outbox", "meta"], "readonly");
    const [files, outbox, metaKeys, metaValues] = await Promise.all([
      request(tx.objectStore("files").getAll()),
      request(tx.objectStore("outbox").getAll()),
      request(tx.objectStore("meta").getAllKeys()),
      request(tx.objectStore("meta").getAll()),
    ]);
    const meta = new Map<string, unknown>();
    metaKeys.forEach((key, index) => meta.set(key as string, metaValues[index]));
    return {
      files: files as FileRecord[],
      outbox: (outbox as OutboxEntry[]).sort((a, b) => a.key - b.key),
      meta,
    };
  }

  async getDoc(id: string): Promise<Uint8Array | undefined> {
    const tx = this.db.transaction("docs", "readonly");
    return await request(tx.objectStore("docs").get(id)) as Uint8Array | undefined;
  }

  commit(changes: StoreTx): Promise<void> {
    if (changes.empty) {
      return Promise.resolve();
    }
    const tx = this.db.transaction([...STORES], "readwrite");
    write(tx, "files", changes.files);
    write(tx, "docs", changes.docs);
    write(tx, "outbox", changes.outbox);
    write(tx, "meta", changes.meta);
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("store write failed"));
      tx.onabort = () => reject(tx.error ?? new Error("store write aborted"));
    });
  }

  close(): void {
    this.db.close();
  }
}

function write(tx: IDBTransaction, name: StoreName, changes: Map<IDBValidKey, unknown>): void {
  const store = tx.objectStore(name);
  for (const [key, value] of changes) {
    if (value === null || value === undefined) {
      store.delete(key);
    } else {
      store.put(value, key);
    }
  }
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("store request failed"));
  });
}

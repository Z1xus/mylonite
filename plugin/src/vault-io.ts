import { App, TFile, normalizePath } from "obsidian";

import { FileKind } from "./sync-types";

export interface FileStat {
  path: string;
  mtime: number;
  size: number;
}

/** The small part of the vault the sync engine uses. */
export interface VaultIO {
  list(): FileStat[];
  stat(path: string): FileStat | null;
  readText(path: string): Promise<string>;
  readBytes(path: string): Promise<Uint8Array>;
  writeText(path: string, text: string): Promise<void>;
  /** Atomic read, change, and write. Returns the written text. */
  processText(path: string, change: (current: string) => string): Promise<string>;
  writeBytes(path: string, bytes: Uint8Array): Promise<void>;
  move(from: string, to: string): Promise<void>;
  trash(path: string): Promise<void>;
}

export function kindOf(path: string): FileKind {
  return path.toLowerCase().endsWith(".md") ? "text" : "blob";
}

export function isValidVaultPath(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 4096
    && !value.startsWith("/")
    && !value.includes("\0")
    && !value.includes("\\")
    && value.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

export function conflictPath(path: string, tag: string): string {
  const slash = path.lastIndexOf("/");
  const dot = path.lastIndexOf(".");
  const suffix = ` conflict-${tag.replace(/^f/, "").slice(0, 8)}`;
  return dot > slash + 1 ? `${path.slice(0, dot)}${suffix}${path.slice(dot)}` : `${path}${suffix}`;
}

export class ObsidianVaultIO implements VaultIO {
  constructor(private readonly app: App) {}

  list(): FileStat[] {
    return this.app.vault.getFiles().map(toStat);
  }

  stat(path: string): FileStat | null {
    const file = this.app.vault.getFileByPath(path);
    return file ? toStat(file) : null;
  }

  readText(path: string): Promise<string> {
    return this.app.vault.read(this.file(path));
  }

  async readBytes(path: string): Promise<Uint8Array> {
    return new Uint8Array(await this.app.vault.readBinary(this.file(path)));
  }

  async writeText(path: string, text: string): Promise<void> {
    const file = this.app.vault.getFileByPath(path);
    if (file) {
      await this.app.vault.modify(file, text);
      return;
    }
    await this.ensureParent(path);
    await this.app.vault.create(path, text);
  }

  processText(path: string, change: (current: string) => string): Promise<string> {
    return this.app.vault.process(this.file(path), change);
  }

  async writeBytes(path: string, bytes: Uint8Array): Promise<void> {
    const data = bytes.slice().buffer;
    const file = this.app.vault.getFileByPath(path);
    if (file) {
      await this.app.vault.modifyBinary(file, data);
      return;
    }
    await this.ensureParent(path);
    await this.app.vault.createBinary(path, data);
  }

  async move(from: string, to: string): Promise<void> {
    await this.ensureParent(to);
    await this.app.vault.rename(this.file(from), to);
  }

  async trash(path: string): Promise<void> {
    const file = this.app.vault.getFileByPath(path);
    if (file) {
      await this.app.fileManager.trashFile(file);
    }
  }

  private file(path: string): TFile {
    const file = this.app.vault.getFileByPath(path);
    if (!file) {
      throw new Error(`file not found: ${path}`);
    }
    return file;
  }

  private async ensureParent(path: string): Promise<void> {
    const parent = path.split("/").slice(0, -1).join("/");
    if (parent && !this.app.vault.getFolderByPath(parent)) {
      await this.app.vault.createFolder(parent);
    }
  }
}

function toStat(file: TFile): FileStat {
  return { path: normalizePath(file.path), mtime: file.stat.mtime, size: file.stat.size };
}

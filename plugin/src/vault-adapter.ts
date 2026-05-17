import { TFile, Vault, normalizePath } from "obsidian";

export function normalizeVaultPath(value: unknown, errorMessage = "invalid vault path"): string {
  if (typeof value !== "string") {
    throw new Error(errorMessage);
  }
  const path = normalizePath(value);
  if (
    path.length === 0
    || path.length > 4096
    || path.startsWith("/")
    || path.includes("\0")
    || path.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error(errorMessage);
  }
  return path;
}

export async function applyMarkdownUpsert(
  vault: Vault,
  suppressedPaths: Set<string>,
  path: string,
  content: string,
): Promise<void> {
  const normalizedPath = normalizeVaultPath(path);
  suppressedPaths.add(normalizedPath);
  const existing = vault.getFileByPath(normalizedPath);
  if (existing) {
    await vault.modify(existing, content);
    return;
  }
  await ensureParentFolder(vault, normalizedPath);
  await vault.create(normalizedPath, content);
}

export async function applyFileDelete(
  vault: Vault,
  suppressedPaths: Set<string>,
  path: string,
): Promise<void> {
  const normalizedPath = normalizeVaultPath(path);
  const existing = vault.getFileByPath(normalizedPath);
  if (!existing) {
    return;
  }
  suppressedPaths.add(normalizedPath);
  await vault.delete(existing);
}

export async function applyFileRename(
  vault: Vault,
  suppressedPaths: Set<string>,
  oldPath: string,
  newPath: string,
): Promise<void> {
  const normalizedOldPath = normalizeVaultPath(oldPath);
  const normalizedNewPath = normalizeVaultPath(newPath);
  const existing = vault.getFileByPath(normalizedOldPath);
  if (!existing) {
    return;
  }
  suppressedPaths.add(normalizedOldPath);
  suppressedPaths.add(normalizedNewPath);
  await ensureParentFolder(vault, normalizedNewPath);
  await vault.rename(existing, normalizedNewPath);
}

export async function applyBinaryUpsert(
  vault: Vault,
  suppressedPaths: Set<string>,
  path: string,
  bytes: Uint8Array,
): Promise<void> {
  const normalizedPath = normalizeVaultPath(path);
  suppressedPaths.add(normalizedPath);
  const existing = vault.getFileByPath(normalizedPath);
  const binary = new Uint8Array(bytes).buffer;
  if (existing) {
    await vault.modifyBinary(existing, binary);
    return;
  }
  await ensureParentFolder(vault, normalizedPath);
  await vault.createBinary(normalizedPath, binary);
}

export async function readFileBytes(vault: Vault, file: TFile): Promise<Uint8Array> {
  return new Uint8Array(await vault.readBinary(file));
}

async function ensureParentFolder(vault: Vault, path: string): Promise<void> {
  const parentPath = path.split("/").slice(0, -1).join("/");
  if (parentPath && !vault.getFolderByPath(parentPath)) {
    await vault.createFolder(parentPath);
  }
}

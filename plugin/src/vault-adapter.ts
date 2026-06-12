import { FileManager, TFile, Vault, normalizePath } from "obsidian";

export type VaultApplyResult =
  | { status: "applied"; path: string }
  | { status: "noop"; path: string }
  | { status: "conflict-created"; path: string; originalPath: string }
  | { status: "missing-local-file"; path: string };

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
  try {
    const existing = vault.getFileByPath(normalizedPath);
    if (existing) {
      await vault.modify(existing, content);
      return;
    }
    await ensureParentFolder(vault, normalizedPath);
    await vault.create(normalizedPath, content);
  } catch (error) {
    suppressedPaths.delete(normalizedPath);
    throw error;
  }
}

export async function applyFileDelete(
  vault: Vault,
  fileManager: FileManager,
  suppressedPaths: Set<string>,
  path: string,
): Promise<void> {
  const normalizedPath = normalizeVaultPath(path);
  const existing = vault.getFileByPath(normalizedPath);
  if (!existing) {
    return;
  }
  suppressedPaths.add(normalizedPath);
  try {
    await fileManager.trashFile(existing);
  } catch (error) {
    suppressedPaths.delete(normalizedPath);
    throw error;
  }
}

export async function applyFileRenameWithCollision(
  vault: Vault,
  suppressedPaths: Set<string>,
  oldPath: string,
  newPath: string,
  fileId: string,
): Promise<VaultApplyResult> {
  const normalizedOldPath = normalizeVaultPath(oldPath);
  const normalizedNewPath = normalizeVaultPath(newPath);
  const existing = vault.getFileByPath(normalizedOldPath);
  if (!existing) {
    return { status: "missing-local-file", path: normalizedOldPath };
  }
  if (normalizedOldPath === normalizedNewPath) {
    return { status: "noop", path: normalizedNewPath };
  }
  const target = vault.getFileByPath(normalizedNewPath);
  const finalPath = target && target !== existing ? conflictPath(normalizedNewPath, fileId) : normalizedNewPath;
  suppressedPaths.add(normalizedOldPath);
  suppressedPaths.add(finalPath);
  try {
    await ensureParentFolder(vault, finalPath);
    await vault.rename(existing, finalPath);
  } catch (error) {
    suppressedPaths.delete(normalizedOldPath);
    suppressedPaths.delete(finalPath);
    throw error;
  }
  return finalPath === normalizedNewPath
    ? { status: "applied", path: finalPath }
    : { status: "conflict-created", path: finalPath, originalPath: normalizedNewPath };
}

export async function applyBinaryUpsert(
  vault: Vault,
  suppressedPaths: Set<string>,
  path: string,
  bytes: Uint8Array,
): Promise<void> {
  const normalizedPath = normalizeVaultPath(path);
  suppressedPaths.add(normalizedPath);
  try {
    const existing = vault.getFileByPath(normalizedPath);
    const binary = new Uint8Array(bytes).buffer;
    if (existing) {
      await vault.modifyBinary(existing, binary);
      return;
    }
    await ensureParentFolder(vault, normalizedPath);
    await vault.createBinary(normalizedPath, binary);
  } catch (error) {
    suppressedPaths.delete(normalizedPath);
    throw error;
  }
}

export async function applyMarkdownUpsertWithCollision(
  vault: Vault,
  suppressedPaths: Set<string>,
  path: string,
  content: string,
  fileId: string,
  allowOverwrite: boolean,
): Promise<VaultApplyResult> {
  const normalizedPath = normalizeVaultPath(path);
  const existing = vault.getFileByPath(normalizedPath);
  const finalPath = existing && !allowOverwrite ? conflictPath(normalizedPath, fileId) : normalizedPath;
  await applyMarkdownUpsert(vault, suppressedPaths, finalPath, content);
  return finalPath === normalizedPath
    ? { status: "applied", path: finalPath }
    : { status: "conflict-created", path: finalPath, originalPath: normalizedPath };
}

export async function applyBinaryUpsertWithCollision(
  vault: Vault,
  suppressedPaths: Set<string>,
  path: string,
  bytes: Uint8Array,
  fileId: string,
  allowOverwrite: boolean,
): Promise<VaultApplyResult> {
  const normalizedPath = normalizeVaultPath(path);
  const existing = vault.getFileByPath(normalizedPath);
  const finalPath = existing && !allowOverwrite ? conflictPath(normalizedPath, fileId) : normalizedPath;
  await applyBinaryUpsert(vault, suppressedPaths, finalPath, bytes);
  return finalPath === normalizedPath
    ? { status: "applied", path: finalPath }
    : { status: "conflict-created", path: finalPath, originalPath: normalizedPath };
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

export function conflictPath(path: string, suffix: string): string {
  const normalized = normalizeVaultPath(path);
  const dot = normalized.lastIndexOf(".");
  const tag = ` conflict-${suffix.slice(0, 8)}`;
  if (dot <= normalized.lastIndexOf("/")) {
    return `${normalized}${tag}`;
  }
  return `${normalized.slice(0, dot)}${tag}${normalized.slice(dot)}`;
}

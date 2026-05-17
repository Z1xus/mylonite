export function normalizePath(path: string): string {
  return path.replaceAll("\\", "/");
}

export class TFile {}

export type Vault = unknown;

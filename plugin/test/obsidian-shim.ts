export function normalizePath(path: string): string {
  return path.replaceAll("\\", "/");
}

export class TFile {}

export class Notice {
  static readonly messages: string[] = [];

  constructor(readonly message: string) {
    Notice.messages.push(message);
  }
}

export type Vault = unknown;

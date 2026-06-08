export function normalizePath(path: string): string {
  return path.replaceAll("\\", "/");
}

export const activeWindow = globalThis as unknown as Window;
Object.defineProperty(globalThis, "activeWindow", {
  configurable: true,
  value: activeWindow,
});
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: activeWindow,
});

export class TFile {}

export class Modal {
  contentEl = document.createElement("div");

  constructor(readonly app: unknown) {}

  open(): void {
    void this.onOpen();
  }

  close(): void {
    this.onClose();
  }

  onOpen(): Promise<void> | void {}

  onClose(): void {}
}

export class Notice {
  static readonly messages: string[] = [];

  constructor(readonly message: string) {
    Notice.messages.push(message);
  }
}

export class Setting {
  settingEl = document.createElement("div");

  constructor(readonly containerEl: HTMLElement) {}

  setName(): this {
    return this;
  }

  setDesc(): this {
    return this;
  }

  setHeading(): this {
    return this;
  }

  addButton(callback: (button: ButtonComponent) => unknown): this {
    callback(new ButtonComponent());
    return this;
  }
}

class ButtonComponent {
  setButtonText(): this {
    return this;
  }

  onClick(): this {
    return this;
  }
}

export async function requestUrl(): Promise<{
  status: number;
  headers: Record<string, string>;
  arrayBuffer: ArrayBuffer;
  json: unknown;
  text: string;
}> {
  throw new Error("requestUrl mock not configured");
}

export type Vault = unknown;

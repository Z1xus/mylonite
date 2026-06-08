import { App, Modal, Setting } from "obsidian";

export function confirmAction(app: App, options: { title: string; message: string; confirmText: string }): Promise<boolean> {
  return new Promise((resolve) => {
    new ConfirmModal(app, options, resolve).open();
  });
}

class ConfirmModal extends Modal {
  private resolved = false;

  constructor(
    app: App,
    private readonly options: { title: string; message: string; confirmText: string },
    private readonly resolve: (confirmed: boolean) => void,
  ) {
    super(app);
  }

  override onOpen(): void {
    this.contentEl.empty();
    new Setting(this.contentEl).setName(this.options.title).setHeading();
    this.contentEl.createEl("p", { text: this.options.message });

    new Setting(this.contentEl)
      .addButton((button) => button
        .setButtonText("Cancel")
        .onClick(() => {
          this.finish(false);
          this.close();
        }))
      .addButton((button) => button
        .setButtonText(this.options.confirmText)
        .onClick(() => {
          this.finish(true);
          this.close();
        }));
  }

  override onClose(): void {
    this.finish(false);
    this.contentEl.empty();
  }

  private finish(confirmed: boolean): void {
    if (this.resolved) {
      return;
    }
    this.resolved = true;
    this.resolve(confirmed);
  }
}

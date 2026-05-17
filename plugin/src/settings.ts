import { App, Plugin, PluginSettingTab, Setting } from "obsidian";

import { DurableSyncState, PendingEncryptedOp } from "./sync-types";

export interface MyloniteSettings {
  serverUrl: string;
  vaultId: string;
  vaultSaltHex: string;
  passphraseStorage: "none" | "secret-storage" | "plugin-data";
  passphraseDevelopmentFallback: string;
  lamport: number;
  lastServerSeq: number;
  pendingOps: PendingEncryptedOp[];
  durableSyncState: DurableSyncState;
  deviceId: string;
  devicePrivateKeyHex: string;
  devicePublicKeyHex: string;
  devicePrivateKeyStorage: "none" | "secret-storage" | "plugin-data";
  pairingToken: string;
  devicePairingRequest: string;
  devicePairingResponse: string;
  devicePairingPrivateKeyHex: string;
  deviceLabel: string;
  debugLogging: boolean;
}

export const DEFAULT_SETTINGS: MyloniteSettings = {
  serverUrl: "http://127.0.0.1:9821",
  vaultId: "",
  vaultSaltHex: "",
  passphraseStorage: "none",
  passphraseDevelopmentFallback: "",
  lamport: 0,
  lastServerSeq: 0,
  pendingOps: [],
  durableSyncState: {
    version: 1,
    index: { version: 1, files: [], tombstones: [] },
    journal: [],
  },
  deviceId: "",
  devicePrivateKeyHex: "",
  devicePublicKeyHex: "",
  devicePrivateKeyStorage: "none",
  pairingToken: "",
  devicePairingRequest: "",
  devicePairingResponse: "",
  devicePairingPrivateKeyHex: "",
  deviceLabel: "Obsidian device",
  debugLogging: false,
};

type MyloniteSettingsPlugin = Plugin & {
  settings: MyloniteSettings;
  saveSettings(): Promise<void>;
  pairFirstDevice(): Promise<void>;
  createDevicePairingRequest(): Promise<void>;
  authorizeDevicePairingRequest(): Promise<void>;
  completeDevicePairing(): Promise<void>;
  createSnapshot(): Promise<void>;
  restoreLatestSnapshot(): Promise<void>;
  unpairDevice(): Promise<void>;
};

export class MyloniteSettingTab extends PluginSettingTab {
  constructor(app: App, private readonly plugin: MyloniteSettingsPlugin) {
    super(app, plugin);
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "Mylonite" });
    const paired = Boolean(this.plugin.settings.vaultId && this.plugin.settings.deviceId);

    new Setting(containerEl)
      .setName("Server URL")
      .setDesc("Used to reach your Mylonite server.")
      .addText((text) => text
        .setPlaceholder("http://127.0.0.1:9821")
        .setValue(this.plugin.settings.serverUrl)
        .onChange(async (value) => {
          this.plugin.settings.serverUrl = value.trim();
          await this.plugin.saveSettings();
        }));

    new Setting(containerEl)
      .setName("Device label")
      .setDesc("Shown in the device list.")
      .addText((text) => text
        .setPlaceholder("Obsidian device")
        .setValue(this.plugin.settings.deviceLabel)
        .onChange(async (value) => {
          this.plugin.settings.deviceLabel = value.trim();
          await this.plugin.saveSettings();
        }));

    if (paired) {
      this.renderPairedSections(containerEl);
    } else {
      this.renderUnpairedSections(containerEl);
    }

    new Setting(containerEl)
      .setName("Debug logging")
      .setDesc("Writes sync details to the developer console.")
      .addToggle((toggle) => toggle
        .setValue(this.plugin.settings.debugLogging)
        .onChange(async (value) => {
          this.plugin.settings.debugLogging = value;
          await this.plugin.saveSettings();
        }));
  }

  private renderPairedSections(containerEl: HTMLElement): void {
    containerEl.createEl("h3", { text: "This device" });

    new Setting(containerEl)
      .setName("Paired")
      .setDesc(`Vault ${this.plugin.settings.vaultId}, device ${this.plugin.settings.deviceId}.`);

    new Setting(containerEl)
      .setName("Encrypted snapshot")
      .setDesc("Uploads this vault so new devices can start faster.")
      .addButton((button) => button
        .setButtonText("Create")
        .onClick(async () => {
          await this.plugin.createSnapshot();
        }));

    new Setting(containerEl)
      .setName("Latest snapshot")
      .setDesc("Restores the newest snapshot from the server.")
      .addButton((button) => button
        .setButtonText("Restore")
        .onClick(async () => {
          await this.plugin.restoreLatestSnapshot();
        }));

    new Setting(containerEl)
      .setName("Unpair device")
      .setDesc("Removes local credentials and stops syncing this vault.")
      .addButton((button) => button
        .setButtonText("Unpair")
        .setWarning()
        .onClick(async () => {
          await this.plugin.unpairDevice();
          this.display();
        }));

    containerEl.createEl("h3", { text: "Add another device" });
    containerEl.createEl("p", {
      text: "Paste the new device's request, then copy the response back to it.",
      cls: "setting-item-description",
    });

    this.addCodeInput(containerEl, {
      name: "Pairing request",
      placeholder: "Paste pairing request",
      value: this.plugin.settings.devicePairingRequest,
      buttonText: "Authorize",
      cta: true,
      onChange: async (value) => {
        this.plugin.settings.devicePairingRequest = value.trim();
        await this.plugin.saveSettings();
      },
      onButtonClick: async () => {
        await this.plugin.authorizeDevicePairingRequest();
        this.display();
      },
    });

    if (this.plugin.settings.devicePairingResponse) {
      this.addCodeOutput(containerEl, {
        name: "Pairing response",
        desc: "Copy this back to the new device.",
        value: this.plugin.settings.devicePairingResponse,
      });
    }
  }

  private renderUnpairedSections(containerEl: HTMLElement): void {
    const hasRequest = Boolean(this.plugin.settings.devicePairingRequest);

    containerEl.createEl("h3", { text: "Pair this device" });
    containerEl.createEl("p", {
      text: hasRequest
        ? "Waiting for a pairing response. Paste it below to continue."
        : "Pick the option that matches your situation.",
      cls: "setting-item-description",
    });

    containerEl.createEl("h4", { text: "First device for a new vault" });
    containerEl.createEl("p", {
      text: "Paste the pairing token from `mylonite init`.",
      cls: "setting-item-description",
    });

    new Setting(containerEl)
      .setName("Pairing token")
      .addText((text) => text
        .setPlaceholder("p...")
        .setValue(this.plugin.settings.pairingToken)
        .onChange(async (value) => {
          this.plugin.settings.pairingToken = value.trim();
          await this.plugin.saveSettings();
        }))
      .addButton((button) => button
        .setButtonText("Pair")
        .setCta()
        .onClick(async () => {
          await this.plugin.pairFirstDevice();
          this.display();
        }));

    containerEl.createEl("h4", { text: "Join an existing vault" });
    containerEl.createEl("p", {
      text: "Create a request, authorize it on a paired device, then paste the response here.",
      cls: "setting-item-description",
    });

    new Setting(containerEl)
      .setName("Pairing request")
      .setDesc(hasRequest
        ? "Copy this to an already-paired device."
        : "Creates a request for this device.")
      .addButton((button) => button
        .setButtonText(hasRequest ? "Regenerate" : "Request")
        .onClick(async () => {
          await this.plugin.createDevicePairingRequest();
          this.display();
        }));

    if (hasRequest) {
      this.addCodeOutput(containerEl, {
        name: "Pairing request",
        desc: "Copy this into the already-paired device.",
        value: this.plugin.settings.devicePairingRequest,
      });
    }

    this.addCodeInput(containerEl, {
      name: "Pairing response",
      desc: "Paste the response from the paired device.",
      placeholder: "Paste pairing response",
      value: this.plugin.settings.devicePairingResponse,
      buttonText: "Complete",
      cta: true,
      onChange: async (value) => {
        this.plugin.settings.devicePairingResponse = value.trim();
        await this.plugin.saveSettings();
      },
      onButtonClick: async () => {
        await this.plugin.completeDevicePairing();
        this.display();
      },
    });
  }

  private addCodeInput(
    containerEl: HTMLElement,
    options: {
      name: string;
      desc?: string;
      placeholder: string;
      value: string;
      buttonText: string;
      cta?: boolean;
      onChange(value: string): Promise<void>;
      onButtonClick(): Promise<void>;
    },
  ): void {
    const setting = new Setting(containerEl)
      .setName(options.name)
      .addTextArea((text) => {
        text
          .setPlaceholder(options.placeholder)
          .setValue(options.value)
          .onChange(options.onChange);
        text.inputEl.rows = 6;
        text.inputEl.spellcheck = false;
        text.inputEl.addClass("mylonite-code-field");
        return text;
      })
      .addButton((button) => {
        button
          .setButtonText(options.buttonText)
          .onClick(options.onButtonClick);
        if (options.cta) {
          button.setCta();
        }
        return button;
      });
    if (options.desc) {
      setting.setDesc(options.desc);
    }
    setting.settingEl.addClass("mylonite-code-setting");
  }

  private addCodeOutput(
    containerEl: HTMLElement,
    options: {
      name: string;
      desc: string;
      value: string;
    },
  ): void {
    const setting = new Setting(containerEl)
      .setName(options.name)
      .setDesc(options.desc)
      .addTextArea((text) => {
        text
          .setValue(options.value)
          .setDisabled(true);
        text.inputEl.rows = 6;
        text.inputEl.spellcheck = false;
        text.inputEl.addClass("mylonite-code-field");
        return text;
      })
      .addButton((button) => button
        .setButtonText("Copy")
        .onClick(async () => {
          await navigator.clipboard.writeText(options.value);
        }));
    setting.settingEl.addClass("mylonite-code-setting");
  }
}

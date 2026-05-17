import { App, Plugin, PluginSettingTab, Setting } from "obsidian";

import { PendingEncryptedOp } from "./sync-types";

export interface MyloniteSettings {
  serverUrl: string;
  vaultId: string;
  vaultSaltHex: string;
  passphraseStorage: "none" | "secret-storage" | "plugin-data";
  passphraseDevelopmentFallback: string;
  lamport: number;
  lastServerSeq: number;
  pendingOps: PendingEncryptedOp[];
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
      .setDesc("The URL of your self-hosted Mylonite server.")
      .addText((text) => text
        .setPlaceholder("http://127.0.0.1:9821")
        .setValue(this.plugin.settings.serverUrl)
        .onChange(async (value) => {
          this.plugin.settings.serverUrl = value.trim();
          await this.plugin.saveSettings();
        }));

    new Setting(containerEl)
      .setName("Device label")
      .setDesc("Shown in the server's device list.")
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
      .setDesc("Write sync details to the developer console.")
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
      .setDesc(`Vault ${this.plugin.settings.vaultId} · device ${this.plugin.settings.deviceId}.`);

    new Setting(containerEl)
      .setName("Encrypted snapshot")
      .setDesc("Upload a full encrypted snapshot of this vault so new devices can bootstrap faster.")
      .addButton((button) => button
        .setButtonText("Create")
        .onClick(async () => {
          await this.plugin.createSnapshot();
        }));

    new Setting(containerEl)
      .setName("Restore latest snapshot")
      .setDesc("Decrypt and apply the newest snapshot from the server.")
      .addButton((button) => button
        .setButtonText("Restore")
        .onClick(async () => {
          await this.plugin.restoreLatestSnapshot();
        }));

    new Setting(containerEl)
      .setName("Unpair this device")
      .setDesc("Remove local Mylonite credentials and stop syncing this Obsidian vault.")
      .addButton((button) => button
        .setButtonText("Unpair")
        .setWarning()
        .onClick(async () => {
          await this.plugin.unpairDevice();
          this.display();
        }));

    containerEl.createEl("h3", { text: "Add another device" });
    containerEl.createEl("p", {
      text: "On the new device, click Request, then paste the request here and click Authorize. Copy the response back to the new device.",
      cls: "setting-item-description",
    });

    new Setting(containerEl)
      .setName("Pairing request from the new device")
      .addTextArea((text) => text
        .setPlaceholder("Paste the pairing request here")
        .setValue(this.plugin.settings.devicePairingRequest)
        .onChange(async (value) => {
          this.plugin.settings.devicePairingRequest = value.trim();
          await this.plugin.saveSettings();
        }))
      .addButton((button) => button
        .setButtonText("Authorize")
        .setCta()
        .onClick(async () => {
          await this.plugin.authorizeDevicePairingRequest();
          this.display();
        }));

    if (this.plugin.settings.devicePairingResponse) {
      new Setting(containerEl)
        .setName("Pairing response")
        .setDesc("Copy this back to the new device and click Complete there.")
        .addTextArea((text) => text
          .setValue(this.plugin.settings.devicePairingResponse)
          .onChange(async (value) => {
            this.plugin.settings.devicePairingResponse = value.trim();
            await this.plugin.saveSettings();
          }));
    }
  }

  private renderUnpairedSections(containerEl: HTMLElement): void {
    const hasRequest = Boolean(this.plugin.settings.devicePairingRequest);

    containerEl.createEl("h3", { text: "Pair this device" });
    containerEl.createEl("p", {
      text: hasRequest
        ? "Waiting for a pairing response. Paste it below and click Complete."
        : "Pick the option that matches your situation.",
      cls: "setting-item-description",
    });

    containerEl.createEl("h4", { text: "First device for a new vault" });
    containerEl.createEl("p", {
      text: "Paste the pairing token printed by `mylonite init` on the server.",
      cls: "setting-item-description",
    });

    new Setting(containerEl)
      .setName("Pairing token")
      .addText((text) => text
        .setPlaceholder("p…")
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
      text: "Generate a pairing request on this device, hand it to an already-paired device, then paste the response it gives you back.",
      cls: "setting-item-description",
    });

    new Setting(containerEl)
      .setName("Step 1 — generate a pairing request")
      .setDesc(hasRequest
        ? "Request generated. Copy it from the box below and authorize it on an already-paired device."
        : "Creates the request shown below.")
      .addButton((button) => button
        .setButtonText(hasRequest ? "Regenerate" : "Request")
        .onClick(async () => {
          await this.plugin.createDevicePairingRequest();
          this.display();
        }));

    if (hasRequest) {
      new Setting(containerEl)
        .setName("Pairing request")
        .setDesc("Copy this into the already-paired device.")
        .addTextArea((text) => text
          .setValue(this.plugin.settings.devicePairingRequest)
          .onChange(async (value) => {
            this.plugin.settings.devicePairingRequest = value.trim();
            await this.plugin.saveSettings();
          }));
    }

    new Setting(containerEl)
      .setName("Step 2 — paste the pairing response")
      .setDesc("The already-paired device produces this. It carries the vault encryption key, so handle it like a password.")
      .addTextArea((text) => text
        .setPlaceholder("Paste the pairing response here")
        .setValue(this.plugin.settings.devicePairingResponse)
        .onChange(async (value) => {
          this.plugin.settings.devicePairingResponse = value.trim();
          await this.plugin.saveSettings();
        }))
      .addButton((button) => button
        .setButtonText("Complete")
        .setCta()
        .onClick(async () => {
          await this.plugin.completeDevicePairing();
          this.display();
        }));
  }
}

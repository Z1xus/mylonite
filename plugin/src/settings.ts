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
      .setDesc("Shown in server device lists.")
      .addText((text) => text
        .setPlaceholder("Obsidian device")
        .setValue(this.plugin.settings.deviceLabel)
        .onChange(async (value) => {
          this.plugin.settings.deviceLabel = value.trim();
          await this.plugin.saveSettings();
        }));

    if (paired) {
      new Setting(containerEl)
        .setName("Paired")
        .setDesc(`Vault ${this.plugin.settings.vaultId} on device ${this.plugin.settings.deviceId}.`);

      new Setting(containerEl)
        .setName("Encrypted snapshot")
        .setDesc("Upload an encrypted snapshot of this vault.")
        .addButton((button) => button
          .setButtonText("Create")
          .onClick(async () => {
            await this.plugin.createSnapshot();
          }));

      new Setting(containerEl)
        .setName("Restore latest snapshot")
        .setDesc("Decrypt and apply the newest server snapshot.")
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

      new Setting(containerEl)
        .setName("Authorize another device")
        .addTextArea((text) => text
          .setPlaceholder("Pairing request from the new device")
          .setValue(this.plugin.settings.devicePairingRequest)
          .onChange(async (value) => {
            this.plugin.settings.devicePairingRequest = value.trim();
            await this.plugin.saveSettings();
          }))
        .addButton((button) => button
          .setButtonText("Authorize")
          .onClick(async () => {
            await this.plugin.authorizeDevicePairingRequest();
            this.display();
          }));

      if (this.plugin.settings.devicePairingResponse) {
        new Setting(containerEl)
          .setName("Pairing response")
          .addTextArea((text) => text
            .setValue(this.plugin.settings.devicePairingResponse)
            .onChange(async (value) => {
              this.plugin.settings.devicePairingResponse = value.trim();
              await this.plugin.saveSettings();
            }));
      }
    } else {
      new Setting(containerEl)
        .setName("Pair first device")
        .addText((text) => text
          .setPlaceholder("Pairing token")
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

      new Setting(containerEl)
        .setName("Join existing vault")
        .addTextArea((text) => text
          .setPlaceholder("Pairing response")
          .setValue(this.plugin.settings.devicePairingResponse)
          .onChange(async (value) => {
            this.plugin.settings.devicePairingResponse = value.trim();
            await this.plugin.saveSettings();
          }))
        .addButton((button) => button
          .setButtonText("Request")
          .onClick(async () => {
            await this.plugin.createDevicePairingRequest();
            this.display();
          }))
        .addButton((button) => button
          .setButtonText("Complete")
          .onClick(async () => {
            await this.plugin.completeDevicePairing();
            this.display();
          }));

      if (this.plugin.settings.devicePairingRequest) {
        new Setting(containerEl)
          .setName("Pairing request")
          .addTextArea((text) => text
            .setValue(this.plugin.settings.devicePairingRequest)
            .onChange(async (value) => {
              this.plugin.settings.devicePairingRequest = value.trim();
              await this.plugin.saveSettings();
            }));
      }
    }

    new Setting(containerEl)
      .setName("Debug logging")
      .setDesc("Write sync development details to the developer console.")
      .addToggle((toggle) => toggle
        .setValue(this.plugin.settings.debugLogging)
        .onChange(async (value) => {
          this.plugin.settings.debugLogging = value;
          await this.plugin.saveSettings();
        }));
  }
}

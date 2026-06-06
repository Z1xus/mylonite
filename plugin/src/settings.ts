import { App, Plugin, PluginSettingTab, Setting } from "obsidian";

import {
  DevicePairingInvitePayload,
  DevicePairingRequestPayload,
  devicePairingInviteQrUrl,
  devicePairingInviteText,
  devicePairingInviteUrl,
  pairingSafetyCode,
  parseDevicePairingInviteInput,
  validatePairingRequestShape,
} from "./pairing";
import { qrSvgDataUrl } from "./qr";
import { DurableSyncState, MarkdownRecoveryEntry, PendingEncryptedBlob, PendingEncryptedOp } from "./sync-types";

export interface MyloniteSettings {
  serverUrl: string;
  vaultId: string;
  vaultSaltHex: string;
  passphraseStorage: "none" | "secret-storage" | "plugin-data";
  passphraseDevelopmentFallback: string;
  lamport: number;
  lastServerSeq: number;
  pendingBlobs: PendingEncryptedBlob[];
  pendingOps: PendingEncryptedOp[];
  recoveryLog: MarkdownRecoveryEntry[];
  durableSyncState: DurableSyncState;
  deviceId: string;
  devicePrivateKeyHex: string;
  devicePublicKeyHex: string;
  devicePrivateKeyStorage: "none" | "secret-storage" | "plugin-data";
  pairingToken: string;
  devicePairingInvite: string;
  devicePairingSessionId: string;
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
  pendingBlobs: [],
  pendingOps: [],
  recoveryLog: [],
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
  devicePairingInvite: "",
  devicePairingSessionId: "",
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
  createDevicePairingInvite(): Promise<void>;
  submitDevicePairingInvite(inviteInput: string): Promise<void>;
  authorizeDevicePairingRequest(): Promise<void>;
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
    const invite = this.currentPairingInvite();
    const request = this.currentPairingRequest();

    new Setting(containerEl)
      .setName(invite ? "Device invite" : "Create invite")
      .setDesc(invite ? "Scan the QR code or enter the code on the new device." : "Creates a short-lived invite for a new device.")
      .addButton((button) => button
        .setButtonText(invite ? "Regenerate" : "Create")
        .onClick(async () => {
          await this.plugin.createDevicePairingInvite();
          this.display();
        }));

    if (invite) {
      this.addInviteDisplay(containerEl, invite);
    }

    if (request) {
      this.addSafetyCode(containerEl, request.request_hash);
      new Setting(containerEl)
        .setName("Pending device")
        .setDesc(`Approve ${request.label} only if the safety code matches on the new device.`)
        .addButton((button) => button
          .setButtonText("Approve")
          .setCta()
          .onClick(async () => {
            await this.plugin.authorizeDevicePairingRequest();
            this.display();
          }));
    }
  }

  private renderUnpairedSections(containerEl: HTMLElement): void {
    const request = this.currentPairingRequest();

    containerEl.createEl("h3", { text: "Pair this device" });
    containerEl.createEl("p", {
      text: request ? "Waiting for approval on an already-paired device." : "Pick the option that matches your situation.",
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
      text: "Scan the invite QR code or enter the invite code from a paired device.",
      cls: "setting-item-description",
    });

    this.addCodeInput(containerEl, {
      name: "Invite code",
      desc: "Enter the grouped invite code shown on the paired device.",
      placeholder: "ABCD-2345-WXYZ",
      value: this.plugin.settings.devicePairingInvite,
      buttonText: request ? "Retry" : "Join",
      cta: !request,
      rows: 3,
      onChange: async (value) => {
        this.plugin.settings.devicePairingInvite = value.trim();
        await this.plugin.saveSettings();
      },
      onButtonClick: async () => {
        await this.plugin.submitDevicePairingInvite(this.plugin.settings.devicePairingInvite);
        this.display();
      },
    });

    if (request) {
      this.addSafetyCode(containerEl, request.request_hash);
    }
  }

  private currentPairingInvite(): DevicePairingInvitePayload | null {
    if (!this.plugin.settings.devicePairingInvite) {
      return null;
    }
    try {
      return parseDevicePairingInviteInput(this.plugin.settings.devicePairingInvite);
    } catch {
      return null;
    }
  }

  private currentPairingRequest(): DevicePairingRequestPayload | null {
    if (!this.plugin.settings.devicePairingRequest) {
      return null;
    }
    try {
      const request = JSON.parse(this.plugin.settings.devicePairingRequest) as DevicePairingRequestPayload;
      validatePairingRequestShape(request);
      return request;
    } catch {
      return null;
    }
  }

  private addInviteDisplay(containerEl: HTMLElement, invite: DevicePairingInvitePayload): void {
    const inviteText = devicePairingInviteText(invite);
    const inviteQrUrl = devicePairingInviteQrUrl(invite);
    const inviteUrl = devicePairingInviteUrl(invite);
    const wrap = containerEl.createDiv({ cls: "mylonite-invite-panel" });
    wrap.createEl("img", {
      attr: {
        src: qrSvgDataUrl(inviteQrUrl),
        alt: "Mylonite device invite QR code",
      },
      cls: "mylonite-invite-qr",
    });
    const details = wrap.createDiv({ cls: "mylonite-invite-details" });
    details.createEl("div", { text: invite.invite_code, cls: "mylonite-invite-code" });
    details.createEl("div", { text: invite.server_url, cls: "setting-item-description mylonite-invite-server" });
    new Setting(details)
      .setName("Invite link")
      .setDesc("Use this when the QR code is unavailable.")
      .addButton((button) => button
        .setButtonText("Copy")
        .onClick(async () => {
          await navigator.clipboard.writeText(inviteUrl);
        }));
    new Setting(details)
      .setName("Invite code")
      .setDesc("Use this with the server URL if the link does not open.")
      .addButton((button) => button
        .setButtonText("Copy")
        .onClick(async () => {
          await navigator.clipboard.writeText(inviteText);
        }));
  }

  private addSafetyCode(containerEl: HTMLElement, requestHash: string): void {
    new Setting(containerEl)
      .setName("Safety code")
      .setDesc("Approve only when this code matches on both devices.")
      .addText((text) => {
        text
          .setValue(pairingSafetyCode(requestHash))
          .setDisabled(true);
        text.inputEl.addClass("mylonite-safety-code");
        return text;
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
      rows?: number;
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
        text.inputEl.rows = options.rows ?? 6;
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
}

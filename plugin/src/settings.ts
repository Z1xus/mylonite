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
import { DurableSyncState, PendingEncryptedBlob, PendingEncryptedOp } from "./sync-types";

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

type MyloniteSettingsHost = {
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
  constructor(app: App, plugin: Plugin, private readonly host: MyloniteSettingsHost) {
    super(app, plugin);
  }

  override display(): void {
    this.render();
  }

  render(): void {
    const { containerEl } = this;
    containerEl.empty();
    const paired = Boolean(this.host.settings.vaultId && this.host.settings.deviceId);

    new Setting(containerEl)
      .setName("Server URL")
      .setDesc("Used to reach your Mylonite server.")
      .addText((text) => text
        .setPlaceholder("http://127.0.0.1:9821")
        .setValue(this.host.settings.serverUrl)
        .onChange(async (value) => {
          this.host.settings.serverUrl = value.trim();
          await this.host.saveSettings();
        }));

    new Setting(containerEl)
      .setName("Device label")
      .setDesc("Shown in the device list.")
      .addText((text) => text
        .setPlaceholder("Obsidian device")
        .setValue(this.host.settings.deviceLabel)
        .onChange(async (value) => {
          this.host.settings.deviceLabel = value.trim();
          await this.host.saveSettings();
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
        .setValue(this.host.settings.debugLogging)
        .onChange(async (value) => {
          this.host.settings.debugLogging = value;
          await this.host.saveSettings();
        }));
  }

  private renderPairedSections(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("This device").setHeading();

    new Setting(containerEl)
      .setName("Paired")
      .setDesc(`Vault ${this.host.settings.vaultId}, device ${this.host.settings.deviceId}.`);

    new Setting(containerEl)
      .setName("Encrypted snapshot")
      .setDesc("Uploads this vault so new devices can start faster.")
      .addButton((button) => button
        .setButtonText("Create")
        .onClick(async () => {
          await this.host.createSnapshot();
        }));

    new Setting(containerEl)
      .setName("Latest snapshot")
      .setDesc("Restores the newest snapshot from the server.")
      .addButton((button) => button
        .setButtonText("Restore")
        .onClick(async () => {
          await this.host.restoreLatestSnapshot();
        }));

    new Setting(containerEl)
      .setName("Unpair device")
      .setDesc("Removes local credentials and stops syncing this vault.")
      .addButton((button) => button
        .setButtonText("Unpair")
        .onClick(async () => {
          await this.host.unpairDevice();
          this.render();
        }));

    new Setting(containerEl).setName("Add another device").setHeading();
    const invite = this.currentPairingInvite();
    const request = this.currentPairingRequest();

    new Setting(containerEl)
      .setName(invite ? "Device invite" : "Create invite")
      .setDesc(invite ? "Scan the QR code or enter the code on the new device." : "Creates a short-lived invite for a new device.")
      .addButton((button) => button
        .setButtonText(invite ? "Regenerate" : "Create")
        .onClick(async () => {
          await this.host.createDevicePairingInvite();
          this.render();
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
            await this.host.authorizeDevicePairingRequest();
            this.render();
          }));
    }
  }

  private renderUnpairedSections(containerEl: HTMLElement): void {
    const request = this.currentPairingRequest();

    new Setting(containerEl).setName("Pair this device").setHeading();
    containerEl.createEl("p", {
      text: request ? "Waiting for approval on an already-paired device." : "Pick the option that matches your situation.",
      cls: "setting-item-description",
    });

    new Setting(containerEl).setName("First device for a new vault").setHeading();
    containerEl.createEl("p", {
      text: "Paste the pairing token from `mylonite init`.",
      cls: "setting-item-description",
    });

    new Setting(containerEl)
      .setName("Pairing token")
      .addText((text) => text
        .setPlaceholder("p...")
        .setValue(this.host.settings.pairingToken)
        .onChange(async (value) => {
          this.host.settings.pairingToken = value.trim();
          await this.host.saveSettings();
        }))
      .addButton((button) => button
        .setButtonText("Pair")
        .setCta()
        .onClick(async () => {
          await this.host.pairFirstDevice();
          this.render();
        }));

    new Setting(containerEl).setName("Join an existing vault").setHeading();
    containerEl.createEl("p", {
      text: "Scan the invite QR code or enter the invite code from a paired device.",
      cls: "setting-item-description",
    });

    this.addCodeInput(containerEl, {
      name: "Invite code",
      desc: "Enter the grouped invite code shown on the paired device.",
      placeholder: "ABCD-2345-WXYZ",
      value: this.host.settings.devicePairingInvite,
      buttonText: request ? "Retry" : "Join",
      cta: !request,
      rows: 3,
      onChange: async (value) => {
        this.host.settings.devicePairingInvite = value.trim();
        await this.host.saveSettings();
      },
      onButtonClick: async () => {
        await this.host.submitDevicePairingInvite(this.host.settings.devicePairingInvite);
        this.render();
      },
    });

    if (request) {
      this.addSafetyCode(containerEl, request.request_hash);
    }
  }

  private currentPairingInvite(): DevicePairingInvitePayload | null {
    if (!this.host.settings.devicePairingInvite) {
      return null;
    }
    try {
      return parseDevicePairingInviteInput(this.host.settings.devicePairingInvite);
    } catch {
      return null;
    }
  }

  private currentPairingRequest(): DevicePairingRequestPayload | null {
    if (!this.host.settings.devicePairingRequest) {
      return null;
    }
    try {
      const request = JSON.parse(this.host.settings.devicePairingRequest) as DevicePairingRequestPayload;
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
          .onChange(async (value) => {
            await options.onChange(value);
          });
        text.inputEl.rows = options.rows ?? 6;
        text.inputEl.spellcheck = false;
        text.inputEl.addClass("mylonite-code-field");
        return text;
      })
      .addButton((button) => {
        button
          .setButtonText(options.buttonText)
          .onClick(async () => {
            await options.onButtonClick();
          });
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

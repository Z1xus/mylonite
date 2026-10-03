import { App, Plugin, PluginSettingTab, Setting, SettingDefinition, SettingDefinitionItem } from "obsidian";

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

export interface MyloniteSettings {
  serverUrl: string;
  vaultId: string;
  vaultSaltHex: string;
  passphraseStorage: "none" | "secret-storage" | "plugin-data";
  passphraseDevelopmentFallback: string;
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
  resync(): Promise<void>;
  unpairDevice(): Promise<void>;
};

export class MyloniteSettingTab extends PluginSettingTab {
  constructor(app: App, plugin: Plugin, private readonly host: MyloniteSettingsHost) {
    super(app, plugin);
  }

  override getSettingDefinitions(): SettingDefinitionItem[] {
    const settings = this.host.settings;
    const paired = () => Boolean(settings.vaultId && settings.deviceId);
    const unpaired = () => !paired();
    const invite = this.currentPairingInvite();
    const request = this.currentPairingRequest();
    return [
      { name: "Server URL", desc: "The address of your sync server.", control: { type: "text", key: "serverUrl" } },
      { name: "Device label", desc: "Shown in the device list.", control: { type: "text", key: "deviceLabel", placeholder: "Obsidian device" } },
      {
        type: "group",
        heading: "This device",
        visible: paired,
        items: [
          { name: "Paired", desc: `Vault ${settings.vaultId}, device ${settings.deviceId}.` },
          {
            name: "Resync",
            desc: "Downloads the vault again and compares it with your files.",
            render: (setting) => void setting.addButton((button) => button.setButtonText("Resync").onClick(() => this.host.resync())),
          },
          {
            name: "Unpair device",
            desc: "Removes local credentials and stops syncing this vault.",
            render: (setting) => void setting.addButton((button) => button.setButtonText("Unpair").setDestructive().onClick(async () => {
              await this.host.unpairDevice();
              this.update();
            })),
          },
        ],
      },
      {
        type: "group",
        heading: "Add another device",
        visible: paired,
        items: [
          {
            name: invite ? "Device invite" : "Create invite",
            desc: invite ? "Scan the code on the new device, or copy the invite." : "Creates a short-lived invite for a new device.",
            render: (setting) => void setting.addButton((button) => button.setButtonText(invite ? "Regenerate" : "Create").onClick(async () => {
              await this.host.createDevicePairingInvite();
              this.update();
            })),
          },
          {
            name: "Invite",
            searchable: false,
            visible: invite !== null,
            render: (setting) => {
              if (invite) {
                this.renderInvite(setting, invite);
              }
            },
          },
          this.safetyCode(request),
          {
            name: "Pending device",
            desc: request ? `Approve ${request.label} only if the safety code matches on the new device.` : "",
            visible: request !== null,
            render: (setting) => void setting.addButton((button) => button.setButtonText("Approve").setCta().onClick(async () => {
              await this.host.authorizeDevicePairingRequest();
              this.update();
            })),
          },
        ],
      },
      {
        type: "group",
        heading: "First device for a new vault",
        visible: unpaired,
        items: [
          {
            name: "Pairing token",
            desc: "Paste the token from `mylonite init`.",
            render: (setting) => void setting
              .addText((text) => text.setValue(settings.pairingToken).onChange(async (value) => {
                settings.pairingToken = value.trim();
                await this.host.saveSettings();
              }))
              .addButton((button) => button.setButtonText("Pair").setCta().onClick(async () => {
                await this.host.pairFirstDevice();
                this.update();
              })),
          },
        ],
      },
      {
        type: "group",
        heading: "Join an existing vault",
        visible: unpaired,
        items: [
          {
            name: "Invite code",
            desc: request ? "Waiting for approval on the paired device." : "Scan the invite or enter the code from a paired device.",
            render: (setting) => {
              setting.settingEl.addClass("mylonite-code-setting");
              setting
                .addTextArea((text) => {
                  text.setValue(settings.devicePairingInvite).onChange(async (value) => {
                    settings.devicePairingInvite = value.trim();
                    await this.host.saveSettings();
                  });
                  text.inputEl.rows = 3;
                  text.inputEl.spellcheck = false;
                  text.inputEl.addClass("mylonite-code-field");
                })
                .addButton((button) => {
                  button.setButtonText(request ? "Retry" : "Join").onClick(async () => {
                    await this.host.submitDevicePairingInvite(settings.devicePairingInvite);
                    this.update();
                  });
                  if (!request) {
                    button.setCta();
                  }
                });
            },
          },
          this.safetyCode(request),
        ],
      },
      { name: "Debug logging", desc: "Writes sync details to the developer console.", control: { type: "toggle", key: "debugLogging" } },
    ];
  }

  override getControlValue(key: string): unknown {
    return this.host.settings[key as keyof MyloniteSettings];
  }

  override async setControlValue(key: string, value: unknown): Promise<void> {
    Object.assign(this.host.settings, { [key]: typeof value === "string" ? value.trim() : value });
    await this.host.saveSettings();
  }

  private safetyCode(request: DevicePairingRequestPayload | null): SettingDefinition {
    return {
      name: "Safety code",
      desc: "Approve only when this code matches on both devices.",
      visible: request !== null,
      render: (setting) => void setting.addText((text) => {
        text.setValue(request ? pairingSafetyCode(request.request_hash) : "").setDisabled(true);
        text.inputEl.addClass("mylonite-safety-code");
      }),
    };
  }

  private renderInvite(setting: Setting, invite: DevicePairingInvitePayload): void {
    setting.settingEl.empty();
    const wrap = setting.settingEl.createDiv({ cls: "mylonite-invite-panel" });
    wrap.createEl("img", {
      attr: { src: qrSvgDataUrl(devicePairingInviteQrUrl(invite)), alt: "Device invite code" },
      cls: "mylonite-invite-qr",
    });
    const details = wrap.createDiv({ cls: "mylonite-invite-details" });
    details.createDiv({ text: invite.invite_code, cls: "mylonite-invite-code" });
    details.createDiv({ text: invite.server_url, cls: "setting-item-description mylonite-invite-server" });
    new Setting(details)
      .setName("Invite link")
      .setDesc("Use this when you can't scan the code.")
      .addButton((button) => button.setButtonText("Copy").onClick(() => navigator.clipboard.writeText(devicePairingInviteUrl(invite))));
    new Setting(details)
      .setName("Invite code")
      .setDesc("Use this with the server URL if the link does not open.")
      .addButton((button) => button.setButtonText("Copy").onClick(() => navigator.clipboard.writeText(devicePairingInviteText(invite))));
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
}

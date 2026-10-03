import { App } from "obsidian";

import { MyloniteSettings } from "./settings";

declare const __MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__: boolean | undefined;

export type SecretField = "devicePrivateKeyHex" | "passphraseDevelopmentFallback" | "devicePairingPrivateKeyHex";

const SECRET_IDS: Record<SecretField, string> = {
  devicePrivateKeyHex: "mylonite-device-key",
  passphraseDevelopmentFallback: "mylonite-vault-passphrase",
  devicePairingPrivateKeyHex: "mylonite-device-pairing-x25519-key",
};

export function loadSecret(app: App, settings: MyloniteSettings, field: SecretField): string {
  const storage = app.secretStorage as App["secretStorage"] | undefined;
  if (!storage) {
    assertPluginDataAllowed();
    return settings[field];
  }
  const stored = storage.getSecret(SECRET_IDS[field]);
  if (stored) {
    return stored;
  }
  if (settings[field]) {
    storage.setSecret(SECRET_IDS[field], settings[field]);
    const value = settings[field];
    settings[field] = "";
    return value;
  }
  return "";
}

export function storeSecret(app: App, settings: MyloniteSettings, field: SecretField, value: string): void {
  const storage = app.secretStorage as App["secretStorage"] | undefined;
  if (storage) {
    storage.setSecret(SECRET_IDS[field], value);
    settings[field] = "";
    return;
  }
  if (value) {
    assertPluginDataAllowed();
  }
  settings[field] = value;
}

function assertPluginDataAllowed(): void {
  if (typeof __MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__ === "boolean" && !__MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__) {
    throw new Error("SecretStorage is unavailable and plugin-data secret fallback is disabled in this build");
  }
}

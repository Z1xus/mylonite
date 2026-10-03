import { App } from "obsidian";

import { MyloniteSettings } from "./settings";

declare const __MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__: boolean | undefined;

type SecretField = "devicePrivateKeyHex" | "passphraseDevelopmentFallback" | "devicePairingPrivateKeyHex";

const SECRET_IDS: Record<SecretField, string> = {
  devicePrivateKeyHex: "mylonite-device-key",
  passphraseDevelopmentFallback: "mylonite-vault-passphrase",
  devicePairingPrivateKeyHex: "mylonite-device-pairing-x25519-key",
};

function loadSecret(app: App, settings: MyloniteSettings, field: SecretField): string {
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

function storeSecret(app: App, settings: MyloniteSettings, field: SecretField, value: string): void {
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

export function loadDevicePrivateKey(app: App, settings: MyloniteSettings): string {
  return loadSecret(app, settings, "devicePrivateKeyHex");
}

export function storeDevicePrivateKey(app: App, settings: MyloniteSettings, privateKeyHex: string): void {
  storeSecret(app, settings, "devicePrivateKeyHex", privateKeyHex);
  settings.devicePrivateKeyStorage = app.secretStorage ? "secret-storage" : "plugin-data";
}

export function clearDevicePrivateKey(app: App, settings: MyloniteSettings): void {
  storeSecret(app, settings, "devicePrivateKeyHex", "");
  settings.devicePrivateKeyStorage = "none";
}

export function loadPassphrase(app: App, settings: MyloniteSettings): string {
  return loadSecret(app, settings, "passphraseDevelopmentFallback");
}

export function storePassphrase(app: App, settings: MyloniteSettings, passphrase: string): void {
  storeSecret(app, settings, "passphraseDevelopmentFallback", passphrase);
  settings.passphraseStorage = app.secretStorage ? "secret-storage" : "plugin-data";
}

export function clearPassphrase(app: App, settings: MyloniteSettings): void {
  storeSecret(app, settings, "passphraseDevelopmentFallback", "");
  settings.passphraseStorage = "none";
}

export function loadDevicePairingPrivateKey(app: App, settings: MyloniteSettings): string {
  return loadSecret(app, settings, "devicePairingPrivateKeyHex");
}

export function storeDevicePairingPrivateKey(app: App, settings: MyloniteSettings, privateKeyHex: string): void {
  storeSecret(app, settings, "devicePairingPrivateKeyHex", privateKeyHex);
}

export function clearDevicePairingPrivateKey(app: App, settings: MyloniteSettings): void {
  storeSecret(app, settings, "devicePairingPrivateKeyHex", "");
}

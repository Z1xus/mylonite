import { App } from "obsidian";

import { MyloniteSettings } from "./settings";

declare const __MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__: boolean | undefined;

export interface SecretStorage {
  getSecret(id: string): string | null;
  setSecret(id: string, secret: string): void;
}

export function secretStorage(app: App): SecretStorage | null {
  const appWithSecrets = app as App & { secretStorage?: SecretStorage };
  return appWithSecrets.secretStorage ?? null;
}

export function loadDevicePrivateKey(app: App, settings: MyloniteSettings): string {
  const storage = secretStorage(app);
  if (storage) {
    return storage.getSecret("mylonite-device-key") ?? "";
  }
  assertPluginDataSecretFallbackAllowed();
  return settings.devicePrivateKeyHex;
}

export function loadPassphrase(app: App, settings: MyloniteSettings): string {
  const storage = secretStorage(app);
  if (storage) {
    return storage.getSecret("mylonite-vault-passphrase") ?? "";
  }
  assertPluginDataSecretFallbackAllowed();
  return settings.passphraseDevelopmentFallback;
}

export function storeDevicePrivateKey(app: App, settings: MyloniteSettings, privateKeyHex: string): void {
  const storage = secretStorage(app);
  if (storage) {
    storage.setSecret("mylonite-device-key", privateKeyHex);
    settings.devicePrivateKeyHex = "";
    settings.devicePrivateKeyStorage = "secret-storage";
    return;
  }
  assertPluginDataSecretFallbackAllowed();
  settings.devicePrivateKeyHex = privateKeyHex;
  settings.devicePrivateKeyStorage = "plugin-data";
}

export function storePassphrase(app: App, settings: MyloniteSettings, passphrase: string): void {
  const storage = secretStorage(app);
  if (storage) {
    storage.setSecret("mylonite-vault-passphrase", passphrase);
    settings.passphraseDevelopmentFallback = "";
    settings.passphraseStorage = "secret-storage";
    return;
  }
  assertPluginDataSecretFallbackAllowed();
  settings.passphraseDevelopmentFallback = passphrase;
  settings.passphraseStorage = "plugin-data";
}

export function clearDevicePrivateKey(app: App, settings: MyloniteSettings): void {
  const storage = secretStorage(app);
  if (storage) {
    storage.setSecret("mylonite-device-key", "");
  }
  settings.devicePrivateKeyHex = "";
  settings.devicePrivateKeyStorage = "none";
}

export function clearPassphrase(app: App, settings: MyloniteSettings): void {
  const storage = secretStorage(app);
  if (storage) {
    storage.setSecret("mylonite-vault-passphrase", "");
  }
  settings.passphraseDevelopmentFallback = "";
  settings.passphraseStorage = "none";
}

export function loadDevicePairingPrivateKey(app: App, settings: MyloniteSettings): string {
  const storage = secretStorage(app);
  if (storage) {
    return storage.getSecret("mylonite-device-pairing-x25519-key") ?? "";
  }
  assertPluginDataSecretFallbackAllowed();
  return settings.devicePairingPrivateKeyHex;
}

export function storeDevicePairingPrivateKey(app: App, settings: MyloniteSettings, privateKeyHex: string): void {
  const storage = secretStorage(app);
  if (storage) {
    storage.setSecret("mylonite-device-pairing-x25519-key", privateKeyHex);
    settings.devicePairingPrivateKeyHex = "";
    return;
  }
  assertPluginDataSecretFallbackAllowed();
  settings.devicePairingPrivateKeyHex = privateKeyHex;
}

export function clearDevicePairingPrivateKey(app: App, settings: MyloniteSettings): void {
  const storage = secretStorage(app);
  if (storage) {
    storage.setSecret("mylonite-device-pairing-x25519-key", "");
  }
  settings.devicePairingPrivateKeyHex = "";
}

function assertPluginDataSecretFallbackAllowed(): void {
  if (!pluginDataSecretFallbackAllowed()) {
    throw new Error("SecretStorage is unavailable and plugin-data secret fallback is disabled in this build");
  }
}

function pluginDataSecretFallbackAllowed(): boolean {
  return typeof __MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__ === "boolean"
    ? __MYLONITE_ALLOW_PLUGIN_DATA_SECRETS__
    : true;
}

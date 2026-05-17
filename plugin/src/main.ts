import { Notice, Plugin } from "obsidian";

import { MyloniteApiClient } from "./api";
import {
  VaultKeys,
  decryptDevicePairingSecret,
  deriveVaultKeys,
  encryptDevicePairingSecret,
  generateDeviceKeypair,
  generateX25519Keypair,
  randomHex,
} from "./crypto";
import {
  clearDevicePairingPrivateKey,
  loadDevicePairingPrivateKey,
  loadDevicePrivateKey,
  loadPassphrase,
  storeDevicePairingPrivateKey,
  storeDevicePrivateKey,
  storePassphrase,
} from "./secrets";
import { DEFAULT_SETTINGS, MyloniteSettings, MyloniteSettingTab } from "./settings";
import { SyncEngine } from "./sync-engine";

export default class MylonitePlugin extends Plugin {
  settings: MyloniteSettings = { ...DEFAULT_SETTINGS };
  private status: HTMLElement | null = null;
  private vaultKeys: Promise<VaultKeys> | null = null;
  private syncEngine = new SyncEngine(this);

  async onload(): Promise<void> {
    await this.loadSettings();

    this.addCommand({
      id: "show-sync-status",
      name: "Show sync status",
      callback: () => new Notice(this.statusText()),
    });
    this.addCommand({
      id: "sync-now",
      name: "Sync now",
      callback: () => void this.syncEngine.catchUp().catch((error) => new Notice(`Mylonite sync failed: ${String(error)}`)),
    });
    this.addCommand({
      id: "create-snapshot",
      name: "Create encrypted snapshot",
      callback: () => void this.syncEngine.createSnapshot().catch((error) => new Notice(`Mylonite snapshot failed: ${String(error)}`)),
    });
    this.addCommand({
      id: "restore-latest-snapshot",
      name: "Restore latest encrypted snapshot",
      callback: () => void this.syncEngine.restoreLatestSnapshot().catch((error) => new Notice(`Mylonite restore failed: ${String(error)}`)),
    });

    this.addSettingTab(new MyloniteSettingTab(this.app, this));
    this.status = this.addStatusBarItem();
    this.updateStatus("idle");

    this.app.workspace.onLayoutReady(() => {
      this.syncEngine.start();
    });
  }

  onunload(): void {
    this.syncEngine.close();
    this.status?.remove();
    this.status = null;
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }

  async pairFirstDevice(): Promise<void> {
    if (!this.settings.serverUrl || !this.settings.pairingToken) {
      new Notice("Enter a server URL and pairing token first.");
      return;
    }

    this.updateStatus("pairing");
    try {
      const existingPrivateKey = loadDevicePrivateKey(this.app, this.settings);
      const keypair = existingPrivateKey && this.settings.devicePublicKeyHex
        ? { privateKeyHex: existingPrivateKey, publicKeyHex: this.settings.devicePublicKeyHex }
        : generateDeviceKeypair();
      const client = new MyloniteApiClient(this.settings.serverUrl);
      const response = await client.pairFirstDevice(
        this.settings.pairingToken,
        this.settings.deviceLabel || "Obsidian device",
        keypair.publicKeyHex,
      );
      this.settings.vaultId = response.vault_id;
      if (!this.settings.vaultSaltHex) {
        this.settings.vaultSaltHex = randomHex(16);
      }
      this.settings.deviceId = response.device_id;
      this.settings.devicePublicKeyHex = keypair.publicKeyHex;
      this.settings.pairingToken = "";
      storeDevicePrivateKey(this.app, this.settings, keypair.privateKeyHex);
      storePassphrase(this.app, this.settings, randomHex(32));
      this.vaultKeys = null;
      await this.saveSettings();
      this.updateStatus("paired");
      new Notice("Mylonite pairing completed.");
    } catch (error) {
      this.updateStatus("pairing failed");
      new Notice(`Mylonite pairing failed: ${String(error)}`);
    }
  }

  async createDevicePairingRequest(): Promise<void> {
    const existingPrivateKey = loadDevicePrivateKey(this.app, this.settings);
    const deviceKeypair = existingPrivateKey && this.settings.devicePublicKeyHex
      ? { privateKeyHex: existingPrivateKey, publicKeyHex: this.settings.devicePublicKeyHex }
      : generateDeviceKeypair();
    const exchangeKeypair = generateX25519Keypair();
    storeDevicePrivateKey(this.app, this.settings, deviceKeypair.privateKeyHex);
    this.settings.devicePublicKeyHex = deviceKeypair.publicKeyHex;
    storeDevicePairingPrivateKey(this.app, this.settings, exchangeKeypair.privateKeyHex);
    this.settings.devicePairingRequest = JSON.stringify({
      version: 1,
      label: this.settings.deviceLabel || "Obsidian device",
      verifying_key: deviceKeypair.publicKeyHex,
      x25519_public_key: exchangeKeypair.publicKeyHex,
    });
    await this.saveSettings();
    new Notice("Mylonite device pairing request generated.");
  }

  async authorizeDevicePairingRequest(): Promise<void> {
    if (!this.settings.vaultId) {
      new Notice("This device must already be paired before authorizing another device.");
      return;
    }
    const secretMaterial = await this.ensureVaultSecretMaterial();
    const request = JSON.parse(this.settings.devicePairingRequest) as DevicePairingRequestPayload;
    validateDevicePairingRequest(request);
    const client = this.createApiClient();
    const registered = await client.registerDevice(
      this.settings.vaultId,
      request.label || "Obsidian device",
      request.verifying_key,
    );
    const exchangeKeypair = generateX25519Keypair();
    const secret = new TextEncoder().encode(JSON.stringify({
      version: 1,
      vault_id: this.settings.vaultId,
      vault_salt_hex: secretMaterial.saltHex,
      passphrase: secretMaterial.passphrase,
      device_id: registered.device_id,
      last_server_seq: this.settings.lastServerSeq,
    }));
    const encrypted = encryptDevicePairingSecret(exchangeKeypair.privateKeyHex, request.x25519_public_key, secret);
    this.settings.devicePairingResponse = JSON.stringify({
      version: 1,
      x25519_public_key: exchangeKeypair.publicKeyHex,
      nonce_hex: encrypted.nonceHex,
      ciphertext_hex: encrypted.ciphertextHex,
    });
    await this.saveSettings();
    new Notice("Mylonite device pairing response generated.");
  }

  async completeDevicePairing(): Promise<void> {
    const privateKeyHex = loadDevicePrivateKey(this.app, this.settings);
    const pairingPrivateKeyHex = loadDevicePairingPrivateKey(this.app, this.settings);
    if (!privateKeyHex || !this.settings.devicePublicKeyHex || !pairingPrivateKeyHex) {
      new Notice("Generate a device pairing request on this device first.");
      return;
    }
    const response = JSON.parse(this.settings.devicePairingResponse) as DevicePairingResponsePayload;
    validateDevicePairingResponse(response);
    const plaintext = decryptDevicePairingSecret(pairingPrivateKeyHex, response.x25519_public_key, {
      nonceHex: response.nonce_hex,
      ciphertextHex: response.ciphertext_hex,
    });
    const secret = JSON.parse(new TextDecoder().decode(plaintext)) as DevicePairingSecretPayload;
    validateDevicePairingSecret(secret);
    this.settings.vaultId = secret.vault_id;
    this.settings.vaultSaltHex = secret.vault_salt_hex;
    this.settings.deviceId = secret.device_id;
    this.settings.lastServerSeq = secret.last_server_seq;
    clearDevicePairingPrivateKey(this.app, this.settings);
    this.settings.devicePairingResponse = "";
    storeDevicePrivateKey(this.app, this.settings, privateKeyHex);
    storePassphrase(this.app, this.settings, secret.passphrase);
    this.vaultKeys = null;
    await this.saveSettings();
    new Notice("Mylonite device pairing completed.");
  }

  createApiClient(): MyloniteApiClient {
    const privateKeyHex = loadDevicePrivateKey(this.app, this.settings);
    return new MyloniteApiClient(this.settings.serverUrl, privateKeyHex && this.settings.deviceId
      ? { deviceId: this.settings.deviceId, privateKeyHex }
      : undefined);
  }

  async createSnapshot(): Promise<void> {
    await this.syncEngine.createSnapshot();
  }

  async restoreLatestSnapshot(): Promise<void> {
    await this.syncEngine.restoreLatestSnapshot();
  }

  updateStatus(state: string): void {
    if (this.status) {
      this.status.setText(`Mylonite: ${state}`);
    }
  }

  private statusText(): string {
    if (!this.settings.serverUrl || !this.settings.vaultId) {
      return "Mylonite is not paired yet.";
    }
    return `Mylonite configured for vault ${this.settings.vaultId} on device ${this.settings.deviceId}.`;
  }

  debug(message: string): void {
    if (this.settings.debugLogging) {
      console.debug(`[mylonite] ${message}`);
    }
  }

  async loadVaultKeys(): Promise<VaultKeys> {
    if (!this.vaultKeys) {
      const secretMaterial = await this.ensureVaultSecretMaterial();
      this.vaultKeys = deriveVaultKeys(secretMaterial.passphrase, secretMaterial.saltHex);
    }
    return this.vaultKeys;
  }

  private async ensureVaultSecretMaterial(): Promise<{ passphrase: string; saltHex: string }> {
    let changed = false;
    if (!this.settings.vaultSaltHex) {
      this.settings.vaultSaltHex = randomHex(16);
      changed = true;
    }
    let passphrase = loadPassphrase(this.app, this.settings);
    if (!passphrase) {
      passphrase = randomHex(32);
      storePassphrase(this.app, this.settings, passphrase);
      changed = true;
    }
    if (changed) {
      this.vaultKeys = null;
      await this.saveSettings();
    }
    return { passphrase, saltHex: this.settings.vaultSaltHex };
  }
}

interface DevicePairingRequestPayload {
  version: number;
  label: string;
  verifying_key: string;
  x25519_public_key: string;
}

interface DevicePairingResponsePayload {
  version: number;
  x25519_public_key: string;
  nonce_hex: string;
  ciphertext_hex: string;
}

interface DevicePairingSecretPayload {
  version: number;
  vault_id: string;
  vault_salt_hex: string;
  passphrase: string;
  device_id: string;
  last_server_seq: number;
}

function validateDevicePairingRequest(payload: DevicePairingRequestPayload): void {
  if (payload.version !== 1 || !validDeviceLabel(payload.label) || !isHex(payload.verifying_key, 64) || !isHex(payload.x25519_public_key, 64)) {
    throw new Error("invalid device pairing request");
  }
}

function validateDevicePairingResponse(payload: DevicePairingResponsePayload): void {
  if (payload.version !== 1 || !isHex(payload.x25519_public_key, 64) || !isHex(payload.nonce_hex, 48) || !isHex(payload.ciphertext_hex)) {
    throw new Error("invalid device pairing response");
  }
}

function validateDevicePairingSecret(payload: DevicePairingSecretPayload): void {
  if (
    payload.version !== 1
    || !validOpaqueId(payload.vault_id)
    || !isHex(payload.vault_salt_hex, 32)
    || typeof payload.passphrase !== "string"
    || payload.passphrase.length === 0
    || !validDeviceId(payload.device_id)
    || !Number.isSafeInteger(payload.last_server_seq)
    || payload.last_server_seq < 0
  ) {
    throw new Error("invalid device pairing secret");
  }
}

function validOpaqueId(value: string): boolean {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && /^[A-Za-z0-9_-]+$/.test(value);
}

function validDeviceId(value: string): boolean {
  return typeof value === "string" && /^d[0-9a-f]{32}$/.test(value);
}

function validDeviceLabel(value: string): boolean {
  return typeof value === "string" && value.trim().length > 0 && new TextEncoder().encode(value).length <= 128;
}

function isHex(value: string, len?: number): boolean {
  return (len === undefined || value.length === len) && /^[0-9a-f]+$/.test(value);
}

import { Notice, Plugin } from "obsidian";

import { MyloniteApiClient, PairingGrantPayload } from "./api";
import { confirmAction } from "./confirm-modal";
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
  clearDevicePrivateKey,
  clearDevicePairingPrivateKey,
  clearPassphrase,
  loadDevicePairingPrivateKey,
  loadDevicePrivateKey,
  loadPassphrase,
  storeDevicePairingPrivateKey,
  storeDevicePrivateKey,
  storePassphrase,
} from "./secrets";
import { DEFAULT_SETTINGS, MyloniteSettings, MyloniteSettingTab } from "./settings";
import {
  DevicePairingInvitePayload,
  DevicePairingRequestPayload,
  DevicePairingResponsePayload,
  DevicePairingSecretPayload,
  createDevicePairingInvitePayload,
  createDevicePairingRequestPayload,
  inviteCodeHash,
  normalizeServerUrl,
  normalizeInviteCode,
  pairingSafetyCode,
  parseDevicePairingInviteInput,
  validateDevicePairingInvite,
  validateDevicePairingRequest,
  validateDevicePairingResponse,
  validateDevicePairingSecret,
  validatePairingRequestShape,
} from "./pairing";
import { LEGACY_SETTING_KEYS, LegacyState, readLegacyState } from "./migrate";
import { SyncEngine } from "./sync-engine";

export default class MylonitePlugin extends Plugin {
  settings: MyloniteSettings = { ...DEFAULT_SETTINGS };
  private status: HTMLElement | null = null;
  private vaultKeys: Promise<VaultKeys> | null = null;
  private syncEngine = new SyncEngine(this);
  private pairingPollTimer: number | null = null;
  private settingTab: MyloniteSettingTab | null = null;
  private legacyState: LegacyState | null = null;
  private legacyData: Record<string, unknown> | null = null;

  async onload(): Promise<void> {
    await this.loadSettings();

    this.addCommand({
      id: "show-sync-status",
      name: "show sync status",
      callback: () => new Notice(this.syncEngine.statusSummary()),
    });
    this.addCommand({
      id: "sync-now",
      name: "sync now",
      callback: () => void this.syncEngine.syncNow().catch((error: unknown) => new Notice(`Couldn't sync. Check the server URL and connection. ${String(error)}`)),
    });

    this.registerObsidianProtocolHandler("mylonite-pair", (params) => {
      const invite = typeof params.invite === "string" ? params.invite : "";
      void this.submitDevicePairingInvite(invite).then(() => this.refreshSettingsTab());
    });

    this.settingTab = new MyloniteSettingTab(this.app, this, this);
    this.addSettingTab(this.settingTab);
    this.status = this.addStatusBarItem();
    this.updateStatus("idle");
    this.startPairingPolling();

    this.app.workspace.onLayoutReady(() => {
      this.syncEngine.start();
    });
  }

  onunload(): void {
    this.stopPairingPolling();
    void this.syncEngine.close();
    this.status?.remove();
    this.status = null;
  }

  async loadSettings(): Promise<void> {
    const storedData = await this.loadData() as unknown;
    const stored: Record<string, unknown> = isRecord(storedData) ? { ...storedData } : {};
    if (LEGACY_SETTING_KEYS.some((key) => key in stored)) {
      this.legacyData = Object.fromEntries(LEGACY_SETTING_KEYS.map((key) => [key, stored[key]]));
      this.legacyState = stored.vaultId ? readLegacyState(stored) : null;
      for (const key of LEGACY_SETTING_KEYS) {
        delete stored[key];
      }
    }
    this.settings = { ...DEFAULT_SETTINGS, ...stored };
  }

  takeLegacyState(): LegacyState | null {
    const state = this.legacyState;
    this.legacyState = null;
    return state;
  }

  async retireLegacyState(): Promise<void> {
    const dir = this.manifest.dir;
    const adapter = this.app.vault.adapter;
    if (dir && this.legacyData) {
      await adapter.write(`${dir}/sync-v2-backup.json`, JSON.stringify(this.legacyData));
      const docPath = `${dir}/doc-${this.settings.vaultId}.bin`;
      if (await adapter.exists(docPath)) {
        await adapter.remove(docPath);
      }
    }
    this.legacyData = null;
    await this.saveSettings();
  }

  async saveSettings(): Promise<void> {
    const started = performance.now();
    try {
      await this.saveData(this.settings);
    } finally {
      const elapsedMs = performance.now() - started;
      if (elapsedMs >= 50) {
        this.debug(`slow sync span saveData settings: ${elapsedMs.toFixed(1)}ms`);
      }
    }
  }

  async pairFirstDevice(): Promise<void> {
    if (!this.settings.serverUrl || !this.settings.pairingToken) {
      new Notice("Missing server URL or token. Enter both to continue.");
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
      this.syncEngine.start();
      new Notice("Device paired.");
    } catch (error) {
      this.updateStatus("pairing failed");
      new Notice(`Pairing failed. Check the token and try again. ${String(error)}`);
    }
  }

  async createDevicePairingInvite(): Promise<void> {
    if (!this.settings.vaultId || !this.settings.serverUrl) {
      new Notice("This device is not ready to create an invite.");
      return;
    }
    try {
      const sessionId = `ps${randomHex(16)}`;
      const invite = createDevicePairingInvitePayload(this.settings.serverUrl);
      const client = this.createApiClient();
      await client.openPairingSession(this.settings.vaultId, sessionId, inviteCodeHash(sessionId, invite.invite_code));
      this.settings.devicePairingInvite = JSON.stringify(invite);
      this.settings.devicePairingSessionId = sessionId;
      this.settings.devicePairingRequest = "";
      this.settings.devicePairingResponse = "";
      await this.saveSettings();
      this.startPairingPolling();
      new Notice(`Device invite ready. Code ${invite.invite_code}.`);
    } catch (error) {
      new Notice(`Could not create invite. Check the server connection and try again. ${String(error)}`);
    }
  }

  async submitDevicePairingInvite(inviteInput: string): Promise<void> {
    let invite: DevicePairingInvitePayload;
    try {
      invite = parseDevicePairingInviteInput(inviteInput);
    } catch (error) {
      try {
        invite = {
          version: 1,
          server_url: normalizeServerUrl(this.settings.serverUrl),
          invite_code: normalizeInviteCode(inviteInput),
        };
        validateDevicePairingInvite(invite);
      } catch {
        new Notice(`Invalid invite. Scan the QR code, paste the invite link, or enter the invite code with the server URL. ${String(error)}`);
        return;
      }
    }
    try {
      const existingPrivateKey = loadDevicePrivateKey(this.app, this.settings);
      const deviceKeypair = existingPrivateKey && this.settings.devicePublicKeyHex
        ? { privateKeyHex: existingPrivateKey, publicKeyHex: this.settings.devicePublicKeyHex }
        : generateDeviceKeypair();
      const exchangeKeypair = generateX25519Keypair();
      const request = createDevicePairingRequestPayload(
        invite.invite_code,
        this.settings.deviceLabel || "Obsidian device",
        deviceKeypair.publicKeyHex,
        exchangeKeypair.publicKeyHex,
      );
      const client = new MyloniteApiClient(invite.server_url);
      const submitted = await client.submitPairingSessionRequest(invite.invite_code, {
        request_hash: request.request_hash,
        label: request.label,
        verifying_key: request.verifying_key,
        x25519_public_key: request.x25519_public_key,
      });
      this.settings.serverUrl = normalizeServerUrl(invite.server_url);
      this.settings.devicePairingInvite = JSON.stringify(invite);
      this.settings.devicePairingSessionId = submitted.session_id;
      this.settings.devicePairingRequest = JSON.stringify(request);
      this.settings.devicePairingResponse = "";
      this.settings.devicePublicKeyHex = deviceKeypair.publicKeyHex;
      storeDevicePrivateKey(this.app, this.settings, deviceKeypair.privateKeyHex);
      storeDevicePairingPrivateKey(this.app, this.settings, exchangeKeypair.privateKeyHex);
      await this.saveSettings();
      this.startPairingPolling();
      new Notice(`Join request sent. Safety code ${pairingSafetyCode(request.request_hash)}.`);
    } catch (error) {
      new Notice(`Could not join invite. Check the invite code and server URL. ${String(error)}`);
    }
  }

  async authorizeDevicePairingRequest(): Promise<void> {
    if (!this.settings.vaultId) {
      new Notice("This device is not paired. Pair it before authorizing another device.");
      return;
    }
    const invite = this.currentPairingInvite();
    const request = this.currentPairingRequest();
    if (!invite || !request || !this.settings.devicePairingSessionId) {
      new Notice("No pending device request to approve.");
      return;
    }
    try {
      validateDevicePairingRequest(request, invite.invite_code);
    } catch (error) {
      new Notice(`Invalid device request. Ask the new device to try again. ${String(error)}`);
      return;
    }
    const approved = await confirmAction(this.app, {
      title: "Approve device",
      message: `Approve "${request.label}"? Safety code: ${pairingSafetyCode(request.request_hash)}`,
      confirmText: "Approve",
    });
    if (!approved) {
      return;
    }
    try {
      const secretMaterial = await this.ensureVaultSecretMaterial();
      const client = this.createApiClient();
      const session = await client.getPairingSession(this.settings.vaultId, this.settings.devicePairingSessionId);
      if (session.status === "expired") {
        new Notice("Invite expired. Create a new invite.");
        return;
      }
      if (session.status === "granted") {
        new Notice("Invite was already approved. Ask the new device to check approval.");
        return;
      }
      if (session.status !== "requested" || session.request.request_hash !== request.request_hash) {
        new Notice("The pending request changed. Review the safety code again.");
        await this.pollPairingState(true);
        return;
      }
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
        request_hash: request.request_hash,
        last_server_seq: 0,
      }));
      const encrypted = encryptDevicePairingSecret(exchangeKeypair.privateKeyHex, request.x25519_public_key, secret);
      const grant: PairingGrantPayload = {
        x25519_public_key: exchangeKeypair.publicKeyHex,
        nonce_hex: encrypted.nonceHex,
        ciphertext_hex: encrypted.ciphertextHex,
      };
      await client.putPairingSessionGrant(this.settings.vaultId, this.settings.devicePairingSessionId, request.request_hash, grant);
      this.settings.devicePairingInvite = "";
      this.settings.devicePairingSessionId = "";
      this.settings.devicePairingRequest = "";
      this.settings.devicePairingResponse = "";
      await this.saveSettings();
      this.stopPairingPolling();
      this.refreshSettingsTab();
      new Notice("Device approved. The new device will finish automatically.");
    } catch (error) {
      new Notice(`Authorization failed. Check the request and try again. ${String(error)}`);
      return;
    }
    try {
      await this.syncEngine.createSnapshot();
    } catch (error) {
      this.debug(`post-approval snapshot failed: ${String(error)}`);
    }
  }

  async completeDevicePairing(): Promise<void> {
    const request = this.currentPairingRequest();
    const privateKeyHex = loadDevicePrivateKey(this.app, this.settings);
    const pairingPrivateKeyHex = loadDevicePairingPrivateKey(this.app, this.settings);
    if (!request || !privateKeyHex || !this.settings.devicePublicKeyHex || !pairingPrivateKeyHex) {
      new Notice("Missing join request. Enter the invite again.");
      return;
    }
    if (!this.settings.devicePairingResponse) {
      new Notice("Still waiting for approval from a paired device.");
      return;
    }
    try {
      const response = JSON.parse(this.settings.devicePairingResponse) as DevicePairingResponsePayload;
      validateDevicePairingResponse(response);
      const plaintext = decryptDevicePairingSecret(pairingPrivateKeyHex, response.x25519_public_key, {
        nonceHex: response.nonce_hex,
        ciphertextHex: response.ciphertext_hex,
      });
      const secret = JSON.parse(new TextDecoder().decode(plaintext)) as DevicePairingSecretPayload;
      validateDevicePairingSecret(secret, request.request_hash);
      this.settings.vaultId = secret.vault_id;
      this.settings.vaultSaltHex = secret.vault_salt_hex;
      this.settings.deviceId = secret.device_id;
      clearDevicePairingPrivateKey(this.app, this.settings);
      this.settings.devicePairingInvite = "";
      this.settings.devicePairingSessionId = "";
      this.settings.devicePairingResponse = "";
      this.settings.devicePairingRequest = "";
      storeDevicePrivateKey(this.app, this.settings, privateKeyHex);
      storePassphrase(this.app, this.settings, secret.passphrase);
      this.vaultKeys = null;
      await this.saveSettings();
      this.stopPairingPolling();
      this.updateStatus("Paired");
      this.syncEngine.start();
      this.refreshSettingsTab();
      new Notice("Device paired.");
    } catch (error) {
      new Notice(`Pairing failed. Check the approval and try again. ${String(error)}`);
    }
  }

  async checkDevicePairingStatus(): Promise<void> {
    await this.pollPairingState(true);
  }

  private startPairingPolling(): void {
    if (this.pairingPollTimer !== null || !this.hasPairingStateToPoll()) {
      return;
    }
    this.pairingPollTimer = this.registerInterval(window.setInterval(() => {
      void this.pollPairingState(false);
    }, 3000));
    void this.pollPairingState(false);
  }

  private stopPairingPolling(): void {
    if (this.pairingPollTimer === null) {
      return;
    }
    window.clearInterval(this.pairingPollTimer);
    this.pairingPollTimer = null;
  }

  private hasPairingStateToPoll(): boolean {
    if (this.settings.vaultId) {
      return Boolean(this.settings.devicePairingInvite && this.settings.devicePairingSessionId);
    }
    return Boolean(this.settings.devicePairingRequest && this.settings.devicePairingSessionId);
  }

  private async pollPairingState(showNotice: boolean): Promise<void> {
    if (this.settings.vaultId) {
      await this.pollPendingPairingRequest(showNotice);
      return;
    }
    await this.pollDevicePairingGrant(showNotice);
  }

  private async pollPendingPairingRequest(showNotice: boolean): Promise<void> {
    if (!this.settings.vaultId || !this.settings.devicePairingInvite || !this.settings.devicePairingSessionId) {
      this.stopPairingPolling();
      return;
    }
    try {
      const session = await this.createApiClient().getPairingSession(this.settings.vaultId, this.settings.devicePairingSessionId);
      if (session.status === "expired") {
        this.settings.devicePairingInvite = "";
        this.settings.devicePairingSessionId = "";
        this.settings.devicePairingRequest = "";
        await this.saveSettings();
        this.stopPairingPolling();
        this.refreshSettingsTab();
        if (showNotice) {
          new Notice("Invite expired. Create a new one.");
        }
        return;
      }
      if (session.status === "waiting") {
        if (showNotice) {
          new Notice("Still waiting for the new device.");
        }
        return;
      }
      if (session.status === "granted") {
        this.settings.devicePairingInvite = "";
        this.settings.devicePairingSessionId = "";
        this.settings.devicePairingRequest = "";
        await this.saveSettings();
        this.stopPairingPolling();
        this.refreshSettingsTab();
        return;
      }
      const invite = this.currentPairingInvite();
      if (!invite) {
        this.settings.devicePairingInvite = "";
        this.settings.devicePairingSessionId = "";
        this.settings.devicePairingRequest = "";
        await this.saveSettings();
        this.stopPairingPolling();
        this.refreshSettingsTab();
        if (showNotice) {
          new Notice("Invite state is invalid. Create a new invite.");
        }
        return;
      }
      const request: DevicePairingRequestPayload = { version: 1, ...session.request };
      validateDevicePairingRequest(request, invite.invite_code);
      if (this.settings.devicePairingRequest !== JSON.stringify(request)) {
        this.settings.devicePairingRequest = JSON.stringify(request);
        await this.saveSettings();
        this.refreshSettingsTab();
        new Notice(`New device request received. Safety code ${pairingSafetyCode(request.request_hash)}.`);
      }
    } catch (error) {
      if (showNotice) {
        new Notice(`Could not check invite. ${String(error)}`);
      } else {
        this.debug(`pairing invite poll failed: ${String(error)}`);
      }
    }
  }

  private async pollDevicePairingGrant(showNotice: boolean): Promise<void> {
    if (this.settings.vaultId || !this.settings.devicePairingRequest || !this.settings.devicePairingSessionId) {
      this.stopPairingPolling();
      return;
    }
    const request = this.currentPairingRequest();
    if (!request) {
      if (showNotice) {
        new Notice("Invalid join request. Enter the invite again.");
      }
      this.stopPairingPolling();
      return;
    }
    try {
      const client = new MyloniteApiClient(this.settings.serverUrl);
      const response = await client.getPairingSessionGrant(this.settings.devicePairingSessionId);
      if (response.status === "expired") {
        clearDevicePairingPrivateKey(this.app, this.settings);
        this.settings.devicePairingSessionId = "";
        this.settings.devicePairingRequest = "";
        this.settings.devicePairingResponse = "";
        await this.saveSettings();
        this.stopPairingPolling();
        this.refreshSettingsTab();
        new Notice("Invite expired. Enter a new one.");
        return;
      }
      if (response.status === "pending") {
        if (showNotice) {
          new Notice(`Still waiting for approval. Safety code ${pairingSafetyCode(request.request_hash)}.`);
        }
        return;
      }
      const grant: DevicePairingResponsePayload = {
        version: 1,
        x25519_public_key: response.grant.x25519_public_key,
        nonce_hex: response.grant.nonce_hex,
        ciphertext_hex: response.grant.ciphertext_hex,
      };
      this.settings.devicePairingResponse = JSON.stringify(grant);
      await this.saveSettings();
      await this.completeDevicePairing();
    } catch (error) {
      if (showNotice) {
        new Notice(`Could not check for approval. ${String(error)}`);
      } else {
        this.debug(`pairing grant poll failed: ${String(error)}`);
      }
    }
  }

  private currentPairingInvite(): DevicePairingInvitePayload | null {
    if (!this.settings.devicePairingInvite) {
      return null;
    }
    try {
      return parseDevicePairingInviteInput(this.settings.devicePairingInvite);
    } catch {
      return null;
    }
  }

  private currentPairingRequest(): DevicePairingRequestPayload | null {
    if (!this.settings.devicePairingRequest) {
      return null;
    }
    try {
      const request = JSON.parse(this.settings.devicePairingRequest) as DevicePairingRequestPayload;
      validatePairingRequestShape(request);
      return request;
    } catch {
      return null;
    }
  }

  createApiClient(): MyloniteApiClient {
    const privateKeyHex = loadDevicePrivateKey(this.app, this.settings);
    return new MyloniteApiClient(this.settings.serverUrl, privateKeyHex && this.settings.deviceId
      ? { deviceId: this.settings.deviceId, privateKeyHex }
      : undefined);
  }

  async resync(): Promise<void> {
    const confirmed = await confirmAction(this.app, {
      title: "Resync this device",
      message: "Mylonite downloads the vault again and compares it with your files. Files that differ are kept as conflict copies. Nothing is deleted.",
      confirmText: "Resync",
    });
    if (confirmed) {
      await this.syncEngine.resync();
    }
  }

  async unpairDevice(): Promise<void> {
    const confirmed = await confirmAction(this.app, {
      title: "Unpair device",
      message: "Unpair this device? It will stop syncing immediately.",
      confirmText: "Unpair",
    });
    if (!confirmed) {
      return;
    }
    this.stopPairingPolling();
    await this.syncEngine.destroy();
    clearDevicePrivateKey(this.app, this.settings);
    clearDevicePairingPrivateKey(this.app, this.settings);
    clearPassphrase(this.app, this.settings);
    this.settings.vaultId = "";
    this.settings.vaultSaltHex = "";
    this.settings.deviceId = "";
    this.settings.devicePublicKeyHex = "";
    this.settings.pairingToken = "";
    this.settings.devicePairingInvite = "";
    this.settings.devicePairingSessionId = "";
    this.settings.devicePairingRequest = "";
    this.settings.devicePairingResponse = "";
    this.vaultKeys = null;
    await this.saveSettings();
    this.updateStatus("unpaired");
    new Notice("Device unpaired.");
  }

  refreshSettingsTab(): void {
    this.settingTab?.render();
  }

  updateStatus(state: string): void {
    if (this.status) {
      this.status.setText(`Mylonite: ${state}`);
    }
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

function isRecord(value: unknown): value is Partial<MyloniteSettings> {
  return typeof value === "object" && value !== null;
}

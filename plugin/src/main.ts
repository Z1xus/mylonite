import { Notice, Plugin } from "obsidian";

import { MyloniteApiClient, PairingGrantPayload } from "./api";
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
import { SyncEngine } from "./sync-engine";

export default class MylonitePlugin extends Plugin {
  settings: MyloniteSettings = { ...DEFAULT_SETTINGS };
  private status: HTMLElement | null = null;
  private vaultKeys: Promise<VaultKeys> | null = null;
  private syncEngine = new SyncEngine(this);
  private pairingPollTimer: number | null = null;
  private settingTab: MyloniteSettingTab | null = null;

  async onload(): Promise<void> {
    await this.loadSettings();

    this.addCommand({
      id: "show-sync-status",
      name: "show sync status",
      callback: () => new Notice(this.statusText()),
    });
    this.addCommand({
      id: "sync-now",
      name: "sync now",
      callback: () => void this.syncEngine.catchUp().catch((error) => new Notice(`Sync failed. Check the server URL and try again. ${String(error)}`)),
    });
    this.addCommand({
      id: "create-snapshot",
      name: "create snapshot",
      callback: () => void this.syncEngine.createSnapshot().catch((error) => new Notice(`Snapshot failed. Check the server connection and try again. ${String(error)}`)),
    });
    this.addCommand({
      id: "restore-latest-snapshot",
      name: "restore snapshot",
      callback: () => void this.syncEngine.restoreLatestSnapshot().catch((error) => new Notice(`Restore failed. Check the server connection and try again. ${String(error)}`)),
    });

    this.registerObsidianProtocolHandler("mylonite-pair", (params) => {
      const invite = typeof params.invite === "string" ? params.invite : "";
      void this.submitDevicePairingInvite(invite).then(() => this.refreshSettingsTab());
    });

    this.settingTab = new MyloniteSettingTab(this.app, this);
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
    this.syncEngine.close();
    this.status?.remove();
    this.status = null;
  }

  async loadSettings(): Promise<void> {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    this.syncEngine.reloadDurableState();
  }

  async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
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
      this.settings.pendingBlobs = [];
      this.settings.pendingOps = [];
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
        new Notice(`Invalid invite. Paste invite text, scan the QR code, or enter a code with the server URL. ${String(error)}`);
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
    const approved = window.confirm(`Approve "${request.label}"?\n\nSafety code: ${pairingSafetyCode(request.request_hash)}`);
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
      await this.syncEngine.createSnapshot({ silent: true });
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
      this.settings.lastServerSeq = secret.last_server_seq;
      this.settings.lamport = 0;
      this.settings.pendingBlobs = [];
      this.settings.pendingOps = [];
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
      this.updateStatus("paired");
      try {
        await this.syncEngine.restoreLatestSnapshot({ deleteMissing: false, silent: true, requireSnapshot: false });
      } catch (error) {
        this.debug(`automatic snapshot restore failed: ${String(error)}`);
        new Notice("Device paired. Snapshot restore failed, so normal sync will catch up instead.");
      }
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
    this.pairingPollTimer = window.setInterval(() => {
      void this.pollPairingState(false);
    }, 3000);
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
        this.stopPairingPolling();
        if (showNotice) {
          new Notice("Invite expired. Enter a new one.");
        }
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

  async createSnapshot(): Promise<void> {
    await this.syncEngine.createSnapshot();
  }

  async restoreLatestSnapshot(): Promise<void> {
    await this.syncEngine.restoreLatestSnapshot();
  }

  async unpairDevice(): Promise<void> {
    const confirmed = window.confirm("Unpair this device? It will stop syncing immediately.");
    if (!confirmed) {
      return;
    }
    this.stopPairingPolling();
    this.syncEngine.close({ flushScheduledUpdates: false });
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
    this.settings.lamport = 0;
    this.settings.lastServerSeq = 0;
    this.settings.pendingBlobs = [];
    this.settings.pendingOps = [];
    this.settings.durableSyncState = {
      version: 1,
      index: { version: 1, files: [], tombstones: [] },
      journal: [],
    };
    this.vaultKeys = null;
    this.syncEngine.reloadDurableState();
    await this.saveSettings();
    this.updateStatus("unpaired");
    new Notice("Device unpaired.");
  }

  refreshSettingsTab(): void {
    this.settingTab?.display();
  }

  updateStatus(state: string): void {
    if (this.status) {
      this.status.setText(`Mylonite: ${state}`);
    }
  }

  private statusText(): string {
    if (!this.settings.serverUrl || !this.settings.vaultId) {
      return "Not paired. Pair this device to start syncing.";
    }
    return `Paired with vault ${this.settings.vaultId}.`;
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

import { afterEach, describe, expect, it, vi } from "vitest";

import { MyloniteApiClient } from "./api";

describe("MyloniteApiClient id validation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects invalid blob ids before building requests", async () => {
    const client = new MyloniteApiClient("http://localhost");

    await expect(client.putBlob("vault-a", "../secret", new Uint8Array())).rejects.toThrow("invalid blob id");
    await expect(client.putBlob("vault-a", "blob-a", new Uint8Array())).rejects.toThrow("invalid blob id");
    await expect(client.getBlob("vault-a", "bad/id")).rejects.toThrow("invalid blob id");
  });

  it("rejects invalid snapshot ids before building requests", async () => {
    const client = new MyloniteApiClient("http://localhost");

    await expect(client.putSnapshot("vault-a", {
      snapshot_id: "bad/id",
      device_id: "device-a",
      covers_through_seq: 1,
      key_version: 1,
      nonce_hex: "00",
      ciphertext_hex: "00",
    })).rejects.toThrow("invalid snapshot id");
    await expect(client.putSnapshot("vault-a", {
      snapshot_id: "snapshot-a",
      device_id: "device-a",
      covers_through_seq: 1,
      key_version: 1,
      nonce_hex: "00",
      ciphertext_hex: "00",
    })).rejects.toThrow("invalid snapshot id");
  });

  it("rejects invalid vault ids before building signed endpoints", async () => {
    const client = new MyloniteApiClient("http://localhost");

    await expect(client.listSnapshots("bad/id")).rejects.toThrow("invalid vault id");
    await expect(client.listOps("bad/id", 0)).rejects.toThrow("invalid vault id");
  });

  it("rejects malformed first-pairing requests before network requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    const client = new MyloniteApiClient("http://localhost");

    await expect(client.pairFirstDevice("bad-token", "device", "a".repeat(64))).rejects.toThrow("invalid pairing token");
    await expect(client.pairFirstDevice("p" + "a".repeat(48), " ", "a".repeat(64))).rejects.toThrow("invalid device label");
    await expect(client.pairFirstDevice("p" + "a".repeat(48), "device", "A".repeat(64))).rejects.toThrow("invalid Ed25519 verifying key");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("validates pairing relay requests before network requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    const client = new MyloniteApiClient("http://localhost");

    await expect(client.openPairingSession("vault-a", "bad-session", "a".repeat(64))).rejects.toThrow("invalid pairing session id");
    await expect(client.openPairingSession("vault-a", `ps${"a".repeat(32)}`, "b".repeat(63))).rejects.toThrow("invalid invite code hash");
    await expect(client.submitPairingSessionRequest("bad-code", {
      request_hash: "a".repeat(64),
      label: "Phone",
      verifying_key: "b".repeat(64),
      x25519_public_key: "c".repeat(64),
    })).rejects.toThrow("invalid invite code");
    await expect(client.submitPairingSessionRequest("ABCD-2345-WXYZ", {
      request_hash: "a".repeat(64),
      label: "",
      verifying_key: "b".repeat(64),
      x25519_public_key: "c".repeat(64),
    })).rejects.toThrow("invalid device label");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects malformed device registration requests before signing", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await expect(client.registerDevice("vault-a", "", "a".repeat(64))).rejects.toThrow("invalid device label");
    await expect(client.registerDevice("vault-a", "device", "a".repeat(63))).rejects.toThrow("invalid Ed25519 verifying key");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("validates pairing relay grants before signing", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await expect(client.putPairingSessionGrant("vault-a", "bad-session", "a".repeat(64), {
      x25519_public_key: "b".repeat(64),
      nonce_hex: "c".repeat(48),
      ciphertext_hex: "dd",
    })).rejects.toThrow("invalid pairing session id");
    await expect(client.putPairingSessionGrant("vault-a", `ps${"a".repeat(32)}`, "b".repeat(64), {
      x25519_public_key: "c".repeat(64),
      nonce_hex: "d".repeat(48),
      ciphertext_hex: "abc",
    })).rejects.toThrow("invalid ciphertext");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects invalid op list cursors before signing requests", async () => {
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await expect(client.listOps("vault-a", -1)).rejects.toThrow("invalid after");
    await expect(client.listOps("vault-a", 0, 0)).rejects.toThrow("invalid limit");
    await expect(client.listOps("vault-a", 0, 1.5)).rejects.toThrow("invalid limit");
  });

  it("rejects malformed signed request auth before network requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("[]", { status: 200 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "device-a", privateKeyHex: "00".repeat(32) });

    await expect(client.listSnapshots("vault-a")).rejects.toThrow("invalid device id");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects malformed encrypted op requests before network requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });
    const op = {
      client_op_id: "a".repeat(64),
      device_id: "d" + "1".repeat(32),
      lamport: 1,
      kind: 5,
      key_version: 1,
      nonce_hex: "b".repeat(48),
      ciphertext_hex: "abc",
    };

    await expect(client.appendOp("vault-a", op)).rejects.toThrow("invalid ciphertext");
    await expect(client.appendOp("vault-a", { ...op, ciphertext_hex: "cc", device_id: "d" + "2".repeat(32) })).rejects.toThrow("request device id does not match authenticated device");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects malformed snapshot upload requests before network requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 201 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await expect(client.putSnapshot("vault-a", {
      snapshot_id: "a".repeat(32),
      device_id: "d" + "1".repeat(32),
      covers_through_seq: 1,
      key_version: 2,
      nonce_hex: "b".repeat(48),
      ciphertext_hex: "cc",
    })).rejects.toThrow("unsupported key version");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("includes explicit op list limits in the signed request path", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("[]", { status: 200 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await client.listOps("vault-a", 12, 512);

    expect(fetchMock).toHaveBeenCalledWith("http://localhost/api/v1/vaults/vault-a/ops?after=12&limit=512", expect.objectContaining({
      headers: expect.objectContaining({
        "x-mylonite-device-id": "d" + "1".repeat(32),
      }),
    }));
  });

  it("signs pairing relay grants against the vault-scoped path", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await client.putPairingSessionGrant("vault-a", `ps${"a".repeat(32)}`, "b".repeat(64), {
      x25519_public_key: "c".repeat(64),
      nonce_hex: "d".repeat(48),
      ciphertext_hex: "ee",
    });

    expect(fetchMock).toHaveBeenCalledWith("http://localhost/api/v1/vaults/vault-a/pairing-sessions/psaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/grant", expect.objectContaining({
      method: "POST",
      headers: expect.objectContaining({
        "x-mylonite-device-id": "d" + "1".repeat(32),
      }),
    }));
  });

  it("opens pairing sessions against the vault-scoped signed path", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      session_id: `ps${"a".repeat(32)}`,
      expires_at_unix: 123,
    }), { status: 200 }));
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await client.openPairingSession("vault-a", `ps${"a".repeat(32)}`, "b".repeat(64));

    expect(fetchMock).toHaveBeenCalledWith("http://localhost/api/v1/vaults/vault-a/pairing-sessions", expect.objectContaining({
      method: "POST",
      headers: expect.objectContaining({
        "x-mylonite-device-id": "d" + "1".repeat(32),
      }),
    }));
  });

  it("requires auth for device listing", async () => {
    const client = new MyloniteApiClient("http://localhost");

    await expect(client.listDevices("vault-a")).rejects.toThrow("device authentication is required");
  });

  it("builds websocket URLs without query signatures", () => {
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    expect(client.websocketUrl("vault-a")).toBe("ws://localhost/ws?vault_id=vault-a&device_id=d11111111111111111111111111111111");
  });

  it("rejects invalid device ids before revocation requests", async () => {
    const client = new MyloniteApiClient("http://localhost", { deviceId: "d" + "1".repeat(32), privateKeyHex: "00".repeat(32) });

    await expect(client.revokeDevice("vault-a", "bad/device")).rejects.toThrow("invalid device id");
  });
});

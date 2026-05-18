import { describe, expect, it } from "vitest";

import {
  createDevicePairingInvitePayload,
  createDevicePairingRequestPayload,
  devicePairingInviteText,
  devicePairingInviteUrl,
  inviteCodeHash,
  pairingSafetyCode,
  parseDevicePairingInviteInput,
  validateDevicePairingRequest,
  validateDevicePairingSecret,
} from "./pairing";

describe("device pairing join payloads", () => {
  it("round trips invite text without relying on protocol handlers", () => {
    const invite = createDevicePairingInvitePayload("http://localhost:9821/");

    const parsed = parseDevicePairingInviteInput(devicePairingInviteText(invite));

    expect(parsed).toEqual({
      ...invite,
      server_url: "http://localhost:9821",
    });
    expect(parsed.invite_code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  });

  it("round trips through a camera-friendly HTTPS invite URL", () => {
    const invite = {
      version: 1,
      server_url: "https://sync.example.com",
      invite_code: "ABCD-2345-WXYZ",
    };

    expect(devicePairingInviteUrl(invite)).toBe("https://sync.example.com/p?c=ABCD2345WXYZ");
    expect(parseDevicePairingInviteInput(devicePairingInviteUrl(invite))).toEqual(invite);
  });

  it("hashes invite codes against the server session id", () => {
    const hash = inviteCodeHash(`ps${"a".repeat(32)}`, "ABCD-2345-WXYZ");

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(inviteCodeHash(`ps${"a".repeat(32)}`, "ABCD-2345-WXYZ")).toBe(hash);
    expect(inviteCodeHash(`ps${"b".repeat(32)}`, "ABCD-2345-WXYZ")).not.toBe(hash);
  });

  it("rejects tampered request hashes", () => {
    const inviteCode = "ABCD-2345-WXYZ";
    const request = createDevicePairingRequestPayload(
      inviteCode,
      "Phone",
      "b".repeat(64),
      "c".repeat(64),
    );

    expect(() => validateDevicePairingRequest({
      ...request,
      label: "Different phone",
    }, inviteCode)).toThrow("invalid device pairing request");
    expect(pairingSafetyCode(request.request_hash)).toMatch(/^\d{3} \d{3}$/);
  });

  it("binds decrypted pairing secrets to the original request hash", () => {
    const request = createDevicePairingRequestPayload(
      "ABCD-2345-WXYZ",
      "Phone",
      "b".repeat(64),
      "c".repeat(64),
    );

    expect(() => validateDevicePairingSecret({
      version: 1,
      vault_id: "vault-a",
      vault_salt_hex: "d".repeat(32),
      passphrase: "secret",
      device_id: `d${"e".repeat(32)}`,
      request_hash: request.request_hash,
      last_server_seq: 0,
    }, request.request_hash)).not.toThrow();

    expect(() => validateDevicePairingSecret({
      version: 1,
      vault_id: "vault-a",
      vault_salt_hex: "d".repeat(32),
      passphrase: "secret",
      device_id: `d${"e".repeat(32)}`,
      request_hash: "f".repeat(64),
      last_server_seq: 0,
    }, request.request_hash)).toThrow("invalid device pairing secret");
  });
});

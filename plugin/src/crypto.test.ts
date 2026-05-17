import { describe, expect, it } from "vitest";
import { blake3 } from "@noble/hashes/blake3.js";

import { bytesToHex, decryptDevicePairingSecret, encryptDevicePairingSecret, generateX25519Keypair, keyedBlobId } from "./crypto";

describe("device pairing secret encryption", () => {
  it("decrypts with the peer X25519 keypair", () => {
    const existingDevice = generateX25519Keypair();
    const newDevice = generateX25519Keypair();
    const plaintext = new TextEncoder().encode("vault secret material");

    const encrypted = encryptDevicePairingSecret(existingDevice.privateKeyHex, newDevice.publicKeyHex, plaintext);
    const decrypted = decryptDevicePairingSecret(newDevice.privateKeyHex, existingDevice.publicKeyHex, encrypted);

    expect(new TextDecoder().decode(decrypted)).toBe("vault secret material");
  });
});

describe("keyed blob ids", () => {
  it("uses keyed BLAKE3 over vault context and plaintext", () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode("binary attachment bytes");
    const material = new TextEncoder().encode("mylonite-blob-id-v1|vault-a|binary attachment bytes");

    expect(keyedBlobId(key, "vault-a", plaintext)).toBe(bytesToHex(blake3(material, { key })));
  });
});

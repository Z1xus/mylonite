import { describe, expect, it } from "vitest";
import { VaultKeys } from "./crypto";
import { decryptBlob, decryptOp, decryptSnapshot, encryptBlob, encryptOp, encryptSnapshot } from "./sync-codec";

const keys: VaultKeys = {
  opKey: new Uint8Array(32).fill(1),
  blobKey: new Uint8Array(32).fill(2),
  blobIdKey: new Uint8Array(32).fill(3),
  snapshotKey: new Uint8Array(32).fill(4),
};

describe("sync codec", () => {
  it("round-trips encrypted op payloads", () => {
    const payload = { path: "note.md", markdown: "hello" };
    const op = encryptOp(keys, "vault-a", "device-a", "a".repeat(64), payload);

    expect(decryptOp(keys, "vault-a", op)).toEqual(payload);
  });

  it("round-trips blob envelopes", () => {
    const plaintext = new TextEncoder().encode("binary contents");
    const encrypted = encryptBlob(keys, "vault-a", plaintext);

    const decrypted = decryptBlob(keys, "vault-a", encrypted.blobId, encrypted.envelope);

    expect(Array.from(decrypted)).toEqual(Array.from(plaintext));
  });

  it("round-trips encrypted snapshots", () => {
    const payload = { files: [{ path: "note.md", markdown: "hello" }] };
    const snapshot = encryptSnapshot(keys, "vault-a", "snapshot-a", 9, payload);

    const decrypted = decryptSnapshot(
      keys,
      "vault-a",
      "snapshot-a",
      9,
      snapshot.nonceHex,
      snapshot.ciphertextHex,
    );

    expect(decrypted).toEqual(payload);
  });
});

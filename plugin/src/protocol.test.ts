import { describe, expect, it } from "vitest";
import { ClientMsgKind, decodeFrame, encodeFrame } from "./protocol";

describe("protocol frames", () => {
  it("round-trips encoded frames", () => {
    const payload = new TextEncoder().encode("hello");
    const encoded = encodeFrame({ kind: ClientMsgKind.Ping, flags: 7, payload });

    const decoded = decodeFrame(encoded);

    expect(decoded.kind).toBe(ClientMsgKind.Ping);
    expect(decoded.flags).toBe(7);
    expect(Array.from(decoded.payload)).toEqual(Array.from(payload));
  });
});

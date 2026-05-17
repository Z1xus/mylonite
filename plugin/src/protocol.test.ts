import { describe, expect, it } from "vitest";
import { ClientMsgKind, ServerMsgKind, decodeFrame, encodeFrame } from "./protocol";

describe("protocol frames", () => {
  it("round-trips encoded frames", () => {
    const payload = new TextEncoder().encode("hello");
    const encoded = encodeFrame({ kind: ClientMsgKind.Ping, flags: 7, payload });

    const decoded = decodeFrame(encoded);

    expect(decoded.kind).toBe(ClientMsgKind.Ping);
    expect(decoded.flags).toBe(7);
    expect(Array.from(decoded.payload)).toEqual(Array.from(payload));
  });

  it("keeps websocket sync kind numbers stable", () => {
    expect(ClientMsgKind.Hello).toBe(1);
    expect(ClientMsgKind.OpPush).toBe(3);
    expect(ClientMsgKind.Ping).toBe(9);
    expect(ServerMsgKind.HelloAck).toBe(2);
    expect(ServerMsgKind.OpBroadcast).toBe(4);
    expect(ServerMsgKind.Pong).toBe(10);
  });
});

const MAGIC_0 = 0x4d;
const MAGIC_1 = 0x59;
const VERSION = 1;
const HEADER_LEN = 10;
const MAX_PAYLOAD_LEN = 16 * 1024 * 1024;

export const ClientMsgKind = {
  Hello: 1,
  OpLogRequest: 2,
  OpPush: 3,
  BlobPut: 4,
  BlobGet: 5,
  SnapshotPut: 6,
  PairingOpen: 7,
  PairingGrant: 8,
  Ping: 9,
} as const;

export const ServerMsgKind = {
  HelloChallenge: 1,
  HelloAck: 2,
  OpLog: 3,
  OpBroadcast: 4,
  BlobAck: 5,
  Blob: 6,
  BlobMissing: 7,
  Snapshot: 8,
  PairingEvent: 9,
  Pong: 10,
  Error: 255,
} as const;

export interface Frame {
  kind: number;
  flags: number;
  payload: Uint8Array;
}

export function encodeFrame(frame: Frame): Uint8Array {
  if (frame.payload.byteLength > MAX_PAYLOAD_LEN) {
    throw new Error("payload length exceeds limit");
  }

  const out = new Uint8Array(HEADER_LEN + frame.payload.byteLength);
  const view = new DataView(out.buffer);
  out[0] = MAGIC_0;
  out[1] = MAGIC_1;
  out[2] = VERSION;
  out[3] = frame.kind;
  view.setUint16(4, frame.flags, false);
  view.setUint32(6, frame.payload.byteLength, false);
  out.set(frame.payload, HEADER_LEN);
  return out;
}

export function decodeFrame(bytes: Uint8Array): Frame {
  if (bytes.byteLength < HEADER_LEN) {
    throw new Error("frame is shorter than the header");
  }
  if (bytes[0] !== MAGIC_0 || bytes[1] !== MAGIC_1) {
    throw new Error("invalid frame magic");
  }
  if (bytes[2] !== VERSION) {
    throw new Error(`unsupported frame version ${bytes[2]}`);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const len = view.getUint32(6, false);
  if (len > MAX_PAYLOAD_LEN) {
    throw new Error("payload length exceeds limit");
  }
  if (bytes.byteLength < HEADER_LEN + len) {
    throw new Error("frame payload is incomplete");
  }

  return {
    kind: bytes[3],
    flags: view.getUint16(4, false),
    payload: bytes.slice(HEADER_LEN, HEADER_LEN + len),
  };
}

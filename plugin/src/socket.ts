import { ClientMsgKind, ServerMsgKind, decodeFrame, encodeFrame } from "./protocol";

const RECONNECT_DELAYS_MS = [1_000, 2_000, 5_000, 15_000, 30_000];
const PING_INTERVAL_MS = 30_000;
const SILENCE_LIMIT_MS = 75_000;

export interface LiveSocketOptions {
  url(): string;
  hello(challengeHex: string): object;
  onRecord(record: unknown): void;
  onLive(live: boolean): void;
  debug(message: string): void;
}

export class LiveSocket {
  private socket: WebSocket | null = null;
  private reconnectTimer: number | null = null;
  private pingTimer: number | null = null;
  private attempt = 0;
  private lastMessageAt = 0;
  private stopped = true;

  constructor(private readonly options: LiveSocketOptions) {}

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.clearTimers();
    this.drop();
  }

  push(op: object): void {
    if (this.socket) {
      this.send(this.socket, ClientMsgKind.OpPush, JSON.stringify(op));
    }
  }

  private connect(): void {
    if (this.stopped || this.socket) {
      return;
    }
    let socket: WebSocket;
    try {
      socket = new WebSocket(this.options.url());
    } catch (error) {
      this.options.debug(`websocket connect failed: ${String(error)}`);
      this.scheduleReconnect();
      return;
    }
    socket.binaryType = "arraybuffer";
    socket.onmessage = (event: MessageEvent<ArrayBuffer>) => this.receive(socket, event.data);
    socket.onclose = () => {
      if (this.socket === socket) {
        this.drop();
        this.scheduleReconnect();
      }
    };
    socket.onerror = () => socket.close();
    this.socket = socket;
    this.lastMessageAt = Date.now();
  }

  private receive(socket: WebSocket, data: ArrayBuffer): void {
    this.lastMessageAt = Date.now();
    try {
      const frame = decodeFrame(new Uint8Array(data));
      const payload = new TextDecoder().decode(frame.payload);
      if (frame.kind === ServerMsgKind.HelloChallenge) {
        const challenge = JSON.parse(payload) as { challenge_hex?: unknown };
        if (typeof challenge.challenge_hex !== "string" || !/^[0-9a-f]{32}$/.test(challenge.challenge_hex)) {
          throw new Error("invalid websocket challenge");
        }
        this.send(socket, ClientMsgKind.Hello, JSON.stringify(this.options.hello(challenge.challenge_hex)));
      } else if (frame.kind === ServerMsgKind.HelloAck) {
        this.attempt = 0;
        this.startPing(socket);
        this.options.onLive(true);
      } else if (frame.kind === ServerMsgKind.OpBroadcast) {
        this.options.onRecord(JSON.parse(payload) as unknown);
      }
    } catch (error) {
      this.options.debug(`websocket message failed: ${String(error)}`);
      socket.close();
    }
  }

  private send(socket: WebSocket, kind: number, payload: string): void {
    const frame = encodeFrame({ kind, flags: 0, payload: new TextEncoder().encode(payload) });
    socket.send(frame.slice().buffer);
  }

  private startPing(socket: WebSocket): void {
    this.clearPing();
    this.pingTimer = window.setInterval(() => {
      if (Date.now() - this.lastMessageAt > SILENCE_LIMIT_MS) {
        socket.close();
        return;
      }
      this.send(socket, ClientMsgKind.Ping, "");
    }, PING_INTERVAL_MS);
  }

  private drop(): void {
    const socket = this.socket;
    this.socket = null;
    this.clearPing();
    if (socket) {
      socket.onclose = null;
      socket.onmessage = null;
      socket.close();
      this.options.onLive(false);
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer !== null) {
      return;
    }
    const delay = RECONNECT_DELAYS_MS[Math.min(this.attempt, RECONNECT_DELAYS_MS.length - 1)];
    this.attempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private clearPing(): void {
    if (this.pingTimer !== null) {
      window.clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private clearTimers(): void {
    this.clearPing();
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
}

import { createConnection } from 'node:net';
import type { Duplex } from 'node:stream';
import {
  FrameDecoder,
  type WarrendConfigure,
  type WarrendConnect,
  type WarrendState,
  configureRequest,
  connectRequest,
  disconnectRequest,
  encodeFrame,
  parseEvent,
} from './protocol.js';

/** Default dev socket path the daemon listens on. */
export const DEFAULT_WARREND_SOCKET = '/tmp/warren-sdk-daemon.sock';

/** Discriminator for {@link WarrendError}. */
export type WarrendErrorCode = 'already_open' | 'not_open';

/** A client-lifecycle misuse error. Never carries socket paths or identity material. */
export class WarrendError extends Error {
  readonly code: WarrendErrorCode;

  constructor(code: WarrendErrorCode, message: string) {
    super(message);
    this.name = 'WarrendError';
    this.code = code;
  }
}

/** A redacted error surfaced to the caller. */
export interface WarrendErrorEvent {
  kind: string;
  message: string;
}

/** Options for {@link WarrendClient}. */
export interface WarrendClientOptions {
  /** Unix socket path of the daemon. Ignored when `connectFactory` is given. */
  socketPath?: string;
  /** Connection factory (Unix socket by default). Inject a fake Duplex in tests. */
  connectFactory?: () => Duplex;
  /** Called on every connection-state event. */
  onState?: (state: WarrendState) => void;
  /** Called on a redacted daemon error or a transport/protocol failure. */
  onError?: (error: WarrendErrorEvent) => void;
  /** Called when the socket closes (the session is torn down). */
  onClose?: () => void;
}

/**
 * Client for the privileged `warrend` daemon (system-VPN mode).
 *
 * Speaks the length-prefixed JSON IPC protocol over a Unix socket. One
 * connection is one session: closing the socket tears the tunnel down
 * (fail-closed). This is pure protocol logic; the datapath runs in the daemon.
 */
export class WarrendClient {
  private socket: Duplex | undefined;
  private readonly options: WarrendClientOptions;

  constructor(options: WarrendClientOptions = {}) {
    this.options = options;
  }

  /** Opens the connection and starts decoding daemon events. */
  open(): void {
    if (this.socket) throw new WarrendError('already_open', 'warrend client already open');
    const socket = this.options.connectFactory
      ? this.options.connectFactory()
      : createConnection(this.options.socketPath ?? DEFAULT_WARREND_SOCKET);
    this.socket = socket;
    // One decoder per session: leftover partial bytes from a previous socket
    // must never corrupt the next session's stream.
    const decoder = new FrameDecoder();
    socket.on('data', (chunk: Buffer) => this.onData(socket, decoder, chunk));
    // Redact the raw error: it may carry the socket path.
    socket.on('error', () =>
      this.options.onError?.({ kind: 'transport', message: 'socket error' }),
    );
    socket.on('close', () => {
      // A stale close from a replaced socket must not detach the live session.
      if (this.socket === socket) this.socket = undefined;
      this.options.onClose?.();
    });
  }

  /** Sends the `configure` request, binding identity and account API. */
  configure(config: WarrendConfigure): void {
    this.send(configureRequest(config));
  }

  /** Sends the `connect` request to bring up the tunnel to an exit. */
  connect(request: WarrendConnect): void {
    this.send(connectRequest(request));
  }

  /** Sends the `disconnect` request. */
  disconnect(): void {
    this.send(disconnectRequest());
  }

  /** Closes the socket, tearing the session down (fail-closed). */
  close(): void {
    this.socket?.end();
    this.socket = undefined;
  }

  private send(message: Record<string, unknown>): void {
    if (!this.socket) throw new WarrendError('not_open', 'warrend client is not open');
    const frame = encodeFrame(message);
    // The configure frame carries the mnemonic in clear; zeroize the buffer
    // once the socket has flushed it (never before: node holds a reference).
    this.socket.write(frame, () => frame.fill(0));
  }

  private onData(socket: Duplex, decoder: FrameDecoder, chunk: Buffer): void {
    let messages: unknown[];
    try {
      messages = decoder.push(chunk);
    } catch {
      this.options.onError?.({ kind: 'protocol', message: 'malformed daemon frame' });
      // Fail-closed: the decoder cannot resync past a corrupt frame, so the
      // session would silently stop delivering daemon events (including
      // 'failed') while looking healthy. Tear it down instead.
      socket.destroy();
      return;
    }
    for (const message of messages) {
      const event = parseEvent(message);
      if (event?.type === 'state') {
        this.options.onState?.(event.state);
      } else if (event?.type === 'error') {
        this.options.onError?.({ kind: event.kind, message: event.message });
      }
    }
  }
}

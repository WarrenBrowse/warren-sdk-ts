import { Buffer } from 'node:buffer';

/** Maximum frame payload accepted, guarding against a malformed length prefix. */
const MAX_FRAME_BYTES = 16 * 1024 * 1024;

/**
 * The connection-state vocabulary emitted by warrend (matches the Dart enum).
 * `draining` is the teardown-in-progress state (killswitch still holding);
 * only `disconnected` means the network is restored.
 */
export type WarrendState =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'draining'
  | 'failed'
  | 'disconnected';

/** `configure` request: binds an identity and account API in the daemon. */
export interface WarrendConfigure {
  mnemonic: string;
  apiBase: string;
  /** Pinned discovery server pubkey (64-char hex). */
  serverPubkeyPin: string;
  multihopRootPin?: string;
  daita?: boolean;
  daitaMachine?: string;
  requestIpv6?: boolean;
}

/** `connect` request: brings up a system-VPN session to an exit. */
export interface WarrendConnect {
  /** Ed25519 exit id (hex) from the verified relay list. */
  exitPubkeyHex: string;
  dnsOverTunnel?: boolean;
}

/** A daemon to app event. */
export type WarrendEvent =
  | { type: 'state'; state: WarrendState }
  | { type: 'error'; kind: string; message: string };

/** Encodes a message as a 4-byte big-endian length prefix plus its UTF-8 JSON. */
export function encodeFrame(message: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(message), 'utf8');
  if (json.length > MAX_FRAME_BYTES) {
    throw new RangeError('warrend frame exceeds the maximum size');
  }
  const frame = Buffer.allocUnsafe(4 + json.length);
  frame.writeUInt32BE(json.length, 0);
  json.copy(frame, 4);
  return frame;
}

/** Stateful decoder turning a byte stream into length-prefixed JSON messages. */
export class FrameDecoder {
  private buffer: Buffer = Buffer.alloc(0);

  /** Appends a chunk and returns every complete message it now contains. */
  push(chunk: Buffer): unknown[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const messages: unknown[] = [];
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (length > MAX_FRAME_BYTES) {
        throw new RangeError('warrend frame exceeds the maximum size');
      }
      if (this.buffer.length < 4 + length) break;
      messages.push(JSON.parse(this.buffer.toString('utf8', 4, 4 + length)));
      this.buffer = this.buffer.subarray(4 + length);
    }
    return messages;
  }
}

/** Builds the `configure` request object in the exact wire shape (camelCase fields). */
export function configureRequest(config: WarrendConfigure): Record<string, unknown> {
  const request: Record<string, unknown> = {
    type: 'configure',
    mnemonic: config.mnemonic,
    apiBase: config.apiBase,
    serverPubkeyPin: config.serverPubkeyPin,
  };
  if (config.multihopRootPin !== undefined) request.multihopRootPin = config.multihopRootPin;
  if (config.daita !== undefined) request.daita = config.daita;
  if (config.daitaMachine !== undefined) request.daitaMachine = config.daitaMachine;
  if (config.requestIpv6 !== undefined) request.requestIpv6 = config.requestIpv6;
  return request;
}

/** Builds the `connect` request object. */
export function connectRequest(request: WarrendConnect): Record<string, unknown> {
  const out: Record<string, unknown> = { type: 'connect', exitPubkeyHex: request.exitPubkeyHex };
  if (request.dnsOverTunnel !== undefined) out.dnsOverTunnel = request.dnsOverTunnel;
  return out;
}

/** Builds the `disconnect` request object. */
export function disconnectRequest(): Record<string, unknown> {
  return { type: 'disconnect' };
}

const STATES: readonly WarrendState[] = [
  'connecting',
  'connected',
  'reconnecting',
  'draining',
  'failed',
  'disconnected',
];

/** Validates and narrows a decoded message into a {@link WarrendEvent}, or null. */
export function parseEvent(message: unknown): WarrendEvent | null {
  if (typeof message !== 'object' || message === null) return null;
  const m = message as Record<string, unknown>;
  if (
    m.type === 'state' &&
    typeof m.state === 'string' &&
    (STATES as readonly string[]).includes(m.state)
  ) {
    return { type: 'state', state: m.state as WarrendState };
  }
  if (m.type === 'error' && typeof m.kind === 'string' && typeof m.message === 'string') {
    return { type: 'error', kind: m.kind, message: m.message };
  }
  return null;
}

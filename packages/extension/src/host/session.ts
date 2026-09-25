import type { ProductChannel } from '@warrenbrowse/sdk-core';
import {
  EXTENSION_PROTOCOL_VERSION,
  type ExtensionEndpoints,
  type ExtensionExitLocation,
  type ExtensionProxyAuth,
  type ExtensionVpnState,
  type HostMessage,
  type HostRequest,
} from '../protocol.js';

/** The tunnel surface the session drives (ProxyTunnel-shaped; fakeable in tests). */
export interface HostTunnel {
  connect(options?: {
    selector?: { exitPubkeyHex?: string; country?: string; city?: string };
    entrySelector?: { country?: string; city?: string };
    httpProxy?: boolean;
  }): Promise<ExtensionEndpoints & ExtensionProxyAuth>;
  shutdown(): Promise<void>;
}

function isChannel(value: unknown): value is ProductChannel {
  return value === 'prod' || value === 'beta';
}

/** Whether a value is a credential a listener can carry: a non-empty string. */
function isCredential(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Builds one tunnel per session from the per-connect account mnemonic. Async so
 * the host can resolve the discovery pin (TOFU) before dialing. `onState`
 * receives every lifecycle transition.
 */
export type HostTunnelFactory = (
  mnemonic: string,
  onState: (state: string) => void,
  /** Tunnel-creation options that cannot wait for connect (engine-level). */
  init?: { daita?: boolean; channel?: ProductChannel },
) => Promise<HostTunnel>;

/** Options for {@link HostSession}. */
export interface HostSessionOptions {
  createTunnel: HostTunnelFactory;
  send: (message: HostMessage) => void;
  /** Verified relay-list locations; absent when the host has no discovery source.
   * `channel` is the one the extension named at hello, if it did. */
  listExits?: (channel: ProductChannel | undefined) => Promise<ExtensionExitLocation[]>;
  /** Signed subscription lookup; the mnemonic follows the connect handling rules. */
  accountStatus?: (
    mnemonic: string,
    channel: ProductChannel | undefined,
  ) => Promise<{ expiresAt: number }>;
}

/**
 * One extension connection worth of host logic: request dispatch and the
 * tunnel lifecycle, independent of the stdio transport so it is testable.
 */
export class HostSession {
  private readonly options: HostSessionOptions;
  private tunnel: HostTunnel | undefined;
  private endpoints: ExtensionEndpoints | undefined;
  private state: ExtensionVpnState = 'disconnected';
  private connecting = false;
  /** The extension's channel, from its hello. */
  private channel: ProductChannel | undefined;

  constructor(options: HostSessionOptions) {
    this.options = options;
  }

  /** Handles one decoded extension request. Never throws. */
  async handle(request: HostRequest): Promise<void> {
    if (typeof request !== 'object' || request === null || typeof request.id !== 'number') {
      return;
    }
    switch (request.type) {
      case 'hello':
        if (request.protocol !== EXTENSION_PROTOCOL_VERSION) {
          this.fail(request.id, 'protocol', 'unsupported protocol version');
        } else if (request.channel !== undefined && !isChannel(request.channel)) {
          this.fail(request.id, 'protocol', 'unknown release channel');
        } else {
          this.channel = request.channel;
          this.options.send({
            id: request.id,
            ok: true,
            type: 'hello',
            protocol: EXTENSION_PROTOCOL_VERSION,
          });
        }
        return;
      case 'status':
        this.options.send({
          id: request.id,
          ok: true,
          type: 'status',
          state: this.state,
          ...(this.endpoints ? { endpoints: this.endpoints } : {}),
        });
        return;
      case 'connect':
        await this.connect(request);
        return;
      case 'disconnect':
        await this.teardown();
        this.options.send({ id: request.id, ok: true, type: 'disconnect' });
        return;
      case 'exits':
        if (!this.options.listExits) {
          this.fail(request.id, 'protocol', 'host has no discovery source');
          return;
        }
        try {
          const locations = await this.options.listExits(this.channel);
          this.options.send({ id: request.id, ok: true, type: 'exits', locations });
        } catch (error) {
          this.fail(request.id, errorCode(error), errorMessage(error, 'exits failed'));
        }
        return;
      case 'account':
        if (!this.options.accountStatus) {
          this.fail(request.id, 'protocol', 'host has no account source');
          return;
        }
        try {
          const { expiresAt } = await this.options.accountStatus(request.mnemonic, this.channel);
          this.options.send({ id: request.id, ok: true, type: 'account', expiresAt });
        } catch (error) {
          this.fail(request.id, errorCode(error), errorMessage(error, 'account failed'));
        }
        return;
      default:
        this.fail((request as { id: number }).id, 'protocol', 'unknown request type');
    }
  }

  /** Tears a live tunnel down; called when the browser side goes away. */
  async close(): Promise<void> {
    await this.teardown();
  }

  private async connect(request: Extract<HostRequest, { type: 'connect' }>): Promise<void> {
    if (this.connecting || this.tunnel) {
      this.fail(request.id, 'already_connected', 'a session is already up');
      return;
    }
    this.connecting = true;
    let tunnel: HostTunnel | undefined;
    try {
      tunnel = await this.options.createTunnel(
        request.mnemonic,
        (state) => {
          this.state = state as ExtensionVpnState;
          this.options.send({ type: 'state', state: this.state });
        },
        {
          ...(request.daita !== undefined ? { daita: request.daita } : {}),
          ...(this.channel ? { channel: this.channel } : {}),
        },
      );
      const { socks5, http, username, password } = await tunnel.connect({
        ...(request.selector ? { selector: request.selector } : {}),
        ...(request.entrySelector ? { entrySelector: request.entrySelector } : {}),
        ...(request.httpProxy !== undefined ? { httpProxy: request.httpProxy } : {}),
      });
      if (!isCredential(username) || !isCredential(password)) {
        throw Object.assign(new Error('the tunnel reported no listener credentials'), {
          code: 'protocol',
        });
      }
      const endpoints: ExtensionEndpoints = { socks5, ...(http ? { http } : {}) };
      this.tunnel = tunnel;
      // Only the addresses stay here, for status: the credentials cross the
      // channel once, in this answer.
      this.endpoints = endpoints;
      this.state = 'connected';
      this.options.send({
        id: request.id,
        ok: true,
        type: 'connect',
        endpoints,
        auth: { username, password },
      });
    } catch (error) {
      // Fail-closed: never leave a half-built tunnel running after an error.
      await tunnel?.shutdown().catch(() => undefined);
      this.state = 'disconnected';
      this.fail(request.id, errorCode(error, 'tunnel'), errorMessage(error, 'connect failed'));
    } finally {
      this.connecting = false;
    }
  }

  private async teardown(): Promise<void> {
    const tunnel = this.tunnel;
    this.tunnel = undefined;
    this.endpoints = undefined;
    this.state = 'disconnected';
    if (tunnel) await tunnel.shutdown().catch(() => undefined);
  }

  private fail(id: number, code: string, message: string): void {
    this.options.send({ id, ok: false, code, message });
  }
}

function errorCode(error: unknown, fallback = 'host'): string {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String((error as { code: unknown }).code)
    : fallback;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

import type {
  NativeProxyEndpoints,
  NativeWarrenProxy,
  ProxyFatalCause,
  ProxyMetrics,
} from '@warrenbrowse/sdk-node';
import { describe, expect, it } from 'vitest';
import { hostTunnelFactory } from '../src/host/run.js';
import { HostSession } from '../src/host/session.js';
import type { HostMessage } from '../src/protocol.js';

/** The native addon at its boundary: its connect reports `reported`. */
class ReportingNative implements NativeWarrenProxy {
  readonly address = 'wbTEST';
  constructor(private readonly reported: NativeProxyEndpoints) {}
  onState(): void {}
  async connect(): Promise<NativeProxyEndpoints> {
    return this.reported;
  }
  async shutdown(): Promise<void> {}
  async metrics(): Promise<ProxyMetrics | null> {
    return null;
  }
  async fatalCause(): Promise<ProxyFatalCause | null> {
    return null;
  }
  async verifyEgress(): Promise<void> {}
  async forwardPort(): Promise<never> {
    throw new Error('unused');
  }
}

const LISTENER = { socks5: '127.0.0.1:1080', username: 'warren', password: 'session-secret' };

async function hostOver(reported: NativeProxyEndpoints): Promise<HostMessage[]> {
  const sent: HostMessage[] = [];
  const session = new HostSession({
    // A configured pin keeps the factory offline (no TOFU fetch).
    createTunnel: hostTunnelFactory(
      { serverPubkeyPin: '00'.repeat(32) },
      () => new ReportingNative(reported),
    ),
    send: (message) => sent.push(message),
  });
  await session.handle({ id: 1, type: 'connect', mnemonic: 'test mnemonic' });
  await session.handle({ id: 2, type: 'status' });
  return sent;
}

describe('the Node host tunnel factory', () => {
  it('hands the exit the engine names to the connect and status answers', async () => {
    const exit = { country: 'RO', city: 'Bucharest' };
    const [connected, status] = await hostOver({ ...LISTENER, exit });
    expect(connected).toMatchObject({ id: 1, ok: true, type: 'connect', exit });
    expect(status).toMatchObject({ id: 2, ok: true, state: 'connected', exit });
  });

  it('names no exit when the engine reports none, as on the failover datapath', async () => {
    const [connected, status] = await hostOver({ ...LISTENER, exit: null });
    expect(connected).toMatchObject({ id: 1, ok: true, type: 'connect' });
    expect(connected).not.toHaveProperty('exit');
    expect(status).not.toHaveProperty('exit');
  });
});

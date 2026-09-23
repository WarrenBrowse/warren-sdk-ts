import { describe, expect, it } from 'vitest';
import { callerAllowed } from '../src/host/run.js';
import { HostSession, type HostTunnel, type HostTunnelFactory } from '../src/host/session.js';
import { EXTENSION_PROTOCOL_VERSION, type HostMessage } from '../src/protocol.js';

const LISTENERS = { socks5: '127.0.0.1:1080', http: '127.0.0.1:8118' };
const AUTH = { username: 'warren', password: 'session-secret' };

class FakeTunnel implements HostTunnel {
  shutdownCalls = 0;
  onStateCb: ((state: string) => void) | undefined;
  seenMnemonic: string | undefined;
  seenConnect: unknown;
  constructor(
    private readonly failWith?: string,
    private readonly auth: Partial<typeof AUTH> = AUTH,
  ) {}

  async connect(
    options?: unknown,
  ): Promise<{ socks5: string; http?: string; username: string; password: string }> {
    this.seenConnect = options;
    if (this.failWith) {
      throw Object.assign(new Error(this.failWith), { code: 'api' });
    }
    this.onStateCb?.('connected');
    return { ...LISTENERS, ...this.auth } as typeof LISTENERS & typeof AUTH;
  }
  async shutdown(): Promise<void> {
    this.shutdownCalls += 1;
  }
}

const M = 'test mnemonic';

function makeSession(
  tunnel: FakeTunnel = new FakeTunnel(),
  extras: {
    listExits?: () => Promise<{ country: string; city: string; active: boolean }[]>;
    accountStatus?: (mnemonic: string) => Promise<{ expiresAt: number }>;
  } = {},
) {
  const sent: HostMessage[] = [];
  let seenInit: { daita?: boolean } | undefined;
  const factory: HostTunnelFactory = async (mnemonic, onState, init) => {
    tunnel.seenMnemonic = mnemonic;
    tunnel.onStateCb = onState;
    seenInit = init;
    return tunnel;
  };
  const session = new HostSession({
    createTunnel: factory,
    send: (m) => sent.push(m),
    ...extras,
  });
  return { session, sent, tunnel, seenInit: () => seenInit };
}

describe('HostSession', () => {
  it('answers hello with the protocol version only (identity-less host)', async () => {
    const { session, sent } = makeSession();
    await session.handle({ id: 1, type: 'hello', protocol: EXTENSION_PROTOCOL_VERSION });
    expect(sent[0]).toEqual({
      id: 1,
      ok: true,
      type: 'hello',
      protocol: EXTENSION_PROTOCOL_VERSION,
    });
  });

  it('rejects an unknown protocol version', async () => {
    const { session, sent } = makeSession();
    await session.handle({ id: 1, type: 'hello', protocol: 42 });
    expect(sent[0]).toMatchObject({ id: 1, ok: false, code: 'protocol' });
  });

  it('refuses a protocol 1 extension, which cannot answer its listeners', async () => {
    const { session, sent } = makeSession();
    await session.handle({ id: 1, type: 'hello', protocol: 1 });
    expect(sent[0]).toMatchObject({ id: 1, ok: false, code: 'protocol' });
  });

  it('connects with the per-request mnemonic and forwards tunnel state events', async () => {
    const { session, sent, tunnel } = makeSession();
    await session.handle({ id: 2, type: 'connect', mnemonic: M, selector: { country: 'NL' } });

    expect(tunnel.seenMnemonic).toBe(M);
    expect(sent).toContainEqual({ type: 'state', state: 'connected' });
    expect(sent).toContainEqual({
      id: 2,
      ok: true,
      type: 'connect',
      endpoints: LISTENERS,
      auth: AUTH,
    });
  });

  it('fails the connect and tears the tunnel down when it hands over no credentials', async () => {
    const tunnel = new FakeTunnel(undefined, { username: 'warren' });
    const { session, sent } = makeSession(tunnel);
    await session.handle({ id: 3, type: 'connect', mnemonic: M });

    expect(sent.at(-1)).toMatchObject({ id: 3, ok: false, code: 'protocol' });
    expect(tunnel.shutdownCalls).toBe(1);
  });

  it('maps a tunnel failure to an error response and tears the tunnel down', async () => {
    const tunnel = new FakeTunnel('subscription expired');
    const { session, sent } = makeSession(tunnel);
    await session.handle({ id: 3, type: 'connect', mnemonic: M });

    expect(sent[0]).toMatchObject({ id: 3, ok: false, code: 'api' });
    expect(tunnel.shutdownCalls).toBe(1);
  });

  it('rejects a second connect while connected', async () => {
    const { session, sent } = makeSession();
    await session.handle({ id: 1, type: 'connect', mnemonic: M });
    await session.handle({ id: 2, type: 'connect', mnemonic: M });
    expect(sent.at(-1)).toMatchObject({ id: 2, ok: false, code: 'already_connected' });
  });

  it('status reflects the lifecycle and disconnect shuts the tunnel down', async () => {
    const { session, sent, tunnel } = makeSession();
    await session.handle({ id: 1, type: 'status' });
    expect(sent[0]).toMatchObject({ id: 1, ok: true, state: 'disconnected' });

    await session.handle({ id: 2, type: 'connect', mnemonic: M });
    await session.handle({ id: 3, type: 'status' });
    expect(sent.at(-1)).toEqual({
      id: 3,
      ok: true,
      type: 'status',
      state: 'connected',
      endpoints: LISTENERS,
    });

    await session.handle({ id: 4, type: 'disconnect' });
    expect(tunnel.shutdownCalls).toBe(1);
    await session.handle({ id: 5, type: 'status' });
    expect(sent.at(-1)).toMatchObject({ id: 5, ok: true, state: 'disconnected' });
  });

  it('answers an unknown or malformed request with a protocol error, without crashing', async () => {
    const { session, sent } = makeSession();
    await session.handle({ id: 9, type: 'reboot' } as never);
    expect(sent[0]).toMatchObject({ id: 9, ok: false, code: 'protocol' });
    await session.handle(null as never);
    expect(sent).toHaveLength(1);
  });

  it('forwards the entry selector to the tunnel connect', async () => {
    const { session, tunnel } = makeSession();
    await session.handle({
      id: 20,
      type: 'connect',
      mnemonic: M,
      selector: { country: 'DE' },
      entrySelector: { country: 'NL' },
    });
    expect(tunnel.seenConnect).toMatchObject({ entrySelector: { country: 'NL' } });
  });

  it('passes the DAITA flag through to the tunnel factory', async () => {
    const { session, seenInit } = makeSession();
    await session.handle({ id: 12, type: 'connect', mnemonic: M, daita: true });
    expect(seenInit()).toEqual({ daita: true });
  });

  it('lists exit locations from the discovery source', async () => {
    const locations = [
      { country: 'NL', city: 'Amsterdam', active: true },
      { country: 'SG', city: 'Singapore', active: true },
    ];
    const { session, sent } = makeSession(new FakeTunnel(), {
      listExits: async () => locations,
    });
    await session.handle({ id: 7, type: 'exits' });
    expect(sent[0]).toEqual({ id: 7, ok: true, type: 'exits', locations });
  });

  it('maps an exits discovery failure to a typed error', async () => {
    const { session, sent } = makeSession(new FakeTunnel(), {
      listExits: async () => {
        throw Object.assign(new Error('list expired'), { code: 'expired' });
      },
    });
    await session.handle({ id: 8, type: 'exits' });
    expect(sent[0]).toMatchObject({ id: 8, ok: false, code: 'expired' });
  });

  it('rejects exits when the host has no discovery source', async () => {
    const { session, sent } = makeSession();
    await session.handle({ id: 9, type: 'exits' });
    expect(sent[0]).toMatchObject({ id: 9, ok: false, code: 'protocol' });
  });

  it('reports the account subscription using the per-request mnemonic', async () => {
    let seen: string | undefined;
    const { session, sent } = makeSession(new FakeTunnel(), {
      accountStatus: async (mnemonic) => {
        seen = mnemonic;
        return { expiresAt: 1790000000 };
      },
    });
    await session.handle({ id: 10, type: 'account', mnemonic: M });
    expect(seen).toBe(M);
    expect(sent[0]).toEqual({ id: 10, ok: true, type: 'account', expiresAt: 1790000000 });
  });

  it('maps an account failure to a typed error', async () => {
    const { session, sent } = makeSession(new FakeTunnel(), {
      accountStatus: async () => {
        throw Object.assign(new Error('no sub'), { code: 'api' });
      },
    });
    await session.handle({ id: 11, type: 'account', mnemonic: M });
    expect(sent[0]).toMatchObject({ id: 11, ok: false, code: 'api' });
  });

  it('close() tears down a live tunnel (browser gone means fail-closed)', async () => {
    const { session, tunnel } = makeSession();
    await session.handle({ id: 1, type: 'connect', mnemonic: M });
    await session.close();
    expect(tunnel.shutdownCalls).toBe(1);
  });
});

describe('callerAllowed', () => {
  const argv = ['/usr/bin/node', 'run-host.mjs', 'chrome-extension://abcdefghijklmnop/'];

  it('accepts any caller when no allowlist is configured', () => {
    expect(callerAllowed(argv, [])).toBe(true);
  });

  it('matches by bare extension id or full origin', () => {
    expect(callerAllowed(argv, ['abcdefghijklmnop'])).toBe(true);
    expect(callerAllowed(argv, ['chrome-extension://abcdefghijklmnop/'])).toBe(true);
    expect(callerAllowed(argv, ['otherextensionid'])).toBe(false);
  });

  it('matches a Firefox gecko id passed verbatim in argv', () => {
    // Firefox hands the host the manifest path plus the extension id, not an origin.
    const firefoxArgv = [
      '/usr/bin/node',
      'run-host.mjs',
      '/path/to/manifest.json',
      'warren@warrenbrowse.com',
    ];
    expect(callerAllowed(firefoxArgv, ['warren@warrenbrowse.com'])).toBe(true);
    expect(callerAllowed(firefoxArgv, ['other@example.com'])).toBe(false);
  });
});

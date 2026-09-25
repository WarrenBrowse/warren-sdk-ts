import { describe, expect, it } from 'vitest';
import {
  NATIVE_BINDING_ABI,
  type NativeWarrenProxy,
  type ProxyFatalCause,
  type ProxyMetrics,
  type ProxyState,
  ProxyTunnel,
  WarrenProxyError,
  isProxyDatapathAvailable,
  nativeBindingStatus,
  proxyDatapathStatus,
} from '../src/index.js';

const datapath = proxyDatapathStatus();
const available = isProxyDatapathAvailable();

const VECTOR_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

function vectorTunnel(): ProxyTunnel {
  return ProxyTunnel.create({
    mnemonic: VECTOR_MNEMONIC,
    apiBase: 'https://api.warrenbrowse.com',
    serverPubkeyPin: '00'.repeat(32),
  });
}

// The native-addon tests are offline (no tunnel is dialed); they are skipped
// where the addon is not built (CI), and the live datapath is validated by
// packages/node/native/validate-egress.mjs instead.
describe('ProxyTunnel facade', () => {
  it.skipIf(!available)('constructs from a mnemonic and derives the vector address offline', () => {
    // Cross-checks the native binding against the frozen BIP39 identity vector.
    expect(vectorTunnel().address).toBe('wbDSf2fncAfyDQkNbkyqjuhi8kpg3z8kCHqL2TYDSM2F1nVED');
  });

  it.skipIf(!available)('maps a native identity error to a typed code', () => {
    const err = (() => {
      try {
        ProxyTunnel.create({ mnemonic: 'not a mnemonic', apiBase: 'x', serverPubkeyPin: 'x' });
      } catch (e) {
        return e;
      }
      throw new Error('expected a throw');
    })();
    expect(err).toBeInstanceOf(WarrenProxyError);
    expect((err as WarrenProxyError).code).toBe('identity');
    expect((err as WarrenProxyError).message).not.toContain('not a mnemonic');
  });

  it.skipIf(!available)('rejects connect after shutdown fail-closed, offline', async () => {
    const tunnel = vectorTunnel();
    await tunnel.shutdown();
    const err = await tunnel.connect().catch((e) => e);
    expect(err).toBeInstanceOf(WarrenProxyError);
    expect((err as WarrenProxyError).code).toBe('tunnel');
  });

  it.skipIf(datapath !== 'missing')(
    'throws a typed unavailable error when the native addon is missing',
    () => {
      const err = (() => {
        try {
          ProxyTunnel.create({ mnemonic: 'x', apiBase: 'x', serverPubkeyPin: 'x' });
        } catch (e) {
          return e;
        }
        throw new Error('expected a throw');
      })();
      expect(err).toBeInstanceOf(WarrenProxyError);
      expect((err as WarrenProxyError).code).toBe('unavailable');
    },
  );
});

/**
 * A scripted native binding: reports one terminal fatal cause. The native
 * datapath is a system boundary, so scripting its verdict is the right seam to
 * test the facade's fatal-kind carrying (and a consumer's stop decision)
 * without a live exit.
 */
class ScriptedNative implements NativeWarrenProxy {
  readonly address = 'wbTEST';
  private stateCb: ((state: string) => void) | null = null;
  constructor(
    private readonly fatal: ProxyFatalCause | null,
    private readonly egressError: string | null = null,
  ) {}
  onState(cb: ((state: string) => void) | null): void {
    this.stateCb = cb;
  }
  emit(state: string): void {
    this.stateCb?.(state);
  }
  async connect(): Promise<{ socks5: string; username: string; password: string }> {
    return { socks5: '127.0.0.1:0', username: 'warren', password: 'x' };
  }
  async shutdown(): Promise<void> {}
  async metrics(): Promise<ProxyMetrics | null> {
    return null;
  }
  async fatalCause(): Promise<ProxyFatalCause | null> {
    return this.fatal;
  }
  async verifyEgress(): Promise<void> {
    // The engine's egress-proof is fail-closed: it rejects (never returns a
    // "false") when egress is not proven, exactly as scripted here.
    if (this.egressError) throw new Error(this.egressError);
  }
  async forwardPort(): Promise<never> {
    throw new Error('unused');
  }
}

describe('ProxyTunnel fatal-cause surface (A4)', () => {
  it('carries each distinct engine fatal kind instead of collapsing them', async () => {
    // The A4 bug is collapsing every fatal to one "tunnel" kind so a
    // subscription rejection loops "reconnecting" forever. Each engine verdict
    // must reach the caller as its own kind, not one generic failure.
    for (const cause of ['NotAuthorized', 'DeviceLimit', 'PolicyRefused'] as const) {
      const tunnel = ProxyTunnel.create({
        mnemonic: 'x',
        apiBase: 'x',
        serverPubkeyPin: 'x',
        nativeFactory: () => new ScriptedNative(cause),
      });
      expect(await tunnel.fatalCause()).toBe(cause);
    }
  });

  it('lets a reconnect-on-failed consumer STOP on a fatal but retry a transient failure', async () => {
    // Model a consumer's reconnect loop reacting to the 'failed' state: it
    // reconnects UNLESS the supervisor latched a fatal cause. A fatal (expired
    // subscription) must stop it; a transient 'failed' (no cause) must not.
    async function wouldReconnectAfterFailure(fatal: ProxyFatalCause | null): Promise<boolean> {
      const native = new ScriptedNative(fatal);
      const states: ProxyState[] = [];
      const tunnel = ProxyTunnel.create({
        mnemonic: 'x',
        apiBase: 'x',
        serverPubkeyPin: 'x',
        nativeFactory: () => native,
        onState: (s) => {
          states.push(s);
        },
      });
      native.emit('failed');
      expect(states).toContain('failed');
      // The consumer honors the engine verdict; it re-decides nothing.
      return (await tunnel.fatalCause()) === null;
    }

    expect(await wouldReconnectAfterFailure('NotAuthorized')).toBe(false);
    expect(await wouldReconnectAfterFailure(null)).toBe(true);
  });
});

describe('ProxyTunnel egress-proof surface', () => {
  it('resolves when the engine proves egress through the tunnel', async () => {
    const tunnel = ProxyTunnel.create({
      mnemonic: 'x',
      apiBase: 'x',
      serverPubkeyPin: 'x',
      nativeFactory: () => new ScriptedNative(null),
    });
    await expect(tunnel.verifyEgress()).resolves.toBeUndefined();
  });

  it('rejects egress-not-proven as its OWN typed kind, not a generic tunnel failure', async () => {
    // The proof is fail-closed: a consumer must be able to tell "egress not
    // proven" (stop, do not hand traffic to a silently-dropping tunnel) from an
    // unrelated tunnel error, so it maps to a distinct `egress` code.
    const tunnel = ProxyTunnel.create({
      mnemonic: 'x',
      apiBase: 'x',
      serverPubkeyPin: 'x',
      nativeFactory: () =>
        new ScriptedNative(null, 'egress: egress not proven after 18 probe attempts'),
    });
    const err = await tunnel.verifyEgress().then(
      () => null,
      (e) => e,
    );
    expect(err).toBeInstanceOf(WarrenProxyError);
    expect((err as WarrenProxyError).code).toBe('egress');
  });
});

/**
 * The addon is built outside `pnpm build`, so a checkout can carry one from an
 * older SDK whose objects lack fields this facade relies on (the listener
 * credentials, 2026-09-23). The binding reports its ABI, and anything else is
 * named `outdated` before a tunnel is ever built on it.
 */
describe('native binding ABI', () => {
  it('reads a binding reporting this facade ABI as ready', () => {
    expect(nativeBindingStatus({ bindingAbi: () => NATIVE_BINDING_ABI })).toBe('ready');
  });

  it('reads a binding that predates the ABI report as outdated', () => {
    expect(nativeBindingStatus({ WarrenProxy: class {} })).toBe('outdated');
  });

  it('reads a binding reporting another ABI as outdated, either way', () => {
    expect(nativeBindingStatus({ bindingAbi: () => NATIVE_BINDING_ABI - 1 })).toBe('outdated');
    expect(nativeBindingStatus({ bindingAbi: () => NATIVE_BINDING_ABI + 1 })).toBe('outdated');
  });

  it.skipIf(!available)('reports the built addon as ready', () => {
    expect(proxyDatapathStatus()).toBe('ready');
  });

  it.skipIf(datapath !== 'missing')('reports a missing addon as missing', () => {
    expect(isProxyDatapathAvailable()).toBe(false);
  });

  it.skipIf(datapath !== 'outdated')('refuses to build a tunnel on an outdated addon', () => {
    const err = (() => {
      try {
        vectorTunnel();
      } catch (e) {
        return e;
      }
      throw new Error('expected a throw');
    })();
    expect(err).toBeInstanceOf(WarrenProxyError);
    expect((err as WarrenProxyError).code).toBe('outdated');
    expect((err as WarrenProxyError).message).toContain('rebuild');
    expect(isProxyDatapathAvailable()).toBe(false);
  });
});

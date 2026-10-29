import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  NATIVE_BINDING_ABI,
  type NativeProxyEndpoints,
  type NativeProxyOptions,
  type NativeWarrenProxy,
  type ProxyFatalCause,
  type ProxyMetrics,
  type ProxyState,
  ProxyTunnel,
  type ProxyTunnelOptions,
  WarrenProxyError,
  defaultDeviceIdentityPath,
  isProxyDatapathAvailable,
  nativeBindingStatus,
  nodeDevicePlatform,
  parseDeviceIdentity,
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

  it.skipIf(!available)('keeps the device identity where the engine registers it', () => {
    const stateDir = join(mkdtempSync(join(tmpdir(), 'warren-napi-')), 'state');
    const tunnel = ProxyTunnel.create({
      mnemonic: VECTOR_MNEMONIC,
      apiBase: 'https://api.warrenbrowse.com',
      serverPubkeyPin: '00'.repeat(32),
      stateDir,
      device: { appVersion: '0.0.0' },
    });

    const kept = parseDeviceIdentity(readFileSync(join(stateDir, 'device.json'), 'utf8'));

    expect(kept?.name.split(' ')).toHaveLength(2);
    expect(tunnel.deviceRevoked()).toBe(false);
    tunnel.forgetDevice();
    expect(() => readFileSync(join(stateDir, 'device.json'))).toThrow();
  });

  it.skipIf(!available)('refuses to register on a platform outside the registry', () => {
    const err = (() => {
      try {
        ProxyTunnel.create({
          mnemonic: VECTOR_MNEMONIC,
          apiBase: 'https://api.warrenbrowse.com',
          serverPubkeyPin: '00'.repeat(32),
          device: {
            appVersion: '0.0.0',
            platform: 'other' as never,
            identityPath: '/nonexistent/d',
          },
        });
      } catch (e) {
        return e;
      }
      throw new Error('expected a throw');
    })();
    expect((err as WarrenProxyError).code).toBe('config');
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
  deviceRevoked?: () => boolean;
  deviceLimitReached?: () => boolean;
  forgetDevice?: () => void;
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
  async connect(): Promise<NativeProxyEndpoints> {
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
    for (const cause of [
      'NotAuthorized',
      'DeviceLimit',
      'PolicyRefused',
      'NoReachableEntry',
    ] as const) {
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

/** A native binding whose connect reports `reported`, as the addon hands it over. */
function tunnelReporting(reported: NativeProxyEndpoints): ProxyTunnel {
  const native = new ScriptedNative(null);
  native.connect = async () => reported;
  return ProxyTunnel.create({
    mnemonic: 'x',
    apiBase: 'x',
    serverPubkeyPin: 'x',
    nativeFactory: () => native,
  });
}

describe('ProxyTunnel connect result', () => {
  const listeners = { socks5: '127.0.0.1:1080', username: 'warren', password: 'secret' };

  it('relays the exit the engine names alongside the listeners', async () => {
    const tunnel = tunnelReporting({
      ...listeners,
      exit: { country: 'RO', city: 'Bucharest' },
    });
    expect(await tunnel.connect()).toEqual({
      ...listeners,
      exit: { country: 'RO', city: 'Bucharest' },
    });
  });

  it('reports no exit when the engine names none, as on the failover datapath', async () => {
    // napi hands a missing optional over as null, and an older addon omits
    // the field: neither may surface as an exit.
    for (const exit of [null, undefined]) {
      const endpoints = await tunnelReporting({ ...listeners, exit }).connect();
      expect(endpoints).toEqual(listeners);
      expect('exit' in endpoints).toBe(false);
    }
  });

  it('drops an exit without a two-letter country instead of relaying it', async () => {
    const endpoints = await tunnelReporting({
      ...listeners,
      exit: { country: '', city: 'Bucharest' },
    }).connect();
    expect('exit' in endpoints).toBe(false);
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

describe('ProxyTunnel device registration', () => {
  /** Builds a tunnel over a scripted native, returning what the engine was handed. */
  function handed(options: Partial<ProxyTunnelOptions>): NativeProxyOptions | null {
    let seen: NativeProxyOptions | null | undefined;
    ProxyTunnel.create({
      mnemonic: 'x',
      apiBase: 'x',
      serverPubkeyPin: 'x',
      ...options,
      nativeFactory: (native) => {
        seen = native;
        return new ScriptedNative(null);
      },
    });
    if (seen === undefined) throw new Error('the factory was not called');
    return seen;
  }

  it('hands the engine the identity beside its state, the OS platform and the version', () => {
    const native = handed({ stateDir: join('state', 'warren'), device: { appVersion: '0.4.2' } });

    expect(native?.device).toEqual({
      identityPath: join('state', 'warren', 'device.json'),
      platform: nodeDevicePlatform(),
      appVersion: '0.4.2',
    });
    expect(native?.stateDir).toBe(join('state', 'warren'));
  });

  it('keeps the identity at the default path without a state directory', () => {
    expect(handed({ device: { appVersion: '0.4.2' } })?.device?.identityPath).toBe(
      defaultDeviceIdentityPath(),
    );
  });

  it('takes an identity path and a platform the caller names', () => {
    const native = handed({
      device: { appVersion: '0.1.8', platform: 'browser', identityPath: '/x/d.json' },
    });

    expect(native?.device).toEqual({
      identityPath: '/x/d.json',
      platform: 'browser',
      appVersion: '0.1.8',
    });
  });

  it('registers nothing without the option', () => {
    expect(handed({})).toBeNull();
  });

  it('reads a revocation and the device cap from the engine, and forgets through it', () => {
    const native = new ScriptedNative(null);
    let forgotten = 0;
    native.deviceRevoked = () => true;
    native.deviceLimitReached = () => true;
    native.forgetDevice = () => {
      forgotten += 1;
    };
    const tunnel = ProxyTunnel.create({
      mnemonic: 'x',
      apiBase: 'x',
      serverPubkeyPin: 'x',
      nativeFactory: () => native,
    });

    expect(tunnel.deviceRevoked()).toBe(true);
    expect(tunnel.deviceLimitReached()).toBe(true);
    tunnel.forgetDevice();
    expect(forgotten).toBe(1);
  });

  it('reads an engine without a device surface as neither revoked nor capped', () => {
    const tunnel = ProxyTunnel.create({
      mnemonic: 'x',
      apiBase: 'x',
      serverPubkeyPin: 'x',
      nativeFactory: () => new ScriptedNative(null),
    });

    expect(tunnel.deviceRevoked()).toBe(false);
    expect(tunnel.deviceLimitReached()).toBe(false);
  });

  it('types a connect the engine refuses for a revoked device or the device cap', async () => {
    for (const code of ['device_revoked', 'device_limit'] as const) {
      const native = new ScriptedNative(null);
      native.connect = async () => {
        throw new Error(`${code}: refused`);
      };
      const tunnel = ProxyTunnel.create({
        mnemonic: 'x',
        apiBase: 'x',
        serverPubkeyPin: 'x',
        nativeFactory: () => native,
      });

      const err = await tunnel.connect().catch((e: unknown) => e);

      expect((err as WarrenProxyError).code).toBe(code);
    }
  });
});

import { describe, expect, it } from 'vitest';
import {
  type ChromeLike,
  type NativePort,
  WarrenBrowserVpn,
  WarrenExtensionError,
} from '../src/index.js';
import type { HostRequest } from '../src/protocol.js';

/** A scripted fake of the chrome extension API surface the client uses. */
function fakeChrome(
  script: (req: HostRequest, port: FakePort) => void,
  options: { control?: string[] } = {},
) {
  const calls: string[] = [];
  const port = new FakePort(script);
  // levelOfControl values returned by successive proxy.settings.get calls;
  // the last one repeats (default: controllable, then controlled after set).
  const control = options.control ?? [
    'controllable_by_this_extension',
    'controlled_by_this_extension',
  ];
  let gets = 0;
  const chrome: ChromeLike = {
    proxy: {
      settings: {
        get: () => {
          calls.push('proxy.get');
          const level = control[Math.min(gets, control.length - 1)];
          gets += 1;
          return { levelOfControl: level };
        },
        set: (details) => {
          calls.push(`proxy.set:${JSON.stringify(details.value)}`);
        },
        clear: () => {
          calls.push('proxy.clear');
        },
      },
    },
    privacy: {
      network: {
        webRTCIPHandlingPolicy: {
          set: (details) => {
            calls.push(`webrtc.set:${details.value}`);
          },
          clear: () => {
            calls.push('webrtc.clear');
          },
        },
        networkPredictionEnabled: {
          set: (details) => {
            calls.push(`prediction.set:${details.value}`);
          },
          clear: () => {
            calls.push('prediction.clear');
          },
        },
      },
    },
    runtime: {
      connectNative: (name: string) => {
        calls.push(`connectNative:${name}`);
        return port;
      },
    },
  };
  return { chrome, calls, port };
}

class FakePort implements NativePort {
  private messageListeners: Array<(msg: unknown) => void> = [];
  private disconnectListeners: Array<() => void> = [];
  disconnected = false;

  constructor(private readonly script: (req: HostRequest, port: FakePort) => void) {}

  postMessage(msg: unknown): void {
    queueMicrotask(() => this.script(msg as HostRequest, this));
  }
  disconnect(): void {
    this.disconnected = true;
  }
  onMessage = {
    addListener: (cb: (msg: unknown) => void) => this.messageListeners.push(cb),
  };
  onDisconnect = {
    addListener: (cb: () => void) => this.disconnectListeners.push(cb),
  };

  emit(msg: unknown): void {
    for (const cb of this.messageListeners) cb(msg);
  }
  die(): void {
    for (const cb of this.disconnectListeners) cb();
  }
}

/** A host that answers hello and connect successfully. */
function healthyHost(req: HostRequest, port: FakePort): void {
  if (req.type === 'hello') {
    port.emit({ id: req.id, ok: true, type: 'hello', protocol: 1, address: 'wbTest' });
  } else if (req.type === 'connect') {
    port.emit({ id: req.id, ok: true, type: 'connect', endpoints: { socks5: '127.0.0.1:1080' } });
  } else if (req.type === 'disconnect') {
    port.emit({ id: req.id, ok: true, type: 'disconnect' });
  }
}

describe('WarrenBrowserVpn.connect', () => {
  it('handshakes, then applies the WebRTC policy BEFORE the proxy settings', async () => {
    const { chrome, calls } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });

    const endpoints = await vpn.connect({ mnemonic: 'm', selector: { country: 'NL' } });

    expect(endpoints.socks5).toBe('127.0.0.1:1080');
    const webrtcIndex = calls.findIndex((c) => c.startsWith('webrtc.set'));
    const proxyIndex = calls.findIndex((c) => c.startsWith('proxy.set'));
    expect(webrtcIndex).toBeGreaterThan(-1);
    expect(proxyIndex).toBeGreaterThan(webrtcIndex);
    expect(calls[webrtcIndex]).toBe('webrtc.set:disable_non_proxied_udp');
  });

  it('points chrome.proxy at the SOCKS5 endpoint with a localhost bypass', async () => {
    const { chrome, calls } = fakeChrome(healthyHost);
    await new WarrenBrowserVpn({ chrome }).connect({ mnemonic: 'm' });

    const proxyCall = calls.find((c) => c.startsWith('proxy.set:'));
    const value = JSON.parse(proxyCall!.slice('proxy.set:'.length));
    expect(value.mode).toBe('fixed_servers');
    expect(value.rules.singleProxy).toEqual({ scheme: 'socks5', host: '127.0.0.1', port: 1080 });
    expect(value.rules.bypassList).toEqual(['localhost', '127.0.0.1']);
  });

  it('never touches proxy settings when the host refuses the connect', async () => {
    const { chrome, calls } = fakeChrome((req, port) => {
      if (req.type === 'hello') {
        port.emit({ id: req.id, ok: true, type: 'hello', protocol: 1, address: 'wbTest' });
      } else {
        port.emit({ id: req.id, ok: false, code: 'api', message: 'subscription expired' });
      }
    });
    const vpn = new WarrenBrowserVpn({ chrome });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect(err).toBeInstanceOf(WarrenExtensionError);
    expect((err as WarrenExtensionError).code).toBe('host');
    expect((err as WarrenExtensionError).hostCode).toBe('api');
    expect(calls.some((c) => c.startsWith('proxy.set'))).toBe(false);
  });

  it('rejects a protocol version mismatch', async () => {
    const { chrome } = fakeChrome((req, port) => {
      if (req.type === 'hello') {
        port.emit({ id: req.id, ok: true, type: 'hello', protocol: 99, address: 'wbTest' });
      }
    });
    const err = await new WarrenBrowserVpn({ chrome }).connect({ mnemonic: 'm' }).catch((e) => e);
    expect((err as WarrenExtensionError).code).toBe('protocol');
  });

  it('rejects a second connect while connected', async () => {
    const { chrome } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });
    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);
    expect((err as WarrenExtensionError).code).toBe('already_connected');
  });

  it('relays the wallet mnemonic to the host in the connect request', async () => {
    const seen: HostRequest[] = [];
    const { chrome } = fakeChrome((req, port) => {
      seen.push(req);
      healthyHost(req, port);
    });
    await new WarrenBrowserVpn({ chrome }).connect({ mnemonic: 'twelve secret words here' });
    const connectReq = seen.find((r) => r.type === 'connect');
    expect(connectReq).toMatchObject({ type: 'connect', mnemonic: 'twelve secret words here' });
  });
});

describe('WarrenBrowserVpn proxy control and leak hardening', () => {
  it('refuses to connect when another extension controls the proxy setting', async () => {
    const { chrome, calls } = fakeChrome(healthyHost, {
      control: ['controlled_by_other_extensions'],
    });
    const vpn = new WarrenBrowserVpn({ chrome });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect(err).toBeInstanceOf(WarrenExtensionError);
    expect((err as WarrenExtensionError).code).toBe('proxy_uncontrollable');
    // Fail early: never dial the host or touch settings without control.
    expect(calls.some((c) => c.startsWith('connectNative'))).toBe(false);
    expect(calls.some((c) => c.startsWith('proxy.set'))).toBe(false);
  });

  it('verifies control after set and fails closed when the set did not take', async () => {
    const { chrome, calls } = fakeChrome(healthyHost, {
      control: ['controllable_by_this_extension', 'controlled_by_other_extensions'],
    });
    const vpn = new WarrenBrowserVpn({ chrome });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect((err as WarrenExtensionError).code).toBe('proxy_uncontrollable');
    // The half-applied leak hardening must be rolled back.
    expect(calls).toContain('webrtc.clear');
    expect(calls).toContain('prediction.clear');
  });

  it('disables DNS prefetch before the proxy is applied and restores it on disconnect', async () => {
    const { chrome, calls } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });

    // The prefetcher resolves DNS locally even under SOCKS5; it must be off
    // before any traffic is routed.
    const predictionIndex = calls.indexOf('prediction.set:false');
    const proxyIndex = calls.findIndex((c) => c.startsWith('proxy.set'));
    expect(predictionIndex).toBeGreaterThan(-1);
    expect(proxyIndex).toBeGreaterThan(predictionIndex);

    await vpn.disconnect();
    expect(calls).toContain('prediction.clear');
  });
});

describe('WarrenBrowserVpn fail-closed behavior', () => {
  it('keeps the proxy settings when the host dies while connected', async () => {
    const { chrome, calls, port } = fakeChrome(healthyHost);
    const states: string[] = [];
    const vpn = new WarrenBrowserVpn({ chrome, onState: (s) => states.push(s) });
    await vpn.connect({ mnemonic: 'm' });

    port.die();

    // Traffic must blackhole on the dead proxy rather than leak around it;
    // only an explicit user disconnect() clears the settings.
    expect(calls).not.toContain('proxy.clear');
    expect(states).toContain('failed');
  });

  it('disconnect() clears the proxy and the WebRTC policy and closes the port', async () => {
    const { chrome, calls, port } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });

    await vpn.disconnect();

    expect(calls).toContain('proxy.clear');
    expect(calls).toContain('webrtc.clear');
    expect(port.disconnected).toBe(true);
  });

  it('disconnect() after a host death still clears the proxy', async () => {
    const { chrome, calls, port } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });
    port.die();

    await vpn.disconnect();

    expect(calls).toContain('proxy.clear');
  });
});

describe('WarrenBrowserVpn split tunneling', () => {
  it('bypass mode adds the rules to the Chromium bypassList', async () => {
    const { chrome, calls } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm', split: { mode: 'bypass', rules: ['bank.example'] } });

    const proxyCall = calls.find((c) => c.startsWith('proxy.set:'));
    const value = JSON.parse(proxyCall!.slice('proxy.set:'.length));
    expect(value.mode).toBe('fixed_servers');
    expect(value.rules.bypassList).toContain('bank.example');
  });

  it('only mode switches Chromium to a PAC script', async () => {
    const { chrome, calls } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm', split: { mode: 'only', rules: ['work.example'] } });

    const proxyCall = calls.find((c) => c.startsWith('proxy.set:'));
    const value = JSON.parse(proxyCall!.slice('proxy.set:'.length));
    expect(value.mode).toBe('pac_script');
    expect(value.pacScript.data).toContain('work.example');
  });

  it('Firefox only mode registers a proxy.onRequest handler that decides per host', async () => {
    let handler: ((req: { url: string }) => unknown) | undefined;
    const base = fakeChrome(healthyHost);
    base.chrome.proxy.settings.set = () => {
      base.calls.push('proxy.set');
      return Promise.resolve(true);
    };
    base.chrome.proxy.onRequest = {
      addListener: (cb: (req: { url: string }) => unknown) => {
        handler = cb;
      },
      removeListener: () => {
        handler = undefined;
      },
    };
    base.chrome.extension = { isAllowedIncognitoAccess: () => Promise.resolve(true) };
    const vpn = new WarrenBrowserVpn({ chrome: base.chrome, platform: 'firefox' });
    await vpn.connect({ mnemonic: 'm', split: { mode: 'only', rules: ['work.example'] } });

    expect(handler).toBeDefined();
    // Matched host -> SOCKS ProxyInfo; unmatched -> direct.
    expect(handler!({ url: 'https://work.example/x' })).toMatchObject({
      type: 'socks',
      host: '127.0.0.1',
      port: 1080,
      proxyDNS: true,
    });
    expect(handler!({ url: 'https://personal.example/x' })).toEqual({ type: 'direct' });

    await vpn.disconnect();
    expect(handler).toBeUndefined();
  });
});

describe('WarrenBrowserVpn on Firefox', () => {
  function firefoxChrome(
    script: (req: HostRequest, port: FakePort) => void,
    options: { incognitoAllowed?: boolean; setResult?: boolean } = {},
  ) {
    const base = fakeChrome(script);
    const values: unknown[] = [];
    base.chrome.proxy.settings.set = (details) => {
      base.calls.push('proxy.set');
      values.push(details.value);
      // Firefox BrowserSetting.set resolves false when the value was not applied.
      return Promise.resolve(options.setResult ?? true);
    };
    base.chrome.extension = {
      isAllowedIncognitoAccess: () => Promise.resolve(options.incognitoAllowed ?? true),
    };
    return { ...base, values };
  }

  it('applies the Firefox manual-socks settings shape with explicit proxyDNS', async () => {
    const { chrome, values } = firefoxChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });
    await vpn.connect({ mnemonic: 'm' });

    expect(values[0]).toEqual({
      proxyType: 'manual',
      socks: '127.0.0.1:1080',
      socksVersion: 5,
      // Default only since Firefox 128; explicit so older ESRs keep DNS on the tunnel.
      proxyDNS: true,
      passthrough: 'localhost, 127.0.0.1',
    });
  });

  it('requires private-browsing access before touching proxy settings', async () => {
    const { chrome, calls } = firefoxChrome(healthyHost, { incognitoAllowed: false });
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect(err).toBeInstanceOf(WarrenExtensionError);
    expect((err as WarrenExtensionError).code).toBe('private_browsing_required');
    expect(calls.some((c) => c.startsWith('proxy.set'))).toBe(false);
  });

  it('treats a false set() result as an uncontrollable proxy and rolls back', async () => {
    const { chrome, calls } = firefoxChrome(healthyHost, { setResult: false });
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect((err as WarrenExtensionError).code).toBe('proxy_uncontrollable');
    expect(calls).toContain('webrtc.clear');
  });
});

describe('WarrenBrowserVpn events and state', () => {
  it('relays host state events and answers status()', async () => {
    const { chrome, port } = fakeChrome((req, p) => {
      healthyHost(req, p);
      if (req.type === 'status') {
        p.emit({ id: req.id, ok: true, type: 'status', state: 'connected' });
      }
    });
    const states: string[] = [];
    const vpn = new WarrenBrowserVpn({ chrome, onState: (s) => states.push(s) });
    await vpn.connect({ mnemonic: 'm' });

    port.emit({ type: 'state', state: 'reconnecting' });

    expect(states).toContain('reconnecting');
    expect((await vpn.status()).state).toBe('connected');
  });
});

describe('WarrenBrowserVpn discovery and account', () => {
  it('lists exit locations from the host', async () => {
    const locations = [
      { country: 'NL', city: 'Amsterdam', active: true },
      { country: 'DE', city: 'Kassel', active: true },
    ];
    const { chrome } = fakeChrome((req, p) => {
      healthyHost(req, p);
      if (req.type === 'exits') {
        p.emit({ id: req.id, ok: true, type: 'exits', locations });
      }
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    expect(await vpn.listExits()).toEqual(locations);
  });

  it('maps an exits failure to a typed host error', async () => {
    const { chrome } = fakeChrome((req, p) => {
      healthyHost(req, p);
      if (req.type === 'exits') {
        p.emit({ id: req.id, ok: false, code: 'expired', message: 'stale list' });
      }
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    const err = await vpn.listExits().catch((e) => e);
    expect(err).toBeInstanceOf(WarrenExtensionError);
    expect((err as WarrenExtensionError).hostCode).toBe('expired');
  });

  it('fetches the subscription status with the vault mnemonic', async () => {
    let seen: string | undefined;
    const { chrome } = fakeChrome((req, p) => {
      healthyHost(req, p);
      if (req.type === 'account') {
        seen = req.mnemonic;
        p.emit({ id: req.id, ok: true, type: 'account', expiresAt: 1790000000 });
      }
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    expect(await vpn.account('words')).toEqual({ expiresAt: 1790000000 });
    expect(seen).toBe('words');
  });
});

describe('WarrenBrowserVpn DAITA', () => {
  it('carries the daita flag on the connect request', async () => {
    let seen: boolean | undefined;
    const { chrome } = fakeChrome((req, p) => {
      if (req.type === 'connect') seen = req.daita;
      healthyHost(req, p);
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm', daita: true });
    expect(seen).toBe(true);
  });
});

describe('WarrenBrowserVpn entry selection', () => {
  it('carries the entry selector on the connect request', async () => {
    let seen: unknown;
    const { chrome } = fakeChrome((req, p) => {
      if (req.type === 'connect') seen = (req as { entrySelector?: unknown }).entrySelector;
      healthyHost(req, p);
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm', entrySelector: { country: 'NL' } });
    expect(seen).toEqual({ country: 'NL' });
  });
});

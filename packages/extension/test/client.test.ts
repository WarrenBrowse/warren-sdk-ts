import { productChannel } from '@warrenbrowse/sdk-core';
import { describe, expect, it, vi } from 'vitest';
import {
  type ChromeLike,
  type NativePort,
  WarrenBrowserVpn,
  WarrenExtensionError,
  buildChromiumLockdownValue,
} from '../src/index.js';
import { EXTENSION_PROTOCOL_VERSION, type HostRequest } from '../src/protocol.js';

const LISTENERS = { socks5: '127.0.0.1:1080', http: '127.0.0.1:8118' };
const AUTH = { username: 'warren', password: 'session-secret' };

/** A scripted fake of the chrome extension API surface the client uses. */
function fakeChrome(
  script: (req: HostRequest, port: FakePort) => void,
  options: { control?: string[]; value?: unknown } = {},
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
          return { levelOfControl: level, value: options.value };
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
    port.emit({ id: req.id, ok: true, type: 'hello', protocol: EXTENSION_PROTOCOL_VERSION });
  } else if (req.type === 'connect') {
    port.emit({ id: req.id, ok: true, type: 'connect', endpoints: LISTENERS, auth: AUTH });
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

  it('points chrome.proxy at the authenticated HTTP listener with a localhost bypass', async () => {
    const { chrome, calls } = fakeChrome(healthyHost);
    await new WarrenBrowserVpn({ chrome }).connect({ mnemonic: 'm' });

    const proxyCall = calls.find((c) => c.startsWith('proxy.set:'));
    const value = JSON.parse(proxyCall!.slice('proxy.set:'.length));
    expect(value.mode).toBe('fixed_servers');
    expect(value.rules.singleProxy).toEqual({ scheme: 'http', host: '127.0.0.1', port: 8118 });
    expect(value.rules.bypassList).toEqual(['localhost', '127.0.0.1']);
  });

  it('asks the host for its HTTP listener on Chromium, which cannot answer SOCKS5 auth', async () => {
    const seen: HostRequest[] = [];
    const { chrome } = fakeChrome((req, p) => {
      seen.push(req);
      healthyHost(req, p);
    });
    await new WarrenBrowserVpn({ chrome }).connect({ mnemonic: 'm', httpProxy: false });

    expect(seen.find((r) => r.type === 'connect')).toMatchObject({ httpProxy: true });
  });

  it('refuses a host that hands over no credentials, before routing anything', async () => {
    const { chrome, calls } = fakeChrome((req, p) => {
      if (req.type === 'connect') {
        p.emit({ id: req.id, ok: true, type: 'connect', endpoints: LISTENERS });
      } else healthyHost(req, p);
    });
    const vpn = new WarrenBrowserVpn({ chrome });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect((err as WarrenExtensionError).code).toBe('protocol');
    expect(calls.some((c) => c.startsWith('proxy.set'))).toBe(false);
    expect(vpn.forListener(LISTENERS.http)).toBeUndefined();
  });

  it('refuses a Chromium connect whose host serves no HTTP listener', async () => {
    const { chrome, calls } = fakeChrome((req, p) => {
      if (req.type === 'connect') {
        p.emit({
          id: req.id,
          ok: true,
          type: 'connect',
          endpoints: { socks5: LISTENERS.socks5 },
          auth: AUTH,
        });
      } else healthyHost(req, p);
    });

    const err = await new WarrenBrowserVpn({ chrome }).connect({ mnemonic: 'm' }).catch((e) => e);

    expect((err as WarrenExtensionError).code).toBe('protocol');
    expect(calls.some((c) => c.startsWith('proxy.set'))).toBe(false);
  });

  it('hands the session credentials only for its own listeners, and only while the tunnel lives', async () => {
    const { chrome, port } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });

    expect(vpn.forListener(LISTENERS.http)).toEqual(AUTH);
    expect(vpn.forListener(LISTENERS.socks5)).toEqual(AUTH);
    expect(vpn.forListener('127.0.0.1:9999')).toBeUndefined();

    port.die();
    expect(vpn.forListener(LISTENERS.http)).toBeUndefined();
  });

  it('forgets the session credentials on disconnect', async () => {
    const { chrome } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });

    await vpn.disconnect();

    expect(vpn.forListener(LISTENERS.http)).toBeUndefined();
  });

  it('never touches proxy settings when the host refuses the connect', async () => {
    const { chrome, calls } = fakeChrome((req, port) => {
      if (req.type === 'hello') {
        port.emit({ id: req.id, ok: true, type: 'hello', protocol: EXTENSION_PROTOCOL_VERSION });
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
  it('moves Chromium off the port a dead host released, onto the block, never direct', async () => {
    const { chrome, calls, port } = fakeChrome(healthyHost);
    const states: string[] = [];
    const vpn = new WarrenBrowserVpn({ chrome, onState: (s) => states.push(s) });
    await vpn.connect({ mnemonic: 'm' });

    port.die();

    // Any local process can bind the released port and would receive the
    // browser's traffic: the browser must stall on a proxy nothing answers.
    expect(calls.filter((c) => c.startsWith('proxy.set:')).at(-1)).toBe(
      `proxy.set:${JSON.stringify(buildChromiumLockdownValue([]))}`,
    );
    expect(calls).not.toContain('proxy.clear');
    expect(vpn.isProxied()).toBe(true);
    expect(states).toContain('failed');
  });

  it('fails a connect whose host dies while the browser is being routed, off its port', async () => {
    const { chrome, calls, port } = fakeChrome(healthyHost);
    const set = chrome.proxy.settings.set.bind(chrome.proxy.settings);
    chrome.proxy.settings.set = (details) => {
      set(details);
      port.die();
    };
    const vpn = new WarrenBrowserVpn({ chrome });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect((err as WarrenExtensionError).code).toBe('host_unavailable');
    expect(calls.filter((c) => c.startsWith('proxy.')).at(-1)).toBe('proxy.clear');
    expect(vpn.forListener(LISTENERS.http)).toBeUndefined();
    expect(vpn.isProxied()).toBe(false);
  });

  it('never routes to, nor answers for, a host that died while the leaks were being closed', async () => {
    const { chrome, calls, port } = fakeChrome(healthyHost);
    const harden = chrome.privacy.network.webRTCIPHandlingPolicy.set.bind(
      chrome.privacy.network.webRTCIPHandlingPolicy,
    );
    chrome.privacy.network.webRTCIPHandlingPolicy.set = (details) => {
      harden(details);
      port.die();
    };
    const vpn = new WarrenBrowserVpn({ chrome });

    await vpn.connect({ mnemonic: 'm' }).catch(() => undefined);

    expect(calls.some((c) => c.startsWith('proxy.set:') && c.includes('8118'))).toBe(false);
    expect(vpn.forListener(LISTENERS.http)).toBeUndefined();
  });

  it('blocks nothing when its host dies after a disconnect that could not clear the proxy', async () => {
    const { chrome, calls, port } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    const lost = vi.fn();
    vpn.onHostLost(lost);
    await vpn.connect({ mnemonic: 'm' });
    chrome.proxy.settings.clear = () => {
      throw new Error('settings unavailable');
    };
    await vpn.disconnect().catch(() => undefined);
    const after = calls.length;

    port.die();

    expect(calls.slice(after).filter((c) => c.startsWith('proxy.set:'))).toEqual([]);
    expect(lost).not.toHaveBeenCalled();
  });

  it('reports the loss of the host that carried the tunnel', async () => {
    const { chrome, port } = fakeChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome });
    const lost = vi.fn();
    vpn.onHostLost(lost);
    await vpn.connect({ mnemonic: 'm' });

    port.die();

    expect(lost).toHaveBeenCalledTimes(1);
  });

  it('reports and blocks nothing when the host exits on an explicit disconnect', async () => {
    const { chrome, calls } = fakeChrome((req, p) => {
      healthyHost(req, p);
      if (req.type === 'disconnect') p.die();
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    const lost = vi.fn();
    vpn.onHostLost(lost);
    await vpn.connect({ mnemonic: 'm' });

    await vpn.disconnect();

    expect(lost).not.toHaveBeenCalled();
    expect(calls.filter((c) => c.startsWith('proxy.')).at(-1)).toBe('proxy.clear');
  });

  it('reports nothing when a host that carried no tunnel dies', async () => {
    const { chrome, port } = fakeChrome((req, p) => {
      healthyHost(req, p);
      if (req.type === 'status') {
        p.emit({ id: req.id, ok: true, type: 'status', state: 'disconnected' });
      }
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    const lost = vi.fn();
    vpn.onHostLost(lost);
    await vpn.connect({ mnemonic: 'm' });
    port.die();
    // Asking for the state spawns a fresh host with no tunnel; its death
    // releases no port the browser is routed at.
    await vpn.status();

    port.die();

    expect(lost).toHaveBeenCalledTimes(1);
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

describe('WarrenBrowserVpn over a routing it already holds', () => {
  const HELD = {
    mode: 'fixed_servers',
    rules: { singleProxy: { scheme: 'https', host: '127.0.0.1', port: 1 }, bypassList: [] },
  };

  it('puts the held routing back when the connect fails, never restoring direct', async () => {
    const { chrome, calls } = fakeChrome(healthyHost, {
      control: ['controlled_by_this_extension', 'controlled_by_other_extensions'],
      value: HELD,
    });
    const vpn = new WarrenBrowserVpn({ chrome });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect((err as WarrenExtensionError).code).toBe('proxy_uncontrollable');
    expect(calls).not.toContain('proxy.clear');
    expect(calls.filter((c) => c.startsWith('proxy.set:')).at(-1)).toBe(
      `proxy.set:${JSON.stringify(HELD)}`,
    );
    // The held routing was hardened when it was installed; unhardening it now
    // would reopen the WebRTC leak under a blocked browser.
    expect(calls).not.toContain('webrtc.clear');
    expect(calls).not.toContain('prediction.clear');
  });

  it('keeps leak hardening this extension already held when a connect fails', async () => {
    // Firefox holds its lockdown in a proxy.onRequest listener, so the proxy
    // setting is not ours while the WebRTC policy is.
    const { chrome, calls } = fakeChrome(healthyHost, {
      control: ['controllable_by_this_extension', 'controlled_by_other_extensions'],
    });
    chrome.privacy.network.webRTCIPHandlingPolicy.get = () => ({
      levelOfControl: 'controlled_by_this_extension',
      value: 'disable_non_proxied_udp',
    });

    await new WarrenBrowserVpn({ chrome }).connect({ mnemonic: 'm' }).catch(() => undefined);

    expect(calls).not.toContain('webrtc.clear');
    expect(calls).not.toContain('prediction.clear');
  });

  it('reconnects over a tunnel whose host died, the browser routed throughout', async () => {
    const { chrome, calls, port } = fakeChrome(
      (req, p) => {
        healthyHost(req, p);
        if (req.type === 'status') {
          p.emit({ id: req.id, ok: true, type: 'status', state: 'disconnected' });
        }
      },
      { control: ['controlled_by_this_extension'] },
    );
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });
    port.die();
    // The popup asks the freshly spawned host for its state before offering
    // to reconnect; that reopens the port without reviving the old tunnel.
    expect((await vpn.status()).state).toBe('disconnected');

    await expect(vpn.connect({ mnemonic: 'm' })).resolves.toEqual(LISTENERS);

    expect(calls).not.toContain('proxy.clear');
    expect(vpn.isProxied()).toBe(true);
  });

  it('applies new split rules in place, with no teardown and no direct window', async () => {
    const seen: HostRequest[] = [];
    const { chrome, calls } = fakeChrome((req, p) => {
      seen.push(req);
      healthyHost(req, p);
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    await vpn.connect({ mnemonic: 'm' });

    await vpn.applySplit({ mode: 'bypass', rules: ['bank.example'] });

    const last = calls.filter((c) => c.startsWith('proxy.set:')).at(-1);
    const value = JSON.parse(last!.slice('proxy.set:'.length));
    expect(value.rules.bypassList).toContain('bank.example');
    expect(calls).not.toContain('proxy.clear');
    expect(seen.map((r) => r.type)).not.toContain('disconnect');
  });

  it('refuses to apply split rules with no tunnel to route through', async () => {
    const { chrome } = fakeChrome(healthyHost);
    const err = await new WarrenBrowserVpn({ chrome })
      .applySplit({ mode: 'all', rules: [] })
      .catch((e) => e);
    expect((err as WarrenExtensionError).code).toBe('not_connected');
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
    // Matched host -> SOCKS ProxyInfo carrying the session credentials;
    // unmatched -> direct.
    expect(handler!({ url: 'https://work.example/x' })).toEqual({
      type: 'socks',
      host: '127.0.0.1',
      port: 1080,
      proxyDNS: true,
      username: 'warren',
      password: 'session-secret',
    });
    expect(handler!({ url: 'https://personal.example/x' })).toEqual({ type: 'direct' });

    await vpn.disconnect();
    expect(handler).toBeUndefined();
  });
});

describe('WarrenBrowserVpn Firefox only-mode handlers', () => {
  /** A Firefox chrome whose onRequest handlers are all observable. */
  function firefoxWithHandlers(script: (req: HostRequest, port: FakePort) => void = healthyHost) {
    const base = fakeChrome(script, { control: ['controlled_by_this_extension'] });
    const handlers = new Set<(req: { url: string }) => unknown>();
    const handlersAtSet: number[] = [];
    base.chrome.proxy.settings.set = () => {
      handlersAtSet.push(handlers.size);
      return Promise.resolve(true);
    };
    base.chrome.proxy.onRequest = {
      addListener: (cb) => {
        handlers.add(cb);
      },
      removeListener: (cb) => {
        handlers.delete(cb);
      },
    };
    base.chrome.extension = { isAllowedIncognitoAccess: () => Promise.resolve(true) };
    return { ...base, handlers, handlersAtSet };
  }

  it('connects in only mode, where Firefox routes through the handler and no proxy setting', async () => {
    const { chrome, handlers } = firefoxWithHandlers();
    chrome.proxy.settings.get = () => ({ levelOfControl: 'controllable_by_this_extension' });
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });

    await expect(
      vpn.connect({ mnemonic: 'm', split: { mode: 'only', rules: ['work.example'] } }),
    ).resolves.toEqual(LISTENERS);
    expect(handlers.size).toBe(1);
  });

  it('keeps the only-mode handler until the new routing is in place', async () => {
    const { chrome, handlers, handlersAtSet } = firefoxWithHandlers();
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });
    await vpn.connect({ mnemonic: 'm', split: { mode: 'only', rules: ['work.example'] } });
    const [onlyMode] = handlers;

    await vpn.applySplit({ mode: 'all', rules: [] });

    // The old handler still tunnelled work.example while the settings changed.
    expect(handlersAtSet.at(-1)).toBe(2);
    expect(handlers.size).toBe(1);
    expect(handlers.has(onlyMode!)).toBe(false);
  });

  it('routes every mode through a handler carrying the session credentials', async () => {
    const { chrome, handlers } = firefoxWithHandlers();
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });
    await vpn.connect({ mnemonic: 'm', split: { mode: 'bypass', rules: ['bank.example'] } });
    const [handler] = handlers;

    expect(handler!({ url: 'https://news.example/' })).toEqual({
      type: 'socks',
      host: '127.0.0.1',
      port: 1080,
      proxyDNS: true,
      ...AUTH,
    });
    expect(handler!({ url: 'https://bank.example/' })).toEqual({ type: 'direct' });
  });

  it('leaves no handler behind after a reconnect over a dead host and a disconnect', async () => {
    const { chrome, handlers, port } = firefoxWithHandlers();
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });
    const only = { mode: 'only' as const, rules: ['work.example'] };
    await vpn.connect({ mnemonic: 'm', split: only });
    port.die();
    await vpn.connect({ mnemonic: 'm', split: only });

    await vpn.disconnect();

    expect(handlers.size).toBe(0);
  });
});

describe('WarrenBrowserVpn disconnect with a silent host', () => {
  it('fails a connect still waiting on the host, so a later connect is not refused', async () => {
    let answer = false;
    const { chrome } = fakeChrome((req, p) => {
      if (answer) healthyHost(req, p);
    });
    const vpn = new WarrenBrowserVpn({ chrome });
    const stuck = vpn.connect({ mnemonic: 'm' }).catch((e: WarrenExtensionError) => e.code);
    await new Promise((r) => setTimeout(r, 0));

    await vpn.disconnect();

    expect(await stuck).toBe('host_unavailable');
    answer = true;
    await expect(vpn.connect({ mnemonic: 'm' })).resolves.toEqual(LISTENERS);
  });

  it('restores direct routing even when the host never answers', async () => {
    vi.useFakeTimers();
    try {
      const { chrome, calls } = fakeChrome((req, p) => {
        if (req.type !== 'disconnect') healthyHost(req, p);
      });
      const vpn = new WarrenBrowserVpn({ chrome });
      await vpn.connect({ mnemonic: 'm' });

      const done = vpn.disconnect();
      await vi.advanceTimersByTimeAsync(10_000);
      await done;

      expect(calls).toContain('proxy.clear');
      expect(vpn.isProxied()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
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
    base.chrome.proxy.onRequest = { addListener: () => undefined, removeListener: () => undefined };
    return { ...base, values };
  }

  it('leaves a dead host to the per-request handler, which fails closed, and still reports it', async () => {
    const { chrome, values, port } = firefoxChrome(healthyHost);
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });
    const lost = vi.fn();
    vpn.onHostLost(lost);
    await vpn.connect({ mnemonic: 'm' });
    const applied = values.length;

    port.die();

    expect(values).toHaveLength(applied);
    expect(lost).toHaveBeenCalledTimes(1);
  });

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

  it('refuses to route a Firefox whose requests it cannot authenticate one by one', async () => {
    const { chrome, calls } = firefoxChrome(healthyHost);
    chrome.proxy.onRequest = undefined;
    const vpn = new WarrenBrowserVpn({ chrome, platform: 'firefox' });

    const err = await vpn.connect({ mnemonic: 'm' }).catch((e) => e);

    expect((err as WarrenExtensionError).code).toBe('proxy_uncontrollable');
    expect(calls.some((c) => c.startsWith('proxy.set'))).toBe(false);
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

describe('WarrenBrowserVpn handshake', () => {
  function recordingHost(seen: HostRequest[]) {
    return (req: HostRequest, p: FakePort) => {
      seen.push(req);
      healthyHost(req, p);
      if (req.type === 'exits') p.emit({ id: req.id, ok: true, type: 'exits', locations: [] });
    };
  }

  it('names its channel in a hello before the first request on a port', async () => {
    const seen: HostRequest[] = [];
    const { chrome } = fakeChrome(recordingHost(seen));
    await new WarrenBrowserVpn({ chrome, channel: 'beta' }).listExits();
    expect(seen.map((r) => r.type)).toEqual(['hello', 'exits']);
    expect(seen[0]).toMatchObject({ protocol: EXTENSION_PROTOCOL_VERSION, channel: 'beta' });
  });

  it('handshakes once per port', async () => {
    const seen: HostRequest[] = [];
    const { chrome } = fakeChrome(recordingHost(seen));
    const vpn = new WarrenBrowserVpn({ chrome, channel: 'beta' });
    await vpn.listExits();
    await vpn.listExits();
    expect(seen.map((r) => r.type)).toEqual(['hello', 'exits', 'exits']);
  });

  it('names the compiled channel when none is given', async () => {
    const seen: HostRequest[] = [];
    const { chrome } = fakeChrome(recordingHost(seen));
    await new WarrenBrowserVpn({ chrome }).listExits();
    expect(seen[0]).toMatchObject({ type: 'hello', channel: productChannel });
  });

  it('asks nothing of a host that refuses the hello', async () => {
    const seen: HostRequest[] = [];
    const { chrome } = fakeChrome((req, p) => {
      seen.push(req);
      p.emit({ id: req.id, ok: false, code: 'protocol', message: 'unsupported protocol version' });
    });
    const err = await new WarrenBrowserVpn({ chrome, channel: 'beta' }).listExits().catch((e) => e);
    expect((err as WarrenExtensionError).code).toBe('protocol');
    expect(seen.map((r) => r.type)).toEqual(['hello']);
  });
});

describe('WarrenBrowserVpn native datapath', () => {
  it('reports the datapath its host named at hello', async () => {
    const { chrome } = fakeChrome((req, p) => {
      if (req.type === 'hello') {
        p.emit({
          id: req.id,
          ok: true,
          type: 'hello',
          protocol: EXTENSION_PROTOCOL_VERSION,
          datapath: 'outdated',
        });
      }
    });
    expect(await new WarrenBrowserVpn({ chrome }).datapath()).toBe('outdated');
  });

  it('reports nothing for a host that names no datapath', async () => {
    const { chrome } = fakeChrome(healthyHost);
    expect(await new WarrenBrowserVpn({ chrome }).datapath()).toBeUndefined();
  });

  it('refuses the probe of a host that refuses the hello', async () => {
    const { chrome } = fakeChrome((req, p) => {
      p.emit({ id: req.id, ok: false, code: 'protocol', message: 'unsupported protocol version' });
    });
    const err = await new WarrenBrowserVpn({ chrome }).datapath().catch((e) => e);
    expect((err as WarrenExtensionError).code).toBe('protocol');
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

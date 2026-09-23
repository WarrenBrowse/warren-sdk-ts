import { describe, expect, it } from 'vitest';
import {
  FAIL_CLOSED_PROXY,
  type IngressEndpoint,
  type LockdownState,
  type MultihopRoutingState,
  type RoutingState,
  type RoutingStore,
  attachChromiumProxyAuth,
  attachFirefoxRouting,
  buildChromiumIngressValue,
  buildChromiumLockdownValue,
  clearChromiumRouting,
  firefoxProxyInfoFor,
  hardenBrowserLeaks,
  installChromiumRouting,
  memoryRoutingStore,
  readChromiumRouting,
  releaseBrowserLeaks,
  routingStoreOver,
} from '../src/index.js';

const HTTPS: IngressEndpoint = { kind: 'https', host: 'de2.edge.example.net', port: 443 };
const MASQUE: IngressEndpoint = {
  kind: 'masque',
  host: 'de2.edge.example.net',
  port: 443,
  masqueTemplate: '/.well-known/masque/udp/{target_host}/{target_port}/',
};
const STATE: RoutingState = {
  tier: 'ingress',
  endpoint: HTTPS,
  split: { mode: 'all', rules: [] },
  exit: { country: 'DE', city: 'Falkenstein' },
  hops: 1,
  installedAt: 1000,
};
const LOCKDOWN: LockdownState = {
  tier: 'lockdown',
  exempt: ['api.example.com'],
  installedAt: 2000,
};
const MULTIHOP: MultihopRoutingState = {
  tier: 'multihop',
  socks5: '127.0.0.1:1080',
  split: { mode: 'only', rules: ['work.example'] },
  installedAt: 3000,
};
const CREDENTIAL = 'a-base64url-credential';
const provider = { current: async () => CREDENTIAL };
const noCredential = { current: async () => undefined };

/** A fake `chrome.proxy.settings` whose value and level of control are observable. */
function fakeSettings(level = 'controllable_by_this_extension') {
  const rec: { value?: unknown; level: string; calls: string[] } = { level, calls: [] };
  const settings = {
    get: async () => {
      rec.calls.push('get');
      return { value: rec.value, levelOfControl: rec.level };
    },
    set: async (details: { value: unknown; scope?: string }) => {
      rec.calls.push(`set:${details.scope ?? ''}`);
      rec.value = details.value;
      if (rec.level === 'controllable_by_this_extension')
        rec.level = 'controlled_by_this_extension';
    },
    clear: async () => {
      rec.calls.push('clear');
      rec.value = undefined;
      if (rec.level === 'controlled_by_this_extension')
        rec.level = 'controllable_by_this_extension';
    },
  };
  return { settings, rec };
}

describe('buildChromiumIngressValue', () => {
  it('points the whole browser at the ingress over TLS with only loopback bypassed', () => {
    expect(buildChromiumIngressValue(HTTPS, { mode: 'all', rules: [] })).toEqual({
      mode: 'fixed_servers',
      rules: {
        singleProxy: { scheme: 'https', host: HTTPS.host, port: 443 },
        bypassList: ['localhost', '127.0.0.1'],
      },
    });
  });

  it('adds bypass rules to the bypass list', () => {
    const value = buildChromiumIngressValue(HTTPS, { mode: 'bypass', rules: ['corp.example'] });
    expect((value as { rules: { bypassList: string[] } }).rules.bypassList).toEqual([
      'localhost',
      '127.0.0.1',
      'corp.example',
    ]);
  });

  it('expresses only mode as a PAC script naming the ingress as an HTTPS proxy', () => {
    const value = buildChromiumIngressValue(HTTPS, { mode: 'only', rules: ['bank.example'] }) as {
      mode: string;
      pacScript: { data: string; mandatory: boolean };
    };
    expect(value.mode).toBe('pac_script');
    expect(value.pacScript.mandatory).toBe(true);
    expect(value.pacScript.data).toContain('HTTPS de2.edge.example.net:443');
    expect(value.pacScript.data).toContain('bank.example');
  });

  it('never emits the quic scheme, which Chromium reads back as plain http', () => {
    const json = JSON.stringify(buildChromiumIngressValue(MASQUE, { mode: 'all', rules: [] }));
    expect(json).not.toContain('quic');
    expect(json).toContain('"scheme":"https"');
  });
});

describe('installChromiumRouting / readChromiumRouting / clearChromiumRouting', () => {
  it('installs, verifies control, and reads back as ours', async () => {
    const { settings, rec } = fakeSettings();
    await installChromiumRouting(settings, STATE);
    expect(rec.calls).toContain('set:regular');
    const read = await readChromiumRouting(settings, HTTPS.host);
    expect(read).toEqual({ controlled: true, ours: true, lockdown: false, host: HTTPS.host });
  });

  it('refuses to install over settings another extension controls', async () => {
    const { settings, rec } = fakeSettings('controlled_by_other_extensions');
    await expect(installChromiumRouting(settings, STATE)).rejects.toMatchObject({
      code: 'proxy_uncontrollable',
    });
    expect(rec.calls).not.toContain('set:regular');
  });

  it('reads a proxy that names another host as not ours', async () => {
    const { settings } = fakeSettings();
    await installChromiumRouting(settings, STATE);
    const read = await readChromiumRouting(settings, 'nl1.edge.example.net');
    expect(read).toEqual({ controlled: true, ours: false, lockdown: false, host: HTTPS.host });
  });

  it('clears the settings and reads back as released', async () => {
    const { settings } = fakeSettings();
    await installChromiumRouting(settings, STATE);
    await clearChromiumRouting(settings);
    expect(await readChromiumRouting(settings, HTTPS.host)).toEqual({
      controlled: false,
      ours: false,
      lockdown: false,
    });
  });

  it('reports a PAC installation as ours when the script names the ingress', async () => {
    const { settings } = fakeSettings();
    await installChromiumRouting(settings, {
      ...STATE,
      split: { mode: 'only', rules: ['bank.example'] },
    });
    expect((await readChromiumRouting(settings, HTTPS.host)).ours).toBe(true);
  });
});

describe('lockdown on Chromium', () => {
  it('points the browser at a proxy that cannot answer, reaching directly only loopback and the exempt hosts', () => {
    expect(buildChromiumLockdownValue(['api.example.com'])).toEqual({
      mode: 'fixed_servers',
      rules: {
        singleProxy: { scheme: 'https', host: '127.0.0.1', port: 1 },
        bypassList: ['localhost', '127.0.0.1', 'api.example.com'],
      },
    });
  });

  it('installs a lockdown record over a live routing with a set, never a clear', async () => {
    const { settings, rec } = fakeSettings();
    await installChromiumRouting(settings, STATE);
    await installChromiumRouting(settings, LOCKDOWN);
    expect(rec.calls).not.toContain('clear');
    expect(rec.value).toEqual(buildChromiumLockdownValue(LOCKDOWN.exempt));
    expect(rec.level).toBe('controlled_by_this_extension');
  });

  it('reads its own lockdown back as a lockdown, and an ingress as not one', async () => {
    const { settings } = fakeSettings();
    await installChromiumRouting(settings, LOCKDOWN);
    expect(await readChromiumRouting(settings, HTTPS.host)).toMatchObject({
      controlled: true,
      ours: false,
      lockdown: true,
    });
    await installChromiumRouting(settings, STATE);
    expect(await readChromiumRouting(settings, HTTPS.host)).toMatchObject({
      ours: true,
      lockdown: false,
    });
  });

  it('refuses to install a lockdown over settings another extension controls', async () => {
    const { settings, rec } = fakeSettings('controlled_by_other_extensions');
    await expect(installChromiumRouting(settings, LOCKDOWN)).rejects.toMatchObject({
      code: 'proxy_uncontrollable',
    });
    expect(rec.calls).not.toContain('set:regular');
  });
});

describe('leak hardening', () => {
  function fakeNetwork() {
    const calls: string[] = [];
    const setting = (name: string) => ({
      set: async (d: { value: unknown }) => {
        calls.push(`${name}.set:${String(d.value)}`);
      },
      clear: async () => {
        calls.push(`${name}.clear`);
      },
    });
    return {
      calls,
      network: {
        webRTCIPHandlingPolicy: setting('webrtc'),
        networkPredictionEnabled: setting('prediction'),
      },
    };
  }

  it('keeps WebRTC off non-proxied UDP and turns the DNS prefetcher off', async () => {
    const { network, calls } = fakeNetwork();
    await hardenBrowserLeaks(network);
    expect(calls).toEqual(['webrtc.set:disable_non_proxied_udp', 'prediction.set:false']);
  });

  it('hands both settings back to the browser on release', async () => {
    const { network, calls } = fakeNetwork();
    await releaseBrowserLeaks(network);
    expect(calls).toEqual(['webrtc.clear', 'prediction.clear']);
  });
});

describe('attachChromiumProxyAuth', () => {
  type Challenge = {
    isProxy: boolean;
    requestId?: string;
    challenger?: { host: string; port: number };
  };
  function fakeWebRequest() {
    const rec: {
      listener?: (details: Challenge, cb: (r: unknown) => void) => void;
      extra?: string[];
    } = {};
    return {
      rec,
      webRequest: {
        onAuthRequired: {
          addListener: (
            listener: (details: Challenge, cb: (r: unknown) => void) => void,
            _filter: { urls: string[] },
            extra?: string[],
          ) => {
            rec.listener = listener;
            rec.extra = extra;
          },
        },
      },
    };
  }
  const answer = (rec: ReturnType<typeof fakeWebRequest>['rec'], details: Challenge) =>
    new Promise((resolve) => rec.listener?.(details, resolve));

  const INGRESS = { host: HTTPS.host, port: HTTPS.port };
  const LISTENER = { host: '127.0.0.1', port: 8118 };
  const SESSION = { username: 'warren', password: 'session-secret' };
  /** The native host's live session, whose HTTP listener is `LISTENER`. */
  const local = {
    forListener: (address: string) => (address === '127.0.0.1:8118' ? SESSION : undefined),
  };
  let request = 0;
  const challenge = (challenger: { host: string; port: number }): Challenge => ({
    isProxy: true,
    requestId: String(++request),
    challenger,
  });
  async function routedAt(record: RoutingState | LockdownState | MultihopRoutingState) {
    const routing = memoryRoutingStore();
    await routing.save(record);
    return routing;
  }

  it('registers an async blocking provider once, for every URL', () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, { local });
    expect(rec.extra).toEqual(['asyncBlocking']);
    expect(rec.listener).toBeDefined();
  });

  it('answers the ingress it routes through with the credential of the moment', async () => {
    const { webRequest, rec } = fakeWebRequest();
    let credential = CREDENTIAL;
    attachChromiumProxyAuth(webRequest, {
      ingress: { credentials: { current: async () => credential }, routing: await routedAt(STATE) },
    });
    expect(await answer(rec, challenge(INGRESS))).toEqual({
      authCredentials: { username: 'warren', password: CREDENTIAL },
    });
    // The epoch rolled: the next challenge gets the next credential, with no
    // routing change in between.
    credential = 'next-epoch';
    expect(await answer(rec, challenge(INGRESS))).toEqual({
      authCredentials: { username: 'warren', password: 'next-epoch' },
    });
  });

  it('answers the native host listener with the session credentials, never the ingress one', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, {
      ingress: { credentials: provider, routing: await routedAt(STATE) },
      local,
    });
    expect(await answer(rec, challenge(LISTENER))).toEqual({ authCredentials: SESSION });
  });

  it('gives a loopback challenge nothing when no live session owns that listener', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, {
      ingress: { credentials: provider, routing: await routedAt(STATE) },
      local,
    });
    expect(await answer(rec, challenge({ host: '127.0.0.1', port: 9999 }))).toEqual({
      cancel: true,
    });
    expect(await answer(rec, challenge({ host: 'localhost', port: 443 }))).toEqual({
      cancel: true,
    });
  });

  it('never hands the session credentials to the ingress', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, { local });
    expect(await answer(rec, challenge(INGRESS))).toEqual({ cancel: true });
  });

  it('answers no challenger the routing does not name', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, {
      ingress: { credentials: provider, routing: await routedAt(STATE) },
      local,
    });
    expect(await answer(rec, challenge({ host: 'other.example.net', port: 443 }))).toEqual({
      cancel: true,
    });
    expect(await answer(rec, challenge({ host: HTTPS.host, port: 8443 }))).toEqual({
      cancel: true,
    });
    expect(await answer(rec, { isProxy: true, requestId: 'no-challenger' })).toEqual({
      cancel: true,
    });
    for (const record of [LOCKDOWN, MULTIHOP]) {
      const other = fakeWebRequest();
      attachChromiumProxyAuth(other.webRequest, {
        ingress: { credentials: provider, routing: await routedAt(record) },
      });
      expect(await answer(other.rec, challenge(INGRESS))).toEqual({ cancel: true });
    }
  });

  it('stalls a request whose session credentials the listener refused once', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, { local });
    const refused = challenge(LISTENER);
    expect(await answer(rec, refused)).toEqual({ authCredentials: SESSION });
    expect(await answer(rec, refused)).toEqual({ cancel: true });
  });

  it('stalls a request whose ingress credential the ingress refused once', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, {
      ingress: { credentials: provider, routing: await routedAt(STATE) },
    });
    const refused = challenge(INGRESS);
    expect(await answer(rec, refused)).toEqual({
      authCredentials: { username: 'warren', password: CREDENTIAL },
    });
    expect(await answer(rec, refused)).toEqual({ cancel: true });
  });

  it('cancels the request rather than prompting when no credential exists', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, {
      ingress: { credentials: noCredential, routing: await routedAt(STATE) },
    });
    expect(await answer(rec, challenge(INGRESS))).toEqual({ cancel: true });
  });

  it('never offers a credential to a site challenge', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, {
      ingress: { credentials: provider, routing: await routedAt(STATE) },
      local,
    });
    expect(await answer(rec, { ...challenge(INGRESS), isProxy: false })).toEqual({});
    expect(await answer(rec, { ...challenge(LISTENER), isProxy: false })).toEqual({});
  });
});

describe('firefoxProxyInfoFor', () => {
  it('carries the credential on an https proxy info', () => {
    expect(firefoxProxyInfoFor(HTTPS, CREDENTIAL)).toEqual([
      {
        type: 'https',
        host: HTTPS.host,
        port: 443,
        proxyAuthorizationHeader: `Basic ${btoa(`warren:${CREDENTIAL}`)}`,
      },
    ]);
  });

  it('offers masque first and the https ingress as failover', () => {
    const infos = firefoxProxyInfoFor(MASQUE, CREDENTIAL);
    expect(infos.map((i) => i.type)).toEqual(['masque', 'https']);
    expect(infos[0]).toMatchObject({ failoverTimeout: 5 });
    expect(infos[1]).toMatchObject({ host: MASQUE.host, port: 443 });
  });

  it('puts the credential in the masque template query too, for the CONNECT-UDP connection', () => {
    // Firefox sends no header on CONNECT-UDP and opens a dedicated connection
    // for it, so the template is the only place a credential can reach it.
    const [masque] = firefoxProxyInfoFor(MASQUE, CREDENTIAL);
    expect(masque?.masqueTemplate).toBe(`${MASQUE.masqueTemplate}?credential=${CREDENTIAL}`);
    expect(masque).toHaveProperty('proxyAuthorizationHeader');
    const [bare] = firefoxProxyInfoFor(MASQUE, undefined);
    expect(bare?.masqueTemplate).toBe(MASQUE.masqueTemplate);
  });

  it('omits the header when there is no credential, so the ingress challenges', () => {
    expect(firefoxProxyInfoFor(HTTPS, undefined)[0]).not.toHaveProperty('proxyAuthorizationHeader');
  });
});

describe('attachFirefoxRouting', () => {
  function fakeProxyApi() {
    const rec: { listener?: (r: { url: string }) => unknown; errors: unknown[] } = { errors: [] };
    return {
      rec,
      proxy: {
        onRequest: {
          addListener: (listener: (r: { url: string }) => unknown) => {
            rec.listener = listener;
          },
        },
        onError: {
          addListener: (listener: (e: unknown) => void) => {
            rec.errors.push(listener);
          },
        },
      },
    };
  }

  it('sends everything direct while no routing is installed', async () => {
    const { proxy, rec } = fakeProxyApi();
    attachFirefoxRouting(proxy, memoryRoutingStore(), provider);
    expect(await rec.listener?.({ url: 'https://example.com/' })).toEqual({ type: 'direct' });
  });

  it('routes through the ingress with the credential once routing is installed', async () => {
    const { proxy, rec } = fakeProxyApi();
    const store = memoryRoutingStore();
    attachFirefoxRouting(proxy, store, provider);
    await store.save(STATE);
    expect(await rec.listener?.({ url: 'https://example.com/' })).toEqual(
      firefoxProxyInfoFor(HTTPS, CREDENTIAL),
    );
  });

  it('keeps loopback and bypassed sites direct', async () => {
    const { proxy, rec } = fakeProxyApi();
    const store = memoryRoutingStore();
    attachFirefoxRouting(proxy, store, provider);
    await store.save({ ...STATE, split: { mode: 'bypass', rules: ['corp.example'] } });
    expect(await rec.listener?.({ url: 'http://localhost:8080/' })).toEqual({ type: 'direct' });
    expect(await rec.listener?.({ url: 'https://app.corp.example/' })).toEqual({ type: 'direct' });
    expect(await rec.listener?.({ url: 'https://example.com/' })).not.toEqual({ type: 'direct' });
  });

  it('fails closed when its own store cannot be read', async () => {
    const { proxy, rec } = fakeProxyApi();
    const broken: RoutingStore = {
      load: async () => {
        throw new Error('storage unavailable');
      },
      save: async () => undefined,
      clear: async () => undefined,
    };
    attachFirefoxRouting(proxy, broken, provider);
    expect(await rec.listener?.({ url: 'https://example.com/' })).toEqual(FAIL_CLOSED_PROXY);
  });

  it('goes back to direct after the routing is cleared', async () => {
    const { proxy, rec } = fakeProxyApi();
    const store = memoryRoutingStore();
    attachFirefoxRouting(proxy, store, provider);
    await store.save(STATE);
    await store.clear();
    expect(await rec.listener?.({ url: 'https://example.com/' })).toEqual({ type: 'direct' });
  });
});

describe('attachFirefoxRouting under a lockdown', () => {
  const SESSION = { username: 'warren', password: 'session-secret' };
  function listen(
    store: RoutingStore,
    local = {
      forListener: (address: string) => (address === MULTIHOP.socks5 ? SESSION : undefined),
    },
  ) {
    let listener: ((r: { url: string }) => unknown) | undefined;
    attachFirefoxRouting(
      {
        onRequest: {
          addListener: (l) => {
            listener = l;
          },
        },
      },
      store,
      provider,
      local,
    );
    return (url: string) => listener?.({ url });
  }

  it('stalls every browsing request, with no credential offered to anyone', async () => {
    const store = memoryRoutingStore();
    await store.save(LOCKDOWN);
    const route = listen(store);
    expect(await route('https://example.com/')).toEqual(FAIL_CLOSED_PROXY);
    expect(await route('http://example.org/path')).toEqual(FAIL_CLOSED_PROXY);
  });

  it('lets exactly the exempt hosts and loopback through, so reconnecting stays possible', async () => {
    const store = memoryRoutingStore();
    await store.save(LOCKDOWN);
    const route = listen(store);
    expect(await route('https://api.example.com/v1/tokens')).toEqual({ type: 'direct' });
    expect(await route('https://API.example.com/')).toEqual({ type: 'direct' });
    expect(await route('http://localhost:3000/')).toEqual({ type: 'direct' });
    expect(await route('https://evil.api.example.com/')).toEqual(FAIL_CLOSED_PROXY);
    expect(await route('https://api.example.com.evil.net/')).toEqual(FAIL_CLOSED_PROXY);
  });

  it('answers a multi-hop record with its SOCKS endpoint and the session credentials', async () => {
    const store = memoryRoutingStore();
    await store.save(MULTIHOP);
    const route = listen(store);
    expect(await route('https://app.work.example/')).toEqual({
      type: 'socks',
      host: '127.0.0.1',
      port: 1080,
      proxyDNS: true,
      username: 'warren',
      password: 'session-secret',
    });
    expect(await route('https://personal.example/')).toEqual({ type: 'direct' });
  });

  it('stalls a multi-hop record no live session owns, as after a restart', async () => {
    const store = memoryRoutingStore();
    await store.save(MULTIHOP);
    const route = listen(store, { forListener: () => undefined });
    expect(await route('https://app.work.example/')).toEqual(FAIL_CLOSED_PROXY);
    expect(await route('https://personal.example/')).toEqual({ type: 'direct' });
  });

  it('stalls a request whose URL it cannot parse while routed', async () => {
    const store = memoryRoutingStore();
    await store.save(STATE);
    expect(await listen(store)('not a url')).toEqual(FAIL_CLOSED_PROXY);
  });
});

describe('routingStoreOver', () => {
  it('round-trips the state through a chrome.storage-shaped area', async () => {
    const items = new Map<string, unknown>();
    const store = routingStoreOver({
      get: async (key) => (items.has(key) ? { [key]: items.get(key) } : {}),
      set: async (entries) => {
        for (const [k, v] of Object.entries(entries)) items.set(k, v);
      },
      remove: async (key) => {
        items.delete(key);
      },
    });
    expect(await store.load()).toBeUndefined();
    await store.save(STATE);
    expect(await store.load()).toEqual(STATE);
    await store.clear();
    expect(await store.load()).toBeUndefined();
  });

  it('round-trips a lockdown and refuses one whose exempt list is not a list of hosts', async () => {
    const items = new Map<string, unknown>();
    const store = routingStoreOver({
      get: async (key) => (items.has(key) ? { [key]: items.get(key) } : {}),
      set: async (entries) => {
        for (const [k, v] of Object.entries(entries)) items.set(k, v);
      },
      remove: async (key) => {
        items.delete(key);
      },
    });
    await store.save(LOCKDOWN);
    expect(await store.load()).toEqual(LOCKDOWN);
    await store.save(MULTIHOP);
    expect(await store.load()).toEqual(MULTIHOP);
    items.set('warren.routing', { tier: 'lockdown', exempt: 'api.example.com', installedAt: 1 });
    expect(await store.load()).toBeUndefined();
  });

  it('ignores a corrupt stored value rather than routing on it', async () => {
    const store = routingStoreOver({
      get: async (key) => ({ [key]: { tier: 'ingress' } }),
      set: async () => undefined,
      remove: async () => undefined,
    });
    expect(await store.load()).toBeUndefined();
  });
});

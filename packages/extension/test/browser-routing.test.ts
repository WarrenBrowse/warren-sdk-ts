import { describe, expect, it } from 'vitest';
import {
  FAIL_CLOSED_PROXY,
  type IngressEndpoint,
  type RoutingState,
  type RoutingStore,
  attachChromiumProxyAuth,
  attachFirefoxRouting,
  buildChromiumIngressValue,
  clearChromiumRouting,
  firefoxProxyInfoFor,
  installChromiumRouting,
  memoryRoutingStore,
  readChromiumRouting,
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
    expect(read).toEqual({ controlled: true, ours: true, host: HTTPS.host });
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
    expect(read).toEqual({ controlled: true, ours: false, host: HTTPS.host });
  });

  it('clears the settings and reads back as released', async () => {
    const { settings } = fakeSettings();
    await installChromiumRouting(settings, STATE);
    await clearChromiumRouting(settings);
    expect(await readChromiumRouting(settings, HTTPS.host)).toEqual({
      controlled: false,
      ours: false,
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

describe('attachChromiumProxyAuth', () => {
  function fakeWebRequest() {
    const rec: {
      listener?: (details: { isProxy: boolean }, cb: (r: unknown) => void) => void;
      extra?: string[];
    } = {};
    return {
      rec,
      webRequest: {
        onAuthRequired: {
          addListener: (
            listener: (details: { isProxy: boolean }, cb: (r: unknown) => void) => void,
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
  const answer = (rec: ReturnType<typeof fakeWebRequest>['rec'], isProxy: boolean) =>
    new Promise((resolve) => rec.listener?.({ isProxy }, resolve));

  it('registers an async blocking provider once, for every URL', () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, provider);
    expect(rec.extra).toEqual(['asyncBlocking']);
    expect(rec.listener).toBeDefined();
  });

  it('answers a proxy challenge with the credential of the moment', async () => {
    const { webRequest, rec } = fakeWebRequest();
    let credential = CREDENTIAL;
    attachChromiumProxyAuth(webRequest, { current: async () => credential });
    expect(await answer(rec, true)).toEqual({
      authCredentials: { username: 'warren', password: CREDENTIAL },
    });
    // The epoch rolled: the next challenge gets the next credential, with no
    // routing change in between.
    credential = 'next-epoch';
    expect(await answer(rec, true)).toEqual({
      authCredentials: { username: 'warren', password: 'next-epoch' },
    });
  });

  it('cancels the request rather than prompting when no credential exists', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, noCredential);
    expect(await answer(rec, true)).toEqual({ cancel: true });
  });

  it('never offers the credential to a site challenge', async () => {
    const { webRequest, rec } = fakeWebRequest();
    attachChromiumProxyAuth(webRequest, provider);
    expect(await answer(rec, false)).toEqual({});
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

  it('ignores a corrupt stored value rather than routing on it', async () => {
    const store = routingStoreOver({
      get: async (key) => ({ [key]: { tier: 'ingress' } }),
      set: async () => undefined,
      remove: async () => undefined,
    });
    expect(await store.load()).toBeUndefined();
  });
});

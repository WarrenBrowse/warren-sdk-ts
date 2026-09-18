import { describe, expect, it } from 'vitest';
import { type BrowserProxyChrome, WarrenBrowserProxy, WarrenExtensionError } from '../src/index.js';

interface Recorded {
  calls: string[];
  authListener?: (details: { isProxy: boolean }) => unknown;
  proxyRequestListener?: (request: { url: string }) => unknown;
  proxyValue?: unknown;
}

/** A fake of just the surface this tier drives, per browser family. */
function fakeChrome(options: { firefox?: boolean; control?: string[] } = {}) {
  const rec: Recorded = { calls: [] };
  const control = options.control ?? [
    'controllable_by_this_extension',
    'controlled_by_this_extension',
  ];
  let gets = 0;
  const chrome: BrowserProxyChrome = {
    proxy: {
      settings: {
        get: () => {
          const level = control[Math.min(gets, control.length - 1)];
          gets += 1;
          rec.calls.push(`proxy.get:${level}`);
          return { levelOfControl: level ?? 'controllable_by_this_extension' };
        },
        set: (details) => {
          rec.proxyValue = details.value;
          rec.calls.push('proxy.set');
        },
        clear: () => {
          rec.proxyValue = undefined;
          rec.calls.push('proxy.clear');
        },
      },
      ...(options.firefox
        ? {
            onRequest: {
              addListener: (listener: (request: { url: string }) => unknown) => {
                rec.proxyRequestListener = listener;
                rec.calls.push('proxy.onRequest.add');
              },
              removeListener: () => {
                rec.proxyRequestListener = undefined;
                rec.calls.push('proxy.onRequest.remove');
              },
            },
          }
        : {}),
    },
    webRequest: {
      onAuthRequired: {
        addListener: (listener) => {
          rec.authListener = listener as (details: { isProxy: boolean }) => unknown;
          rec.calls.push('auth.add');
        },
        removeListener: () => {
          rec.authListener = undefined;
          rec.calls.push('auth.remove');
        },
      },
    },
  };
  return { chrome, rec };
}

const ENDPOINT = { host: 'de2.edge.example.net', port: 443 };
const CREDENTIAL = 'a-base64url-credential';

describe('WarrenBrowserProxy on Chromium', () => {
  it('points the whole browser at the remote ingress over TLS', async () => {
    const { chrome, rec } = fakeChrome();
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'chromium' });

    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    // `https` is the one scheme that gets there: Chromium silently downgrades
    // `quic` to plain `http`, which would send the CONNECT in clear.
    expect(rec.proxyValue).toEqual({
      mode: 'fixed_servers',
      rules: {
        singleProxy: { scheme: 'https', host: ENDPOINT.host, port: ENDPOINT.port },
        bypassList: ['localhost', '127.0.0.1'],
      },
    });
  });

  it('answers the proxy auth challenge with the current credential', async () => {
    const { chrome, rec } = fakeChrome();
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'chromium' });
    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    const answer = rec.authListener?.({ isProxy: true });

    expect(answer).toEqual({
      authCredentials: { username: 'warren', password: CREDENTIAL },
    });
  });

  it('answers a later challenge with the rotated credential', async () => {
    // Credentials are epoch-bound, so one is replaced roughly hourly without
    // the proxy configuration being torn down under the user's browsing.
    const { chrome, rec } = fakeChrome();
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'chromium' });
    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    proxy.setCredential('the-next-epoch-credential');

    expect(rec.authListener?.({ isProxy: true })).toEqual({
      authCredentials: { username: 'warren', password: 'the-next-epoch-credential' },
    });
  });

  it('never answers a challenge that did not come from a proxy', async () => {
    // A site's own 401 must not receive the tunnel credential.
    const { chrome, rec } = fakeChrome();
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'chromium' });
    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    expect(rec.authListener?.({ isProxy: false })).toEqual({});
  });

  it('refuses to connect when another extension owns the proxy settings', async () => {
    const { chrome } = fakeChrome({ control: ['controlled_by_other_extensions'] });
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'chromium' });

    await expect(proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL })).rejects.toThrow(
      WarrenExtensionError,
    );
  });

  it('clears the proxy and the auth provider on disconnect', async () => {
    const { chrome, rec } = fakeChrome();
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'chromium' });
    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    await proxy.disconnect();

    expect(rec.proxyValue).toBeUndefined();
    expect(rec.authListener).toBeUndefined();
    expect(rec.calls).toContain('proxy.clear');
  });

  it('reports itself proxied only while the settings are installed', async () => {
    const { chrome } = fakeChrome();
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'chromium' });
    expect(proxy.isProxied()).toBe(false);

    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });
    expect(proxy.isProxied()).toBe(true);

    await proxy.disconnect();
    expect(proxy.isProxied()).toBe(false);
  });
});

describe('WarrenBrowserProxy on Firefox', () => {
  it('routes through proxy.onRequest rather than proxy.settings', async () => {
    // Measured 2026-09-18 on Firefox 155: `proxy.settings.set` is refused with
    // "requires private browsing permission", an about:addons grant this tier
    // must not depend on. `proxy.onRequest` needs no such grant.
    const { chrome, rec } = fakeChrome({ firefox: true });
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'firefox' });

    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    expect(rec.calls).toContain('proxy.onRequest.add');
    expect(rec.calls).not.toContain('proxy.set');
  });

  it('attaches the credential to the proxy info, sparing the 407 round trip', async () => {
    const { chrome, rec } = fakeChrome({ firefox: true });
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'firefox' });
    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    const info = rec.proxyRequestListener?.({ url: 'https://example.com/' });

    expect(info).toEqual({
      type: 'https',
      host: ENDPOINT.host,
      port: ENDPOINT.port,
      proxyAuthorizationHeader: `Basic ${btoa(`warren:${CREDENTIAL}`)}`,
    });
  });

  it('sends loopback direct so the extension can still reach a local host', async () => {
    const { chrome, rec } = fakeChrome({ firefox: true });
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'firefox' });
    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    expect(rec.proxyRequestListener?.({ url: 'http://127.0.0.1:8080/' })).toEqual({
      type: 'direct',
    });
  });

  it('removes the request listener on disconnect', async () => {
    const { chrome, rec } = fakeChrome({ firefox: true });
    const proxy = new WarrenBrowserProxy({ chrome, platform: 'firefox' });
    await proxy.connect({ endpoint: ENDPOINT, credential: CREDENTIAL });

    await proxy.disconnect();

    expect(rec.proxyRequestListener).toBeUndefined();
    expect(proxy.isProxied()).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';
import {
  type SplitTunnelConfig,
  buildChromiumProxyValue,
  buildFirefoxProxyValue,
  hostMatchesRule,
  pageHostOf,
  shouldTunnelHost,
  shouldTunnelRequest,
} from '../src/split.js';

const SOCKS = '127.0.0.1:1080';
const HTTP = '127.0.0.1:8118';

describe('hostMatchesRule', () => {
  it('matches an exact host', () => {
    expect(hostMatchesRule('example.com', 'example.com')).toBe(true);
    expect(hostMatchesRule('example.org', 'example.com')).toBe(false);
  });

  it('matches subdomains of a bare domain rule', () => {
    expect(hostMatchesRule('mail.example.com', 'example.com')).toBe(true);
    expect(hostMatchesRule('a.b.example.com', 'example.com')).toBe(true);
    // Not a suffix boundary: notexample.com must not match example.com.
    expect(hostMatchesRule('notexample.com', 'example.com')).toBe(false);
  });

  it('supports a leading-dot and *. wildcard rule (subdomains only)', () => {
    expect(hostMatchesRule('a.example.com', '*.example.com')).toBe(true);
    expect(hostMatchesRule('example.com', '*.example.com')).toBe(false);
    expect(hostMatchesRule('a.example.com', '.example.com')).toBe(true);
  });

  it('is case-insensitive and matches the * catch-all', () => {
    expect(hostMatchesRule('EXAMPLE.com', 'example.COM')).toBe(true);
    expect(hostMatchesRule('anything.test', '*')).toBe(true);
  });
});

describe('shouldTunnelHost', () => {
  it('tunnels everything in all mode', () => {
    const cfg: SplitTunnelConfig = { mode: 'all', rules: [] };
    expect(shouldTunnelHost('example.com', cfg)).toBe(true);
  });

  it('always keeps loopback direct regardless of mode', () => {
    for (const mode of ['all', 'bypass', 'only'] as const) {
      expect(shouldTunnelHost('localhost', { mode, rules: ['localhost'] })).toBe(false);
      expect(shouldTunnelHost('127.0.0.1', { mode, rules: [] })).toBe(false);
    }
  });

  it('bypass mode sends matched hosts direct, the rest through the tunnel', () => {
    const cfg: SplitTunnelConfig = { mode: 'bypass', rules: ['bank.example'] };
    expect(shouldTunnelHost('bank.example', cfg)).toBe(false);
    expect(shouldTunnelHost('news.example', cfg)).toBe(true);
  });

  it('only mode tunnels matched hosts and sends the rest direct', () => {
    const cfg: SplitTunnelConfig = { mode: 'only', rules: ['work.example'] };
    expect(shouldTunnelHost('work.example', cfg)).toBe(true);
    expect(shouldTunnelHost('personal.example', cfg)).toBe(false);
  });
});

describe('shouldTunnelRequest', () => {
  const PAGES: SplitTunnelConfig = { mode: 'only', rules: ['video.example'], pageResources: true };

  it('tunnels what a page of a listed site loads, whatever its host, with page resources on', () => {
    expect(shouldTunnelRequest({ host: 'cdn.example', pageHost: 'www.video.example' }, PAGES)).toBe(
      true,
    );
    expect(shouldTunnelRequest({ host: 'cdn.example', pageHost: 'news.example' }, PAGES)).toBe(
      false,
    );
    expect(shouldTunnelRequest({ host: 'cdn.example' }, PAGES)).toBe(false);
  });

  it('sends the third-party requests of a listed page direct without page resources', () => {
    const cfg: SplitTunnelConfig = { mode: 'only', rules: ['video.example'] };
    expect(shouldTunnelRequest({ host: 'cdn.example', pageHost: 'video.example' }, cfg)).toBe(
      false,
    );
    expect(shouldTunnelRequest({ host: 'video.example' }, cfg)).toBe(true);
  });

  it('keeps loopback direct even from a listed page', () => {
    expect(shouldTunnelRequest({ host: 'localhost', pageHost: 'video.example' }, PAGES)).toBe(
      false,
    );
  });

  it('leaves bypass mode to the host rules', () => {
    const cfg: SplitTunnelConfig = { mode: 'bypass', rules: ['bank.example'], pageResources: true };
    expect(shouldTunnelRequest({ host: 'cdn.example', pageHost: 'bank.example' }, cfg)).toBe(true);
    expect(shouldTunnelRequest({ host: 'bank.example', pageHost: 'news.example' }, cfg)).toBe(
      false,
    );
  });
});

describe('pageHostOf', () => {
  // Shapes recorded from Firefox 156's proxy.onRequest: the frame ancestors
  // list the immediate parent first and the top-level page last.
  const TOP = 'https://www.video.example/watch';

  it('names the top-level page of a request made inside nested frames', () => {
    expect(
      pageHostOf({
        url: 'https://cdn.example/a.png',
        type: 'image',
        documentUrl: 'https://inner.example/frame.html',
        frameAncestors: [{ url: 'https://embed.example/player' }, { url: TOP }],
      }),
    ).toBe('www.video.example');
  });

  it('names the document itself for a request of the top-level page', () => {
    expect(
      pageHostOf({ url: 'https://cdn.example/a.js', documentUrl: TOP, frameAncestors: [] }),
    ).toBe('www.video.example');
  });

  it('names no page for a top-level navigation, which leaves the page it comes from', () => {
    expect(
      pageHostOf({ url: 'https://news.example/', type: 'main_frame', documentUrl: TOP }),
    ).toBeUndefined();
  });

  it('names no page for a request outside any document, or with an unreadable one', () => {
    expect(pageHostOf({ url: 'https://cdn.example/a.js' })).toBeUndefined();
    expect(
      pageHostOf({ url: 'https://cdn.example/a.js', documentUrl: 'not a url' }),
    ).toBeUndefined();
  });
});

describe('buildChromiumProxyValue', () => {
  it('all mode points fixed_servers at the HTTP listener with the loopback bypass only', () => {
    const value = buildChromiumProxyValue(HTTP, { mode: 'all', rules: [] }) as {
      mode: string;
      rules: { singleProxy: unknown; bypassList: string[] };
    };
    expect(value.mode).toBe('fixed_servers');
    expect(value.rules.singleProxy).toEqual({ scheme: 'http', host: '127.0.0.1', port: 8118 });
    expect(value.rules.bypassList).toEqual(['localhost', '127.0.0.1']);
  });

  it('bypass mode appends the rules to the native bypassList', () => {
    const value = buildChromiumProxyValue(HTTP, {
      mode: 'bypass',
      rules: ['bank.example', '*.corp.example'],
    }) as { mode: string; rules: { bypassList: string[] } };
    expect(value.mode).toBe('fixed_servers');
    expect(value.rules.bypassList).toEqual([
      'localhost',
      '127.0.0.1',
      'bank.example',
      '*.corp.example',
    ]);
  });

  it('only mode emits a PAC script routing matched hosts to the HTTP listener', () => {
    const value = buildChromiumProxyValue(HTTP, { mode: 'only', rules: ['work.example'] }) as {
      mode: string;
      pacScript: { data: string };
    };
    expect(value.mode).toBe('pac_script');
    const pac = value.pacScript.data;
    expect(pac).toContain('FindProxyForURL');
    expect(pac).toContain("'PROXY 127.0.0.1:8118'");
    expect(pac).not.toContain('SOCKS');
    expect(pac).toContain('work.example');
    // Loopback must stay direct even inside the PAC.
    expect(pac).toContain('DIRECT');
  });
});

describe('buildFirefoxProxyValue', () => {
  it('all mode sets manual socks with the loopback passthrough', () => {
    const value = buildFirefoxProxyValue(SOCKS, { mode: 'all', rules: [] }) as {
      proxyType: string;
      socks: string;
      socksVersion: number;
      proxyDNS: boolean;
      passthrough: string;
    };
    expect(value).toEqual({
      proxyType: 'manual',
      socks: '127.0.0.1:1080',
      socksVersion: 5,
      proxyDNS: true,
      passthrough: 'localhost, 127.0.0.1',
    });
  });

  it('bypass mode extends the passthrough with the rules', () => {
    const value = buildFirefoxProxyValue(SOCKS, {
      mode: 'bypass',
      rules: ['bank.example'],
    }) as { passthrough: string };
    expect(value.passthrough).toBe('localhost, 127.0.0.1, bank.example');
  });
});

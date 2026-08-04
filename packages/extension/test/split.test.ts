import { describe, expect, it } from 'vitest';
import {
  type SplitTunnelConfig,
  buildChromiumProxyValue,
  buildFirefoxProxyValue,
  hostMatchesRule,
  shouldTunnelHost,
} from '../src/split.js';

const SOCKS = '127.0.0.1:1080';

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

describe('buildChromiumProxyValue', () => {
  it('all mode uses fixed_servers with the loopback bypass only', () => {
    const value = buildChromiumProxyValue(SOCKS, { mode: 'all', rules: [] }) as {
      mode: string;
      rules: { singleProxy: unknown; bypassList: string[] };
    };
    expect(value.mode).toBe('fixed_servers');
    expect(value.rules.singleProxy).toEqual({ scheme: 'socks5', host: '127.0.0.1', port: 1080 });
    expect(value.rules.bypassList).toEqual(['localhost', '127.0.0.1']);
  });

  it('bypass mode appends the rules to the native bypassList', () => {
    const value = buildChromiumProxyValue(SOCKS, {
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

  it('only mode emits a PAC script routing matched hosts to the socks proxy', () => {
    const value = buildChromiumProxyValue(SOCKS, { mode: 'only', rules: ['work.example'] }) as {
      mode: string;
      pacScript: { data: string };
    };
    expect(value.mode).toBe('pac_script');
    const pac = value.pacScript.data;
    expect(pac).toContain('FindProxyForURL');
    expect(pac).toContain('SOCKS5 127.0.0.1:1080');
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

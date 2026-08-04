/**
 * Split tunneling: which hosts follow the tunnel and which go direct.
 *
 * `all` tunnels everything; `bypass` tunnels everything except `rules`; `only`
 * tunnels just `rules`. Loopback is always direct so the extension can reach
 * its own local SOCKS host. The matcher is shared by the Chromium PAC script
 * and the Firefox `proxy.onRequest` path so both platforms decide identically.
 */

/** Split tunneling mode. */
export type SplitTunnelMode = 'all' | 'bypass' | 'only';

/** Split tunneling configuration. `rules` are host patterns (see {@link hostMatchesRule}). */
export interface SplitTunnelConfig {
  mode: SplitTunnelMode;
  rules: string[];
}

/** The default: tunnel all traffic. */
export const DEFAULT_SPLIT: SplitTunnelConfig = { mode: 'all', rules: [] };

const LOOPBACK_BYPASS = ['localhost', '127.0.0.1'];

/**
 * Whether `host` matches a rule. A bare domain (`example.com`) matches itself
 * and every subdomain; a `.example.com` or `*.example.com` rule matches
 * subdomains only; `*` matches everything. Case-insensitive.
 */
export function hostMatchesRule(host: string, rule: string): boolean {
  const h = host.toLowerCase();
  const r = rule.toLowerCase();
  if (r === '*') return true;
  if (r.startsWith('*.')) {
    const suffix = r.slice(1); // ".example.com"
    return h.endsWith(suffix);
  }
  if (r.startsWith('.')) {
    return h.endsWith(r);
  }
  return h === r || h.endsWith(`.${r}`);
}

function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h === '127.0.0.1' || h === '[::1]';
}

/** Whether traffic to `host` should follow the tunnel under `config`. */
export function shouldTunnelHost(host: string, config: SplitTunnelConfig): boolean {
  // Loopback is never tunneled: the SOCKS host itself lives there.
  if (isLoopback(host)) return false;
  const matched = config.rules.some((rule) => hostMatchesRule(host, rule));
  switch (config.mode) {
    case 'bypass':
      return !matched;
    case 'only':
      return matched;
    default:
      return true;
  }
}

function parseSocks(socks5: string): { host: string; port: number } {
  const sep = socks5.lastIndexOf(':');
  return { host: socks5.slice(0, sep), port: Number(socks5.slice(sep + 1)) };
}

/** Builds a PAC script routing tunneled hosts to the SOCKS proxy, others direct. */
function buildPacScript(socks5: string, config: SplitTunnelConfig): string {
  // The rule list and mode are embedded as data; loopback is always DIRECT.
  const rules = JSON.stringify(config.rules.map((r) => r.toLowerCase()));
  const onlyMode = config.mode === 'only';
  return `function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host === 'localhost' || dnsDomainIs(host, '.localhost') || host === '127.0.0.1' || host === '::1') return 'DIRECT';
  var rules = ${rules};
  var matched = false;
  for (var i = 0; i < rules.length; i++) {
    var r = rules[i];
    if (r === '*') { matched = true; break; }
    if (r.charAt(0) === '*') r = r.slice(1);
    if (r.charAt(0) === '.') { if (host.slice(-r.length) === r) { matched = true; break; } continue; }
    if (host === r || host.slice(-(r.length + 1)) === '.' + r) { matched = true; break; }
  }
  var tunnel = ${onlyMode ? 'matched' : '!matched'};
  return tunnel ? 'SOCKS5 ${socks5}' : 'DIRECT';
}`;
}

/** Builds the `chrome.proxy.settings` value for a Chromium browser. */
export function buildChromiumProxyValue(socks5: string, config: SplitTunnelConfig): unknown {
  // `only` needs per-host logic the native bypassList cannot express, so it
  // falls to a PAC script; `all`/`bypass` use the more robust fixed_servers.
  if (config.mode === 'only') {
    return {
      mode: 'pac_script',
      pacScript: { data: buildPacScript(socks5, config), mandatory: true },
    };
  }
  const { host, port } = parseSocks(socks5);
  const bypassList =
    config.mode === 'bypass' ? [...LOOPBACK_BYPASS, ...config.rules] : LOOPBACK_BYPASS;
  return {
    mode: 'fixed_servers',
    rules: { singleProxy: { scheme: 'socks5', host, port }, bypassList },
  };
}

/**
 * Builds the `browser.proxy.settings` value for Firefox. Only `all`/`bypass`
 * are expressible here (via `passthrough`); `only` mode uses
 * {@link shouldTunnelHost} through a `proxy.onRequest` handler instead.
 */
export function buildFirefoxProxyValue(socks5: string, config: SplitTunnelConfig): unknown {
  const passthrough =
    config.mode === 'bypass'
      ? [...LOOPBACK_BYPASS, ...config.rules].join(', ')
      : LOOPBACK_BYPASS.join(', ');
  return {
    proxyType: 'manual',
    socks: socks5,
    socksVersion: 5,
    // Default only since Firefox 128; explicit so older ESRs keep DNS on the tunnel.
    proxyDNS: true,
    passthrough,
  };
}

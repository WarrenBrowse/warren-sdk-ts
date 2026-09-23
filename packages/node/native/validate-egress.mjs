// Live egress validation through the PACKAGED public API (@warrenbrowse/sdk-node
// ProxyTunnel), backed by the napi-rs native datapath. Requires a built package
// (`pnpm -C packages/node build`) and the native addon
// (`napi build --release --dts index.generated.d.ts` in native/warren-napi;
// the --dts keeps the curated index.d.ts untouched). The mnemonic is read from
// the environment at runtime and never stored.
//
//   WARREN_MNEMONIC="<subscribed 12 words>" node packages/node/native/validate-egress.mjs

import net from 'node:net';
import { ProxyTunnel, WarrenApiClient, apiBaseUrl, verifySignedRelayList } from '../dist/index.js';

const API_BASE = process.env.WARREN_API_BASE ?? apiBaseUrl;
// With another API than the build's own and no explicit pin, the signer of
// that API's current relay list is trusted on first use, as the native host
// does.
const PIN =
  process.env.WARREN_SERVER_PUBKEY_PIN ??
  (API_BASE === apiBaseUrl
    ? '4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e'
    : verifySignedRelayList(await new WarrenApiClient({ baseUrl: API_BASE }).exits())
        .serverPubkeyHex);
const ECHO_URL = 'http://checkip.amazonaws.com/';

// A SOCKS5 CONNECT to ip:port through the listener, authenticated with the
// session credentials (RFC 1929). Resolves once the exit relayed the SYN-ACK.
function socks5(proxyHost, proxyPort, auth, ip, port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, proxyHost);
    let stage = 'greet';
    s.on('connect', () => s.write(Buffer.from([5, 1, 2])));
    s.on('data', (d) => {
      if (stage === 'greet') {
        if (d[0] !== 5 || d[1] !== 2) return reject(new Error('username/password refused'));
        const user = Buffer.from(auth.username);
        const pass = Buffer.from(auth.password);
        s.write(
          Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]),
        );
        stage = 'auth';
      } else if (stage === 'auth') {
        if (d[0] !== 1 || d[1] !== 0) return reject(new Error('credentials refused'));
        const o = ip.split('.').map(Number);
        s.write(Buffer.from([5, 1, 0, 1, o[0], o[1], o[2], o[3], (port >> 8) & 255, port & 255]));
        stage = 'connect';
      } else if (stage === 'connect') {
        s.destroy();
        return d[1] === 0 ? resolve(true) : reject(new Error(`CONNECT rep=${d[1]}`));
      }
    });
    s.on('error', reject);
    setTimeout(() => {
      s.destroy();
      reject(new Error('timeout'));
    }, 8000);
  });
}

// One plain-HTTP request through the HTTP listener, in absolute form, with
// `authorization` as its Proxy-Authorization (none when null). Resolves with
// the status line and the body.
function httpProxyGet(proxyHost, proxyPort, authorization, url) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, proxyHost);
    const { host } = new URL(url);
    const auth = authorization ? `Proxy-Authorization: ${authorization}\r\n` : '';
    s.on('connect', () => s.write(`GET ${url} HTTP/1.1\r\nHost: ${host}\r\n${auth}\r\n`));
    let raw = Buffer.alloc(0);
    s.on('data', (d) => {
      raw = Buffer.concat([raw, d]);
    });
    s.on('end', () => {
      const text = raw.toString('utf8');
      const [head, ...body] = text.split('\r\n\r\n');
      resolve({ status: head.split('\r\n')[0], body: body.join('\r\n\r\n').trim() });
    });
    s.on('error', reject);
    setTimeout(() => {
      s.destroy();
      reject(new Error('timeout'));
    }, 15000);
  });
}

const withTimeout = (p, ms) =>
  Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error('t/o')), ms))]);

const mnemonic = process.env.WARREN_MNEMONIC;
if (!mnemonic) {
  console.error('set WARREN_MNEMONIC to a subscribed account');
  process.exit(2);
}

const tunnel = ProxyTunnel.create({ mnemonic, apiBase: API_BASE, serverPubkeyPin: PIN });
console.log('client identity :', tunnel.address.slice(0, 8));
const {
  socks5: socksAddr,
  http: httpAddr,
  username,
  password,
} = await tunnel.connect({
  httpProxy: true,
});
console.log('SOCKS5 proxy up :', socksAddr, '| HTTP proxy up :', httpAddr);
const auth = { username, password };
const [sh, sp] = socksAddr.split(':');

// The engine's own proof: the listener proves it holds the session's
// credentials, then an authenticated CONNECT goes through it.
await tunnel.verifyEgress();
console.log('engine egress proof    : ok');

let connectOk = false;
for (let i = 1; i <= 15 && !connectOk; i++) {
  connectOk = await withTimeout(socks5(sh, +sp, auth, '1.1.1.1', 443), 2600)
    .then(() => true)
    .catch(() => false);
  if (connectOk) {
    console.log(`egress probe 1.1.1.1:443 CONNECT ok (SYN-ACK via the exit, attempt ${i})`);
  }
}

// The HTTP listener refuses a request without the session credentials, and
// forwards a plain http:// one that carries them through the tunnel.
const [hh, hp] = httpAddr.split(':');
const refused = await httpProxyGet(hh, +hp, null, ECHO_URL);
console.log('HTTP, no credentials   :', refused.status);
const basic = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
let forwarded = { status: '', body: '' };
for (let i = 1; i <= 5 && !forwarded.status.startsWith('HTTP/1.1 200'); i++) {
  forwarded = await httpProxyGet(hh, +hp, basic, ECHO_URL).catch((e) => ({
    status: String(e.message),
    body: '',
  }));
}
console.log('HTTP, plain GET via exit:', forwarded.status, '| exit address:', forwarded.body);

await tunnel.shutdown();
console.log('proxy shut down.');

const httpOk =
  refused.status.startsWith('HTTP/1.1 407') &&
  forwarded.status.startsWith('HTTP/1.1 200') &&
  /^\d+\.\d+\.\d+\.\d+$/.test(forwarded.body);
if (!connectOk || !httpOk) {
  console.error(`FAIL: socks egress ${connectOk}, http listener ${httpOk}`);
  process.exit(1);
}
console.log('PASS: SOCKS5 and plain-HTTP egress through the sealed tunnel, both authenticated');

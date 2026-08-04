// Live egress validation through the PACKAGED public API (@warrenbrowse/sdk-node
// ProxyTunnel), backed by the napi-rs native datapath. Requires a built package
// (`pnpm -C packages/node build`) and the native addon
// (`napi build --release --dts index.generated.d.ts` in native/warren-napi;
// the --dts keeps the curated index.d.ts untouched). The mnemonic is read from
// the environment at runtime and never stored.
//
//   WARREN_MNEMONIC="<subscribed 12 words>" node packages/node/native/validate-egress.mjs

import dns from 'node:dns/promises';
import net from 'node:net';
import { ProxyTunnel, apiBaseUrl } from '../dist/index.js';

const API_BASE = apiBaseUrl;
const PIN = '4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e';
const ECHO_HOST = 'checkip.amazonaws.com';

function socks5(proxyHost, proxyPort, ip, port, { http, host } = {}) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, proxyHost);
    let stage = 'greet';
    let body = Buffer.alloc(0);
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      if (stage === 'greet') {
        if (d[0] !== 5 || d[1] !== 0) return reject(new Error('no-auth refused'));
        const o = ip.split('.').map(Number);
        s.write(Buffer.from([5, 1, 0, 1, o[0], o[1], o[2], o[3], (port >> 8) & 255, port & 255]));
        stage = 'connect';
      } else if (stage === 'connect') {
        if (d[1] !== 0) return reject(new Error('CONNECT rep=' + d[1]));
        if (!http) {
          s.destroy();
          return resolve(true);
        }
        s.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
        if (d.length > 10) body = Buffer.concat([body, d.subarray(10)]);
        stage = 'http';
      } else {
        body = Buffer.concat([body, d]);
      }
    });
    s.on('end', () =>
      resolve(http ? (body.toString('utf8').split('\r\n\r\n')[1] || '').trim() : true),
    );
    s.on('error', reject);
    setTimeout(() => {
      s.destroy();
      reject(new Error('timeout'));
    }, 8000);
  });
}

const withTimeout = (p, ms) =>
  Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error('t/o')), ms))]);

const mnemonic = process.env.WARREN_MNEMONIC;
if (!mnemonic) {
  console.error('set WARREN_MNEMONIC to a subscribed account');
  process.exit(2);
}

const echoIp = (await dns.lookup(ECHO_HOST, { family: 4 })).address;
void echoIp;

const tunnel = ProxyTunnel.create({ mnemonic, apiBase: API_BASE, serverPubkeyPin: PIN });
console.log('client identity :', tunnel.address);
const { socks5: socksAddr } = await tunnel.connect();
console.log('SOCKS5 proxy up :', socksAddr);
const [sh, sp] = socksAddr.split(':');

let connectOk = false;
for (let i = 1; i <= 15 && !connectOk; i++) {
  connectOk = await withTimeout(socks5(sh, +sp, '1.1.1.1', 443), 2600)
    .then(() => true)
    .catch(() => false);
  if (connectOk) {
    console.log(`egress probe 1.1.1.1:443 CONNECT ok (SYN-ACK via the exit, attempt ${i})`);
  }
}

await tunnel.shutdown();
console.log('proxy shut down.');

if (!connectOk) {
  console.error('FAIL: no egress through tunnel');
  process.exit(1);
}
console.log('PASS: TCP egress through the sealed tunnel confirmed (via packaged ProxyTunnel)');

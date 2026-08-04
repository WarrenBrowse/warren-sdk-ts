// Live end-to-end validation of the extension's NATIVE HOST over its real
// stdio native-messaging framing, exactly as a browser drives it. It spawns
// the packaged host (`dist/host` via run-host.mjs), speaks the uint32-LE +
// JSON v1 protocol, and proves the whole extension datapath: hello handshake,
// exits listing, account lookup, connect (real multi-hop tunnel to a prod
// exit), a real HTTP egress through the SOCKS5 the host opened, then a clean
// disconnect. The mnemonic is passed in the connect frame (as the extension
// vault would) and never stored.
//
//   WARREN_MNEMONIC="<subscribed 12 words>" node packages/extension/validate-host-egress.mjs

import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { apiBaseUrl } from '@warrenbrowse/sdk-core';

const here = path.dirname(fileURLToPath(import.meta.url));
const MAX = 1024 * 1024;

const mnemonic = process.env.WARREN_MNEMONIC;
if (!mnemonic) {
  console.error('set WARREN_MNEMONIC to a subscribed account');
  process.exit(2);
}

// --- native messaging codec (uint32 LE length + UTF-8 JSON) ---
function encode(message) {
  const json = Buffer.from(JSON.stringify(message), 'utf8');
  const frame = Buffer.allocUnsafe(4 + json.length);
  frame.writeUInt32LE(json.length, 0);
  json.copy(frame, 4);
  return frame;
}
class Decoder {
  buffer = Buffer.alloc(0);
  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const out = [];
    while (this.buffer.length >= 4) {
      const len = this.buffer.readUInt32LE(0);
      if (len > MAX) throw new RangeError('frame too big');
      if (this.buffer.length < 4 + len) break;
      out.push(JSON.parse(this.buffer.toString('utf8', 4, 4 + len)));
      this.buffer = this.buffer.subarray(4 + len);
    }
    return out;
  }
}

// --- egress probe: a SOCKS5 CONNECT to a fixed IPv4:port through the host's
// proxy. A SYN-ACK relayed back (rep=0) proves the sealed multi-hop tunnel
// carries real traffic to the internet at the exit. Same method the proven
// datapath baseline (validate-egress.mjs) uses. ---
function socks5Connect(proxyHost, proxyPort, ip, port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, proxyHost);
    let stage = 'greet';
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', (d) => {
      if (stage === 'greet') {
        if (d[0] !== 5 || d[1] !== 0) return reject(new Error('no-auth refused'));
        const o = ip.split('.').map(Number);
        s.write(Buffer.from([5, 1, 0, 1, o[0], o[1], o[2], o[3], (port >> 8) & 255, port & 255]));
        stage = 'connect';
      } else if (stage === 'connect') {
        if (d[1] !== 0) return reject(new Error(`CONNECT rep=${d[1]}`));
        s.destroy();
        resolve(`${ip}:${port}`);
      }
    });
    s.on('error', reject);
    setTimeout(() => {
      s.destroy();
      reject(new Error('timeout'));
    }, 3000);
  });
}

// --- drive the host ---
const host = spawn(process.execPath, [path.join(here, 'scripts', 'run-host.mjs')], {
  cwd: here,
  env: { ...process.env, WARREN_API_BASE: apiBaseUrl },
  stdio: ['pipe', 'pipe', 'inherit'],
});

const decoder = new Decoder();
const pending = new Map();
let idSeq = 0;
const events = [];
host.stdout.on('data', (chunk) => {
  for (const msg of decoder.push(chunk)) {
    if (msg.type === 'state') {
      events.push(msg.state);
      continue;
    }
    const p = pending.get(msg.id);
    if (p) {
      pending.delete(msg.id);
      p(msg);
    }
  }
});

function call(req, timeoutMs = 45000) {
  const id = ++idSeq;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`timeout on ${req.type}`));
    }, timeoutMs);
    pending.set(id, (m) => {
      clearTimeout(t);
      resolve(m);
    });
    host.stdin.write(encode({ id, ...req }));
  });
}

function fail(msg) {
  console.error('FAIL:', msg);
  host.kill('SIGTERM');
  process.exit(1);
}

try {
  const hello = await call({ type: 'hello', protocol: 1 });
  if (!hello.ok || hello.protocol !== 1) fail(`hello: ${JSON.stringify(hello)}`);
  console.log('hello ok        : protocol', hello.protocol);

  const exits = await call({ type: 'exits' });
  if (!exits.ok || !Array.isArray(exits.locations) || exits.locations.length === 0)
    fail(`exits: ${JSON.stringify(exits)}`);
  const active = exits.locations.filter((l) => l.active);
  console.log('exits ok        :', exits.locations.length, 'locations,', active.length, 'active');

  const account = await call({ type: 'account', mnemonic });
  if (!account.ok) fail(`account: ${JSON.stringify(account)}`);
  const exp = new Date(account.expiresAt * 1000).toISOString();
  console.log('account ok      : subscription expires', exp);

  const connect = await call({ type: 'connect', mnemonic });
  if (!connect.ok || !connect.endpoints?.socks5) fail(`connect: ${JSON.stringify(connect)}`);
  const [sh, sp] = connect.endpoints.socks5.split(':');
  console.log(
    'connect ok      : SOCKS5',
    connect.endpoints.socks5,
    '| states:',
    events.join(' -> '),
  );

  // Real egress: a CONNECT to 1.1.1.1:443 relayed to a SYN-ACK proves the
  // sealed multi-hop tunnel carries internet traffic at the exit.
  let egress = '';
  for (let i = 1; i <= 20 && !egress; i++) {
    egress = await socks5Connect(sh, +sp, '1.1.1.1', 443).catch(() => '');
    if (!egress) await new Promise((r) => setTimeout(r, 800));
    else console.log(`egress ok       : CONNECT ${egress} SYN-ACK via the exit (attempt ${i})`);
  }
  if (!egress) fail('no egress through the tunnel');

  const disconnect = await call({ type: 'disconnect' });
  if (!disconnect.ok) fail(`disconnect: ${JSON.stringify(disconnect)}`);
  console.log('disconnect ok   : states:', events.join(' -> '));

  host.stdin.end();
  console.log(
    '\nVERDICT: PASS  (host protocol + real multi-hop egress through the extension datapath)',
  );
  process.exit(0);
} catch (e) {
  fail(e.message);
}

// Live validation of the warren-host binary over its real stdio native
// messaging framing, launched exactly as Chromium launches it (the caller
// origin as its argument). Always: hello naming the beta channel, then the
// verified exit list. With WARREN_MNEMONIC set, also: account lookup, connect
// (a real multi-hop tunnel), an authenticated SOCKS5 CONNECT through the
// listener the helper opened, and disconnect. The mnemonic travels only inside
// the connect and account frames, as the extension vault sends it.
//
//   node validate-egress.mjs <path to warren-host>
//   WARREN_MNEMONIC="<subscribed 12 words>" node validate-egress.mjs <path to warren-host>
//
// WARREN_HOST_CALLER overrides the caller origin (default: the beta
// extension's), WARREN_HOST_CHANNEL the channel named at hello (default beta).

import { spawn } from 'node:child_process';
import net from 'node:net';
import process from 'node:process';

const bin = process.argv[2];
if (!bin) {
  console.error('usage: node validate-egress.mjs <path to warren-host>');
  process.exit(2);
}
const caller =
  process.env.WARREN_HOST_CALLER ?? 'chrome-extension://dgkleicjbkfinjhhhmalipaepnlchfib/';
const channel = process.env.WARREN_HOST_CHANNEL ?? 'beta';
const mnemonic = process.env.WARREN_MNEMONIC;

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
      if (this.buffer.length < 4 + len) break;
      out.push(JSON.parse(this.buffer.toString('utf8', 4, 4 + len)));
      this.buffer = this.buffer.subarray(4 + len);
    }
    return out;
  }
}

// RFC 1929 authenticated SOCKS5 CONNECT to a fixed IPv4:port. A success reply
// relayed back means the exit completed the TCP handshake with the target.
function socks5Connect(host, port, auth, ip, targetPort) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, host);
    let stage = 'greet';
    const timer = setTimeout(() => {
      s.destroy();
      reject(new Error('timeout'));
    }, 5000);
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
        s.write(Buffer.from([5, 1, 0, 1, ...o, (targetPort >> 8) & 255, targetPort & 255]));
        stage = 'connect';
      } else {
        clearTimeout(timer);
        s.destroy();
        if (d[1] !== 0) return reject(new Error(`CONNECT rep=${d[1]}`));
        resolve(`${ip}:${targetPort}`);
      }
    });
    s.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

const host = spawn(bin, [caller], { stdio: ['pipe', 'pipe', 'inherit'] });
const decoder = new Decoder();
const pending = new Map();
const events = [];
let nextId = 0;
host.stdout.on('data', (chunk) => {
  for (const msg of decoder.push(chunk)) {
    if (msg.type === 'state' && msg.id === undefined) {
      events.push(msg.state);
      continue;
    }
    pending.get(msg.id)?.(msg);
    pending.delete(msg.id);
  }
});
host.on('exit', (code) => {
  for (const [, resolve] of pending)
    resolve({ ok: false, code: 'exited', message: `helper exited ${code}` });
});

function call(request, timeoutMs = 60000) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout on ${request.type}`)), timeoutMs);
    pending.set(id, (m) => {
      clearTimeout(timer);
      resolve(m);
    });
    host.stdin.write(encode({ id, ...request }));
  });
}

function fail(message) {
  console.error('FAIL:', message);
  host.kill('SIGTERM');
  process.exit(1);
}

try {
  const hello = await call({ type: 'hello', protocol: 3, channel });
  if (!hello.ok || hello.protocol !== 3 || hello.datapath !== 'ready')
    fail(`hello: ${JSON.stringify(hello)}`);
  console.log(
    `hello ok        : protocol ${hello.protocol}, datapath ${hello.datapath}, channel ${channel}`,
  );

  const exits = await call({ type: 'exits' });
  if (!exits.ok || !Array.isArray(exits.locations) || exits.locations.length === 0)
    fail(`exits: ${JSON.stringify(exits)}`);
  const active = exits.locations.filter((l) => l.active);
  console.log(`exits ok        : ${exits.locations.length} locations, ${active.length} active`);

  if (!mnemonic) {
    console.log('\nWARREN_MNEMONIC is not set: stopping before account and connect. Live part:');
    console.log(`  WARREN_MNEMONIC="<subscribed 12 words>" node ${process.argv[1]} ${bin}`);
    host.stdin.end();
    console.log('\nVERDICT: PASS (offline part: framing, hello, verified exit list)');
    process.exit(0);
  }

  const account = await call({ type: 'account', mnemonic });
  if (!account.ok) fail(`account: ${account.code}: ${account.message}`);
  console.log(
    `account ok      : subscription expires ${new Date(account.expiresAt * 1000).toISOString()}`,
  );

  const connect = await call({ type: 'connect', mnemonic });
  if (!connect.ok || !connect.endpoints?.socks5 || !connect.auth?.password)
    fail(
      `connect: ${connect.ok ? 'no endpoints or credentials' : `${connect.code}: ${connect.message}`}`,
    );
  const status = await call({ type: 'status' });
  if (JSON.stringify(status).includes(connect.auth.password))
    fail('status carried the listener credentials');
  console.log(
    `connect ok      : SOCKS5 ${connect.endpoints.socks5} | states: ${events.join(' -> ')}`,
  );

  const [sh, sp] = connect.endpoints.socks5.split(':');
  let egress = '';
  for (let i = 1; i <= 20 && !egress; i++) {
    egress = await socks5Connect(sh, Number(sp), connect.auth, '1.1.1.1', 443).catch(() => '');
    if (egress)
      console.log(`egress ok       : CONNECT ${egress} relayed by the exit (attempt ${i})`);
    else await new Promise((r) => setTimeout(r, 800));
  }
  if (!egress) fail('no egress through the tunnel');
  const wrong = await socks5Connect(
    sh,
    Number(sp),
    { username: connect.auth.username, password: 'wrong' },
    '1.1.1.1',
    443,
  )
    .then(() => 'accepted')
    .catch(() => 'refused');
  if (wrong !== 'refused') fail('the listener accepted a wrong password');
  console.log('auth ok         : a wrong password is refused by the listener');

  const disconnect = await call({ type: 'disconnect' });
  if (!disconnect.ok) fail(`disconnect: ${JSON.stringify(disconnect)}`);
  console.log(`disconnect ok   : states: ${events.join(' -> ')}`);
  host.stdin.end();
  console.log('\nVERDICT: PASS (helper protocol + real multi-hop egress through the helper)');
  process.exit(0);
} catch (e) {
  fail(e.message);
}

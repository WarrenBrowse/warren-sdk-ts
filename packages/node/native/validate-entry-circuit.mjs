// Live validation of ENTRY-SELECTED multihop circuits: dial the fleet through
// one country's entry relay to a DIFFERENT country's exit. A successful sealed
// handshake is itself the proof the entry hop was dialed correctly: the setup
// frame is HPKE-sealed to the EXIT but the QUIC connection is dialed at the
// ENTRY relay's endpoint, so a wrong entry endpoint cannot complete the tunnel.
// We then confirm real TCP egress flows through the resulting circuit.
//
//   WARREN_MNEMONIC="<subscribed 12 words>" node packages/node/native/validate-entry-circuit.mjs
//
// Optional: WARREN_ENTRY_COUNTRY / WARREN_EXIT_COUNTRY (defaults NL -> DE).
// Requires a built package (`pnpm -C packages/node build`) and the native addon.

import net from 'node:net';
import {
  ProxyTunnel,
  WarrenApiClient,
  apiBaseUrl,
  verifyMultihopDirectory,
} from '../dist/index.js';

const API_BASE = apiBaseUrl;
const PIN = '4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e';

const mnemonic = process.env.WARREN_MNEMONIC;
if (!mnemonic) {
  console.error('set WARREN_MNEMONIC to a subscribed account');
  process.exit(2);
}
const ENTRY = process.env.WARREN_ENTRY_COUNTRY || 'NL';
const EXIT = process.env.WARREN_EXIT_COUNTRY || 'DE';

// TCP CONNECT probe through the SOCKS5 proxy to a literal IP (no DNS needed):
// a SYN-ACK back means the byte path traversed the sealed tunnel to the exit.
function tcpConnectThrough(proxyHost, proxyPort, ip, port) {
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
        s.destroy();
        return d[1] === 0 ? resolve(true) : reject(new Error('CONNECT rep=' + d[1]));
      }
    });
    s.on('error', reject);
    setTimeout(() => {
      s.destroy();
      reject(new Error('timeout'));
    }, 6000);
  });
}

async function egressThrough(label, opts) {
  const tunnel = ProxyTunnel.create({ mnemonic, apiBase: API_BASE, serverPubkeyPin: PIN });
  try {
    const { socks5 } = await tunnel.connect(opts);
    const [h, p] = socks5.split(':');
    let ok = false;
    for (let i = 1; i <= 15 && !ok; i++) {
      ok = await tcpConnectThrough(h, +p, '1.1.1.1', 443)
        .then(() => true)
        .catch(() => false);
    }
    console.log(`${label}: ${ok ? 'egress OK (SYN-ACK via the exit)' : 'NO EGRESS'}`);
    return ok;
  } finally {
    await tunnel.shutdown();
  }
}

// Confirm the fleet actually has distinct entry/exit nodes for this pair.
const client = new WarrenApiClient({ baseUrl: API_BASE });
const dir = verifyMultihopDirectory(await client.multihopDirectory(), [PIN], []);
const exitNode = dir.exits.find((e) => e.country === EXIT);
const entryNode = dir.exits.find((e) => e.country === ENTRY);
if (!exitNode || !entryNode) {
  console.error(`fleet has no ${ENTRY} entry and/or ${EXIT} exit; set WARREN_ENTRY/EXIT_COUNTRY`);
  process.exit(2);
}
if (exitNode.exitIdHex === entryNode.exitIdHex) {
  console.error(`${ENTRY} and ${EXIT} resolve to the same node; pick two distinct countries`);
  process.exit(2);
}
console.log(`fleet: entry ${ENTRY} (${entryNode.endpoint}) -> exit ${EXIT} (${exitNode.endpoint})`);

const crossOk = await egressThrough(`entry=${ENTRY} -> exit=${EXIT}`, {
  selector: { country: EXIT },
  entrySelector: { country: ENTRY },
});
const defaultOk = await egressThrough(`default circuit -> exit ${EXIT}`, {
  selector: { country: EXIT },
});

if (crossOk && defaultOk) {
  console.log(
    'PASS: entry-selected multihop circuit egressed end-to-end through a distinct entry.',
  );
  process.exit(0);
}
console.error('FAIL: an entry-selected or default circuit did not egress');
process.exit(1);

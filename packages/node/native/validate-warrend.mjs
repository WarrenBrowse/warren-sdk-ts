// Validates the TS WarrendClient against the REAL warrend daemon (system-VPN
// IPC), not a fake socket. To avoid fighting an existing default-route VPN, this
// connects to a deliberately BOGUS exit id: the daemon attempts it and fails at
// lookup BEFORE any TUN/routing change, so it emits real `state`/`error` events
// without rerouting traffic. That proves the wire framing + request shapes +
// event parsing are compatible with the real daemon.
//
// The daemon needs root (TUN) and exits cleanly when this client disconnects.
// Run with the dev-sudoers drop-in installed (see warrend/scripts/dev-sudoers.sh):
//
//   sudo -n <warrend> /tmp/warren-it.sock &
//   WARREN_MNEMONIC="<12 words>" WARREND_SOCK=/tmp/warren-it.sock node validate-warrend.mjs

import { WarrendClient, apiBaseUrl } from '../dist/index.js';

const SOCK = process.env.WARREND_SOCK || '/tmp/warren-sdk-daemon.sock';
const API_BASE = apiBaseUrl;
const PIN = '4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e';
const BOGUS_EXIT = '00'.repeat(32);

const mnemonic = process.env.WARREN_MNEMONIC;
if (!mnemonic) {
  console.error('set WARREN_MNEMONIC');
  process.exit(2);
}

const states = [];
const errors = [];
let closed = false;

const client = new WarrendClient({
  socketPath: SOCK,
  onState: (s) => {
    states.push(s);
    console.log('state:', s);
  },
  onError: (e) => {
    errors.push(e);
    console.log('error:', e.kind, '-', e.message);
  },
  onClose: () => {
    closed = true;
  },
});

client.open();
client.configure({ mnemonic, apiBase: API_BASE, serverPubkeyPin: PIN });
client.connect({ exitPubkeyHex: BOGUS_EXIT });

const start = Date.now();
while (Date.now() - start < 25000 && states.length === 0 && errors.length === 0 && !closed) {
  await new Promise((r) => setTimeout(r, 200));
}

client.disconnect();
client.close();
await new Promise((r) => setTimeout(r, 400));

console.log(`\nstates=${JSON.stringify(states)} errors=${errors.length} closed=${closed}`);
if (states.length === 0 && errors.length === 0) {
  console.error('FAIL: no daemon -> client event; IPC round-trip not proven');
  process.exit(1);
}
console.log('PASS: real warrend daemon drove the TS WarrendClient (framing + events validated)');

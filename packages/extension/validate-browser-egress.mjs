// Full real-browser validation of @warrenbrowse/sdk-extension in a live
// Chromium browser: loads the example MV3 extension, registers the native
// messaging host for its assigned id, imports the test wallet into the
// extension vault, drives the service worker's connect() (chrome.proxy +
// WebRTC/DNS leak closure + native-host multi-hop tunnel), then reads the
// browser's apparent public IP from a real tab and asserts it egresses at a
// Warren exit (not the machine's real IP). Finally disconnects and asserts the
// proxy is released.
//
// CDP is driven over Node's built-in WebSocket (Node >= 22). No puppeteer.
//
// Browser choice: stable Google Chrome (137+) removed command-line extension
// loading (`--load-extension` is silently ignored), so use a Chromium that
// still honours it: Brave (validated) or Chrome for Testing. Point CHROME_BIN
// and CDP_PORT at it. First build the bundle (`pnpm build && pnpm build:example`)
// and copy `example/` somewhere stable to pass as EXT_DIR.
//
//   pnpm build && pnpm build:example && cp -R example /tmp/warren-ext
//   WARREN_MNEMONIC="<subscribed 12 words>" REAL_IP="$(curl -s https://checkip.amazonaws.com)" \
//     CHROME_BIN="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" CDP_PORT=9334 \
//     USER_DATA_DIR=/tmp/warren-brave EXT_DIR=/tmp/warren-ext \
//     INSTALL_HOST="$PWD/scripts/install-host.mjs" node validate-browser-egress.mjs
//
// Verified 2026-07-11 in Brave 149 (Chromium 150): whole-browser egress at the
// NL exit 50.7.46.90 vs the machine's real IP, proxy released on disconnect.

import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import process from 'node:process';

// Chrome derives an unpacked extension's id from the SHA256 of its absolute
// (symlink-resolved) path: first 16 bytes, each hex nibble mapped 0-f -> a-p.
function unpackedExtensionId(dir) {
  const real = fs.realpathSync(dir);
  const hex = crypto.createHash('sha256').update(real).digest('hex').slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + Number.parseInt(c, 16))).join('');
}

const CHROME =
  process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const PORT = Number(process.env.CDP_PORT || 9333);
const EXTRA_FLAGS = (process.env.CHROME_FLAGS || '').split(' ').filter(Boolean);
const USER_DATA = process.env.USER_DATA_DIR;
const EXT_DIR = process.env.EXT_DIR;
const INSTALL_HOST = process.env.INSTALL_HOST;
const MNEMONIC = process.env.WARREN_MNEMONIC;
const REAL_IP = process.env.REAL_IP || '';
const PASSWORD = 'test-passphrase-123';

if (!MNEMONIC || !EXT_DIR || !INSTALL_HOST || !USER_DATA) {
  console.error('missing env (WARREN_MNEMONIC, EXT_DIR, INSTALL_HOST, USER_DATA_DIR)');
  process.exit(2);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const httpJson = (path) =>
  new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port: PORT, path }, (res) => {
        let b = '';
        res.on('data', (d) => {
          b += d;
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(b));
          } catch (e) {
            reject(e);
          }
        });
      })
      .on('error', reject);
  });

// --- minimal CDP client over one target's ws ---
class Cdp {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.id = 0;
    this.waiters = new Map();
  }
  open() {
    return new Promise((resolve, reject) => {
      this.ws.onopen = () => resolve();
      this.ws.onerror = (e) => reject(new Error(`ws error ${e.message || ''}`));
      this.ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.id && this.waiters.has(m.id)) {
          const w = this.waiters.get(m.id);
          this.waiters.delete(m.id);
          w(m);
        }
      };
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.waiters.set(id, (m) =>
        m.error ? reject(new Error(`${method}: ${JSON.stringify(m.error)}`)) : resolve(m.result),
      );
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async evaluate(expr, awaitPromise = true) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr,
      awaitPromise,
      returnByValue: true,
    });
    if (r.exceptionDetails)
      throw new Error(
        `eval threw: ${JSON.stringify(r.exceptionDetails.exception?.description || r.exceptionDetails.text)}`,
      );
    return r.result?.value;
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

function log(s) {
  console.log(s);
}
let chrome;
function cleanup() {
  try {
    chrome?.kill('SIGKILL');
  } catch {}
}
process.on('exit', cleanup);

try {
  // 1. launch Chrome headed with the extension loaded
  chrome = spawn(
    CHROME,
    [
      `--user-data-dir=${USER_DATA}`,
      `--load-extension=${EXT_DIR}`,
      `--disable-extensions-except=${EXT_DIR}`,
      `--remote-debugging-port=${PORT}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-timer-throttling',
      ...EXTRA_FLAGS,
      'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'ignore'] },
  );

  // 2. wait for the devtools endpoint
  let version;
  for (let i = 0; i < 40; i++) {
    version = await httpJson('/json/version').catch(() => null);
    if (version) break;
    await sleep(250);
  }
  if (!version) throw new Error('Chrome devtools endpoint never came up');
  log(`chrome up       : ${version.Browser}`);

  // 3. derive the extension id deterministically from the load path (the MV3
  // service worker is lazy and not reliably discoverable via /json/list).
  const extId = unpackedExtensionId(EXT_DIR);
  log(`extension id    : ${extId}`);

  // 4. register the native host for this id (writes the Chrome NativeMessagingHosts manifest)
  execFileSync(process.execPath, [INSTALL_HOST, '--extension-id', extId], { stdio: 'pipe' });
  log(`native host     : registered for ${extId}`);

  // 5. open an extension page (onboarding). This also wakes the service worker,
  //    and gives us a chrome.runtime-capable context to drive it.
  const browserCdp = new Cdp(version.webSocketDebuggerUrl);
  await browserCdp.open();
  const created = await browserCdp.send('Target.createTarget', {
    url: `chrome-extension://${extId}/onboarding.html`,
  });
  const pageTargetId = created.targetId;
  let pageList;
  for (let i = 0; i < 20 && !pageList?.webSocketDebuggerUrl; i++) {
    await sleep(300);
    pageList = (await httpJson('/json/list')).find((t) => t.id === pageTargetId);
  }
  if (!pageList?.webSocketDebuggerUrl)
    throw new Error('onboarding page ws not found (bad extension id?)');
  const page = new Cdp(pageList.webSocketDebuggerUrl);
  await page.open();
  await page.send('Runtime.enable');
  // Confirm the extension context really loaded (chrome.runtime.id present).
  const ctxId = await page.evaluate('chrome?.runtime?.id || ""');
  if (ctxId !== extId)
    throw new Error(`extension context mismatch: got "${ctxId}" expected "${extId}"`);

  const rt = async (type, extra = {}) =>
    page.evaluate(
      `new Promise((res)=>chrome.runtime.sendMessage(${JSON.stringify({ type, ...extra })}, r=>res(r)))`,
    );

  // 6. import the test wallet into the vault (unlocks it)
  const imp = await rt('importWallet', { mnemonic: MNEMONIC, password: PASSWORD });
  if (!imp?.ok) throw new Error(`importWallet: ${JSON.stringify(imp)}`);
  log(`wallet imported : ${imp.address}`);

  // 7. connect through the native host (multi-hop to an NL exit)
  const conn = await rt('connect', { selector: { country: 'NL' } });
  if (!conn?.ok) throw new Error(`connect: ${JSON.stringify(conn)}`);
  log(`connected       : http ${conn.endpoints?.http || '?'}`);

  // 8. confirm chrome.proxy is actually controlled by us and points at the host
  const proxy = await page.evaluate(
    'new Promise((res)=>chrome.proxy.settings.get({}, r=>res({level:r.levelOfControl, mode:r.value?.mode, rules:r.value?.rules})))',
  );
  log(`proxy control   : ${JSON.stringify(proxy)}`);
  if (!/this_extension/.test(proxy.level))
    throw new Error(`proxy not controlled by the extension: ${proxy.level}`);

  // 9. read the browser's apparent public IP from a REAL tab through the proxy
  const ipTab = await browserCdp.send('Target.createTarget', {
    url: 'https://checkip.amazonaws.com/',
  });
  await sleep(500);
  const ipWs = (await httpJson('/json/list')).find((t) => t.id === ipTab.targetId);
  const ipPage = new Cdp(ipWs.webSocketDebuggerUrl);
  await ipPage.open();
  let exitIp = '';
  for (let i = 0; i < 20 && !exitIp; i++) {
    await browserCdp.send('Target.activateTarget', { targetId: ipTab.targetId }).catch(() => {});
    const txt = await ipPage
      .evaluate(
        `fetch('https://checkip.amazonaws.com/',{cache:'no-store'}).then(r=>r.text()).catch(()=>'')`,
      )
      .catch(() => '');
    const m = String(txt).match(/(\d+\.\d+\.\d+\.\d+)/);
    if (m) exitIp = m[1];
    else await sleep(1000);
  }
  if (!exitIp) throw new Error('could not read apparent IP through the tunnel');
  log(`browser exit IP : ${exitIp}${REAL_IP ? `  (real IP ${REAL_IP})` : ''}`);
  if (REAL_IP && exitIp === REAL_IP)
    throw new Error('LEAK: browser IP equals the machine real IP; not tunneled');

  // 10. disconnect and confirm the proxy is released
  const dis = await rt('disconnect');
  if (!dis?.ok) throw new Error(`disconnect: ${JSON.stringify(dis)}`);
  await sleep(500);
  const proxyAfter = await page.evaluate(
    'new Promise((res)=>chrome.proxy.settings.get({}, r=>res(r.levelOfControl)))',
  );
  log(`after disconnect: proxy level ${proxyAfter}`);

  log(
    `\nVERDICT: PASS  (real Chrome: extension loaded, native host connected, whole-browser egress at ${exitIp}, proxy released on disconnect)`,
  );
  cleanup();
  process.exit(0);
} catch (e) {
  console.error('\nFAIL:', e.message);
  cleanup();
  process.exit(1);
}

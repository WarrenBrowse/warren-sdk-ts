/**
 * Warren vpn-desk example: the trusted side of the app.
 *
 * The mnemonic and seed live in this Node process only; the browser page is
 * pure UI over the loopback JSON API below. No-log discipline: the mnemonic,
 * seed and full identity material are never logged (redact to an 8-char
 * prefix if a value is ever needed for debugging).
 */
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  InMemoryGenerationStore,
  InMemoryServerKeyStore,
  NoRelayMatchError,
  ProxyTunnel,
  WarrenApiClient,
  WarrenApiError,
  WarrenDiscoveryError,
  WarrenMnemonicError,
  WarrenProxyError,
  acceptSignedRelayList,
  apiBaseUrl,
  encodeAddress,
  isProxyDatapathAvailable,
  keyPairFromSeed,
  seedFromMnemonic,
  selectExit,
  wipeKeyPair,
} from '@warrenbrowse/sdk-node';

const HOST = '127.0.0.1';
const PORT = 8642;
const API_BASE = process.env.WARREN_API_BASE ?? apiBaseUrl;
const PIN = process.env.WARREN_SERVER_PUBKEY_PIN;
const PUBLIC_DIR = resolve(fileURLToPath(new URL('.', import.meta.url)), 'public');
const EXITS_CACHE_SECS = 300;
const MAX_BODY_BYTES = 64 * 1024;

const mnemonic = process.env.WARREN_MNEMONIC;
if (!mnemonic) {
  console.error(
    'WARREN_MNEMONIC is not set.\n' +
      'Run with the BIP39 mnemonic of a subscribed Warren account:\n' +
      '  WARREN_MNEMONIC="word1 word2 ..." pnpm start',
  );
  process.exit(1);
}

let address;
let apiClient;
try {
  const seed = seedFromMnemonic(mnemonic);
  const pair = keyPairFromSeed(seed);
  address = encodeAddress(pair.publicKey);
  apiClient = new WarrenApiClient({ baseUrl: API_BASE, seed });
  // The client derived and holds its own signing key; drop our copies now.
  wipeKeyPair(pair);
  seed.fill(0);
} catch (err) {
  if (err instanceof WarrenMnemonicError) {
    console.error('WARREN_MNEMONIC is not a valid BIP39 mnemonic (word list, count or checksum).');
    process.exit(1);
  }
  throw err;
}

// In-memory stores: the anti-rollback floor and the TOFU server pin last for
// this process only. A real app supplies persistent implementations.
const generationStore = new InMemoryGenerationStore();
const serverKeyStore = new InMemoryServerKeyStore();

const datapathAvailable = isProxyDatapathAvailable();

let exitsCache = null;

async function verifiedRelayList() {
  const now = Math.floor(Date.now() / 1000);
  if (
    exitsCache &&
    now - exitsCache.fetchedAt < EXITS_CACHE_SECS &&
    now < exitsCache.list.expiresAt
  ) {
    return exitsCache.list;
  }
  const raw = await apiClient.exits();
  const list = acceptSignedRelayList(raw, {
    pins: PIN ? [PIN] : undefined,
    generationStore,
    serverKeyStore,
  });
  exitsCache = { list, fetchedAt: now };
  return list;
}

let tunnel = null;
let endpoints = null;
let currentExit = null;
let tunnelState = 'disconnected';
let connectInFlight = false;
const sseClients = new Set();

function statusSnapshot() {
  return {
    state: tunnelState,
    datapathAvailable,
    address,
    apiBase: API_BASE,
    exit: currentExit,
    endpoints,
  };
}

function broadcastState() {
  const frame = `event: state\ndata: ${JSON.stringify(statusSnapshot())}\n\n`;
  for (const client of sseClients) client.write(frame);
}

function setTunnelState(state) {
  tunnelState = state;
  if (state === 'disconnected' || state === 'failed') {
    endpoints = null;
    currentExit = null;
  }
  broadcastState();
}

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
  }
}

/**
 * Maps SDK typed errors to clean JSON error payloads. Raw causes and server
 * bodies (which may echo identity material) never reach the page.
 */
function errorPayload(err) {
  if (err instanceof HttpError) return { status: err.status, code: err.code, message: err.message };
  if (err instanceof WarrenProxyError) {
    return { status: err.code === 'unavailable' ? 503 : 502, code: err.code, message: err.message };
  }
  if (err instanceof WarrenApiError) {
    return { status: 502, code: `api_${err.code}`, message: err.message };
  }
  if (err instanceof WarrenDiscoveryError) {
    return { status: 502, code: `discovery_${err.code}`, message: err.message };
  }
  if (err instanceof WarrenMnemonicError) {
    return { status: 500, code: 'identity', message: 'invalid mnemonic' };
  }
  if (err instanceof NoRelayMatchError) {
    return { status: 404, code: 'no_exit_match', message: 'no exit matches the selection' };
  }
  return { status: 500, code: 'internal', message: 'internal error' };
}

async function handleConnect(body) {
  if (!datapathAvailable) {
    throw new HttpError(
      503,
      'unavailable',
      'native datapath addon is not built; running in control-plane only mode',
    );
  }
  if (connectInFlight) throw new HttpError(409, 'busy', 'a connect is already in progress');
  if (tunnel) throw new HttpError(409, 'already_connected', 'disconnect first');
  connectInFlight = true;
  try {
    const list = await verifiedRelayList();
    const advanced = body.advanced && typeof body.advanced === 'object' ? body.advanced : {};

    const selector = {};
    if (typeof body.exitPubkeyHex === 'string' && body.exitPubkeyHex) {
      selector.exitPubkeyHex = body.exitPubkeyHex;
    } else if (typeof body.country === 'string' && body.country) {
      selector.country = body.country;
      if (typeof body.city === 'string' && body.city) selector.city = body.city;
    }

    // Resolve the selection against the verified list up front, both to show
    // the chosen exit in the UI and to reject impossible selections early.
    let chosen;
    if (selector.exitPubkeyHex) {
      chosen = list.relays.find((r) => r.active && r.endpointIdHex === selector.exitPubkeyHex);
      if (!chosen) throw new NoRelayMatchError();
    } else {
      const location = selector.country
        ? selector.city
          ? { kind: 'city', country: selector.country, city: selector.city }
          : { kind: 'country', country: selector.country }
        : { kind: 'any' };
      chosen = selectExit(list.relays, { location });
    }

    // Datapath pin: the explicit env pin when given, otherwise the signer key
    // the control plane just verified (TOFU-pinned in serverKeyStore).
    const options = {
      mnemonic,
      apiBase: API_BASE,
      serverPubkeyPin: PIN ?? list.serverPubkeyHex,
      onState: setTunnelState,
    };
    if (advanced.daita === true) options.daita = true;
    if (advanced.requestIpv6 === true) options.requestIpv6 = true;

    const t = ProxyTunnel.create(options);
    tunnel = t;
    setTunnelState('connecting');

    // One-shot datapath (supervised: false) so metrics() returns live counters.
    const connectOptions = { selector, supervised: false };
    if (advanced.httpProxy === true) connectOptions.httpProxy = true;
    endpoints = await t.connect(connectOptions);
    currentExit = { country: chosen.country, city: chosen.city };
    setTunnelState('connected');
    return { endpoints, exit: currentExit };
  } catch (err) {
    // Fail-closed: never leave a half-open tunnel behind a failed connect.
    if (tunnel) {
      const t = tunnel;
      tunnel = null;
      await t.shutdown().catch(() => undefined);
    }
    setTunnelState('disconnected');
    throw err;
  } finally {
    connectInFlight = false;
  }
}

async function handleDisconnect() {
  if (!tunnel) return { ok: true };
  const t = tunnel;
  tunnel = null;
  await t.shutdown();
  setTunnelState('disconnected');
  return { ok: true };
}

async function handleMetrics() {
  if (!tunnel) return { metrics: null };
  return { metrics: await tunnel.metrics() };
}

async function handleExits() {
  const list = await verifiedRelayList();
  const exits = list.relays
    .filter((r) => r.active)
    .map((r) => ({
      pubkeyHex: r.endpointIdHex,
      country: r.country,
      city: r.city,
      ipv6Egress: r.ipv6Egress,
    }));
  const countries = new Map();
  for (const exit of exits) {
    const cities = countries.get(exit.country) ?? new Set();
    cities.add(exit.city);
    countries.set(exit.country, cities);
  }
  return {
    generation: list.generation,
    expiresAt: list.expiresAt,
    countries: [...countries.entries()]
      .map(([code, cities]) => ({ code, cities: [...cities].sort() }))
      .sort((a, b) => a.code.localeCompare(b.code)),
    exits,
  };
}

function readJsonBody(req) {
  return new Promise((resolvePromise, rejectPromise) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        rejectPromise(new HttpError(413, 'body_too_large', 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (chunks.length === 0) {
        resolvePromise({});
        return;
      }
      try {
        resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        rejectPromise(new HttpError(400, 'bad_json', 'request body is not valid JSON'));
      }
    });
    req.on('error', () => rejectPromise(new HttpError(400, 'bad_request', 'request aborted')));
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

function openEventStream(res) {
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-store',
    connection: 'keep-alive',
  });
  res.write(`event: state\ndata: ${JSON.stringify(statusSnapshot())}\n\n`);
  sseClients.add(res);
  // Comment lines keep intermediaries and the browser from timing out the stream.
  const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 25000);
  res.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

async function serveStatic(pathname, res) {
  const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = resolve(PUBLIC_DIR, rel);
  if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + sep)) {
    sendJson(res, 404, { error: { code: 'not_found', message: 'not found' } });
    return;
  }
  try {
    const data = await readFile(file);
    res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' });
    res.end(data);
  } catch {
    sendJson(res, 404, { error: { code: 'not_found', message: 'not found' } });
  }
}

async function route(req, res) {
  const url = new URL(req.url ?? '/', `http://${HOST}:${PORT}`);
  const key = `${req.method} ${url.pathname}`;
  switch (key) {
    case 'GET /api/status':
      sendJson(res, 200, statusSnapshot());
      return;
    case 'GET /api/exits':
      sendJson(res, 200, await handleExits());
      return;
    case 'POST /api/connect':
      sendJson(res, 200, await handleConnect(await readJsonBody(req)));
      return;
    case 'POST /api/disconnect':
      sendJson(res, 200, await handleDisconnect());
      return;
    case 'GET /api/metrics':
      sendJson(res, 200, await handleMetrics());
      return;
    case 'GET /api/events':
      openEventStream(res);
      return;
    default:
      if (url.pathname.startsWith('/api/')) {
        sendJson(res, 404, { error: { code: 'not_found', message: 'unknown API route' } });
        return;
      }
      await serveStatic(url.pathname, res);
  }
}

const server = createServer((req, res) => {
  route(req, res).catch((err) => {
    const { status, code, message } = errorPayload(err);
    if (!res.headersSent) sendJson(res, status, { error: { code, message } });
    else res.end();
  });
});

let closing = false;

// Fail-closed: tear the tunnel down before the process exits.
async function shutdown() {
  if (closing) return;
  closing = true;
  try {
    if (tunnel) await tunnel.shutdown();
  } catch {
    // best effort; the process is exiting anyway
  }
  for (const client of sseClients) client.end();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

server.listen(PORT, HOST, () => {
  console.log(`warren vpn-desk: http://${HOST}:${PORT}`);
  console.log(`account: ${address.slice(0, 8)}... | api: ${API_BASE}`);
  if (!datapathAvailable) {
    console.log('native datapath addon not found: control-plane only mode (no connect)');
  }
});

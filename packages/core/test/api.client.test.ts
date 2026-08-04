import { hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  type HttpRequest,
  type HttpResponse,
  type HttpTransport,
  USER_AGENT,
  WarrenApiClient,
  WarrenApiError,
  WarrenTransportError,
  randomNonceHex,
  signRequest,
} from '../src/index.js';

const SEED = hexToBytes('42'.repeat(32));
/** Address derived from SEED, pinned by vectors/identity.json request_signature. */
const SEED_ADDRESS = 'wbBfa1jcETanWzVVK4Hh166fwo6YSNaarwT2XnDQ1vNdSigx4';
const FIXED_NOW = 1700000000;
const FIXED_NONCE = '09'.repeat(16);

function recordingTransport(handler: (req: HttpRequest) => HttpResponse | Promise<HttpResponse>): {
  transport: HttpTransport;
  requests: HttpRequest[];
} {
  const requests: HttpRequest[] = [];
  return {
    requests,
    transport: {
      async send(req) {
        requests.push(req);
        return handler(req);
      },
    },
  };
}

const ok = (body: string): HttpResponse => ({ status: 200, body });

function header(req: HttpRequest, name: string): string | undefined {
  return req.headers[name];
}

describe('WarrenApiClient', () => {
  it('unsigned call attaches no X-Warren-* headers', async () => {
    const { transport, requests } = recordingTransport(() => ok('"signed-relay-list"'));
    const client = new WarrenApiClient({ baseUrl: 'https://api.example.com/', transport });

    const body = await client.exits();

    expect(body).toBe('"signed-relay-list"');
    const req = requests[0]!;
    expect(req.method).toBe('GET');
    expect(req.url).toBe('https://api.example.com/v1/exits');
    expect(header(req, 'X-Warren-PubKey')).toBeUndefined();
    expect(header(req, 'X-Warren-Sig')).toBeUndefined();
  });

  it('signed call attaches the four headers and signs like the pinned signer', async () => {
    const { transport, requests } = recordingTransport(() => ok('{"expires_at":1893456000}'));
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport,
      now: () => FIXED_NOW,
      nonce: () => FIXED_NONCE,
    });

    const sub = await client.subscription();
    expect(sub.expires_at).toBe(1893456000);

    const req = requests[0]!;
    const expected = signRequest(SEED, 'GET', '/v1/subscription', '', FIXED_NOW, FIXED_NONCE);
    expect(header(req, 'X-Warren-PubKey')).toBe(SEED_ADDRESS);
    expect(header(req, 'X-Warren-Sig')).toBe(expected.signatureHex);
    expect(header(req, 'X-Warren-Timestamp')).toBe(String(FIXED_NOW));
    expect(header(req, 'X-Warren-Nonce')).toBe(FIXED_NONCE);
  });

  it('every request carries the product user-agent on both paths', async () => {
    // One shared versionless token (the production app's value) so the API
    // cannot distinguish client kinds. Browser fetch silently drops the
    // header; setting it is still correct there and effective on Node.
    const { transport, requests } = recordingTransport(() => ok('{"expires_at":1893456000}'));
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport,
      now: () => FIXED_NOW,
      nonce: () => FIXED_NONCE,
    });

    await client.exits();
    await client.subscription();

    expect(header(requests[0]!, 'user-agent')).toBe(USER_AGENT);
    expect(header(requests[1]!, 'user-agent')).toBe(USER_AGENT);
    expect(USER_AGENT).toBe('warren-app');
  });

  it('serializes a JSON body and omits undefined optional fields', async () => {
    const { transport, requests } = recordingTransport(() => ok('{"expires_at":42}'));
    const client = new WarrenApiClient({ baseUrl: 'https://api.example.com', transport });

    await client.register({ pubkey_ss58: SEED_ADDRESS, voucher_secret: 'sekret' });

    const req = requests[0]!;
    expect(req.method).toBe('POST');
    expect(req.url).toBe('https://api.example.com/v1/register');
    expect(header(req, 'content-type')).toBe('application/json');
    expect(JSON.parse(req.body)).toEqual({ pubkey_ss58: SEED_ADDRESS, voucher_secret: 'sekret' });
    expect(req.body).not.toContain('referral_code');
  });

  it('serializes the IncidentReason enum as SCREAMING_SNAKE_CASE', async () => {
    const { transport, requests } = recordingTransport(() => ({ status: 204, body: '' }));
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport,
      now: () => FIXED_NOW,
      nonce: () => FIXED_NONCE,
    });

    await client.reportExitDown({
      exit_pubkey_hex: 'ab'.repeat(32),
      reason_code: 'HANDSHAKE_FAIL',
      ts_unix: 0,
    });

    expect(requests[0]!.body).toContain('"reason_code":"HANDSHAKE_FAIL"');
  });

  it('maps a non-2xx response to a redacted WarrenApiError', async () => {
    const { transport } = recordingTransport(() => ({ status: 500, body: 'ip=1.2.3.4 leaked' }));
    const client = new WarrenApiClient({ baseUrl: 'https://api.example.com', transport });

    const err = await client.exits().catch((e) => e);
    expect(err).toBeInstanceOf(WarrenApiError);
    expect(err.code).toBe('server');
    expect(err.status).toBe(500);
    expect(err.body).toBe('ip=1.2.3.4 leaked');
    expect(err.message).not.toContain('1.2.3.4');
  });

  it('falls back to an alternative host on connect failure', async () => {
    const { transport, requests } = recordingTransport((req) => {
      if (new URL(req.url).hostname === 'api.example.com') throw new Error('blocked');
      return ok('{"expires_at":7}');
    });
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport,
      alternativeHosts: ['mirror.example.net'],
      now: () => FIXED_NOW,
      nonce: () => FIXED_NONCE,
    });

    const sub = await client.subscription();

    expect(sub.expires_at).toBe(7);
    expect(requests.map((r) => new URL(r.url).hostname)).toEqual([
      'api.example.com',
      'mirror.example.net',
    ]);
  });

  it('throws all_hosts_blocked when every candidate connect-fails', async () => {
    const { transport, requests } = recordingTransport(() => {
      throw new Error('blocked');
    });
    const client = new WarrenApiClient({ baseUrl: 'https://api.example.com', transport });

    const err = await client.exits().catch((e) => e);
    expect(err).toBeInstanceOf(WarrenApiError);
    expect(err.code).toBe('all_hosts_blocked');
    // primary (SNI) + primary (no-SNI), no alternatives configured.
    expect(requests).toHaveLength(2);
    expect(requests[1]!.useSni).toBe(false);
  });

  it('a non-2xx response never advances the host fallback', async () => {
    const { transport, requests } = recordingTransport(() => ({ status: 500, body: '' }));
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      transport,
      alternativeHosts: ['mirror.example.net'],
    });

    const err = await client.exits().catch((e) => e);

    // A connected response, even an error status, stops the sequence: retrying
    // it on other hosts would replay signed nonces and hide the real failure.
    expect(err.code).toBe('server');
    expect(requests).toHaveLength(1);
  });

  it('a post-connect transport failure stops the fallback with code transport', async () => {
    const { transport, requests } = recordingTransport(() => {
      throw new WarrenTransportError('stream reset after connect', { connect: false });
    });
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      transport,
      alternativeHosts: ['mirror.example.net'],
    });

    const err = await client.exits().catch((e) => e);

    expect(err).toBeInstanceOf(WarrenApiError);
    expect(err.code).toBe('transport');
    expect(requests).toHaveLength(1);
  });

  it('a connect-flagged WarrenTransportError advances the fallback', async () => {
    const { transport, requests } = recordingTransport((req) => {
      if (new URL(req.url).hostname === 'api.example.com' && req.useSni) {
        throw new WarrenTransportError('connect failed', { connect: true });
      }
      return ok('"list"');
    });
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      transport,
      alternativeHosts: ['mirror.example.net'],
    });

    expect(await client.exits()).toBe('"list"');
    expect(requests.map((r) => new URL(r.url).hostname)).toEqual([
      'api.example.com',
      'mirror.example.net',
    ]);
  });

  it('signs once per request: every fallback attempt carries the same headers', async () => {
    // Pins the Rust reference semantics (signed_request runs before the host
    // sequence); re-signing per attempt would be a cross-SDK divergence.
    const { transport, requests } = recordingTransport((req) => {
      if (new URL(req.url).hostname === 'api.example.com') throw new Error('blocked');
      return ok('{"expires_at":7}');
    });
    let calls = 0;
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport,
      alternativeHosts: ['mirror.example.net'],
      now: () => FIXED_NOW,
      nonce: () => {
        calls += 1;
        return FIXED_NONCE;
      },
    });

    await client.subscription();

    expect(calls).toBe(1);
    expect(header(requests[0]!, 'X-Warren-Sig')).toBe(header(requests[1]!, 'X-Warren-Sig'));
    expect(header(requests[0]!, 'X-Warren-Nonce')).toBe(header(requests[1]!, 'X-Warren-Nonce'));
  });

  it('preserves a path-bearing base URL and explicit port across the fallback', async () => {
    const { transport, requests } = recordingTransport((req) => {
      if (new URL(req.url).hostname === 'api.example.com') throw new Error('blocked');
      return ok('"list"');
    });
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com:8443/gateway',
      transport,
      alternativeHosts: ['mirror.example.net'],
    });

    await client.exits();

    expect(requests[0]!.url).toBe('https://api.example.com:8443/gateway/v1/exits');
    expect(requests[1]!.url).toBe('https://mirror.example.net:8443/gateway/v1/exits');
  });

  it('rejects a signed call with bad_clock when the clock precedes the epoch', async () => {
    const { transport, requests } = recordingTransport(() => ok('{}'));
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport,
      now: () => -5,
    });

    const err = await client.subscription().catch((e) => e);

    expect(err).toBeInstanceOf(WarrenApiError);
    expect(err.code).toBe('bad_clock');
    expect(requests).toHaveLength(0);
  });

  it('rejects a signed call when no identity seed is configured', async () => {
    const { transport } = recordingTransport(() => ok('{}'));
    const client = new WarrenApiClient({ baseUrl: 'https://api.example.com', transport });

    const err = await client.subscription().catch((e) => e);
    expect(err).toBeInstanceOf(WarrenApiError);
    expect(err.code).toBe('no_identity');
  });

  it('pullPendingVoucher returns null on 404 and the secret on 200', async () => {
    const pending = recordingTransport(() => ({ status: 404, body: '' }));
    const ready = recordingTransport(() => ok('{"voucher_secret":"v-123"}'));

    const c1 = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      transport: pending.transport,
    });
    const c2 = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      transport: ready.transport,
    });

    expect(await c1.pullPendingVoucher('pend-1')).toBeNull();
    expect(await c2.pullPendingVoucher('pend-1')).toBe('v-123');
    expect(ready.requests[0]!.url).toBe('https://api.example.com/v1/checkout/pend-1/voucher');
  });
});

describe('WarrenApiClient extended endpoints', () => {
  function signedClient(handler: (req: HttpRequest) => HttpResponse | Promise<HttpResponse>) {
    const rec = recordingTransport(handler);
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport: rec.transport,
      now: () => FIXED_NOW,
      nonce: () => FIXED_NONCE,
    });
    return { client, requests: rec.requests };
  }

  it('sessionOpen posts a signed JSON body', async () => {
    const { client, requests } = signedClient(() => ok('{"admitted":true,"max":5,"current":1}'));
    const res = await client.sessionOpen({
      pubkey_ss58: SEED_ADDRESS,
      device_id_hex: 'ab'.repeat(16),
      exit_id: 'exit-1',
    });
    expect(res).toEqual({ admitted: true, max: 5, current: 1 });
    const req = requests[0]!;
    expect(req.url).toBe('https://api.example.com/v1/session/open');
    expect(header(req, 'X-Warren-Sig')).toBeDefined();
  });

  it('reportPubkeyMismatch fills default country_code/city and maps ts', async () => {
    const { client, requests } = signedClient(() => ({ status: 204, body: '' }));
    await client.reportPubkeyMismatch({
      exitIdHex: '00'.repeat(16),
      oldPubkeyHex: '11',
      newPubkeyHex: '22',
      tsUnix: 7,
    });
    expect(JSON.parse(requests[0]!.body)).toEqual({
      exit_id_hex: '00'.repeat(16),
      old_pubkey_hex: '11',
      new_pubkey_hex: '22',
      country_code: '',
      city: '',
      ts_unix: 7,
    });
  });

  it('initApplePayment signs an empty body', async () => {
    const { client, requests } = signedClient(() => ok('{"app_account_token":"uuid"}'));
    const res = await client.initApplePayment();
    expect(res.app_account_token).toBe('uuid');
    const req = requests[0]!;
    expect(req.body).toBe('');
    expect(header(req, 'content-type')).toBeUndefined();
    expect(header(req, 'X-Warren-Sig')).toBeDefined();
  });

  it('check performs a signed GET /v1/check', async () => {
    const { client, requests } = signedClient(() => ok('{"ok":true,"expires_at":9}'));
    const res = await client.check();
    expect(res).toEqual({ ok: true, expires_at: 9 });
    const req = requests[0]!;
    expect(req.method).toBe('GET');
    expect(req.url).toBe('https://api.example.com/v1/check');
    expect(header(req, 'X-Warren-Sig')).toBeDefined();
  });

  it('deleteAccount performs a signed DELETE /v1/account', async () => {
    const { client, requests } = signedClient(() => ({ status: 204, body: '' }));
    await client.deleteAccount();
    const req = requests[0]!;
    expect(req.method).toBe('DELETE');
    expect(req.url).toBe('https://api.example.com/v1/account');
    expect(req.body).toBe('');
    expect(header(req, 'X-Warren-Sig')).toBeDefined();
  });

  it('sessionClose posts a signed JSON body to /v1/session/close', async () => {
    const { client, requests } = signedClient(() => ({ status: 204, body: '' }));
    await client.sessionClose({ pubkey_ss58: SEED_ADDRESS, device_id_hex: 'ab'.repeat(16) });
    const req = requests[0]!;
    expect(req.method).toBe('POST');
    expect(req.url).toBe('https://api.example.com/v1/session/close');
    expect(JSON.parse(req.body)).toEqual({
      pubkey_ss58: SEED_ADDRESS,
      device_id_hex: 'ab'.repeat(16),
    });
    expect(header(req, 'X-Warren-Sig')).toBeDefined();
  });

  it('checkApplePayment posts the StoreKit payload signed', async () => {
    const { client, requests } = signedClient(() => ok('{"credited":true,"expires_at":3}'));
    const res = await client.checkApplePayment({ signed_transaction: 'jws-blob' });
    expect(res).toEqual({ credited: true, expires_at: 3 });
    const req = requests[0]!;
    expect(req.url).toBe('https://api.example.com/v1/payments/apple/check');
    expect(JSON.parse(req.body)).toEqual({ signed_transaction: 'jws-blob' });
    expect(header(req, 'X-Warren-Sig')).toBeDefined();
  });

  it('maps an invalid JSON response body to code response', async () => {
    const { client } = signedClient(() => ok('not json'));
    const err = await client.subscription().catch((e) => e);
    expect(err).toBeInstanceOf(WarrenApiError);
    expect(err.code).toBe('response');
  });

  it('multihopDirectory returns null on 404 and the raw JSON on 200', async () => {
    const missing = signedClient(() => ({ status: 404, body: '' }));
    const present = signedClient(() => ok('{"dir":1}'));
    expect(await missing.client.multihopDirectory()).toBeNull();
    expect(await present.client.multihopDirectory()).toBe('{"dir":1}');
    expect(header(present.requests[0]!, 'X-Warren-Sig')).toBeUndefined();
  });
});

describe('WarrenApiClient.dispose', () => {
  it('wipes the signing key: signed calls throw no_identity, unsigned keep working', async () => {
    const { transport } = recordingTransport(() => ok('"list"'));
    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com',
      seed: SEED,
      transport,
    });

    client.dispose();

    const err = await client.subscription().catch((e) => e);
    expect(err).toBeInstanceOf(WarrenApiError);
    expect(err.code).toBe('no_identity');
    expect(await client.exits()).toBe('"list"');
  });
});

describe('randomNonceHex', () => {
  it('is 32 lowercase hex chars and non-repeating', () => {
    const a = randomNonceHex();
    const b = randomNonceHex();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});

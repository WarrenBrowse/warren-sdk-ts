import type { HttpRequest, HttpResponse, HttpTransport } from '@warrenbrowse/sdk-core';
import { describe, expect, it } from 'vitest';
import * as web from '../src/index.js';
import { WarrenWebClient } from '../src/index.js';

function recordingTransport(handler: (req: HttpRequest) => HttpResponse): {
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

describe('WarrenWebClient', () => {
  it('calls unsigned endpoints without any X-Warren-* signing headers', async () => {
    const { transport, requests } = recordingTransport(() => ok('"relay-list"'));
    const client = new WarrenWebClient({ baseUrl: 'https://api.example.com', transport });

    await client.exits();
    await client.register({ pubkey_ss58: 'wbX', voucher_secret: 's' });

    for (const req of requests) {
      expect(req.headers['X-Warren-PubKey']).toBeUndefined();
      expect(req.headers['X-Warren-Sig']).toBeUndefined();
    }
    expect(requests.map((r) => r.url)).toEqual([
      'https://api.example.com/v1/exits',
      'https://api.example.com/v1/register',
    ]);
  });

  it('pullPendingVoucher and multihopDirectory delegate unsigned with 404 -> null', async () => {
    const notReady = recordingTransport(() => ({ status: 404, body: '' }));
    const ready = recordingTransport(() => ok('{"voucher_secret":"v-9"}'));
    const c1 = new WarrenWebClient({
      baseUrl: 'https://api.example.com',
      transport: notReady.transport,
    });
    const c2 = new WarrenWebClient({
      baseUrl: 'https://api.example.com',
      transport: ready.transport,
    });

    expect(await c1.pullPendingVoucher('p', 'ab'.repeat(32))).toBeNull();
    expect(await c1.multihopDirectory()).toBeNull();
    expect(await c2.pullPendingVoucher('p', 'ab'.repeat(32))).toBe('v-9');
    expect(ready.requests[0]!.method).toBe('POST');
    expect(ready.requests[0]!.url).toBe('https://api.example.com/v1/checkout/p/voucher');
    expect(ready.requests[0]!.headers['X-Warren-Sig']).toBeUndefined();
  });

  it('exposes no signed methods on the type surface', () => {
    const client = new WarrenWebClient({ baseUrl: 'https://api.example.com' });
    // The browser client has no seed and no signed calls.
    expect('subscription' in client).toBe(false);
    expect('deleteAccount' in client).toBe(false);
  });

  it('offers no way to mint anonymous tokens, so a page never reserves an epoch', () => {
    // Issuance is wallet-signed and its batch derives from the wallet seed,
    // which a page never holds. A page minting from the CSPRNG instead would
    // reserve the account's epoch and lock the wallet's other clients out.
    const client = new WarrenWebClient({ baseUrl: 'https://api.example.com' });
    expect('tokenTransport' in client).toBe(false);
    expect('browserProxyTokenTransport' in client).toBe(false);
    for (const name of ['TokenManager', 'mintEpoch', 'acquireTokens', 'blindToken']) {
      expect(name in web, name).toBe(false);
    }
  });
});

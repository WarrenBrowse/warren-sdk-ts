import { hexToBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import { describe, expect, it } from 'vitest';
import {
  BLINDING_PURPOSE_SESSION,
  type HttpRequest,
  type HttpResponse,
  type HttpTransport,
  WarrenApiClient,
  acquireTokens,
  blindingKeyFromSeed,
} from '../src/index.js';

const SEED = hexToBytes('42'.repeat(32));
const N_HEX =
  'b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd549';
const D_HEX =
  '9189ce27b54eb3005374832593c74abe758f098e4e88ce9836c7d21c30ad794ec65dcab0cb2b066b2f5af93baf5a9233a12d994e934db6477bd5fb30e7a759ec825bbb5d52b7d02e177f93bbf0a23285e9ca6f83b20da54187294a73e43a138c12bbd54e03f3b0e7c8765a5a092b110c1193151a8ab7c210861c7db8a6c4bd6ec4a840ae20fef1367ea42018e5258d9c81b83b2c03ffd344ff09056817e463c44bd4504d2923704bc3eb945d7502ac48886ad3bdeafe3827bed71b7715258bc8a9b9fa6fdf1cfab57f5fbf4e4a429651cde13dc67b690cfd9074f384e7203a22ab29168996d3bf89c919031ff8e757af3676db2b0775f1375910844aefed1d29';
const SPKI_HEX =
  '30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd5490203010001';
const KEY_ID = 'ad4229a4eea9ada97d55c227b90f95c33b021890b8a7c2a52312062f12d55809';
const EPOCH_SECS = 86400;
const EPOCH = 42;
const NOW = EPOCH * EPOCH_SECS;

function os2ip(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return r;
}
function i2osp(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

const directory = {
  issuer_name: 'issuer.warren.test',
  token_type: 2,
  epoch_secs: EPOCH_SECS,
  context_label: 'warren/token/epoch',
  quota_per_epoch: 2,
  prefetch_epochs: 1,
  keys: [
    {
      epoch: EPOCH,
      token_key_id: KEY_ID,
      spki_b64: base64urlnopad.encode(hexToBytes(SPKI_HEX)),
      not_before: 0,
      not_after: 4102444800,
    },
  ],
};

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

describe('WarrenApiClient token transport + acquireTokens (end-to-end)', () => {
  it('GETs the directory unsigned, POSTs issue signed, and mints spendable tokens', async () => {
    const n = os2ip(hexToBytes(N_HEX));
    const d = os2ip(hexToBytes(D_HEX));
    const { transport, requests } = recordingTransport((req) => {
      if (req.url.endsWith('/v1/tokens/keys')) {
        return { status: 200, body: JSON.stringify(directory) };
      }
      if (req.url.endsWith('/v1/tokens/issue')) {
        const body = JSON.parse(req.body) as { epochs: { epoch: number; blinded: string[] }[] };
        const ep = body.epochs[0]!;
        const blind_signatures = ep.blinded.map((b64) =>
          base64urlnopad.encode(i2osp(modPow(os2ip(base64urlnopad.decode(b64)), d, n), 256)),
        );
        return {
          status: 200,
          body: JSON.stringify({
            epochs: [{ epoch: ep.epoch, issued: true, blind_signatures, token_key_id: KEY_ID }],
          }),
        };
      }
      return { status: 404, body: '' };
    });

    const client = new WarrenApiClient({
      baseUrl: 'https://api.example.com/',
      transport,
      seed: SEED,
      now: () => NOW,
    });

    const { epoch, tokens } = await acquireTokens(client.tokenTransport(), {
      nowUnixSecs: NOW,
      count: 2,
      blindingKey: blindingKeyFromSeed(SEED, BLINDING_PURPOSE_SESSION),
    });

    expect(epoch).toBe(EPOCH);
    expect(tokens).toHaveLength(2);
    for (const t of tokens) {
      expect(t.serialize().length).toBe(354);
    }

    // The directory GET is unsigned; the issuance POST is wallet-signed.
    const keysReq = requests.find((r) => r.url.endsWith('/v1/tokens/keys'))!;
    const issueReq = requests.find((r) => r.url.endsWith('/v1/tokens/issue'))!;
    expect(keysReq.method).toBe('GET');
    expect(keysReq.headers['X-Warren-Sig']).toBeUndefined();
    expect(issueReq.method).toBe('POST');
    expect(issueReq.headers['X-Warren-Sig']).toBeDefined();
    expect(issueReq.headers['X-Warren-PubKey']).toBeDefined();
  });
});

import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import { describe, expect, it } from 'vitest';
import { WarrenEdgeError } from '../src/edge/errors.js';
import {
  type TokenIssueRequest,
  type TokenIssueResponse,
  type TokenIssuerDirectory,
  type TokenTransport,
  acquireTokens,
} from '../src/edge/token-acquire.js';
import { issuerPublicKeyFromSpki } from '../src/edge/token.js';

// The FIXED test issuer key (warrenguard-token `IssuerSecretKey::generate(seed
// 0xED9E5EED)`), exported once.
const N_HEX =
  'b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd549';
const D_HEX =
  '9189ce27b54eb3005374832593c74abe758f098e4e88ce9836c7d21c30ad794ec65dcab0cb2b066b2f5af93baf5a9233a12d994e934db6477bd5fb30e7a759ec825bbb5d52b7d02e177f93bbf0a23285e9ca6f83b20da54187294a73e43a138c12bbd54e03f3b0e7c8765a5a092b110c1193151a8ab7c210861c7db8a6c4bd6ec4a840ae20fef1367ea42018e5258d9c81b83b2c03ffd344ff09056817e463c44bd4504d2923704bc3eb945d7502ac48886ad3bdeafe3827bed71b7715258bc8a9b9fa6fdf1cfab57f5fbf4e4a429651cde13dc67b690cfd9074f384e7203a22ab29168996d3bf89c919031ff8e757af3676db2b0775f1375910844aefed1d29';
const SPKI_HEX =
  '30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd5490203010001';
const KEY_ID = 'ad4229a4eea9ada97d55c227b90f95c33b021890b8a7c2a52312062f12d55809';
const EPOCH_SECS = 86400;
const EPOCH = 42;

function os2ip(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
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

/** A fake account API backed by the fixed test issuer (signs blinded requests
 * with `d`, exactly as the server's blind_sign does). */
function fakeTransport(): TokenTransport {
  const directory: TokenIssuerDirectory = {
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
  const n = os2ip(hexToBytes(N_HEX));
  const d = os2ip(hexToBytes(D_HEX));
  return {
    async getDirectory() {
      return directory;
    },
    async issue(request: TokenIssueRequest): Promise<TokenIssueResponse> {
      const ep = request.epochs[0]!;
      const blindSignatures = ep.blinded.map((b64) => {
        const blinded = os2ip(base64urlnopad.decode(b64));
        return base64urlnopad.encode(i2osp(modPow(blinded, d, n), 256));
      });
      return {
        epochs: [
          {
            epoch: ep.epoch,
            issued: true,
            blind_signatures: blindSignatures,
            token_key_id: KEY_ID,
          },
        ],
      };
    },
  };
}

describe('issuerPublicKeyFromSpki', () => {
  it('parses n and the key id out of the RSASSA-PSS SPKI DER', () => {
    const pk = issuerPublicKeyFromSpki(hexToBytes(SPKI_HEX));
    expect(pk.n).toBe(os2ip(hexToBytes(N_HEX)));
    expect(pk.e).toBe(65537n);
    expect(bytesToHex(pk.keyId)).toBe(KEY_ID);
  });
});

describe('acquireTokens (v7 session-token acquisition flow)', () => {
  it('fetches the directory, blinds, issues, and finalizes spendable tokens', async () => {
    const { epoch, tokens } = await acquireTokens(fakeTransport(), {
      nowUnixSecs: EPOCH * EPOCH_SECS + 10,
      count: 2,
    });
    expect(epoch).toBe(EPOCH);
    expect(tokens).toHaveLength(2);
    for (const t of tokens) {
      const bytes = t.serialize();
      expect(bytes.length).toBe(354);
      // token_type prefix + the issuer key id at offset 2+32+32.
      expect(bytes[0]).toBe(0x00);
      expect(bytes[1]).toBe(0x02);
      expect(bytesToHex(bytes.subarray(66, 98))).toBe(KEY_ID);
    }
    // Two distinct random blinds/nonces -> two distinct tokens.
    expect(bytesToHex(tokens[0]!.serialize())).not.toBe(bytesToHex(tokens[1]!.serialize()));
  });

  it('rejects an epoch the issuer refused', async () => {
    const base = fakeTransport();
    const transport: TokenTransport = {
      getDirectory: base.getDirectory,
      async issue() {
        return { epochs: [{ epoch: EPOCH, issued: false, reject_reason: 'quota_exhausted' }] };
      },
    };
    const promise = acquireTokens(transport, { nowUnixSecs: EPOCH * EPOCH_SECS, count: 1 });
    await expect(promise).rejects.toThrow(/quota_exhausted/);
    const err = await promise.catch((e) => e);
    expect(err).toBeInstanceOf(WarrenEdgeError);
    expect((err as WarrenEdgeError).code).toBe('epoch_rejected');
  });
});

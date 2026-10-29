/**
 * A fake account API over the FIXED test issuer key, shared by the token
 * manager suites.
 */
import { hexToBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import {
  BLINDING_PURPOSE_SESSION,
  type TokenIssueRequest,
  type TokenIssueResponse,
  type TokenIssuerDirectory,
  type TokenTransport,
  WarrenApiError,
  blindingKeyFromSeed,
} from '../../src/index.js';

// The FIXED test issuer key (warrenguard-token `IssuerSecretKey::generate(seed
// 0xED9E5EED)`); the same fixture the acquire tests use. The key is epoch-
// independent, so the fake directory can advertise it for several epochs.
const N_HEX =
  'b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd549';
const D_HEX =
  '9189ce27b54eb3005374832593c74abe758f098e4e88ce9836c7d21c30ad794ec65dcab0cb2b066b2f5af93baf5a9233a12d994e934db6477bd5fb30e7a759ec825bbb5d52b7d02e177f93bbf0a23285e9ca6f83b20da54187294a73e43a138c12bbd54e03f3b0e7c8765a5a092b110c1193151a8ab7c210861c7db8a6c4bd6ec4a840ae20fef1367ea42018e5258d9c81b83b2c03ffd344ff09056817e463c44bd4504d2923704bc3eb945d7502ac48886ad3bdeafe3827bed71b7715258bc8a9b9fa6fdf1cfab57f5fbf4e4a429651cde13dc67b690cfd9074f384e7203a22ab29168996d3bf89c919031ff8e757af3676db2b0775f1375910844aefed1d29';
export const SPKI_HEX =
  '30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd5490203010001';
export const KEY_ID = 'ad4229a4eea9ada97d55c227b90f95c33b021890b8a7c2a52312062f12d55809';
export const EPOCH_SECS = 86400;
export const EPOCH = 42;
export const NOW = EPOCH * EPOCH_SECS + 10;
/** The session blinding key of a test wallet: every minting manager needs one. */
export const SESSION_KEY = blindingKeyFromSeed(
  new Uint8Array(32).fill(3),
  BLINDING_PURPOSE_SESSION,
);

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

export type IssueAction =
  | 'sign'
  | 'already_issued'
  | 'not_subscribed'
  | 'throw'
  | 'clock_skew'
  | 'unauthorized';

/**
 * A fake account API backed by the fixed test issuer, with per-epoch behavior
 * driven by `behavior(epoch, call)` and an issue-call counter per epoch (so a
 * test can prove which epochs were re-asked and which were settled).
 */
export function fakeTransport(cfg: {
  epochs: number[];
  quota?: number;
  counts: Map<number, number>;
  behavior?: (epoch: number, call: number) => IssueAction;
  /** When present, mimics the issuer's once-per-account-epoch ledger: the first
   * batch takes the epoch, the same batch is served again, any other is
   * refused. Keyed epoch -> the batch that took it. */
  ledger?: Map<number, string>;
}): TokenTransport {
  const quota = cfg.quota ?? 2;
  const n = os2ip(hexToBytes(N_HEX));
  const d = os2ip(hexToBytes(D_HEX));
  const directory: TokenIssuerDirectory = {
    issuer_name: 'issuer.warren.test',
    token_type: 2,
    epoch_secs: EPOCH_SECS,
    context_label: 'warren/token/epoch',
    quota_per_epoch: quota,
    prefetch_epochs: cfg.epochs.length,
    keys: cfg.epochs.map((epoch) => ({
      epoch,
      token_key_id: KEY_ID,
      spki_b64: base64urlnopad.encode(hexToBytes(SPKI_HEX)),
      not_before: 0,
      not_after: 4102444800,
    })),
  };
  return {
    async getDirectory() {
      return directory;
    },
    async issue(request: TokenIssueRequest): Promise<TokenIssueResponse> {
      const ep = request.epochs[0]!;
      const call = (cfg.counts.get(ep.epoch) ?? 0) + 1;
      cfg.counts.set(ep.epoch, call);
      const action = cfg.behavior ? cfg.behavior(ep.epoch, call) : 'sign';
      if (action === 'throw') throw new Error('transient network failure');
      if (action === 'clock_skew') {
        throw new WarrenApiError('clock_skew', 'refused', { status: 401 });
      }
      if (action === 'unauthorized') {
        throw new WarrenApiError('server', 'server returned status 401', { status: 401 });
      }
      if (action !== 'sign') {
        return { epochs: [{ epoch: ep.epoch, issued: false, reject_reason: action }] };
      }
      if (cfg.ledger) {
        const batch = ep.blinded.join('.');
        const held = cfg.ledger.get(ep.epoch);
        if (held === undefined) cfg.ledger.set(ep.epoch, batch);
        else if (held !== batch) {
          return {
            epochs: [{ epoch: ep.epoch, issued: false, reject_reason: 'already_issued' }],
          };
        }
      }
      const blind_signatures = ep.blinded.map((b64) =>
        base64urlnopad.encode(i2osp(modPow(os2ip(base64urlnopad.decode(b64)), d, n), 256)),
      );
      return {
        epochs: [{ epoch: ep.epoch, issued: true, blind_signatures, token_key_id: KEY_ID }],
      };
    },
  };
}

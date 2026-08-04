import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  blindToken,
  challengeDigestForEpoch,
  finalizeToken,
  issuerPublicKey,
  serializeTokenChallenge,
} from '../src/edge/token.js';

/**
 * Cross-implementation proof that the TS blind-RSA token client
 * (RSABSSA-SHA384-PSS-Deterministic, RFC 9474/9578) mints a Privacy Pass token a
 * real Warren exit verifies. The issuer key is the FIXED
 * `IssuerSecretKey::generate(seed 0xED9E5EED)` from warrenguard-token (its n/e/d
 * exported once); the frozen token below is verified by a Rust
 * `IssuerPublicKey::verify_token` in
 * `warrenguard/crates/warrenguard-token/tests/edge_js_token_vector.rs`.
 */
const N = hexToBytes(
  'b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd549',
);
const E = hexToBytes('010001');
const D = hexToBytes(
  '9189ce27b54eb3005374832593c74abe758f098e4e88ce9836c7d21c30ad794ec65dcab0cb2b066b2f5af93baf5a9233a12d994e934db6477bd5fb30e7a759ec825bbb5d52b7d02e177f93bbf0a23285e9ca6f83b20da54187294a73e43a138c12bbd54e03f3b0e7c8765a5a092b110c1193151a8ab7c210861c7db8a6c4bd6ec4a840ae20fef1367ea42018e5258d9c81b83b2c03ffd344ff09056817e463c44bd4504d2923704bc3eb945d7502ac48886ad3bdeafe3827bed71b7715258bc8a9b9fa6fdf1cfab57f5fbf4e4a429651cde13dc67b690cfd9074f384e7203a22ab29168996d3bf89c919031ff8e757af3676db2b0775f1375910844aefed1d29',
);
const SPKI = hexToBytes(
  '30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100b2a9ec6c63bbdecfe5665f484756a99b7938cceaee171972d58128f1285af7525f1a374ace320d0dc071bf1aa2be300a3874abce3a63761cf450f07c9d21e8fb68513d739ac978f977a173f006210696d762c28b657209a4e458476ab034e67881a0098f9fcbc62aa563ab2ee7ac92b14d97c870b500e54aaeaae705ab9c29e05d040fd067fc03b79aba6cbbfa89f167d445daa1a73730143b1e510439a628346279e6d30bfdbba898d72333b9f13343f6246bcb7d2ca83366f5bf70cd72cb1e13a1daa793ce8a40d966235d34925ad8e2b67d70fe91d8278f84c8f89b271663c6e44e5eae2f8879eab42425de39bd81c71730c7f4cc969e81c0dee81bacd5490203010001',
);
const KEY_ID = 'ad4229a4eea9ada97d55c227b90f95c33b021890b8a7c2a52312062f12d55809';

const NONCE = new Uint8Array(32).fill(0x11);
const CHALLENGE_DIGEST = new Uint8Array(32).fill(0x22);
const BLIND = 12345678901234567890123456789n; // fixed, coprime to n

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

describe('TokenChallenge (RFC 9577) cross-impl digest', () => {
  it('reproduces the Rust TokenChallenge serialization and digest', () => {
    // From warrenguard-token `TokenChallenge::for_epoch("issuer.warren.test",
    // "warren/token/epoch", 42)`.
    const ser = serializeTokenChallenge({
      issuerName: 'issuer.warren.test',
      redemptionContext: hexToBytes(
        '55d9c0ffa1b40a95dda4ddf3ee7f76a57c97fb23099d655dd5caa517f0ca395e',
      ),
    });
    expect(bytesToHex(ser)).toBe(
      '000200126973737565722e77617272656e2e746573742055d9c0ffa1b40a95dda4ddf3ee7f76a57c97fb23099d655dd5caa517f0ca395e0000',
    );
    const digest = challengeDigestForEpoch('issuer.warren.test', 'warren/token/epoch', 42n);
    expect(bytesToHex(digest)).toBe(
      '213e39eb48adda418612d64147c3d6c4a50a4e0ab6ab51db4e1be4ec45876ac9',
    );
  });
});

describe('blind-RSA Privacy Pass token client (cross-impl vector)', () => {
  it('mints a token whose key id and structure match the Rust issuer', () => {
    const pk = issuerPublicKey(N, E, SPKI);
    expect(bytesToHex(pk.keyId)).toBe(KEY_ID);

    // Client: blind the token pre-image (fixed nonce + blind for determinism).
    const { blindedRequest, state } = blindToken(pk, CHALLENGE_DIGEST, {
      nonce: NONCE,
      blind: BLIND,
      salt: new Uint8Array(48).fill(0x33),
    });
    expect(blindedRequest.length).toBe(256);

    // Issuer (test-only): blind_sign = blinded^d mod n.
    const n = os2ip(N);
    const d = os2ip(D);
    const blindSig = i2osp(modPow(os2ip(blindedRequest), d, n), 256);

    // Client: finalize -> a verified token; finalizeToken throws if the
    // unblinded RSASSA-PSS signature does not verify, so reaching here proves
    // the PSS + unblinding path is internally correct.
    const token = finalizeToken(pk, blindSig, state);
    const serialized = token.serialize();
    expect(serialized.length).toBe(354);
    expect(serialized[0]).toBe(0x00);
    expect(serialized[1]).toBe(0x02); // token_type prefix

    // This exact serialization is frozen and verified by the Rust
    // `edge_js_token_vector.rs` cross-test (verify_token accepts it).
    expect(bytesToHex(serialized)).toBe(
      '000211111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222ad4229a4eea9ada97d55c227b90f95c33b021890b8a7c2a52312062f12d558099ff7115e1a0cf3b83bf39d5fcf666b1f5e90cf578ff219b2b7c4a689282bbac5f855ccd5e34cdddaa586a7aa89ac68112d279ff57350ac30e0ff2c4279a5715c5f745b556813357c0be6c1470f21f9b2e7cbb5accc9ed3fe63a5cb9728827c5380b40571cb4f462c48fa9697d6dd5ede530dbab8a829cebcfe28227d0ff96eb4a4ae8a16258aee285bdd924d6c63080175c32ecdd988586434789902871da04aabde21d851015ca9c10b2231931d5bfc97f40b4c8a8d3c54814ca279c1c4202806f254e94faaa67e4325097d3817029631c0364ee3a19576f7c8c238b90e9fb21b6c308292564a471e97c1db709d731a5ed8cdc577f0782c45692abce6542c9c',
    );
  });
});

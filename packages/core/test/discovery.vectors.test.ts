import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { WarrenDiscoveryError, isExpired, verifySignedRelayList } from '../src/index.js';

const vectorsPath = fileURLToPath(new URL('../../../vectors/relays.json', import.meta.url));
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const SIGNED_JSON: string = vector.signed_json;
const PUBKEY: string = vector.server_pubkey_hex;

describe('verifySignedRelayList golden vector', () => {
  it('verifies the frozen list against the pinned pubkey and resolves the node', () => {
    const verified = verifySignedRelayList(SIGNED_JSON, [PUBKEY]);
    const e = vector.expected;

    expect(verified.generation).toBe(e.generation);
    expect(verified.signedAt).toBe(e.signed_at);
    expect(verified.expiresAt).toBe(e.expires_at);
    expect(verified.relays).toHaveLength(e.relay_count);

    const relay = verified.relays[0]!;
    const exp = e.relays[0];
    expect(relay.endpointIdHex).toBe(exp.endpoint_id_hex);
    expect(relay.exitIdHex).toBe(exp.exit_id_hex);
    expect(relay.country).toBe(exp.country);
    expect(relay.city).toBe(exp.city);
    expect(relay.weight).toBe(exp.weight);
    expect(relay.ipv6Egress).toBe(exp.ipv6_egress);
    expect(relay.addrs).toEqual(exp.addrs);
  });

  it('verifies without a pin (trust on first use)', () => {
    expect(verifySignedRelayList(SIGNED_JSON).relays).toHaveLength(1);
  });
});

describe('verifySignedRelayList rejections', () => {
  it('rejects an unpinned signer', () => {
    const err = catchError(() => verifySignedRelayList(SIGNED_JSON, ['00'.repeat(32)]));
    expect(err).toBeInstanceOf(WarrenDiscoveryError);
    expect((err as WarrenDiscoveryError).code).toBe('server_pubkey_mismatch');
  });

  it('rejects a tampered payload (bad signature)', () => {
    const tampered = SIGNED_JSON.replace('"weight":100', '"weight":101');
    const err = catchError(() => verifySignedRelayList(tampered, [PUBKEY]));
    expect((err as WarrenDiscoveryError).code).toBe('bad_signature');
  });

  it('rejects an unknown field (deny_unknown_fields)', () => {
    const withExtra = SIGNED_JSON.replace('"version":10', '"version":10,"rogue":1');
    const err = catchError(() => verifySignedRelayList(withExtra, [PUBKEY]));
    expect((err as WarrenDiscoveryError).code).toBe('json');
  });

  it('rejects an unsupported version', () => {
    // Re-sign-independent: version is checked before the signature. The
    // previous v9 list must be rejected since the bump to v10.
    const v9 = SIGNED_JSON.replace('"version":10', '"version":9');
    const err = catchError(() => verifySignedRelayList(v9, [PUBKEY]));
    expect((err as WarrenDiscoveryError).code).toBe('unsupported_version');
  });

  it('does not leak the pubkey in the mismatch error message', () => {
    const err = catchError(() => verifySignedRelayList(SIGNED_JSON, ['00'.repeat(32)]));
    expect((err as Error).message).not.toContain(PUBKEY);
  });
});

describe('isExpired', () => {
  it('compares now against expires_at', () => {
    const verified = verifySignedRelayList(SIGNED_JSON, [PUBKEY]);
    expect(isExpired(verified, verified.expiresAt - 1)).toBe(false);
    expect(isExpired(verified, verified.expiresAt)).toBe(true);
  });
});

function catchError(fn: () => unknown): unknown {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error('expected the call to throw');
}

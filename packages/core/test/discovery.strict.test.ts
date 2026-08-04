import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import { type WarrenDiscoveryError, encodeAddress, verifySignedRelayList } from '../src/index.js';

/**
 * Strict-verification cases the golden vector cannot pin: the vector carries
 * one well-formed node signed by a canonical key, so encoding-acceptance
 * divergences from the Rust verifier (ed25519-dalek: cofactorless, canonical
 * encodings only) need locally minted fixtures.
 */

const SERVER_SEED = new Uint8Array(32).fill(9);
const SERVER_PUB = bytesToHex(ed25519.getPublicKey(SERVER_SEED));

/**
 * The Ed25519 identity point in its non-canonical encoding (y = p + 1).
 * ZIP215 verifiers decode it (mod p) and accept a zero signature over any
 * message; RFC8032-strict verifiers (the Rust engine) reject the encoding.
 */
const NONCANONICAL_IDENTITY = `ee${'ff'.repeat(30)}7f`;
const CANONICAL_IDENTITY = `01${'00'.repeat(31)}`;

// biome-ignore lint/suspicious/noExplicitAny: freely-mutable wire objects for minting fixtures.
function mintList(nodes: any[], overrides: Record<string, unknown> = {}): string {
  const unsigned = {
    version: 10,
    nodes,
    generation: 1,
    signed_at: 1000,
    expires_at: 1000 + 3600,
    server_pubkey_hex: SERVER_PUB,
    ...overrides,
  };
  const signatureHex = bytesToHex(ed25519.sign(utf8ToBytes(JSON.stringify(unsigned)), SERVER_SEED));
  return JSON.stringify({ ...unsigned, signature_hex: signatureHex });
}

// biome-ignore lint/suspicious/noExplicitAny: wire node object.
function wireNode(addr: string, weight = 100): any {
  return {
    id: 'ab'.repeat(32),
    exit_id: 'cd'.repeat(16),
    location: { country: 'RO', city: 'City' },
    weight,
    active: true,
    egress: { ipv4: true, ipv6: false },
    endpoints: [
      { addr, family: 'ipv4', listeners: [{ port: 443, transport: 'quic', alpn: 'h3' }] },
    ],
  };
}

function expectError(fn: () => unknown): WarrenDiscoveryError {
  try {
    fn();
  } catch (e) {
    return e as WarrenDiscoveryError;
  }
  throw new Error('expected a throw');
}

describe('verifySignedRelayList strict encoding checks', () => {
  it('accepts a locally minted canonical list (fixture sanity)', () => {
    const verified = verifySignedRelayList(mintList([wireNode('198.51.100.1')]));
    expect(verified.relays).toHaveLength(1);
    expect(verified.relays[0]!.addrs).toEqual(['198.51.100.1:443']);
  });

  it('rejects a ZIP215-only signature (non-canonical identity pubkey, zero sig)', () => {
    const forged = JSON.parse(mintList([]));
    forged.server_pubkey_hex = NONCANONICAL_IDENTITY;
    forged.signature_hex = CANONICAL_IDENTITY + '00'.repeat(32);
    const err = expectError(() => verifySignedRelayList(JSON.stringify(forged)));
    expect(['bad_signature', 'pubkey_not_on_curve']).toContain(err.code);
  });

  it('rejects a ZIP215-only signature (non-canonical R)', () => {
    const forged = JSON.parse(mintList([]));
    forged.server_pubkey_hex = CANONICAL_IDENTITY;
    forged.signature_hex = NONCANONICAL_IDENTITY + '00'.repeat(32);
    const err = expectError(() => verifySignedRelayList(JSON.stringify(forged)));
    expect(['bad_signature', 'pubkey_not_on_curve']).toContain(err.code);
  });

  it('rejects an IPv4 endpoint with leading-zero octets like the Rust parser', () => {
    const err = expectError(() => verifySignedRelayList(mintList([wireNode('001.2.3.4')])));
    expect(err.code).toBe('invalid_endpoint_address');
  });

  it('rejects a validity window above the 7-day cap', () => {
    const json = mintList([], { signed_at: 1000, expires_at: 1000 + 8 * 24 * 60 * 60 });
    expect(expectError(() => verifySignedRelayList(json)).code).toBe('validity_too_long');
  });

  it('rejects a non-hex server pubkey with invalid_hex', () => {
    const forged = JSON.parse(mintList([]));
    forged.server_pubkey_hex = 'zz'.repeat(32);
    expect(expectError(() => verifySignedRelayList(JSON.stringify(forged))).code).toBe(
      'invalid_hex',
    );
  });

  it('rejects a wrong-length pubkey or signature with invalid_hex', () => {
    const shortKey = JSON.parse(mintList([]));
    shortKey.server_pubkey_hex = 'ab';
    expect(expectError(() => verifySignedRelayList(JSON.stringify(shortKey))).code).toBe(
      'invalid_hex',
    );
    const shortSig = JSON.parse(mintList([]));
    shortSig.signature_hex = 'ab';
    expect(expectError(() => verifySignedRelayList(JSON.stringify(shortSig))).code).toBe(
      'invalid_hex',
    );
  });

  it('rejects a node id that is neither hex nor a valid address', () => {
    const badNode = wireNode('198.51.100.1');
    badNode.id = 'not-hex-not-an-address';
    const err = expectError(() => verifySignedRelayList(mintList([badNode])));
    expect(err.code).toBe('invalid_node_id');
  });

  it('rejects a non-32-hex exit id', () => {
    const badNode = wireNode('198.51.100.1');
    badNode.exit_id = 'xyz';
    expect(expectError(() => verifySignedRelayList(mintList([badNode]))).code).toBe(
      'invalid_node_id',
    );
  });

  it('resolves an SS58 node id to its pubkey hex', () => {
    const pub = new Uint8Array(32).fill(5);
    const ssNode = wireNode('198.51.100.1');
    ssNode.id = encodeAddress(pub);
    const verified = verifySignedRelayList(mintList([ssNode]));
    expect(verified.relays[0]!.endpointIdHex).toBe(bytesToHex(pub));
  });

  it('brackets IPv6 endpoint addresses and keeps only QUIC listeners', () => {
    const v6Node = wireNode('198.51.100.1');
    v6Node.egress = { ipv4: false, ipv6: true };
    v6Node.endpoints = [
      {
        addr: '2001:db8::1',
        family: 'ipv6',
        listeners: [
          { port: 443, transport: 'quic', alpn: 'h3' },
          { port: 8080, transport: 'tcp', alpn: 'http/1.1' },
        ],
      },
    ];
    const verified = verifySignedRelayList(mintList([v6Node]));
    expect(verified.relays[0]!.addrs).toEqual(['[2001:db8::1]:443']);
    expect(verified.relays[0]!.hasIpv6).toBe(true);
  });

  it('passes cover_domain through to the resolved relay', () => {
    const covered = wireNode('198.51.100.1');
    covered.cover_domain = 'cdn.example.com';
    const verified = verifySignedRelayList(mintList([covered]));
    expect(verified.relays[0]!.coverDomain).toBe('cdn.example.com');
  });

  it('rejects an integer field above Number.MAX_SAFE_INTEGER with a json error', () => {
    // A genuine huge u64 loses precision at JSON.parse, so the canonical
    // re-serialization silently diverges from serde; fail it as malformed
    // input instead of a misleading bad_signature.
    const err = expectError(() =>
      verifySignedRelayList(mintList([wireNode('198.51.100.1', 1e20)])),
    );
    expect(err.code).toBe('json');
  });
});

import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  type WarrenDirectoryError,
  isDirectoryExpired,
  verifyMultihopDirectory,
} from '../src/index.js';

// PKI contexts duplicated from the module: the happy-path test cross-checks that
// these match (a drift would fail every operational signature).
const ROOT_OP = utf8ToBytes('warren/multihop/v1/root-signs-operational');
const EXIT_V1 = utf8ToBytes('warren/multihop/v1/operational-signs-exit');
const EXIT_V2 = utf8ToBytes('warren/multihop/v2/operational-signs-exit');
const EXIT_PQ = utf8ToBytes('warren/multihop/v2/operational-signs-exit-pq');
const RELAY_V1 = utf8ToBytes('warren/multihop/v1/operational-signs-relay');
const NODE_V1 = utf8ToBytes('warren/multihop/v1/operational-signs-node');

const seed = (b: number): Uint8Array => new Uint8Array(32).fill(b);
const fill = (n: number, b: number): Uint8Array => new Uint8Array(n).fill(b);
const pub = (s: Uint8Array): string => bytesToHex(ed25519.getPublicKey(s));
const sign = (s: Uint8Array, ...parts: Uint8Array[]): string =>
  bytesToHex(ed25519.sign(concatBytes(...parts), s));
function asnBe(asn: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, asn, false);
  return out;
}

interface NodeOpts {
  dnsDisabled?: boolean;
  variant?: 'v1' | 'v2' | 'pq';
  exitSignSeed?: Uint8Array;
  attestationSeed?: Uint8Array;
  badRelaySig?: boolean;
  edgeCertSha256?: string;
  /** Attached to the wire; the 'pq' variant signs over it. */
  mlkemEkHex?: string;
  /** v10 TLS-over-TCP carrier flag on the relay descriptor (after cover_domain). */
  relayTcpFallback?: boolean;
  /** The exit's cover domain, the name a browser proxy dials and validates. */
  coverDomain?: string;
  /** The relay's second address family (`/v2` route), after `endpoint`. */
  relayEndpointV6?: string;
  /** The relay's X.509 cover-domain SNI, after `endpoint_v6`. */
  relayCoverDomain?: string;
}

// biome-ignore lint/suspicious/noExplicitAny: a freely-mutable wire object for minting test fixtures.
function node(op: Uint8Array, tag: number, country: string, asn: number, o: NodeOpts = {}): any {
  const relayId = fill(16, tag);
  const relayEd = fill(32, tag + 1);
  const exitId = fill(16, tag + 2);
  const exitEd = fill(32, tag + 3);
  const exitX = fill(32, tag + 4);
  const endpoint = `198.51.100.${tag}:443`;
  const dns = o.dnsDisabled ?? false;
  const exitSeed = o.exitSignSeed ?? op;
  const attSeed = o.attestationSeed ?? op;
  const exitSig =
    o.variant === 'pq'
      ? sign(
          exitSeed,
          EXIT_PQ,
          exitId,
          exitX,
          Uint8Array.of(dns ? 1 : 0),
          hexToBytes(o.mlkemEkHex ?? ''),
        )
      : o.variant === 'v1'
        ? sign(exitSeed, EXIT_V1, exitId, exitX)
        : sign(exitSeed, EXIT_V2, exitId, exitX, Uint8Array.of(dns ? 1 : 0));
  const exit: Record<string, unknown> = {
    exit_id: bytesToHex(exitId),
    exit_ed25519_pubkey: bytesToHex(exitEd),
    exit_x25519_multihop_pubkey: bytesToHex(exitX),
    endpoint,
    // Frozen between endpoint and signature, matching the Rust serde order.
    ...(o.coverDomain !== undefined ? { cover_domain: o.coverDomain } : {}),
    signature: exitSig,
  };
  if (dns) exit.dns_disabled = true;
  // Frozen after dns_disabled, matching the Rust serde declaration order.
  if (o.mlkemEkHex !== undefined) exit.exit_mlkem768_pubkey = o.mlkemEkHex;
  // biome-ignore lint/suspicious/noExplicitAny: mutable wire relay fixture.
  const relay: any = {
    relay_id: bytesToHex(relayId),
    relay_ed25519_pubkey: bytesToHex(relayEd),
    endpoint,
  };
  // Frozen in the Rust serde declaration order: endpoint, endpoint_v6,
  // cover_domain, tcp_fallback, signature; each skipped when absent.
  if (o.relayEndpointV6 !== undefined) relay.endpoint_v6 = o.relayEndpointV6;
  if (o.relayCoverDomain !== undefined) relay.cover_domain = o.relayCoverDomain;
  if (o.relayTcpFallback) relay.tcp_fallback = true;
  relay.signature = o.badRelaySig ? '00'.repeat(64) : sign(op, RELAY_V1, relayId, relayEd);
  // biome-ignore lint/suspicious/noExplicitAny: mutable wire node fixture.
  const n: any = {
    relay,
    exit,
    country,
    city: 'City',
    asn,
    weight: 100,
    attestation_hex: sign(attSeed, NODE_V1, relayId, exitEd, asnBe(asn), utf8ToBytes(country)),
  };
  // Server-envelope tier, frozen last: only present when the node has an edge.
  if (o.edgeCertSha256 !== undefined) n.edge_cert_sha256 = o.edgeCertSha256;
  return n;
}

interface MintOpts {
  generation?: number;
  signedAt?: number;
  expiresAt?: number;
}

function mint(
  root: Uint8Array,
  op: Uint8Array,
  server: Uint8Array,
  // biome-ignore lint/suspicious/noExplicitAny: wire node objects.
  nodes: any[],
  o: MintOpts = {},
): string {
  const opPubHex = pub(op);
  const unsigned = {
    version: 2,
    nodes,
    generation: o.generation ?? 1,
    signed_at: o.signedAt ?? 1000,
    expires_at: o.expiresAt ?? 1000 + 3600,
    operational_pubkey_hex: opPubHex,
    operational_cert_hex: sign(root, ROOT_OP, hexToBytes(opPubHex)),
    server_pubkey_hex: pub(server),
  };
  const signatureHex = bytesToHex(ed25519.sign(utf8ToBytes(JSON.stringify(unsigned)), server));
  return JSON.stringify({ ...unsigned, signature_hex: signatureHex });
}

const ROOT = seed(1);
const OP = seed(2);
const SERVER = seed(3);
const serverPin = pub(SERVER);
const rootPin = pub(ROOT);

function expectError(fn: () => unknown): WarrenDirectoryError {
  try {
    fn();
  } catch (e) {
    return e as WarrenDirectoryError;
  }
  throw new Error('expected a throw');
}

describe('verifyMultihopDirectory happy path', () => {
  it('returns every fully-vouched exit', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100), node(OP, 20, 'NL', 200)]);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits).toHaveLength(2);
    expect(dir.dropped).toBe(0);
    expect(dir.exits[0]!.country).toBe('RO');
    expect(dir.exits[0]!.endpoint).toBe('198.51.100.10:443');
  });

  it('surfaces an attested dns_disabled=true', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { dnsDisabled: true })]);
    expect(json).toContain('"dns_disabled":true');
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits[0]!.dnsDisabled).toBe(true);
  });

  it('expiry boundary', () => {
    const dir = verifyMultihopDirectory(mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]), [
      serverPin,
    ]);
    expect(isDirectoryExpired(dir, dir.expiresAt - 1)).toBe(false);
    expect(isDirectoryExpired(dir, dir.expiresAt)).toBe(true);
  });
});

describe('verifyMultihopDirectory rejections', () => {
  it('rejects an unpinned server key', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);
    expect(expectError(() => verifyMultihopDirectory(json, ['00'.repeat(32)])).code).toBe(
      'server_pubkey_mismatch',
    );
  });

  it('accepts an unpinned directory on first use (TOFU) when no pins are given', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);
    const dir = verifyMultihopDirectory(json);
    expect(dir.exits).toHaveLength(1);
  });

  it('rejects a non-hex envelope signature with invalid_hex', () => {
    const forged = JSON.parse(mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]));
    forged.signature_hex = 'zz'.repeat(64);
    expect(expectError(() => verifyMultihopDirectory(JSON.stringify(forged))).code).toBe(
      'invalid_hex',
    );
  });

  it('rejects a ZIP215-only envelope signature (non-canonical R encoding)', () => {
    // Server pubkey = the identity point (canonical, decodes fine), envelope
    // R = the identity in its non-canonical y = p + 1 encoding, s = 0. That
    // verifies under ZIP215 for any message; ed25519-dalek (the engine)
    // rejects the encoding, so the strict verifier must too.
    const forged = JSON.parse(mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]));
    forged.server_pubkey_hex = `01${'00'.repeat(31)}`;
    forged.signature_hex = `ee${'ff'.repeat(30)}7f${'00'.repeat(32)}`;
    expect(expectError(() => verifyMultihopDirectory(JSON.stringify(forged))).code).toBe(
      'bad_envelope_signature',
    );
  });

  it('rejects an unsupported version', () => {
    const json = mint(ROOT, OP, SERVER, []).replace('"version":2', '"version":1');
    expect(expectError(() => verifyMultihopDirectory(json, [serverPin])).code).toBe(
      'unsupported_version',
    );
  });

  it('rejects a too-long validity window', () => {
    const json = mint(ROOT, OP, SERVER, [], { expiresAt: 1000 + 7 * 24 * 60 * 60 + 1 });
    expect(expectError(() => verifyMultihopDirectory(json, [serverPin])).code).toBe(
      'validity_too_long',
    );
  });

  it('rejects a tampered envelope', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]).replace('"City"', '"Citx"');
    expect(expectError(() => verifyMultihopDirectory(json, [serverPin])).code).toBe(
      'bad_envelope_signature',
    );
  });

  it('rejects an unknown top-level field', () => {
    const json = mint(ROOT, OP, SERVER, []).replace('{', '{"surprise":true,');
    expect(expectError(() => verifyMultihopDirectory(json, [serverPin])).code).toBe('json');
  });

  it('rejects a bad operational certificate against a pinned root', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);
    expect(expectError(() => verifyMultihopDirectory(json, [serverPin], [pub(seed(9))])).code).toBe(
      'bad_operational_cert',
    );
  });
});

describe('verifyMultihopDirectory drops un-vouched nodes', () => {
  it('drops a node whose exit descriptor is forged', () => {
    const json = mint(ROOT, OP, SERVER, [
      node(OP, 10, 'RO', 100),
      node(OP, 20, 'NL', 200, { exitSignSeed: seed(99) }),
    ]);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits).toHaveLength(1);
    expect(dir.dropped).toBe(1);
    expect(dir.exits[0]!.country).toBe('RO');
  });

  it('drops a node with a forged attestation', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { attestationSeed: seed(99) })]);
    expect(verifyMultihopDirectory(json, [serverPin]).exits).toHaveLength(0);
  });

  it('drops a node whose country was relabeled after attestation', () => {
    const n = node(OP, 10, 'RO', 100);
    n.country = 'DE';
    expect(verifyMultihopDirectory(mint(ROOT, OP, SERVER, [n]), [serverPin]).exits).toHaveLength(0);
  });

  it('drops a node with a forged relay descriptor', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { badRelaySig: true })]);
    expect(verifyMultihopDirectory(json, [serverPin]).exits).toHaveLength(0);
  });

  it('accepts a legacy v1 descriptor with dns_disabled=false but drops a v1 dns_disabled=true', () => {
    const ok = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { variant: 'v1' })]);
    expect(verifyMultihopDirectory(ok, [serverPin]).exits[0]!.dnsDisabled).toBe(false);

    const downgrade = mint(ROOT, OP, SERVER, [
      node(OP, 20, 'NL', 200, { variant: 'v1', dnsDisabled: true }),
    ]);
    expect(verifyMultihopDirectory(downgrade, [serverPin]).exits).toHaveLength(0);
  });
});

describe('verifyMultihopDirectory post-quantum descriptors', () => {
  const ek = 'e1'.repeat(1184);

  it('verifies a directory carrying exit_mlkem768_pubkey (frozen last in the envelope preimage)', () => {
    // The key rides the signed canonical bytes: the verifier must model it and
    // reproduce it after dns_disabled, or the envelope check fails.
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { mlkemEkHex: ek })]);
    expect(json).toContain(`"exit_mlkem768_pubkey":"${ek}"`);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits).toHaveLength(1);
  });

  it('vouches a PQ-signed exit descriptor and surfaces the signed ML-KEM key', () => {
    const json = mint(ROOT, OP, SERVER, [
      node(OP, 10, 'RO', 100, { variant: 'pq', mlkemEkHex: ek }),
      node(OP, 20, 'NL', 200),
    ]);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.dropped).toBe(0);
    const pq = dir.exits.find((e) => e.country === 'RO');
    const classical = dir.exits.find((e) => e.country === 'NL');
    expect(pq?.exitMlkem768PubkeyHex).toBe(ek);
    expect(classical?.exitMlkem768PubkeyHex).toBeUndefined();
  });

  it('never surfaces a key a classical signature merely transported (anti-downgrade)', () => {
    // The v2 signature does not cover the key, so the node stays classically
    // vouched, but the unbound key must not become usable PQ material.
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { mlkemEkHex: ek })]);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits).toHaveLength(1);
    expect(dir.exits[0]!.exitMlkem768PubkeyHex).toBeUndefined();
  });

  it('drops a PQ-signed descriptor whose ML-KEM key has the wrong length', () => {
    // Honestly signed over a 100-byte key: the length gate rejects it before
    // any signature question, and no classical context can rescue a
    // PQ-context signature.
    const shortEk = 'ab'.repeat(100);
    const json = mint(ROOT, OP, SERVER, [
      node(OP, 10, 'RO', 100, { variant: 'pq', mlkemEkHex: shortEk }),
    ]);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits).toHaveLength(0);
    expect(dir.dropped).toBe(1);
  });

  it('keeps a PQ-signed dns_disabled=true exit (the bit is PQ-attested)', () => {
    // Unlike the unattested /v1 case, the PQ payload covers the dns byte, so
    // advertising dns_disabled=true is trustworthy, not a downgrade suspect.
    const json = mint(ROOT, OP, SERVER, [
      node(OP, 10, 'RO', 100, { variant: 'pq', mlkemEkHex: ek, dnsDisabled: true }),
    ]);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits).toHaveLength(1);
    expect(dir.exits[0]!.dnsDisabled).toBe(true);
    expect(dir.exits[0]!.exitMlkem768PubkeyHex).toBe(ek);
  });
});

describe('verifyMultihopDirectory edge cert pin (server-envelope tier)', () => {
  const pin = 'ab'.repeat(32);

  it('an edge-less directory stays byte-identical to the pre-edge wire', () => {
    // The additive field must never appear when absent, so existing v2 clients
    // see identical bytes and no directory-version rotation is needed.
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);
    expect(json).not.toContain('edge_cert_sha256');
    expect(verifyMultihopDirectory(json, [serverPin], [rootPin]).exits).toHaveLength(1);
  });

  it('verifies a directory carrying an edge cert and surfaces it on the exit', () => {
    // Signed over the canonical preimage: the verifier must reproduce the field
    // in its frozen last position for the envelope signature to check out.
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { edgeCertSha256: pin })]);
    expect(json).toContain(`"edge_cert_sha256":"${pin}"`);
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits[0]!.edgeCertSha256).toBe(pin);
  });

  it('rejects a swapped edge cert pin (proves it is inside the server envelope)', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { edgeCertSha256: pin })]);
    const tampered = json.replace(pin, 'cd'.repeat(32));
    expect(expectError(() => verifyMultihopDirectory(tampered, [serverPin])).code).toBe(
      'bad_envelope_signature',
    );
  });

  it('surfaces the exit cover domain, the name a browser proxy dials', () => {
    const json = mint(ROOT, OP, SERVER, [
      node(OP, 10, 'RO', 100, { coverDomain: 'ro1.edge.example.net' }),
    ]);

    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);

    expect(dir.exits[0]!.coverDomain).toBe('ro1.edge.example.net');
  });

  it('leaves the cover domain absent when the node publishes none', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);

    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);

    expect(dir.exits[0]!.coverDomain).toBeUndefined();
  });

  it('rejects a swapped cover domain (the browser would send its credential there)', () => {
    const json = mint(ROOT, OP, SERVER, [
      node(OP, 10, 'RO', 100, { coverDomain: 'ro1.edge.example.net' }),
    ]);
    const tampered = json.replace('ro1.edge.example.net', 'evil.example.net');

    expect(expectError(() => verifyMultihopDirectory(tampered, [serverPin])).code).toBe(
      'bad_envelope_signature',
    );
  });
});

describe('verifyMultihopDirectory relay tcp_fallback carrier capability', () => {
  it('a relay without tcp_fallback stays byte-identical to the pre-v10 wire', () => {
    // The additive flag must never appear when absent, so existing clients see
    // identical envelope bytes and no directory-version rotation is needed.
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);
    expect(json).not.toContain('tcp_fallback');
    expect(verifyMultihopDirectory(json, [serverPin], [rootPin]).exits).toHaveLength(1);
  });

  it('verifies a directory whose relay advertises tcp_fallback (frozen before signature)', () => {
    // The flag rides the signed canonical bytes: the verifier must reproduce it
    // after cover_domain and before the relay signature, or the envelope fails.
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100, { relayTcpFallback: true })]);
    expect(json).toContain('"tcp_fallback":true');
    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);
    expect(dir.exits).toHaveLength(1);
    expect(dir.dropped).toBe(0);
  });

  it('rejects a tcp_fallback injected after signing (proves it is inside the envelope)', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);
    // Inject after the relay endpoint (its first occurrence), a valid wire
    // position; the verifier reproduces it, so the canonical bytes diverge from
    // what was signed.
    const tampered = json.replace(
      '"endpoint":"198.51.100.10:443"',
      '"endpoint":"198.51.100.10:443","tcp_fallback":true',
    );
    expect(expectError(() => verifyMultihopDirectory(tampered, [serverPin])).code).toBe(
      'bad_envelope_signature',
    );
  });
});

describe('verifyMultihopDirectory relay endpoint_v6 (the /v2 route)', () => {
  const V6 = '[2001:db8::10]:443';

  it('verifies a relay carrying its second address family and surfaces it on the exit', () => {
    const json = mint(ROOT, OP, SERVER, [
      node(OP, 10, 'RO', 100, {
        relayEndpointV6: V6,
        relayCoverDomain: 'cover.example',
        relayTcpFallback: true,
      }),
    ]);

    const dir = verifyMultihopDirectory(json, [serverPin], [rootPin]);

    expect(dir.dropped).toBe(0);
    expect(dir.exits[0]?.endpoint).toBe('198.51.100.10:443');
    expect(dir.exits[0]?.endpointV6).toBe(V6);
  });

  it('leaves endpointV6 absent for a relay with a single address family', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);

    const exit = verifyMultihopDirectory(json, [serverPin], [rootPin]).exits[0];

    expect(exit).toBeDefined();
    expect(exit && 'endpointV6' in exit).toBe(false);
  });

  it('rejects an endpoint_v6 injected after signing (proves it is inside the envelope)', () => {
    const json = mint(ROOT, OP, SERVER, [node(OP, 10, 'RO', 100)]);
    const tampered = json.replace(
      '"endpoint":"198.51.100.10:443"',
      `"endpoint":"198.51.100.10:443","endpoint_v6":"${V6}"`,
    );

    expect(expectError(() => verifyMultihopDirectory(tampered, [serverPin])).code).toBe(
      'bad_envelope_signature',
    );
  });
});

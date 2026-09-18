import { ed25519 } from '@noble/curves/ed25519';
import { concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { verifyExitDescriptorPq } from '../edge/pq-descriptor.js';

/** Directory wire version this verifier accepts. */
export const MULTIHOP_DIRECTORY_VERSION = 2;
/** Maximum `expires_at - signed_at` window: 7 days (anti-freeze cap). */
const MAX_VALIDITY_SECS = 7 * 24 * 60 * 60;

// PKI domain-separation contexts (raw bytes, never JSON).
const ROOT_OPERATIONAL_V1 = utf8ToBytes('warren/multihop/v1/root-signs-operational');
const OPERATIONAL_EXIT_V1 = utf8ToBytes('warren/multihop/v1/operational-signs-exit');
const OPERATIONAL_EXIT_V2 = utf8ToBytes('warren/multihop/v2/operational-signs-exit');
const OPERATIONAL_RELAY_V1 = utf8ToBytes('warren/multihop/v1/operational-signs-relay');
const OPERATIONAL_NODE_V1 = utf8ToBytes('warren/multihop/v1/operational-signs-node');

/** Discriminator for {@link WarrenDirectoryError}, mirroring the Rust `DirectoryError`. */
export type WarrenDirectoryErrorCode =
  | 'json'
  | 'unsupported_version'
  | 'server_pubkey_mismatch'
  | 'invalid_hex'
  | 'bad_envelope_signature'
  | 'bad_operational_cert'
  | 'validity_too_long'
  | 'expired'
  | 'rolled_back';

/** An error from verifying the multi-hop directory. No identity material in the message. */
export class WarrenDirectoryError extends Error {
  readonly code: WarrenDirectoryErrorCode;
  constructor(code: WarrenDirectoryErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenDirectoryError';
    this.code = code;
  }
}

/** A verified exit usable as an HPKE recipient. */
export interface VerifiedExit {
  /** 32-char hex of the 16-byte exit id. */
  readonly exitIdHex: string;
  /** 64-char hex of the exit's Ed25519 identity (TLS RPK pin). PKI-bound via the attestation. */
  readonly exitEd25519PubkeyHex: string;
  /** 64-char hex of the exit's long-lived X25519 HPKE recipient key. */
  readonly exitX25519PubkeyHex: string;
  /** QUIC endpoint to dial (the entry-relay endpoint). */
  readonly endpoint: string;
  readonly country: string;
  readonly city: string;
  readonly weight: number;
  /** The exit runs no in-tunnel DNS forwarder. */
  readonly dnsDisabled: boolean;
  /** 64-char hex SHA-256 of the node's ephemeral EdgeConnect cert, for browser
   * `serverCertificateHashes` pinning of the WebTransport edge on the
   * well-known `WARREN_EDGE_PORT` (8443, see `../edge/well-known.js`). Absent
   * when the node has no edge. */
  readonly edgeCertSha256?: string;
  /** The node's public cover domain, the hostname a browser dials for the
   * CONNECT proxy tier and validates its certificate against. Carried by the
   * server-signed envelope, the same trust tier as {@link edgeCertSha256}: the
   * per-node exit signature does not cover it. Absent when the node publishes
   * no cover domain, in which case there is no name to point a browser at. */
  readonly coverDomain?: string;
  /** Lowercase hex of the exit's ML-KEM-768 recipient key (the X-Wing hybrid
   * seal half), present ONLY when the PQ operational signature bound it. A key
   * a classical signature merely transported is never surfaced: it would be
   * downgrade-forgeable PQ material. */
  readonly exitMlkem768PubkeyHex?: string;
}

/** A verified multi-hop directory: trusted exits plus freshness metadata. */
export interface VerifiedDirectory {
  readonly exits: readonly VerifiedExit[];
  readonly generation: number;
  readonly signedAt: number;
  readonly expiresAt: number;
  /** Nodes dropped because they were not fully vouched (diagnostics). */
  readonly dropped: number;
  /** The verified envelope signer (64-char lowercase hex), for TOFU pinning. */
  readonly serverPubkeyHex: string;
}

/** Returns whether the directory is expired at the given wall-clock time. */
export function isDirectoryExpired(dir: VerifiedDirectory, nowUnixSecs: number): boolean {
  return nowUnixSecs >= dir.expiresAt;
}

function failJson(message: string, cause?: unknown): never {
  throw new WarrenDirectoryError('json', message, cause !== undefined ? { cause } : undefined);
}

/** Validates an object's keys: every required present, extras only from `optional`. */
function asObject(
  v: unknown,
  required: readonly string[],
  optional: readonly string[],
  ctx: string,
): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) failJson(`${ctx} must be an object`);
  const record = v as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!required.includes(key) && !optional.includes(key)) {
      failJson(`unknown field "${key}" in ${ctx}`);
    }
  }
  for (const key of required) {
    if (!(key in record)) failJson(`missing field "${key}" in ${ctx}`);
  }
  return record;
}

function asArray(v: unknown, ctx: string): unknown[] {
  if (!Array.isArray(v)) failJson(`${ctx} must be an array`);
  return v;
}
function asString(v: unknown, ctx: string): string {
  if (typeof v !== 'string') failJson(`${ctx} must be a string`);
  return v;
}
function asU64(v: unknown, ctx: string): number {
  // Safe-integer bound: above 2^53 the value already lost precision at
  // JSON.parse and the canonical re-serialization would diverge from serde.
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) {
    failJson(`${ctx} must be a non-negative integer`);
  }
  return v;
}
function asBool(v: unknown, ctx: string): boolean {
  if (typeof v !== 'boolean') failJson(`${ctx} must be a boolean`);
  return v;
}
/** Validates a fixed-length lowercase-hex field (serde `hexn` errors on a bad length). */
function asFixedHex(v: unknown, bytes: number, ctx: string): string {
  const s = asString(v, ctx);
  if (!new RegExp(`^[0-9a-fA-F]{${bytes * 2}}$`).test(s))
    failJson(`${ctx} must be ${bytes}-byte hex`);
  return s.toLowerCase();
}
/** Validates a variable-length hex field (mirrors Rust `hex::decode`: even
 * length, hex digits; the byte-length policy is the verifier's, not the
 * parser's, so a wrong-length key drops one node instead of the directory). */
function asHex(v: unknown, ctx: string): string {
  const s = asString(v, ctx);
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) failJson(`${ctx} must be hex`);
  return s.toLowerCase();
}

/** A validated node, in canonical (frozen) field order. */
interface CanonicalNode {
  relay: {
    relay_id: string;
    relay_ed25519_pubkey: string;
    endpoint: string;
    // ADR-0004 X.509 cover-domain SNI; optional, outside the descriptor signature.
    cover_domain?: string;
    // TLS-over-TCP carrier capability; frozen after cover_domain, skipped when
    // absent/false, outside the descriptor signature.
    tcp_fallback?: boolean;
    signature: string;
  };
  exit: {
    exit_id: string;
    exit_ed25519_pubkey: string;
    exit_x25519_multihop_pubkey: string;
    endpoint?: string;
    cover_domain?: string;
    signature: string;
    dns_disabled?: boolean;
    exit_mlkem768_pubkey?: string;
  };
  country: string;
  city: string;
  asn: number;
  weight: number;
  attestation_hex: string;
  // Server-envelope-signed edge cert pin (64-char hex SHA-256), overlaid live by
  // warren-api; absent when the node advertises no edge. Frozen last, so an
  // edge-less directory stays byte-identical to the pre-edge wire.
  edge_cert_sha256?: string;
}

function validateNode(raw: unknown, i: number): CanonicalNode {
  const node = asObject(
    raw,
    ['relay', 'exit', 'country', 'city', 'weight', 'attestation_hex'],
    ['asn', 'edge_cert_sha256'],
    `nodes[${i}]`,
  );
  const relayRaw = asObject(
    node.relay,
    ['relay_id', 'relay_ed25519_pubkey', 'endpoint', 'signature'],
    ['cover_domain', 'tcp_fallback'],
    `nodes[${i}].relay`,
  );
  const exitRaw = asObject(
    node.exit,
    ['exit_id', 'exit_ed25519_pubkey', 'exit_x25519_multihop_pubkey', 'signature'],
    ['endpoint', 'cover_domain', 'dns_disabled', 'exit_mlkem768_pubkey'],
    `nodes[${i}].exit`,
  );

  const exit: CanonicalNode['exit'] = {
    exit_id: asFixedHex(exitRaw.exit_id, 16, 'exit_id'),
    exit_ed25519_pubkey: asFixedHex(exitRaw.exit_ed25519_pubkey, 32, 'exit_ed25519_pubkey'),
    exit_x25519_multihop_pubkey: asFixedHex(
      exitRaw.exit_x25519_multihop_pubkey,
      32,
      'exit_x25519_multihop_pubkey',
    ),
    // Optional fields keep their frozen wire positions: endpoint, then
    // cover_domain, between the x25519 key and the signature.
    ...(exitRaw.endpoint !== undefined
      ? { endpoint: asString(exitRaw.endpoint, 'exit.endpoint') }
      : {}),
    ...(exitRaw.cover_domain !== undefined
      ? { cover_domain: asString(exitRaw.cover_domain, 'exit.cover_domain') }
      : {}),
    signature: asFixedHex(exitRaw.signature, 64, 'exit.signature'),
    ...(exitRaw.dns_disabled !== undefined
      ? { dns_disabled: asBool(exitRaw.dns_disabled, 'dns_disabled') }
      : {}),
    ...(exitRaw.exit_mlkem768_pubkey !== undefined
      ? { exit_mlkem768_pubkey: asHex(exitRaw.exit_mlkem768_pubkey, 'exit_mlkem768_pubkey') }
      : {}),
  };

  return {
    relay: {
      relay_id: asFixedHex(relayRaw.relay_id, 16, 'relay_id'),
      relay_ed25519_pubkey: asFixedHex(relayRaw.relay_ed25519_pubkey, 32, 'relay_ed25519_pubkey'),
      endpoint: asString(relayRaw.endpoint, 'relay.endpoint'),
      ...(relayRaw.cover_domain !== undefined
        ? { cover_domain: asString(relayRaw.cover_domain, 'relay.cover_domain') }
        : {}),
      ...(relayRaw.tcp_fallback !== undefined
        ? { tcp_fallback: asBool(relayRaw.tcp_fallback, 'relay.tcp_fallback') }
        : {}),
      signature: asFixedHex(relayRaw.signature, 64, 'relay.signature'),
    },
    exit,
    country: asString(node.country, 'country'),
    city: asString(node.city, 'city'),
    asn: node.asn !== undefined ? asU64(node.asn, 'asn') : 0,
    weight: asU64(node.weight, 'weight'),
    attestation_hex: asString(node.attestation_hex, 'attestation_hex'),
    ...(node.edge_cert_sha256 !== undefined
      ? { edge_cert_sha256: asFixedHex(node.edge_cert_sha256, 32, 'edge_cert_sha256') }
      : {}),
  };
}

/** Re-serializes one node in canonical (frozen) order for the envelope preimage. */
function canonicalNode(n: CanonicalNode): unknown {
  const exit: Record<string, unknown> = {
    exit_id: n.exit.exit_id,
    exit_ed25519_pubkey: n.exit.exit_ed25519_pubkey,
    exit_x25519_multihop_pubkey: n.exit.exit_x25519_multihop_pubkey,
  };
  if (n.exit.endpoint !== undefined) exit.endpoint = n.exit.endpoint;
  if (n.exit.cover_domain !== undefined) exit.cover_domain = n.exit.cover_domain;
  exit.signature = n.exit.signature;
  if (n.exit.dns_disabled) exit.dns_disabled = true;
  // Frozen after dns_disabled (the Rust serde declaration order); absent on a
  // classical descriptor so its canonical form is unchanged.
  if (n.exit.exit_mlkem768_pubkey !== undefined)
    exit.exit_mlkem768_pubkey = n.exit.exit_mlkem768_pubkey;
  const relay: Record<string, unknown> = {
    relay_id: n.relay.relay_id,
    relay_ed25519_pubkey: n.relay.relay_ed25519_pubkey,
    endpoint: n.relay.endpoint,
  };
  if (n.relay.cover_domain !== undefined) relay.cover_domain = n.relay.cover_domain;
  // Frozen after cover_domain (the Rust serde declaration order); skip_serializing_if
  // is_false, so an absent/false capability re-serializes byte-identical.
  if (n.relay.tcp_fallback) relay.tcp_fallback = true;
  relay.signature = n.relay.signature;
  const out: Record<string, unknown> = {
    relay,
    exit,
    country: n.country,
    city: n.city,
    asn: n.asn,
    weight: n.weight,
    attestation_hex: n.attestation_hex,
  };
  // Frozen last (serde `skip_serializing_if`): only present when overlaid, so an
  // edge-less node re-serializes byte-identical to the pre-edge canonical form.
  if (n.edge_cert_sha256 !== undefined) out.edge_cert_sha256 = n.edge_cert_sha256;
  return out;
}

function pubkey(hex: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(hex);
  } catch (cause) {
    throw new WarrenDirectoryError('invalid_hex', 'invalid pubkey hex', { cause });
  }
  if (bytes.length !== 32) throw new WarrenDirectoryError('invalid_hex', 'pubkey must be 32 bytes');
  try {
    ed25519.ExtendedPoint.fromHex(bytes);
  } catch (cause) {
    throw new WarrenDirectoryError('invalid_hex', 'pubkey is not a valid Ed25519 point', { cause });
  }
  return bytes;
}

function sig64(hex: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(hex);
  } catch (cause) {
    throw new WarrenDirectoryError('invalid_hex', 'invalid signature hex', { cause });
  }
  if (bytes.length !== 64)
    throw new WarrenDirectoryError('invalid_hex', 'signature must be 64 bytes');
  return bytes;
}

/** Verifies `pub` signed `context || parts`. Returns false on any failure (never throws). */
function verifyParts(
  pub: Uint8Array,
  sigHex: string,
  context: Uint8Array,
  parts: Uint8Array[],
): boolean {
  let signature: Uint8Array;
  try {
    signature = hexToBytes(sigHex);
    if (signature.length !== 64) return false;
  } catch {
    return false;
  }
  try {
    // zip215: false matches the engine's ed25519-dalek verify (cofactorless,
    // canonical encodings only).
    return ed25519.verify(signature, concatBytes(context, ...parts), pub, { zip215: false });
  } catch {
    return false;
  }
}

function asnBe(asn: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, asn >>> 0, false);
  return out;
}

/** The operational-vouched view of one node: the effective `dns_disabled` plus
 * the ML-KEM key when (and only when) the PQ signature bound it. */
interface NodeVouch {
  dnsDisabled: boolean;
  exitMlkem768PubkeyHex?: string;
}

/** Returns the vouched node view, or null if the node is not fully vouched. */
function vouchNode(operational: Uint8Array, n: CanonicalNode): NodeVouch | null {
  const relayOk = verifyParts(operational, n.relay.signature, OPERATIONAL_RELAY_V1, [
    hexToBytes(n.relay.relay_id),
    hexToBytes(n.relay.relay_ed25519_pubkey),
  ]);
  if (!relayOk) return null;

  // The attestation is the only operational-key binding of exit_ed25519_pubkey
  // (the exit descriptor signs the x25519 key, not the RPK identity).
  const attestationOk = verifyParts(operational, n.attestation_hex, OPERATIONAL_NODE_V1, [
    hexToBytes(n.relay.relay_id),
    hexToBytes(n.exit.exit_ed25519_pubkey),
    asnBe(n.asn),
    utf8ToBytes(n.country),
  ]);
  if (!attestationOk) return null;

  const dnsDisabled = n.exit.dns_disabled ?? false;
  const exitId = hexToBytes(n.exit.exit_id);
  const exitX = hexToBytes(n.exit.exit_x25519_multihop_pubkey);

  // PQ first (mirrors the Rust client and the relay's any-version order): its
  // context binds both the ML-KEM key and the dns byte, so a PQ-verified exit
  // needs no further dns policy. On failure the classical contexts still get
  // their try, but the key stays unsurfaced (anti-downgrade).
  if (n.exit.exit_mlkem768_pubkey !== undefined) {
    try {
      verifyExitDescriptorPq(operational, {
        exitId,
        exitX25519MultihopPubkey: exitX,
        dnsDisabled,
        exitMlkem768Pubkey: hexToBytes(n.exit.exit_mlkem768_pubkey),
        signature: hexToBytes(n.exit.signature),
      });
      return { dnsDisabled, exitMlkem768PubkeyHex: n.exit.exit_mlkem768_pubkey };
    } catch {
      // Not PQ-bound; fall through to /v2 then /v1.
    }
  }

  // /v2 binds the dns byte under the signature; trustworthy.
  if (
    verifyParts(operational, n.exit.signature, OPERATIONAL_EXIT_V2, [
      exitId,
      exitX,
      Uint8Array.of(dnsDisabled ? 1 : 0),
    ])
  ) {
    return { dnsDisabled };
  }
  // Legacy /v1 does not cover the dns byte: a v1-only descriptor advertising
  // dns_disabled=true is a suspected downgrade and is dropped.
  if (verifyParts(operational, n.exit.signature, OPERATIONAL_EXIT_V1, [exitId, exitX])) {
    return dnsDisabled ? null : { dnsDisabled: false };
  }
  return null;
}

/**
 * Verifies the signed multi-hop directory (v2) and returns the trusted exits.
 *
 * Trust chain (all Ed25519): the pinned server key signs the canonical directory
 * envelope; the root key certifies the operational key; the operational key signs
 * each node's relay descriptor, exit descriptor, and geo+RPK attestation. A node
 * failing any of those is dropped (`dropped` counts them). Anti-rollback
 * (`generation`) and expiry ({@link isDirectoryExpired}) are caller-enforced.
 *
 * @param expectedServerPubkeys Pinned online server keys (empty = trust on first use).
 * @param expectedRootPubkeys Pinned offline root keys (empty = trust on first use).
 * @throws {WarrenDirectoryError}
 */
export function verifyMultihopDirectory(
  json: string,
  expectedServerPubkeys?: readonly string[],
  expectedRootPubkeys?: readonly string[],
): VerifiedDirectory {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (cause) {
    failJson('directory is not valid JSON', cause);
  }

  const top = asObject(
    parsed,
    [
      'version',
      'nodes',
      'generation',
      'signed_at',
      'expires_at',
      'operational_pubkey_hex',
      'operational_cert_hex',
      'server_pubkey_hex',
      'signature_hex',
    ],
    [],
    'directory',
  );

  const version = asU64(top.version, 'version');
  if (version !== MULTIHOP_DIRECTORY_VERSION) {
    throw new WarrenDirectoryError(
      'unsupported_version',
      `unsupported directory version ${version}`,
    );
  }

  const serverPubkeyHex = asString(top.server_pubkey_hex, 'server_pubkey_hex');
  const operationalPubkeyHex = asString(top.operational_pubkey_hex, 'operational_pubkey_hex');
  const operationalCertHex = asString(top.operational_cert_hex, 'operational_cert_hex');
  const signatureHex = asString(top.signature_hex, 'signature_hex');
  const generation = asU64(top.generation, 'generation');
  const signedAt = asU64(top.signed_at, 'signed_at');
  const expiresAt = asU64(top.expires_at, 'expires_at');
  const nodes = asArray(top.nodes, 'nodes').map(validateNode);

  if (expectedServerPubkeys && expectedServerPubkeys.length > 0) {
    const got = serverPubkeyHex.toLowerCase();
    if (!expectedServerPubkeys.some((p) => p.toLowerCase() === got)) {
      throw new WarrenDirectoryError(
        'server_pubkey_mismatch',
        'directory server pubkey not pinned',
      );
    }
  }

  // (1) server envelope over the canonical preimage (typed, frozen field order).
  const canonical = JSON.stringify({
    version,
    nodes: nodes.map(canonicalNode),
    generation,
    signed_at: signedAt,
    expires_at: expiresAt,
    operational_pubkey_hex: operationalPubkeyHex,
    operational_cert_hex: operationalCertHex,
    server_pubkey_hex: serverPubkeyHex,
  });
  const serverPubkey = pubkey(serverPubkeyHex);
  const envelopeSig = sig64(signatureHex);
  let envelopeOk: boolean;
  try {
    envelopeOk = ed25519.verify(envelopeSig, utf8ToBytes(canonical), serverPubkey, {
      zip215: false,
    });
  } catch (cause) {
    throw new WarrenDirectoryError('bad_envelope_signature', 'envelope signature failed', {
      cause,
    });
  }
  if (!envelopeOk) {
    throw new WarrenDirectoryError('bad_envelope_signature', 'envelope signature did not verify');
  }

  // Anti-freeze, checked only after the envelope verifies (authenticated fields).
  if (expiresAt - signedAt > MAX_VALIDITY_SECS) {
    throw new WarrenDirectoryError('validity_too_long', 'directory validity window exceeds 7 days');
  }

  // (2) operational certificate against the pinned root (empty = TOFU).
  const operational = pubkey(operationalPubkeyHex);
  if (expectedRootPubkeys && expectedRootPubkeys.length > 0) {
    const certOk = expectedRootPubkeys.some((rootHex) => {
      let root: Uint8Array;
      try {
        root = pubkey(rootHex);
      } catch {
        return false;
      }
      return verifyParts(root, operationalCertHex, ROOT_OPERATIONAL_V1, [operational]);
    });
    if (!certOk) {
      throw new WarrenDirectoryError('bad_operational_cert', 'operational certificate failed');
    }
  }

  // (3) every operational-signed part of each node; drop any not fully vouched.
  const exits: VerifiedExit[] = [];
  for (const n of nodes) {
    const vouch = vouchNode(operational, n);
    if (vouch === null) continue;
    exits.push({
      exitIdHex: n.exit.exit_id,
      exitEd25519PubkeyHex: n.exit.exit_ed25519_pubkey,
      exitX25519PubkeyHex: n.exit.exit_x25519_multihop_pubkey,
      // The client dials the entry relay, never the exit egress IP (redacted).
      endpoint: n.relay.endpoint,
      country: n.country,
      city: n.city,
      weight: n.weight,
      dnsDisabled: vouch.dnsDisabled,
      ...(n.edge_cert_sha256 !== undefined ? { edgeCertSha256: n.edge_cert_sha256 } : {}),
      ...(n.exit.cover_domain !== undefined ? { coverDomain: n.exit.cover_domain } : {}),
      ...(vouch.exitMlkem768PubkeyHex !== undefined
        ? { exitMlkem768PubkeyHex: vouch.exitMlkem768PubkeyHex }
        : {}),
    });
  }

  return {
    exits,
    generation,
    signedAt,
    expiresAt,
    dropped: nodes.length - exits.length,
    serverPubkeyHex: serverPubkeyHex.toLowerCase(),
  };
}

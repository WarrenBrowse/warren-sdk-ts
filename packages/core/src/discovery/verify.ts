import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { decodeAddress } from '../identity/ss58.js';
import { WarrenDiscoveryError } from './errors.js';
import type { Relay, VerifiedRelayList } from './relay.js';

/** The only supported signed-list version. */
export const SIGNED_VERSION = 10;
/** Maximum `expires_at - signed_at` window: 7 days, the anti-freeze cap. */
const MAX_VALIDITY_SECS = 7 * 24 * 60 * 60;

const HEX64 = /^[0-9a-f]{64}$/i;
const HEX32 = /^[0-9a-f]{32}$/i;

function fail(code: WarrenDiscoveryError['code'], message: string, cause?: unknown): never {
  throw new WarrenDiscoveryError(code, message, cause !== undefined ? { cause } : undefined);
}

/** Validates an object's keys exactly: every required key present, no extras (deny_unknown_fields). */
function asObject(
  v: unknown,
  keys: readonly string[],
  ctx: string,
  optionalKeys: readonly string[] = [],
): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    fail('json', `${ctx} must be an object`);
  }
  const record = v as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!keys.includes(key) && !optionalKeys.includes(key)) {
      fail('json', `unknown field "${key}" in ${ctx}`);
    }
  }
  // Required keys must all be present; optionalKeys may be absent (they are
  // skip_serializing_if fields like the v8 cover_domain).
  for (const key of keys) {
    if (!(key in record)) fail('json', `missing field "${key}" in ${ctx}`);
  }
  return record;
}

function asArray(v: unknown, ctx: string): unknown[] {
  if (!Array.isArray(v)) fail('json', `${ctx} must be an array`);
  return v;
}

function asString(v: unknown, ctx: string): string {
  if (typeof v !== 'string') fail('json', `${ctx} must be a string`);
  return v;
}

function asU64(v: unknown, ctx: string): number {
  // Safe-integer bound: a u64 above 2^53 already lost precision at JSON.parse,
  // so the canonical re-serialization would silently diverge from serde; fail
  // it as malformed input instead of a misleading bad_signature.
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) {
    fail('json', `${ctx} must be a non-negative integer`);
  }
  return v;
}

function asBool(v: unknown, ctx: string): boolean {
  if (typeof v !== 'boolean') fail('json', `${ctx} must be a boolean`);
  return v;
}

function isIpv4(s: string): boolean {
  const parts = s.split('.');
  // No leading zeros: Rust's IpAddr parser rejects them, and acceptance must
  // not diverge on signed data.
  return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

function isIpv6(s: string): boolean {
  if (!s.includes(':')) return false;
  try {
    // The URL parser validates bracketed IPv6 hosts and is isomorphic.
    new URL(`http://[${s}]/`);
    return true;
  } catch {
    return false;
  }
}

/** A validated node, kept in canonical field order for re-serialization. */
interface CanonicalNode {
  id: string;
  exit_id: string;
  location: { country: string; city: string };
  weight: number;
  active: boolean;
  egress: { ipv4: boolean; ipv6: boolean };
  endpoints: Array<{
    addr: string;
    family: string;
    listeners: Array<{ port: number; transport: string; alpn: string }>;
  }>;
  /** v6 X.509 cover-domain SNI (wg-0005); absent on RPK nodes. */
  cover_domain?: string;
  /** v9 per-node NAT-PMP port-forward capability; skipped when absent. */
  port_forward?: boolean;
  /** v10 per-node TLS-over-TCP carrier capability; last field, skipped when absent. */
  tcp_fallback?: boolean;
}

function validateNode(raw: unknown, index: number): CanonicalNode {
  const node = asObject(
    raw,
    ['id', 'exit_id', 'location', 'weight', 'active', 'egress', 'endpoints'],
    `nodes[${index}]`,
    ['cover_domain', 'port_forward', 'tcp_fallback'],
  );
  const location = asObject(node.location, ['country', 'city'], `nodes[${index}].location`);
  const egress = asObject(node.egress, ['ipv4', 'ipv6'], `nodes[${index}].egress`);
  const endpoints = asArray(node.endpoints, `nodes[${index}].endpoints`).map((ep, j) => {
    const endpoint = asObject(
      ep,
      ['addr', 'family', 'listeners'],
      `nodes[${index}].endpoints[${j}]`,
    );
    const listeners = asArray(endpoint.listeners, `nodes[${index}].endpoints[${j}].listeners`).map(
      (l, k) => {
        const listener = asObject(
          l,
          ['port', 'transport', 'alpn'],
          `nodes[${index}].endpoints[${j}].listeners[${k}]`,
        );
        return {
          port: asU64(listener.port, 'port'),
          transport: asString(listener.transport, 'transport'),
          alpn: asString(listener.alpn, 'alpn'),
        };
      },
    );
    return {
      addr: asString(endpoint.addr, 'addr'),
      family: asString(endpoint.family, 'family'),
      listeners,
    };
  });
  return {
    id: asString(node.id, 'id'),
    exit_id: asString(node.exit_id, 'exit_id'),
    location: {
      country: asString(location.country, 'country'),
      city: asString(location.city, 'city'),
    },
    weight: asU64(node.weight, 'weight'),
    active: asBool(node.active, 'active'),
    egress: { ipv4: asBool(egress.ipv4, 'ipv4'), ipv6: asBool(egress.ipv6, 'ipv6') },
    endpoints,
    ...(node.cover_domain === undefined
      ? {}
      : { cover_domain: asString(node.cover_domain, `nodes[${index}].cover_domain`) }),
    // v9: NAT-PMP port-forward capability, last field, skipped when absent.
    // Echo the input's presence so the canonical re-serialization matches the
    // signed bytes exactly (mirrors the cover_domain handling above).
    ...(node.port_forward === undefined
      ? {}
      : { port_forward: asBool(node.port_forward, `nodes[${index}].port_forward`) }),
    // v10: TLS-over-TCP carrier capability, appended after port_forward as the
    // last field, skipped when absent (same echo-presence pattern).
    ...(node.tcp_fallback === undefined
      ? {}
      : { tcp_fallback: asBool(node.tcp_fallback, `nodes[${index}].tcp_fallback`) }),
  };
}

/** Resolves a node into a dialable {@link Relay}, validating ids, addresses and families. */
function resolveRelay(node: CanonicalNode): Relay {
  const endpointIdHex = HEX64.test(node.id)
    ? node.id.toLowerCase()
    : ((): string => {
        try {
          return bytesToHex(decodeAddress(node.id));
        } catch (cause) {
          return fail('invalid_node_id', 'node id is neither hex nor a valid address', cause);
        }
      })();

  if (!HEX32.test(node.exit_id)) {
    fail('invalid_node_id', 'exit id is not 32-char hex');
  }

  let hasIpv4 = false;
  let hasIpv6 = false;
  const addrs: string[] = [];
  for (const ep of node.endpoints) {
    const v4 = isIpv4(ep.addr);
    const v6 = isIpv6(ep.addr);
    if (!v4 && !v6) fail('invalid_endpoint_address', 'endpoint address is not an IP literal');
    if (ep.family === 'ipv4') {
      if (!v4) fail('endpoint_family_mismatch', 'declared ipv4 but address is not ipv4');
      hasIpv4 = true;
    } else if (ep.family === 'ipv6') {
      if (!v6) fail('endpoint_family_mismatch', 'declared ipv6 but address is not ipv6');
      hasIpv6 = true;
    } else {
      fail('endpoint_family_mismatch', 'endpoint family must be "ipv4" or "ipv6"');
    }
    for (const listener of ep.listeners) {
      // Only QUIC listeners are dialable (frozen wire contract: transport=quic, alpn=h3).
      if (listener.transport === 'quic') {
        addrs.push(
          ep.family === 'ipv6' ? `[${ep.addr}]:${listener.port}` : `${ep.addr}:${listener.port}`,
        );
      }
    }
  }

  return {
    endpointIdHex,
    exitIdHex: node.exit_id.toLowerCase(),
    country: node.location.country,
    city: node.location.city,
    weight: node.weight,
    active: node.active,
    ipv6Egress: node.egress.ipv6,
    hasIpv4,
    hasIpv6,
    addrs,
    ...(node.cover_domain === undefined ? {} : { coverDomain: node.cover_domain }),
  };
}

/**
 * Verifies a Warren signed relay list (v10) and returns its resolved relays.
 *
 * Checks the version, the Ed25519 signature over the canonical payload, and the
 * 7-day validity-window cap. The signed message is the compact JSON of the
 * payload in fixed field order, minus `signature_hex`, reproducing
 * `serde_json::to_vec` byte-for-byte.
 *
 * The caller MUST still enforce anti-rollback (reject a `generation` below the
 * last seen) and expiry (reject once {@link isExpired}).
 *
 * @param signedJson The raw signed-list JSON string.
 * @param expectedServerPubkeys Pinned server pubkeys (64-char hex). When omitted
 *   or empty, any validly signed list is accepted (trust on first use).
 * @throws {WarrenDiscoveryError}
 */
export function verifySignedRelayList(
  signedJson: string,
  expectedServerPubkeys?: readonly string[],
): VerifiedRelayList {
  let parsed: unknown;
  try {
    parsed = JSON.parse(signedJson);
  } catch (cause) {
    return fail('json', 'relay list is not valid JSON', cause);
  }

  const top = asObject(
    parsed,
    [
      'version',
      'nodes',
      'generation',
      'signed_at',
      'expires_at',
      'server_pubkey_hex',
      'signature_hex',
    ],
    'signed relay list',
  );

  const version = asU64(top.version, 'version');
  if (version !== SIGNED_VERSION) {
    fail('unsupported_version', `unsupported signed-list version ${version}`);
  }

  const serverPubkeyHex = asString(top.server_pubkey_hex, 'server_pubkey_hex');
  const signatureHex = asString(top.signature_hex, 'signature_hex');
  const generation = asU64(top.generation, 'generation');
  const signedAt = asU64(top.signed_at, 'signed_at');
  const expiresAt = asU64(top.expires_at, 'expires_at');
  const nodes = asArray(top.nodes, 'nodes').map(validateNode);

  if (expectedServerPubkeys && expectedServerPubkeys.length > 0) {
    const got = serverPubkeyHex.toLowerCase();
    if (!expectedServerPubkeys.some((p) => p.toLowerCase() === got)) {
      fail('server_pubkey_mismatch', 'relay list is signed by an unpinned key');
    }
  }

  let pubkeyBytes: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    pubkeyBytes = hexToBytes(serverPubkeyHex);
    signatureBytes = hexToBytes(signatureHex);
  } catch (cause) {
    return fail('invalid_hex', 'server pubkey or signature is not valid hex', cause);
  }
  if (pubkeyBytes.length !== 32 || signatureBytes.length !== 64) {
    fail('invalid_hex', 'server pubkey or signature has the wrong length');
  }

  // Reproduce serde_json::to_vec(UnsignedRelayList): compact JSON, fixed field
  // order, signature_hex omitted. Rebuilt from validated fields so incoming
  // whitespace, key order and unknown fields cannot alter the signed bytes.
  const canonical = JSON.stringify({
    version,
    nodes,
    generation,
    signed_at: signedAt,
    expires_at: expiresAt,
    server_pubkey_hex: serverPubkeyHex,
  });

  let signatureOk: boolean;
  try {
    // zip215: false matches the engine's ed25519-dalek verify (cofactorless,
    // canonical encodings only); the noble default would accept encodings the
    // Rust SDK rejects.
    signatureOk = ed25519.verify(signatureBytes, utf8ToBytes(canonical), pubkeyBytes, {
      zip215: false,
    });
  } catch (cause) {
    return fail('pubkey_not_on_curve', 'server pubkey is not a valid Ed25519 point', cause);
  }
  if (!signatureOk) {
    fail('bad_signature', 'relay list signature did not verify');
  }

  if (expiresAt - signedAt > MAX_VALIDITY_SECS) {
    fail('validity_too_long', 'relay list validity window exceeds the 7-day cap');
  }

  return {
    generation,
    signedAt,
    expiresAt,
    relays: nodes.map(resolveRelay),
    serverPubkeyHex: serverPubkeyHex.toLowerCase(),
  };
}

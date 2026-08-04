import type { Relay } from './relay.js';

/** Geographic constraint on exit selection. */
export type LocationConstraint =
  | { kind: 'any' }
  | { kind: 'country'; country: string }
  | { kind: 'city'; country: string; city: string };

/** Which IP families a relay must offer to qualify. */
export type IpAvailability = 'both' | 'ipv4_only' | 'ipv6_only';

/** A query constraining which relays may be selected. */
export interface ExitQuery {
  /** Geographic constraint. Defaults to any. */
  location?: LocationConstraint;
  /** Required IP family availability. Defaults to `both` (at least one of v4/v6). */
  ipAvailability?: IpAvailability;
  /** Require a working IPv6 egress source. Defaults to false. */
  requireIpv6Egress?: boolean;
}

/** Thrown when no relay matches an {@link ExitQuery}. */
export class NoRelayMatchError extends Error {
  constructor() {
    super('no relay matches the query');
    this.name = 'NoRelayMatchError';
  }
}

function locationMatches(constraint: LocationConstraint | undefined, relay: Relay): boolean {
  if (!constraint || constraint.kind === 'any') return true;
  const sameCountry = relay.country.toLowerCase() === constraint.country.toLowerCase();
  if (constraint.kind === 'country') return sameCountry;
  return sameCountry && relay.city.toLowerCase() === constraint.city.toLowerCase();
}

function ipMatches(availability: IpAvailability | undefined, relay: Relay): boolean {
  switch (availability ?? 'both') {
    case 'ipv4_only':
      return relay.hasIpv4;
    case 'ipv6_only':
      return relay.hasIpv6;
    default:
      return relay.hasIpv4 || relay.hasIpv6;
  }
}

/** Returns whether a relay satisfies every constraint of the query. */
export function relayMatches(relay: Relay, query: ExitQuery): boolean {
  if (!relay.active) return false;
  if (!locationMatches(query.location, relay)) return false;
  if (!ipMatches(query.ipAvailability, relay)) return false;
  if (query.requireIpv6Egress && !relay.ipv6Egress) return false;
  return true;
}

function candidates(relays: readonly Relay[], query: ExitQuery): Relay[] {
  return relays.filter((r) => relayMatches(r, query));
}

/**
 * Selects the first relay matching the query, ignoring weight. Deterministic.
 *
 * @throws {NoRelayMatchError}
 */
export function selectExit(relays: readonly Relay[], query: ExitQuery = {}): Relay {
  const match = candidates(relays, query)[0];
  if (!match) throw new NoRelayMatchError();
  return match;
}

function weightedPick(pool: Relay[], rng: () => number): Relay {
  const total = pool.reduce((acc, r) => acc + r.weight, 0);
  // pool is pre-filtered to weight > 0, so total > 0 unless pool came in degenerate.
  if (total === 0) return pool[0] as Relay;
  let roll = Math.floor(rng() * total);
  for (const relay of pool) {
    if (roll < relay.weight) return relay;
    roll -= relay.weight;
  }
  return pool[pool.length - 1] as Relay;
}

/**
 * Selects a relay weighted by `weight`, excluding zero-weight relays.
 *
 * @param rng A source of floats in `[0, 1)`. Defaults to `Math.random`.
 * @throws {NoRelayMatchError}
 */
export function selectExitWeighted(
  relays: readonly Relay[],
  query: ExitQuery = {},
  rng: () => number = Math.random,
): Relay {
  const pool = candidates(relays, query).filter((r) => r.weight > 0);
  if (pool.length === 0) throw new NoRelayMatchError();
  return weightedPick(pool, rng);
}

/** Deterministic PRNG (mulberry32) for reproducible per-attempt selection. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Deterministic weighted selection seeded by the retry attempt.
 *
 * The same attempt index always yields the same relay (idempotent retry), while
 * successive attempts explore the weighted space. The RNG is intentionally not
 * identical across language SDKs: only signed-list verification is wire-frozen,
 * selection is a local policy.
 *
 * @throws {NoRelayMatchError}
 */
export function selectExitForAttempt(
  relays: readonly Relay[],
  query: ExitQuery,
  retryAttempt: number,
): Relay {
  return selectExitWeighted(relays, query, mulberry32(retryAttempt));
}

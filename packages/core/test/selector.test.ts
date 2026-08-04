import { describe, expect, it } from 'vitest';
import {
  NoRelayMatchError,
  type Relay,
  relayMatches,
  selectExit,
  selectExitForAttempt,
  selectExitWeighted,
} from '../src/index.js';

function relay(over: Partial<Relay>): Relay {
  return {
    endpointIdHex: '11'.repeat(32),
    exitIdHex: 'aa'.repeat(16),
    country: 'NL',
    city: 'Amsterdam',
    weight: 100,
    active: true,
    ipv6Egress: false,
    hasIpv4: true,
    hasIpv6: false,
    addrs: ['1.2.3.4:443'],
    ...over,
  };
}

describe('relayMatches', () => {
  const nl = relay({ country: 'NL', city: 'Amsterdam' });

  it('matches country case-insensitively', () => {
    expect(relayMatches(nl, { location: { kind: 'country', country: 'nl' } })).toBe(true);
    expect(relayMatches(nl, { location: { kind: 'country', country: 'FR' } })).toBe(false);
  });

  it('matches city only within the country', () => {
    expect(relayMatches(nl, { location: { kind: 'city', country: 'NL', city: 'amsterdam' } })).toBe(
      true,
    );
    expect(relayMatches(nl, { location: { kind: 'city', country: 'NL', city: 'Rotterdam' } })).toBe(
      false,
    );
  });

  it('excludes inactive relays', () => {
    expect(relayMatches(relay({ active: false }), {})).toBe(false);
  });

  it('filters on IP availability', () => {
    const v4only = relay({ hasIpv4: true, hasIpv6: false });
    const v6only = relay({ hasIpv4: false, hasIpv6: true });
    expect(relayMatches(v4only, { ipAvailability: 'ipv6_only' })).toBe(false);
    expect(relayMatches(v6only, { ipAvailability: 'ipv6_only' })).toBe(true);
    expect(relayMatches(v4only, { ipAvailability: 'ipv4_only' })).toBe(true);
  });

  it('honors requireIpv6Egress', () => {
    expect(relayMatches(relay({ ipv6Egress: false }), { requireIpv6Egress: true })).toBe(false);
    expect(relayMatches(relay({ ipv6Egress: true }), { requireIpv6Egress: true })).toBe(true);
  });
});

describe('selectExit', () => {
  it('returns the first matching relay and throws when none match', () => {
    const relays = [relay({ country: 'FR' }), relay({ country: 'NL', city: 'Amsterdam' })];
    expect(selectExit(relays, { location: { kind: 'country', country: 'NL' } }).country).toBe('NL');
    expect(() => selectExit(relays, { location: { kind: 'country', country: 'DE' } })).toThrow(
      NoRelayMatchError,
    );
  });
});

describe('selectExitWeighted', () => {
  const a = relay({ country: 'A', weight: 30 });
  const b = relay({ country: 'B', weight: 70 });

  it('picks by cumulative weight with an injected RNG', () => {
    expect(selectExitWeighted([a, b], {}, () => 0).country).toBe('A');
    expect(selectExitWeighted([a, b], {}, () => 0.5).country).toBe('B');
  });

  it('excludes zero-weight relays', () => {
    const zero = relay({ country: 'Z', weight: 0 });
    expect(() => selectExitWeighted([zero], {})).toThrow(NoRelayMatchError);
  });
});

describe('selectExitForAttempt', () => {
  it('is deterministic for a given attempt and explores the pool across attempts', () => {
    const relays = [relay({ country: 'A', weight: 50 }), relay({ country: 'B', weight: 50 })];
    const first = selectExitForAttempt(relays, {}, 3);
    expect(selectExitForAttempt(relays, {}, 3)).toBe(first);
    // Successive attempts must not be pinned to a single relay: over 20 seeds a
    // 50/50 pool yields both (kills an "always return relays[0]" regression).
    const seen = new Set(
      Array.from({ length: 20 }, (_, i) => selectExitForAttempt(relays, {}, i).country),
    );
    expect(seen).toEqual(new Set(['A', 'B']));
  });
});

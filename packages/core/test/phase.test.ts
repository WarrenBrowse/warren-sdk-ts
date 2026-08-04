import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  type ConnectionPhase,
  type EgressEvidence,
  type TunnelStatus,
  egressVerified,
  reducePhase,
} from '../src/phase.js';

interface Vector {
  status: TunnelStatus;
  egress: EgressEvidence;
  phase: ConnectionPhase;
}

// The shared fixture generated from `warren_contract::phase` (the Rust home
// replays the same file), so the TS reduction cannot drift from the contract.
const vectors: Vector[] = JSON.parse(
  readFileSync(new URL('./fixtures/phase-reduction.json', import.meta.url), 'utf8'),
) as Vector[];

describe('reducePhase', () => {
  it('replays every shared phase-reduction vector', () => {
    expect(vectors).toHaveLength(36);
    for (const v of vectors) {
      expect(reducePhase(v.status, v.egress), JSON.stringify(v)).toBe(v.phase);
    }
  });

  it('never shows protected without verified egress', () => {
    // The A8 invariant: the extension used to map connected -> protected
    // unconditionally; the shared reduction must degrade on any dead-egress
    // evidence.
    for (const v of vectors) {
      if (v.phase === 'protected') {
        expect(v.status.state).toBe('connected');
        expect(egressVerified(v.egress)).toBe(true);
      }
    }
  });

  it('defaults to verified egress when no evidence is supplied', () => {
    expect(reducePhase({ state: 'connected' })).toBe('protected');
    expect(reducePhase({ state: 'connected' }, { hostOffline: true, exitEgressDead: false })).toBe(
      'interrupted',
    );
  });

  it('keeps the kill-switch block distinct from exposure', () => {
    expect(reducePhase({ state: 'disconnected', lockedDown: true })).toBe('blocked');
    expect(reducePhase({ state: 'disconnected', lockedDown: false })).toBe('exposed');
    expect(reducePhase({ state: 'error', blockingError: false })).toBe('blocked');
    expect(reducePhase({ state: 'error', blockingError: true })).toBe('exposed');
  });
});

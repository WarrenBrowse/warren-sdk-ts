/**
 * Shared connection-phase contract: the single reduction of a tunnel's runtime
 * status into the coarse phase that drives the "protected" green state on
 * every Warren client surface (desktop app renderer, browser extension, web).
 *
 * This is the TypeScript mirror of `warren_contract::phase` (the Rust home);
 * the two are pinned to each other by the shared `phase-reduction.json`
 * fixture replayed on both sides, so the reduction cannot drift between the
 * contract and a client surface without a test going red.
 *
 * The `protected` invariant: it may be shown only when the tunnel is
 * `connected` AND egress is verified alive. "Connected" alone is not enough
 * (the daemon holds it through offline grace windows and an exit can stop
 * forwarding over a live session), and a kill switch holding traffic is
 * `blocked`, never `protected`: `blocked` asserts "nothing leaks",
 * `protected` asserts "traffic flows".
 */

/** The coarse connection phase presented to the user. */
export type ConnectionPhase = 'exposed' | 'connecting' | 'protected' | 'interrupted' | 'blocked';

/**
 * Neutral, daemon-agnostic tunnel status: the union of the states the desktop
 * daemon and the extension host each report, so one reduction serves both.
 * The shape (a lowercase `state` tag plus camelCase fields) matches the Rust
 * contract's serialization.
 */
export type TunnelStatus =
  | { state: 'connected' }
  | { state: 'connecting' }
  | { state: 'disconnecting' }
  | { state: 'draining' }
  | { state: 'reconnecting' }
  | { state: 'disconnected'; lockedDown: boolean }
  | { state: 'error'; blockingError: boolean };

/**
 * Liveness evidence about the egress path, gathered outside the tunnel state
 * machine (an active egress probe and the host-reachability watcher). It is
 * the extra input that keeps `protected` honest.
 */
export interface EgressEvidence {
  /** The local host lost connectivity while the tunnel still reports connected. */
  hostOffline: boolean;
  /** The exit stopped forwarding (egress-probe verdict) over a live session. */
  exitEgressDead: boolean;
}

/** Evidence with nothing known to be wrong (the verified-alive default). */
export const VERIFIED_EGRESS: EgressEvidence = { hostOffline: false, exitEgressDead: false };

/** Egress is verified alive: only then may `connected` be shown as `protected`. */
export function egressVerified(evidence: EgressEvidence): boolean {
  return !evidence.hostOffline && !evidence.exitEgressDead;
}

/**
 * Reduces a tunnel status plus egress evidence to the single phase every
 * client presents. This is the one place the "protected" green state is
 * decided; consumers merely render the result.
 */
export function reducePhase(
  status: TunnelStatus,
  evidence: EgressEvidence = VERIFIED_EGRESS,
): ConnectionPhase {
  switch (status.state) {
    case 'connected':
      return egressVerified(evidence) ? 'protected' : 'interrupted';
    case 'connecting':
    case 'disconnecting':
    case 'draining':
      return 'connecting';
    case 'reconnecting':
      return 'interrupted';
    case 'disconnected':
      return status.lockedDown ? 'blocked' : 'exposed';
    case 'error':
      // A failed block may be leaking: that is exposure, not a clean block.
      return status.blockingError ? 'exposed' : 'blocked';
  }
}

/**
 * Bridges the extension's host-relayed VPN state onto the shared
 * connection-phase contract (`@warrenbrowse/sdk-core` `reducePhase`), so the
 * extension renders the same "protected" semantics as every other Warren
 * surface instead of deciding its own.
 */

import {
  type ConnectionPhase,
  type EgressEvidence,
  type TunnelStatus,
  VERIFIED_EGRESS,
  reducePhase,
} from '@warrenbrowse/sdk-core';
import type { ExtensionVpnState } from './protocol.js';

/**
 * Maps a host-relayed VPN state to the neutral tunnel status the shared
 * reduction consumes. `proxied` is whether the browser's proxy settings are
 * still pointed at the tunnel (see `WarrenBrowserVpn.isProxied`): the client
 * is fail-closed, so with the proxy installed a dead host or a failed tunnel
 * BLACKHOLES traffic (nothing leaks) rather than exposing it.
 */
export function tunnelStatusOfVpnState(state: ExtensionVpnState, proxied: boolean): TunnelStatus {
  switch (state) {
    case 'connecting':
      return { state: 'connecting' };
    case 'connected':
      return { state: 'connected' };
    case 'reconnecting':
      return { state: 'reconnecting' };
    case 'draining':
      return { state: 'draining' };
    case 'failed':
      // With the proxy still installed the failure is held (blackhole, no
      // leak); without it nothing blocks and traffic flows in the clear.
      return { state: 'error', blockingError: !proxied };
    case 'disconnected':
      return { state: 'disconnected', lockedDown: proxied };
  }
}

/** Inputs to {@link phaseOfVpnState} beyond the raw host state. */
export interface VpnPhaseInputs {
  /** Whether the browser proxy settings still point at the tunnel. */
  proxied: boolean;
  /** Egress liveness evidence; omit for none (verified-alive default). */
  egress?: EgressEvidence;
}

/**
 * The single phase reduction for the extension surface: host state plus the
 * fail-closed proxy posture plus optional egress evidence, through the shared
 * contract. UI code renders the result and never re-decides it.
 */
export function phaseOfVpnState(state: ExtensionVpnState, inputs: VpnPhaseInputs): ConnectionPhase {
  return reducePhase(
    tunnelStatusOfVpnState(state, inputs.proxied),
    inputs.egress ?? VERIFIED_EGRESS,
  );
}

import { describe, expect, it } from 'vitest';
import { phaseOfVpnState, tunnelStatusOfVpnState } from '../src/phase.js';

describe('phaseOfVpnState', () => {
  it('connected with verified egress is protected', () => {
    expect(phaseOfVpnState('connected', { proxied: true })).toBe('protected');
  });

  it('connected with the host offline degrades to interrupted', () => {
    // The A8 divergence this bridge closes: the extension used to map
    // connected -> protected unconditionally, green while nothing flowed.
    expect(
      phaseOfVpnState('connected', {
        proxied: true,
        egress: { hostOffline: true, exitEgressDead: false },
      }),
    ).toBe('interrupted');
    expect(
      phaseOfVpnState('connected', {
        proxied: true,
        egress: { hostOffline: false, exitEgressDead: true },
      }),
    ).toBe('interrupted');
  });

  it('transitional states are connecting, a redial is interrupted', () => {
    expect(phaseOfVpnState('connecting', { proxied: false })).toBe('connecting');
    expect(phaseOfVpnState('draining', { proxied: true })).toBe('connecting');
    expect(phaseOfVpnState('reconnecting', { proxied: true })).toBe('interrupted');
  });

  it('a failure while proxied is the held blackhole, not exposure', () => {
    // Fail-closed client: proxy settings stay installed until an explicit
    // disconnect, so a dead host blackholes traffic. Showing red "exposed"
    // there would tell the user they are leaking when they are not.
    expect(phaseOfVpnState('failed', { proxied: true })).toBe('blocked');
    expect(phaseOfVpnState('failed', { proxied: false })).toBe('exposed');
  });

  it('disconnected is exposure only once the proxy settings are cleared', () => {
    expect(phaseOfVpnState('disconnected', { proxied: false })).toBe('exposed');
    expect(phaseOfVpnState('disconnected', { proxied: true })).toBe('blocked');
  });

  it('maps every host state onto the neutral status vocabulary', () => {
    expect(tunnelStatusOfVpnState('failed', true)).toEqual({
      state: 'error',
      blockingError: false,
    });
    expect(tunnelStatusOfVpnState('disconnected', true)).toEqual({
      state: 'disconnected',
      lockedDown: true,
    });
  });
});

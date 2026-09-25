import { describe, expect, it } from 'vitest';
import {
  type ControlMessage,
  MAX_SESSION_TOKENS,
  type SessionAttempt,
  type SessionTokenLease,
  WarrenEdgeError,
  walkSessionTokens,
} from '../src/index.js';

const ASSIGN: ControlMessage = {
  type: 'ipAssign',
  ipv4: new Uint8Array([10, 66, 0, 7]),
  prefixLen: 16,
  gatewayIpv4: new Uint8Array([10, 66, 0, 1]),
  ipv6: null,
  prefixLenV6: 0,
  gatewayIpv6: null,
  daitaSpec: null,
};
const REJECTED: ControlMessage = { type: 'rejected' };

const token = (marker: number) => new Uint8Array([marker]);

/** A fake exit answering each presented token from `replies` (by marker), and
 * recording which tokens were presented and which attempts were closed. */
function exit(replies: Record<number, ControlMessage | Error>) {
  const presented: number[] = [];
  const closed: number[] = [];
  const attempt = async (t: Uint8Array): Promise<SessionAttempt & { marker: number }> => {
    const marker = t[0] ?? -1;
    presented.push(marker);
    const reply = replies[marker] ?? REJECTED;
    if (reply instanceof Error) throw reply;
    return { control: reply, marker, close: () => closed.push(marker) };
  };
  return { attempt, presented, closed };
}

/** A claim registry like `TokenManager.claim`, observable by marker. */
function registry(heldAtStart: number[] = []) {
  const held = new Set(heldAtStart);
  const claim = (t: Uint8Array): SessionTokenLease | undefined => {
    const marker = t[0] ?? -1;
    if (held.has(marker)) return undefined;
    held.add(marker);
    return { release: () => held.delete(marker) };
  };
  return { claim, held };
}

async function codeOf(p: Promise<unknown>): Promise<string | undefined> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  return err instanceof WarrenEdgeError ? err.code : undefined;
}

describe('walkSessionTokens', () => {
  it('admits on the lead token with one setup presenting it alone', async () => {
    const { attempt, presented } = exit({ 1: ASSIGN });

    const walked = await walkSessionTokens([token(1), token(2)], attempt);

    expect(presented).toEqual([1]);
    expect(walked.attempt.control).toBe(ASSIGN);
    expect(walked.token[0]).toBe(1);
  });

  it('walks past a refused serial, closing that attempt and releasing its hold', async () => {
    const { attempt, presented, closed } = exit({ 1: REJECTED, 2: ASSIGN });
    const { claim, held } = registry();

    const walked = await walkSessionTokens([token(1), token(2), token(3)], attempt, claim);

    expect(presented).toEqual([1, 2]);
    expect(closed).toEqual([1]);
    expect(walked.token[0]).toBe(2);
    expect([...held]).toEqual([2]);
    walked.lease?.release();
    expect(held.size).toBe(0);
  });

  it('skips a token another live session of this process holds', async () => {
    const { attempt, presented } = exit({ 1: ASSIGN, 2: ASSIGN });
    const { claim } = registry([1]);

    const walked = await walkSessionTokens([token(1), token(2)], attempt, claim);

    expect(presented).toEqual([2]);
    expect(walked.token[0]).toBe(2);
  });

  it('stops on a reply another token cannot change', async () => {
    const { attempt, presented } = exit({ 1: { type: 'ipExhausted' }, 2: ASSIGN });

    const walked = await walkSessionTokens([token(1), token(2)], attempt);

    expect(presented).toEqual([1]);
    expect(walked.attempt.control.type).toBe('ipExhausted');
  });

  it('is bounded by the stack a request may carry', async () => {
    const { attempt, presented } = exit({});
    const stack = Array.from({ length: MAX_SESSION_TOKENS + 3 }, (_, i) => token(i));

    expect(await codeOf(walkSessionTokens(stack, attempt))).toBe('no_session_token');
    expect(presented).toHaveLength(MAX_SESSION_TOKENS);
  });

  it('fails typed when every token is refused, holding none of them', async () => {
    const { attempt, closed } = exit({});
    const { claim, held } = registry();

    expect(await codeOf(walkSessionTokens([token(1), token(2)], attempt, claim))).toBe(
      'no_session_token',
    );
    expect(closed).toEqual([1, 2]);
    expect(held.size).toBe(0);
  });

  it('fails typed without any setup when no token is free', async () => {
    const { attempt, presented } = exit({ 1: ASSIGN });
    const { claim } = registry([1]);

    expect(await codeOf(walkSessionTokens([token(1)], attempt, claim))).toBe('no_session_token');
    expect(await codeOf(walkSessionTokens([], attempt))).toBe('no_session_token');
    expect(presented).toEqual([]);
  });

  it('releases the hold when a setup fails for another reason, and lets the error through', async () => {
    const { attempt } = exit({ 1: new Error('handshake lost') });
    const { claim, held } = registry();

    await expect(walkSessionTokens([token(1), token(2)], attempt, claim)).rejects.toThrow(
      'handshake lost',
    );
    expect(held.size).toBe(0);
  });
});

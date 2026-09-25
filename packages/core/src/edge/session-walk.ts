/**
 * How a session is admitted on an anonymous v7 token: by walking the current
 * epoch's stack, one token per setup, the TypeScript twin of the Rust
 * `MultihopClientTunnel::connect` token walk.
 *
 * Every client of a wallet holds the same tokens (the batch derives from the
 * wallet), and an exit leases a serial to one live session in the whole fleet.
 * It answers a serial leased elsewhere with the same sealed `Rejected` it gives
 * an invalid token, and it spends the FIRST token of a request that verifies,
 * so presenting the whole stack at once would stop at a leased lead. A refusal
 * spends nothing, so the walk leads each setup with the next token instead,
 * bounded by the stack and by {@link MAX_SESSION_TOKENS}.
 */

import type { ControlMessage } from './control.js';
import { WarrenEdgeError } from './errors.js';
import { MAX_SESSION_TOKENS } from './setup.js';
import type { SessionTokenLease } from './token-manager.js';

/**
 * The placement hint an independent session sends (`prefer_ipv4 = 0.0.0.0`):
 * never co-housed on an address another live session of this serial holds on
 * the exit. An exit renews a serial leased on itself, so two sessions leading
 * with one token on the same exit are both admitted; this keeps them apart.
 */
export const INDEPENDENT_SESSION_PLACEMENT: Uint8Array = new Uint8Array(4);

/** One setup attempt: the exit's control reply, on a connection of its own. */
export interface SessionAttempt {
  readonly control: ControlMessage;
  /** Tears down the attempt's connection. */
  close(): void;
}

/** The admitted (or otherwise answered) attempt a walk ends on. */
export interface SessionWalkResult<A extends SessionAttempt> {
  attempt: A;
  /** The token the exit answered. A bearer credential: never log it. */
  token: Uint8Array;
  /** The hold on `token`, when the walk claimed one; the caller releases it
   * when the session ends. */
  lease: SessionTokenLease | undefined;
}

/**
 * Walks `stack` (`TokenManager.sessionStack(now)`): claims the next token (when
 * `claim` is given, skipping one another live session holds), runs one
 * `attempt` presenting it alone (handed the lease, so the attempt's connection
 * can hold it for the session's life), and on a `rejected` reply closes that
 * attempt, releases the token and moves on. Any other reply (an assignment, a drain, an
 * exhausted pool) ends the walk: another token cannot change it.
 *
 * @throws {WarrenEdgeError} `no_session_token` when no token was admitted: the
 * stack held none this session could claim, or the exit refused every one. An
 * error thrown by `attempt` propagates, with the token released.
 */
export async function walkSessionTokens<A extends SessionAttempt>(
  stack: readonly Uint8Array[],
  attempt: (token: Uint8Array, lease: SessionTokenLease | undefined) => Promise<A>,
  claim?: (token: Uint8Array) => SessionTokenLease | undefined,
): Promise<SessionWalkResult<A>> {
  let refused = 0;
  for (const token of stack.slice(0, MAX_SESSION_TOKENS)) {
    const lease = claim?.(token);
    if (claim !== undefined && lease === undefined) continue;
    let answered: A;
    try {
      answered = await attempt(token, lease);
    } catch (error) {
      lease?.release();
      throw error;
    }
    if (answered.control.type === 'rejected') {
      answered.close();
      lease?.release();
      refused += 1;
      continue;
    }
    return { attempt: answered, token, lease };
  }
  throw new WarrenEdgeError(
    'no_session_token',
    refused === 0
      ? 'no session token free this epoch'
      : `the exit refused every session token presented (${refused})`,
  );
}

/**
 * Deriving a token batch from the wallet instead of the CSPRNG, so a client
 * that loses its store can re-ask for the credentials it already owns.
 *
 * The issuer signs an account's batch once per epoch and refuses any other
 * batch for that epoch, because a second one would mint credentials over the
 * quota. A client whose store is wiped mid-epoch (a reinstall, a fresh profile,
 * a cleared storage) therefore used to be locked out until the epoch rolled:
 * its credentials existed and it could not ask for them again.
 *
 * Deriving the blinding from the wallet closes that: the same wallet rebuilds
 * the same blinded messages, and blind-RSA signing is deterministic, so the
 * issuer recognises the batch and hands back the identical signatures
 * (warren-api `issuance_batch_digest`). No credential is created that did not
 * exist before, and the per-epoch cap is untouched.
 *
 * What this costs: the blinding is no longer unpredictable to someone holding
 * the wallet seed, so that holder could compute which tokens the account owns.
 * They already hold the account. It stays unpredictable to the issuer, to the
 * exit, and to anyone else, which is where unlinkability lives.
 */

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';

/** Separates this use of the wallet seed from every other one. */
const BLINDING_SALT = utf8ToBytes('warren/token-blinding/v1');

/**
 * The `purpose` of the browser-proxy credential class. Canonical: every client
 * of a class must use the same label, or two installs of one wallet derive
 * different batches and cannot recover each other's. A class that adopts this
 * later adds its own label here rather than inventing one at the call site.
 */
export const BLINDING_PURPOSE_BROWSER_PROXY = 'browser-proxy/v1';

/**
 * A byte source for one blinded token request. {@link blindToken} draws its
 * nonce, its PSS salt and its blinding factor from it, in that order.
 */
export type TokenRandom = (byteLength: number) => Uint8Array;

/**
 * A 32-byte key for {@link deterministicTokenRandom}, derived from the wallet
 * seed and a `purpose` (the credential class: a browser credential and a tunnel
 * token must not derive from the same stream).
 *
 * One-way: holding the returned key does not give back the seed, so a component
 * that only mints credentials never needs to hold the wallet itself.
 */
export function blindingKeyFromSeed(seed: Uint8Array, purpose: string): Uint8Array {
  return hkdf(sha256, seed, BLINDING_SALT, utf8ToBytes(purpose), 32);
}

/**
 * The deterministic byte stream for slot `index` of `epoch`.
 *
 * The stream is a function of `(key, epoch, index)` alone, so the same wallet
 * rebuilds the same batch on any machine at any time. The NUMBER and ORDER of
 * draws {@link blindToken} makes is therefore part of the recovery contract:
 * changing them changes every derived batch, and a client upgraded mid-epoch
 * falls back to waiting the epoch out (it does not lose anything it holds).
 */
export function deterministicTokenRandom(
  key: Uint8Array,
  epoch: number,
  index: number,
): TokenRandom {
  let block = 0;
  return (byteLength: number): Uint8Array => {
    const out = new Uint8Array(byteLength);
    for (let at = 0; at < byteLength; at += 32) {
      out.set(
        hkdf(sha256, key, BLINDING_SALT, info(epoch, index, block++), 32).subarray(
          0,
          Math.min(32, byteLength - at),
        ),
        at,
      );
    }
    return out;
  };
}

/** `epoch || index || block`, fixed width so no two triples share an info. */
function info(epoch: number, index: number, block: number): Uint8Array {
  const out = new Uint8Array(16);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, BigInt(epoch));
  view.setUint32(8, index);
  view.setUint32(12, block);
  return out;
}

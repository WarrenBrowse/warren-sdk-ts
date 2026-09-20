/**
 * v7 session-token acquisition: fetch the issuer directory, blind a batch of
 * token pre-images, hand the blinded requests to the wallet-signed issuance
 * endpoint, and finalize the returned blind signatures into spendable
 * {@link Token}s. Wire-compatible with the Warren account API
 * (`GET /v1/tokens/keys`, `POST /v1/tokens/issue`) and the Rust
 * `warren-api-client` mint flow.
 *
 * Transport-agnostic on purpose: the caller supplies `getDirectory` and the
 * wallet-signed `issue` callback (the account API POST is signed by the
 * subscriber wallet; that is the ONE step that names the account, and the
 * blind-RSA construction unlinks the finalized tokens from it). This keeps the
 * crypto/flow here testable without a live API or a wallet.
 */

import { bytesToHex } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import { WarrenEdgeError } from './errors.js';
import { deterministicTokenRandom } from './token-blinding.js';
import {
  type IssuerPublicKey,
  type Token,
  type TokenClientState,
  blindToken,
  challengeDigestForEpoch,
  finalizeToken,
  issuerPublicKeyFromSpki,
} from './token.js';

/** One issuer key entry in a {@link TokenIssuerDirectory} (`GET /v1/tokens/keys`). */
export interface TokenIssuerKey {
  epoch: number;
  /** Hex `SHA-256(spki)`; must equal the derived key id. */
  token_key_id: string;
  /** base64url-nopad RSASSA-PSS `SubjectPublicKeyInfo` DER. */
  spki_b64: string;
  not_before: number;
  not_after: number;
}

/** The anonymous session-token issuer directory. */
export interface TokenIssuerDirectory {
  issuer_name: string;
  token_type: number;
  epoch_secs: number;
  context_label: string;
  quota_per_epoch: number;
  prefetch_epochs: number;
  keys: TokenIssuerKey[];
}

/** The wallet-signed `POST /v1/tokens/issue` request body. */
export interface TokenIssueRequest {
  epochs: { epoch: number; blinded: string[] }[];
}

/** The `POST /v1/tokens/issue` response body. */
export interface TokenIssueResponse {
  epochs: {
    epoch: number;
    issued: boolean;
    blind_signatures?: string[];
    token_key_id?: string;
    reject_reason?: string;
  }[];
}

/** The transport the caller injects (real fetch + wallet signing, or a fake). */
export interface TokenTransport {
  /** `GET /v1/tokens/keys`. */
  getDirectory(): Promise<TokenIssuerDirectory>;
  /** Wallet-signed `POST /v1/tokens/issue`. */
  issue(request: TokenIssueRequest): Promise<TokenIssueResponse>;
}

/**
 * Resolves the {@link IssuerPublicKey} for `epoch` from a directory, verifying
 * the derived key id matches the published `token_key_id`.
 *
 * @throws {WarrenEdgeError} `token_issuer` if no key covers `epoch` or the key
 * id does not match.
 */
export function issuerKeyForEpoch(directory: TokenIssuerDirectory, epoch: number): IssuerPublicKey {
  const entry = directory.keys.find((k) => k.epoch === epoch);
  if (!entry) {
    throw new WarrenEdgeError('token_issuer', `no issuer key for epoch ${epoch}`);
  }
  const pk = issuerPublicKeyFromSpki(base64urlnopad.decode(entry.spki_b64));
  const derivedKeyId = bytesToHex(pk.keyId);
  if (derivedKeyId !== entry.token_key_id) {
    throw new WarrenEdgeError(
      'token_issuer',
      'issuer key id does not match the derived SHA-256(spki)',
    );
  }
  return pk;
}

/**
 * The current epoch number for `directory` at `nowUnixSecs` (`now / epoch_secs`).
 *
 * @throws {WarrenEdgeError} `token_issuer` if the directory's `epoch_secs` is not positive.
 */
export function currentEpoch(directory: TokenIssuerDirectory, nowUnixSecs: number): number {
  if (directory.epoch_secs <= 0) {
    throw new WarrenEdgeError('token_issuer', 'directory epoch_secs must be positive');
  }
  return Math.floor(nowUnixSecs / directory.epoch_secs);
}

/**
 * Mints up to `count` session tokens for one specific `epoch` against an
 * already-fetched `directory`: blinds `count` pre-images against the epoch key,
 * POSTs them via the wallet-signed transport, and finalizes the returned blind
 * signatures. Returns fewer than `count` only if the issuer signed fewer
 * (quota); throws if the epoch was rejected.
 *
 * Splitting the directory fetch out (vs {@link acquireTokens}) lets a token
 * manager fetch the directory once and mint several prefetch epochs from it,
 * matching the Rust `mint_tokens` shape.
 *
 * With a `blindingKey` the batch is derived from the wallet rather than the
 * CSPRNG ({@link deterministicTokenRandom}), so a client that lost its store
 * re-asks for the credentials it already owns instead of waiting the epoch out.
 *
 * @throws {WarrenEdgeError} `epoch_rejected` (carrying the issuer's
 * `rejectReason`) if the issuer refused the epoch; `token_issuer` if the
 * issuer's response is otherwise inconsistent.
 */
export async function mintEpoch(
  transport: TokenTransport,
  directory: TokenIssuerDirectory,
  epoch: number,
  count: number,
  blindingKey?: Uint8Array,
): Promise<Token[]> {
  const pk = issuerKeyForEpoch(directory, epoch);
  const wanted = Math.min(count, directory.quota_per_epoch);
  const challengeDigest = challengeDigestForEpoch(
    directory.issuer_name,
    directory.context_label,
    BigInt(epoch),
  );

  const blindedB64: string[] = [];
  const states: TokenClientState[] = [];
  for (let i = 0; i < wanted; i++) {
    const { blindedRequest, state } =
      blindingKey === undefined
        ? blindToken(pk, challengeDigest)
        : blindToken(pk, challengeDigest, {
            random: deterministicTokenRandom(blindingKey, epoch, i),
          });
    blindedB64.push(base64urlnopad.encode(blindedRequest));
    states.push(state);
  }

  const response = await transport.issue({ epochs: [{ epoch, blinded: blindedB64 }] });
  const epochResult = response.epochs.find((e) => e.epoch === epoch);
  if (!epochResult || !epochResult.issued) {
    throw new WarrenEdgeError(
      'epoch_rejected',
      `issuer did not sign epoch ${epoch}${
        epochResult?.reject_reason ? `: ${epochResult.reject_reason}` : ''
      }`,
      epochResult?.reject_reason ? { rejectReason: epochResult.reject_reason } : undefined,
    );
  }
  const sigs = epochResult.blind_signatures ?? [];
  return sigs.map((sigB64, i) => {
    const state = states[i];
    if (!state) {
      throw new WarrenEdgeError(
        'token_issuer',
        'issuer returned more blind signatures than requested',
      );
    }
    return finalizeToken(pk, base64urlnopad.decode(sigB64), state);
  });
}

/**
 * Acquires up to `count` session tokens for the epoch `nowUnixSecs` falls in:
 * fetches the directory, then mints that single epoch ({@link mintEpoch}).
 *
 * The returned tokens' `serialize()` bytes are the 354-byte `SessionToken`s an
 * `IpRequestV7` carries (`WarrenEdgeConnection.openTunnel`).
 *
 * Minting at connect time correlates issuance with session timing (doc 64); a
 * {@link TokenManager} that refreshes ahead of need and only pops here is the
 * anti-correlation-safe path. This one-shot remains for tests and the raw flow.
 *
 * @throws {WarrenEdgeError} `epoch_rejected` if the issuer refused the epoch;
 * `token_issuer` if the issuer's response is otherwise inconsistent.
 */
export async function acquireTokens(
  transport: TokenTransport,
  opts: { nowUnixSecs: number; count?: number },
): Promise<{ epoch: number; tokens: Token[] }> {
  const directory = await transport.getDirectory();
  const epoch = currentEpoch(directory, opts.nowUnixSecs);
  const tokens = await mintEpoch(
    transport,
    directory,
    epoch,
    opts.count ?? directory.quota_per_epoch,
  );
  return { epoch, tokens };
}

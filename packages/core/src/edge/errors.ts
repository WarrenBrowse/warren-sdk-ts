/** Discriminator for {@link WarrenEdgeError}. */
export type WarrenEdgeErrorCode =
  /** A verified exit advertises no edge (`edgeCertSha256` absent): EdgeConnect
   * refuses rather than dial a WebTransport URL it cannot pin. */
  | 'no_edge_pin'
  /** The token issuer directory or an issuance response is missing, malformed,
   * or otherwise inconsistent (bad key id, wrong signature length, etc). */
  | 'token_issuer'
  /** The issuer rejected the current epoch (quota exhausted, unknown epoch). */
  | 'epoch_rejected'
  /** A token manager was asked to mint without a wallet blinding key. A batch
   * drawn from the CSPRNG would reserve the account's epoch and lock every
   * other client of the wallet out of it, so none is ever sent. */
  | 'no_blinding_key'
  /** The WebTransport handshake or transport to the edge failed. */
  | 'handshake';

/**
 * A typed EdgeConnect (browser WebTransport tier) error.
 *
 * No-log discipline: messages never carry secret material (full pubkeys,
 * session tokens, mnemonics); a short prefix is fine when a value is genuinely
 * needed for debugging.
 */
export class WarrenEdgeError extends Error {
  readonly code: WarrenEdgeErrorCode;
  /**
   * The issuer's machine-readable reject code for an `epoch_rejected` error
   * (`already_issued`, `not_subscribed`, `out_of_window`, `bad_batch`). Only
   * `already_issued` is definitive for the rest of the epoch; every other reason
   * can heal, so a token manager settles an epoch on `already_issued` alone and
   * leaves the others retryable.
   */
  readonly rejectReason?: string;

  constructor(
    code: WarrenEdgeErrorCode,
    message: string,
    options?: { cause?: unknown; rejectReason?: string },
  ) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenEdgeError';
    this.code = code;
    if (options?.rejectReason !== undefined) this.rejectReason = options.rejectReason;
  }
}

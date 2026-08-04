/** Discriminator for {@link WarrenDiscoveryError}, mirroring the Rust `SignedError`. */
export type WarrenDiscoveryErrorCode =
  /** Malformed JSON, a missing field, or an unknown field (deny_unknown_fields). */
  | 'json'
  /** `version` is not the supported signed-list version (`SIGNED_VERSION`). */
  | 'unsupported_version'
  /** The list is signed by a key not in the caller's pin set. */
  | 'server_pubkey_mismatch'
  /** `expires_at - signed_at` exceeds the maximum validity window (7 days). */
  | 'validity_too_long'
  /** A pubkey or signature hex string failed to decode. */
  | 'invalid_hex'
  /** The server pubkey hex decoded but is not a valid Ed25519 point. */
  | 'pubkey_not_on_curve'
  /** The Ed25519 signature did not verify against the canonical payload. */
  | 'bad_signature'
  /** A node id is neither a 64-char hex string nor a valid `wb...` address. */
  | 'invalid_node_id'
  /** An endpoint address did not parse as an IP literal. */
  | 'invalid_endpoint_address'
  /** An endpoint's declared family does not match its address. */
  | 'endpoint_family_mismatch'
  /** The list is past `expires_at` (acceptance policy, `acceptSignedRelayList`). */
  | 'expired'
  /** `generation` is below the trusted anti-rollback floor (acceptance policy). */
  | 'rolled_back';

/**
 * An error from verifying a signed relay list.
 *
 * No-log discipline: pubkeys and identity material are never placed in
 * {@link Error.message}.
 */
export class WarrenDiscoveryError extends Error {
  readonly code: WarrenDiscoveryErrorCode;

  constructor(code: WarrenDiscoveryErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenDiscoveryError';
    this.code = code;
  }
}

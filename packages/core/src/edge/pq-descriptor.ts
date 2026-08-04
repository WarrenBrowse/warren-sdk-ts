/**
 * The Warren `/v2` signed exit descriptor for the post-quantum hybrid seal, and
 * its anti-downgrade negotiation. Byte-for-byte compatible with the Rust
 * `warrenguard-multihop` `exit_descriptor.rs` PQ path, pinned by
 * `vectors/pq_hpke_seal_v2.json` (`exit_descriptor_pq`).
 *
 * The decision to use the X-Wing seal is driven ONLY by the Ed25519-signed
 * `exit_mlkem768_pubkey`, NEVER by an unauthenticated wire bit. A middlebox that
 * strips the ML-KEM key from the descriptor invalidates the operational
 * signature, so a client that set `require_pq` sees no valid signed key and
 * REFUSES the dial ({@link WarrenPqError} `pq_downgrade`). A client that did not
 * require PQ falls back to the classical X25519 seal. This is the anti-downgrade
 * anchor.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

/** Ed25519 signature context for the operational key signing an exit's PQ
 * descriptor; must equal the Rust `WARREN_PKI_OPERATIONAL_EXIT_PQ_V1`. Distinct
 * from `/v1` and `/v2` so no cross-version signature is ever accepted. */
export const WARREN_PKI_OPERATIONAL_EXIT_PQ_V1 = utf8ToBytes(
  'warren/multihop/v2/operational-signs-exit-pq',
);

/** ML-KEM-768 encapsulation-key length in bytes; a signed key of any other
 * length is rejected. */
export const MLKEM768_ENCAPS_KEY_LEN = 1184;

const EXIT_ID_LEN = 16;
const X25519_PUBKEY_LEN = 32;
const ED25519_PUBKEY_LEN = 32;
const ED25519_SIG_LEN = 64;

/** Discriminator for {@link WarrenPqError}. */
export type WarrenPqErrorCode =
  /** PQ was required but the signed descriptor advertises no ML-KEM key; a
   * downgrade to classical is refused. */
  | 'pq_downgrade'
  /** The descriptor carries no `exit_mlkem768_pubkey`. */
  | 'missing_pq_key'
  /** The `exit_mlkem768_pubkey` is not {@link MLKEM768_ENCAPS_KEY_LEN} bytes. */
  | 'bad_pq_key_length'
  /** The operational signature does not verify over the canonical PQ payload. */
  | 'bad_signature';

/** A typed post-quantum descriptor / negotiation error. No-log discipline:
 * messages never carry key material. */
export class WarrenPqError extends Error {
  readonly code: WarrenPqErrorCode;

  constructor(code: WarrenPqErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'WarrenPqError';
    this.code = code;
  }
}

/** A parsed signed exit descriptor carrying the optional PQ recipient key. */
export interface ExitDescriptorPq {
  /** 16-byte exit identifier. */
  exitId: Uint8Array;
  /** The exit's long-lived X25519 multihop public (`pk_X`, 32 bytes). */
  exitX25519MultihopPubkey: Uint8Array;
  /** The signed `dns_disabled` attestation bit. */
  dnsDisabled: boolean;
  /** The exit's ML-KEM-768 recipient key (1184 bytes) when it advertises PQ;
   * absent (or explicitly `undefined`, e.g. after a middlebox strips it) on a
   * classical descriptor. Covered by the PQ signature. */
  exitMlkem768Pubkey?: Uint8Array | undefined;
  /** The operational key's Ed25519 signature over the canonical payload. */
  signature: Uint8Array;
}

/** Whether the post-quantum hybrid seal is used against an exit. */
export enum PqAvailability {
  /** The exit published a validly SIGNED ML-KEM-768 key; use the X-Wing seal. */
  Available = 'available',
  /** No signed ML-KEM key and PQ not required; use the classical X25519 seal. */
  ClassicalFallback = 'classical_fallback',
}

function hexField(value: unknown, field: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new WarrenPqError('bad_signature', `descriptor field "${field}" must be a hex string`);
  }
  try {
    return hexToBytes(value);
  } catch (cause) {
    throw new WarrenPqError('bad_signature', `descriptor field "${field}" is not valid hex`, {
      cause,
    });
  }
}

/**
 * Parse a signed PQ exit descriptor from its JSON form (the shape minted by the
 * engine and carried in the golden vector). `exit_mlkem768_pubkey` is optional;
 * unrelated fields (e.g. `exit_ed25519_pubkey`) are ignored.
 */
export function parseExitDescriptorPqJson(json: string): ExitDescriptorPq {
  const parsed = JSON.parse(json) as Record<string, unknown>;
  return {
    exitId: hexField(parsed.exit_id, 'exit_id'),
    exitX25519MultihopPubkey: hexField(
      parsed.exit_x25519_multihop_pubkey,
      'exit_x25519_multihop_pubkey',
    ),
    dnsDisabled: parsed.dns_disabled === true,
    exitMlkem768Pubkey:
      parsed.exit_mlkem768_pubkey === undefined || parsed.exit_mlkem768_pubkey === null
        ? undefined
        : hexField(parsed.exit_mlkem768_pubkey, 'exit_mlkem768_pubkey'),
    signature: hexField(parsed.signature, 'signature'),
  };
}

/**
 * Build the canonical payload the operational signer must sign in the `/v2` PQ
 * PKI context. Mirrors `exit_descriptor_signing_payload_pq`.
 *
 * Layout: `WARREN_PKI_OPERATIONAL_EXIT_PQ_V1 || exit_id(16) || x25519_pubkey(32)
 * || dns_disabled_byte(1) || mlkem768_ek(1184)`.
 */
export function exitDescriptorSigningPayloadPq(
  exitId: Uint8Array,
  exitX25519MultihopPubkey: Uint8Array,
  dnsDisabled: boolean,
  exitMlkem768Pubkey: Uint8Array,
): Uint8Array {
  if (exitId.length !== EXIT_ID_LEN) {
    throw new WarrenPqError('bad_signature', `exit_id must be ${EXIT_ID_LEN} bytes`);
  }
  if (exitX25519MultihopPubkey.length !== X25519_PUBKEY_LEN) {
    throw new WarrenPqError('bad_signature', `x25519 pubkey must be ${X25519_PUBKEY_LEN} bytes`);
  }
  const ctx = WARREN_PKI_OPERATIONAL_EXIT_PQ_V1;
  const out = new Uint8Array(
    ctx.length + EXIT_ID_LEN + X25519_PUBKEY_LEN + 1 + exitMlkem768Pubkey.length,
  );
  let o = 0;
  out.set(ctx, o);
  o += ctx.length;
  out.set(exitId, o);
  o += EXIT_ID_LEN;
  out.set(exitX25519MultihopPubkey, o);
  o += X25519_PUBKEY_LEN;
  out[o] = dnsDisabled ? 1 : 0;
  o += 1;
  out.set(exitMlkem768Pubkey, o);
  return out;
}

/**
 * Verify a signed PQ exit descriptor under the operational key. Binds the
 * ML-KEM-768 recipient key under the operational signature; the distinct context
 * string means a `/v1` or `/v2` signature can never satisfy this verifier.
 * Mirrors `verify_exit_descriptor_pq`.
 *
 * @throws {WarrenPqError} `missing_pq_key` if no ML-KEM key is present,
 * `bad_pq_key_length` if it is the wrong length, `bad_signature` if the
 * signature does not verify.
 */
export function verifyExitDescriptorPq(
  operationalPubkey: Uint8Array,
  descriptor: ExitDescriptorPq,
): void {
  const ek = descriptor.exitMlkem768Pubkey;
  if (ek === undefined) {
    throw new WarrenPqError('missing_pq_key', 'descriptor advertises no ML-KEM key');
  }
  if (ek.length !== MLKEM768_ENCAPS_KEY_LEN) {
    throw new WarrenPqError('bad_pq_key_length', 'ML-KEM key has the wrong length');
  }
  if (
    operationalPubkey.length !== ED25519_PUBKEY_LEN ||
    descriptor.signature.length !== ED25519_SIG_LEN
  ) {
    throw new WarrenPqError(
      'bad_signature',
      'operational pubkey or signature has the wrong length',
    );
  }
  const payload = exitDescriptorSigningPayloadPq(
    descriptor.exitId,
    descriptor.exitX25519MultihopPubkey,
    descriptor.dnsDisabled,
    ek,
  );
  let ok: boolean;
  try {
    // zip215: false matches ed25519-dalek verify_strict (cofactorless, canonical
    // encodings only), the exact check the engine's operational verifier uses.
    ok = ed25519.verify(descriptor.signature, payload, operationalPubkey, { zip215: false });
  } catch (cause) {
    throw new WarrenPqError('bad_signature', 'operational pubkey is not a valid Ed25519 point', {
      cause,
    });
  }
  if (!ok) {
    throw new WarrenPqError('bad_signature', 'PQ descriptor signature did not verify');
  }
}

/**
 * Decide whether to use the post-quantum hybrid seal against an exit, with
 * anti-downgrade protection. The decision is driven ONLY by the operational
 * signature over the exit's ML-KEM key. Mirrors `negotiate_pq`.
 *
 * - A valid signed ML-KEM key => {@link PqAvailability.Available}.
 * - Otherwise with `requirePq` set => throws {@link WarrenPqError} `pq_downgrade`.
 * - Otherwise => {@link PqAvailability.ClassicalFallback}.
 *
 * @throws {WarrenPqError} `pq_downgrade` if `requirePq` is set but no valid
 * signed ML-KEM key is present.
 */
export function negotiatePq(
  operationalPubkey: Uint8Array,
  descriptor: ExitDescriptorPq,
  requirePq: boolean,
): PqAvailability {
  try {
    verifyExitDescriptorPq(operationalPubkey, descriptor);
    return PqAvailability.Available;
  } catch (err) {
    if (!(err instanceof WarrenPqError)) {
      throw err;
    }
    if (requirePq) {
      throw new WarrenPqError(
        'pq_downgrade',
        'pq required but the signed descriptor advertises no valid ML-KEM key (downgrade refused)',
        { cause: err },
      );
    }
    return PqAvailability.ClassicalFallback;
  }
}

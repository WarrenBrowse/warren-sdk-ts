import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { type WarrenKeyPair, keyPairFromSeed } from './derivation.js';
import { encodeAddress } from './ss58.js';

/** Canonical names of the four `X-Warren-*` authentication headers. */
export const HEADER_PUBKEY = 'X-Warren-PubKey';
export const HEADER_SIGNATURE = 'X-Warren-Sig';
export const HEADER_TIMESTAMP = 'X-Warren-Timestamp';
export const HEADER_NONCE = 'X-Warren-Nonce';

/**
 * Builds the canonical message that is signed and verified.
 *
 * `METHOD \n path \n timestamp \n nonce_hex \n sha256_hex(body)`. The separator
 * is always LF, never CRLF. Frozen by `vectors/identity.json`; any drift breaks
 * every signature.
 */
export function canonicalMessage(
  method: string,
  path: string,
  timestamp: number | bigint,
  nonceHex: string,
  bodyHashHex: string,
): string {
  return `${method}\n${path}\n${timestamp}\n${nonceHex}\n${bodyHashHex}`;
}

/** A signed request's material, ready to attach as the four `X-Warren-*` headers. */
export interface RequestSignature {
  /** Signer public key as a Warren SS58 address (`wb...`). */
  readonly pubkeySs58: string;
  /** Ed25519 signature of the canonical message, 128 hex chars (64 bytes). */
  readonly signatureHex: string;
  /** Unix epoch-seconds timestamp the canonical message was built with. */
  readonly timestamp: number | bigint;
  /** The 32-hex-char nonce (16 bytes). */
  readonly nonceHex: string;
}

/** Returns the four `X-Warren-*` headers as `[name, value]` pairs, in a stable order. */
export function signatureHeaders(sig: RequestSignature): Array<[string, string]> {
  return [
    [HEADER_PUBKEY, sig.pubkeySs58],
    [HEADER_SIGNATURE, sig.signatureHex],
    [HEADER_TIMESTAMP, String(sig.timestamp)],
    [HEADER_NONCE, sig.nonceHex],
  ];
}

/**
 * Signs a Warren API request from an already-derived keypair.
 *
 * Hashes the body with SHA-256, builds the canonical message and signs it.
 * Ed25519 is deterministic (RFC 8032), so the signature is reproducible. Prefer
 * this over {@link signRequest} when signing many requests for one identity: it
 * avoids re-running the HKDF derivation on every call.
 */
export function signWithKeyPair(
  keyPair: WarrenKeyPair,
  method: string,
  path: string,
  body: string,
  timestamp: number | bigint,
  nonceHex: string,
): RequestSignature {
  const bodyHashHex = bytesToHex(sha256(utf8ToBytes(body)));
  const message = canonicalMessage(method, path, timestamp, nonceHex, bodyHashHex);
  const signature = ed25519.sign(utf8ToBytes(message), keyPair.secretKey);
  return {
    pubkeySs58: encodeAddress(keyPair.publicKey),
    signatureHex: bytesToHex(signature),
    timestamp,
    nonceHex,
  };
}

/**
 * Signs a Warren API request from a 32-byte seed.
 *
 * Derives the Ed25519 key from `seed32`, then signs as {@link signWithKeyPair}.
 * Pinned by `vectors/identity.json`.
 */
export function signRequest(
  seed32: Uint8Array,
  method: string,
  path: string,
  body: string,
  timestamp: number | bigint,
  nonceHex: string,
): RequestSignature {
  return signWithKeyPair(keyPairFromSeed(seed32), method, path, body, timestamp, nonceHex);
}

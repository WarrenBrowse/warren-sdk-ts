/**
 * Warren protocol v7 session-setup constants, shared across the v7 anonymous-
 * token admission path (ADR-0006 / warren-core doc 64): the protocol version,
 * the fixed session-token length and the stack bound a primary presents, and
 * the `features` bitmask. Kept byte-for-byte in step with the Rust
 * `warrenguard-wire` constants and the exit's `IpRequestV7` control decoder.
 */

/** Warren application protocol version for v7. */
export const PROTOCOL_VERSION_V7 = 7;
/** One serialized Privacy Pass session token (raw bytes, no length prefix). */
export const SESSION_TOKEN_LEN = 354;
/** Upper bound on the token stack a primary may present. */
export const MAX_SESSION_TOKENS = 8;

/** v7 feature bits (`features` bitmask). */
export const FEATURE_MULTIPATH = 1 << 0;
/** Request server-side port forwarding. */
export const FEATURE_PORT_FORWARD = 1 << 1;

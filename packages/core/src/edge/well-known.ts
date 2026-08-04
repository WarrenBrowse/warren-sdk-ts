/**
 * The fixed UDP port every Warren edge listens on for browser WebTransport
 * (HTTP/3). A single well-known port keeps the browser client zero-config: it
 * derives the edge URL from a directory node's host plus this port and never
 * needs a per-node port published in the directory.
 *
 * Must stay in lockstep with the Rust source of truth
 * `warrenguard_config::WARREN_EDGE_PORT` (8443), which is compile-time asserted
 * below the NAT-PMP user-forward range (49152-65535) so a user port-forward can
 * never collide with the edge listener.
 */
export const WARREN_EDGE_PORT = 8443;

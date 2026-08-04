import { x25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import { decodeMultihopFrame } from '../src/edge/frame.js';
import { WarrenClientSession } from '../src/edge/seal.js';

/**
 * Cross-implementation seal vector. The exit X25519 public key is the one the
 * Rust `derive_exit_keypair([0x11; 32])` produces (captured from warrenguard),
 * the ephemeral is fixed so the sealed bytes are deterministic, and the SAME
 * frame is opened by a Rust `ExitSession` in
 * `warrenguard/crates/warrenguard-multihop/tests/edge_client_js_vector.rs`,
 * proving the TS seal is byte-for-byte HPKE-compatible with a real Warren exit.
 */
const EXIT_PUB_HEX = '1a239249ea74403babc01f32df9931a16f71ac8972c461d69fed15640e310639';
const EPHEMERAL_PRIV = new Uint8Array(32).fill(0x22);
const EXIT_ID = new Uint8Array(16).fill(0xa1);
const EPOCH = 7;
const SEQ = 42n;
const PAYLOAD = new TextEncoder().encode('warren-edge-connect-hello');

// Frozen wire bytes of the sealed frame (filled from the first run; a change
// here is a wire break the Rust cross-test would also catch).
const FROZEN_FRAME_HEX =
  '01a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1072a0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20c57666dcab30e6081656b3808a8af4e41934bb4770df10f3753092221b3e5ac2a3de86eaf0dc180c47c0';

describe('WarrenClientSession seal (cross-impl HPKE vector)', () => {
  it('produces the frozen sealed frame bytes deterministically', () => {
    const session = WarrenClientSession.create(hexToBytes(EXIT_PUB_HEX), EXIT_ID, EPHEMERAL_PRIV);
    // The encapsulated key is the ephemeral X25519 public key.
    expect(bytesToHex(session.encapsulatedKey)).toBe(
      bytesToHex(x25519.getPublicKey(EPHEMERAL_PRIV)),
    );

    const bytes = session.sealFrameBytes(PAYLOAD, EPOCH, SEQ);

    // Structural round-trip (framing), independent of the crypto.
    const decoded = decodeMultihopFrame(bytes);
    expect(decoded.epoch).toBe(EPOCH);
    expect(decoded.seq).toBe(SEQ);
    expect(decoded.ciphertext.length).toBe(PAYLOAD.length);
    expect(decoded.aeadTag.length).toBe(16);

    if (FROZEN_FRAME_HEX !== '__FILL__') {
      expect(bytesToHex(bytes)).toBe(FROZEN_FRAME_HEX);
    }
  });

  it('is deterministic for a fixed ephemeral (same inputs, same bytes)', () => {
    const mk = () =>
      WarrenClientSession.create(hexToBytes(EXIT_PUB_HEX), EXIT_ID, EPHEMERAL_PRIV).sealFrameBytes(
        PAYLOAD,
        EPOCH,
        SEQ,
      );
    expect(bytesToHex(mk())).toBe(bytesToHex(mk()));
  });

  it('changes the per-packet key with seq (distinct ciphertext for seq+1)', () => {
    const session = WarrenClientSession.create(hexToBytes(EXIT_PUB_HEX), EXIT_ID, EPHEMERAL_PRIV);
    const a = session.seal(PAYLOAD, EPOCH, SEQ);
    const b = session.seal(PAYLOAD, EPOCH, SEQ + 1n);
    expect(bytesToHex(a.ciphertext)).not.toBe(bytesToHex(b.ciphertext));
  });

  it('opens a reverse frame sealed by a real Rust exit (cross-impl)', () => {
    // Frozen reverse frame produced by warrenguard `ExitSession::seal_response`
    // for the SAME session (exit ikm [0x11;32], client ephemeral [0x22;32]),
    // epoch 7, seq 99, plaintext "exit-reply-to-browser". Proves the client
    // opens exit->client frames byte-for-byte (reverse HPKE export path).
    const reverseHex =
      '01a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a107630faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f200093fbafe93b32ac6be23dfeb0be4fb8159436a90f4b0b6bfbfa18844c42c9b4646c3c34719d';
    const session = WarrenClientSession.create(hexToBytes(EXIT_PUB_HEX), EXIT_ID, EPHEMERAL_PRIV);
    const frame = decodeMultihopFrame(hexToBytes(reverseHex));
    const plaintext = session.openResponse(frame);
    expect(new TextDecoder().decode(plaintext)).toBe('exit-reply-to-browser');
  });
});

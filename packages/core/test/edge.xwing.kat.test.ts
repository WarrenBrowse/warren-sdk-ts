import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  XWING_CT_LEN,
  XWING_LABEL,
  XWING_MLKEM_CT_LEN,
  XWING_MLKEM_EK_LEN,
  xwingCombiner,
  xwingReferenceFlow,
} from '../src/edge/xwing.js';

/**
 * Official X-Wing (draft-connolly-cfrg-xwing-kem) known-answer vectors, shared
 * across every Warren SDK (`warren-vectors/xwing_kem.json`). Replaying keygen ->
 * encaps -> decaps through the exact combiner + ML-KEM-768 + X25519 code and
 * asserting pk/ct/shared_secret byte-for-byte is the non-negotiable correctness
 * gate: a wrong combiner transcript, label position, or ciphertext layout fails
 * here. The same vectors are replayed by the Rust engine's `xwing_kat.rs`.
 */
const vectorsPath = fileURLToPath(new URL('../../../vectors/xwing_kem.json', import.meta.url));
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8'));

describe('X-Wing hybrid KEM (official draft KATs)', () => {
  it('pins the combiner label to the frozen 6 bytes 5c2e2f2f5e5c', () => {
    expect(bytesToHex(XWING_LABEL)).toBe('5c2e2f2f5e5c');
    expect(vector.combiner_label_hex).toBe('5c2e2f2f5e5c');
  });

  it('pins the X-Wing length constants (ek 1184, ct_M 1088, full ct 1120)', () => {
    expect(XWING_MLKEM_EK_LEN).toBe(1184);
    expect(XWING_MLKEM_CT_LEN).toBe(1088);
    expect(XWING_CT_LEN).toBe(1120);
  });

  it.each(vector.vectors.map((v: unknown, i: number) => [i, v]))(
    'reproduces vector[%i] pk, ct and shared_secret byte-for-byte',
    (
      _i,
      v: { seed_hex: string; eseed_hex: string; pk_hex: string; ct_hex: string; ss_hex: string },
    ) => {
      const out = xwingReferenceFlow(hexToBytes(v.seed_hex), hexToBytes(v.eseed_hex));
      expect(bytesToHex(out.publicKey)).toBe(v.pk_hex);
      expect(bytesToHex(out.ciphertext)).toBe(v.ct_hex);
      // Encaps and decaps must both land on the official shared secret.
      expect(bytesToHex(out.sharedSecretEncaps)).toBe(v.ss_hex);
      expect(bytesToHex(out.sharedSecretDecaps)).toBe(v.ss_hex);
    },
  );

  it('matches the engine combiner cross-check anchor (label last, not XOR)', () => {
    // Independent anchor from warrenguard `xwing.rs`
    // (combiner of 0x01*32, 0x02*32, 0x03*32, 0x04*32). If the code XOR'd the
    // secrets, reordered the transcript, or put the label first, this fails.
    const got = xwingCombiner(
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      new Uint8Array(32).fill(0x03),
      new Uint8Array(32).fill(0x04),
    );
    expect(bytesToHex(got)).toBe(
      '5c6bfaf8c3ec48ab3cee7c12129b39913b8a7fa1234115da7e1c55608ad19fb6',
    );
  });

  it('flips the shared secret when the X25519 ciphertext half is tampered', () => {
    // The combiner binds ct_X into the transcript, so a changed ct_X must change
    // the secret (proves ct_X is really hashed, not dropped).
    const a = xwingCombiner(
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      new Uint8Array(32).fill(0x03),
      new Uint8Array(32).fill(0x04),
    );
    const b = xwingCombiner(
      new Uint8Array(32).fill(0x01),
      new Uint8Array(32).fill(0x02),
      new Uint8Array(32).fill(0x09),
      new Uint8Array(32).fill(0x04),
    );
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});

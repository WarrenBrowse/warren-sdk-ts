import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  PqAvailability,
  WarrenPqError,
  exitDescriptorSigningPayloadPq,
  negotiatePq,
  parseExitDescriptorPqJson,
  verifyExitDescriptorPq,
} from '../src/edge/pq-descriptor.js';

/**
 * Signed PQ exit descriptor + anti-downgrade vector
 * (`warren-vectors/pq_hpke_seal_v2.json` -> `exit_descriptor_pq`). The decision
 * to use the X-Wing seal is driven ONLY by the Ed25519-signed `exit_mlkem768_pubkey`,
 * never by a wire bit: a client that requires PQ but sees no signed ML-KEM key
 * must refuse (PqDowngrade).
 */
const vectorsPath = fileURLToPath(
  new URL('../../../vectors/pq_hpke_seal_v2.json', import.meta.url),
);
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const dpq = vector.exit_descriptor_pq;
const OPERATIONAL_PUBKEY = hexToBytes(dpq.operational_pubkey_hex);

describe('/v2 signed PQ exit descriptor + anti-downgrade', () => {
  it('reproduces the canonical PQ signing payload byte-for-byte', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    const payload = exitDescriptorSigningPayloadPq(
      d.exitId,
      d.exitX25519MultihopPubkey,
      d.dnsDisabled,
      d.exitMlkem768Pubkey as Uint8Array,
    );
    expect(bytesToHex(payload)).toBe(dpq.signing_payload_hex);
  });

  it('verifies the signed PQ descriptor against the operational key', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    expect(() => verifyExitDescriptorPq(OPERATIONAL_PUBKEY, d)).not.toThrow();
  });

  it('drives PQ availability from the signature: negotiate => Available', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    expect(negotiatePq(OPERATIONAL_PUBKEY, d, true)).toBe(PqAvailability.Available);
    expect(negotiatePq(OPERATIONAL_PUBKEY, d, false)).toBe(PqAvailability.Available);
  });

  it('rejects a descriptor whose ML-KEM key was tampered (bad signature)', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    (d.exitMlkem768Pubkey as Uint8Array)[0] ^= 0x01;
    expect(() => verifyExitDescriptorPq(OPERATIONAL_PUBKEY, d)).toThrow(WarrenPqError);
  });

  it('refuses to downgrade: require_pq + stripped ML-KEM key => PqDowngrade', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    d.exitMlkem768Pubkey = undefined; // a middlebox strips the PQ key
    const err = (() => {
      try {
        negotiatePq(OPERATIONAL_PUBKEY, d, true);
        return undefined;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(WarrenPqError);
    expect((err as WarrenPqError).code).toBe('pq_downgrade');
  });

  it('falls back to classical when PQ is not required and no signed ML-KEM key is present', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    d.exitMlkem768Pubkey = undefined;
    expect(negotiatePq(OPERATIONAL_PUBKEY, d, false)).toBe(PqAvailability.ClassicalFallback);
  });

  it('reports a missing ML-KEM key distinctly from a bad signature', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    d.exitMlkem768Pubkey = undefined;
    const err = (() => {
      try {
        verifyExitDescriptorPq(OPERATIONAL_PUBKEY, d);
        return undefined;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(WarrenPqError);
    expect((err as WarrenPqError).code).toBe('missing_pq_key');
  });

  it('rejects an ML-KEM key of the wrong length', () => {
    const d = parseExitDescriptorPqJson(dpq.descriptor_json);
    d.exitMlkem768Pubkey = new Uint8Array(1183);
    const err = (() => {
      try {
        verifyExitDescriptorPq(OPERATIONAL_PUBKEY, d);
        return undefined;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(WarrenPqError);
    expect((err as WarrenPqError).code).toBe('bad_pq_key_length');
  });
});

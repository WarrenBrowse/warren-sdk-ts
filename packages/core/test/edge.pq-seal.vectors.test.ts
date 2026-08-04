import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import { encodeMultihopFrameV2 } from '../src/edge/frame-v2.js';
import { WarrenPqClientSession, WarrenPqExitSession } from '../src/edge/pq-seal.js';
import { xwingRecipientFromComponentSeeds } from '../src/edge/xwing.js';

/**
 * Shared cross-implementation golden vector for the Warren `/v2` post-quantum
 * multihop seal (`warren-vectors/pq_hpke_seal_v2.json`). The exit recipient key
 * is derived from the vector's independent component seeds; the client seals with
 * the vector's fixed encaps randomness, so the produced setup + reverse frames
 * must match the frozen bytes an exit (Rust `PqExitSession`) decrypts against.
 */
const vectorsPath = fileURLToPath(
  new URL('../../../vectors/pq_hpke_seal_v2.json', import.meta.url),
);
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8'));

const recipient = vector.recipient;
const encaps = vector.encaps;
const fwd = vector.forward_setup;
const rev = vector.reverse_reply;

function pair() {
  const { publicKey, secretKey } = xwingRecipientFromComponentSeeds(
    hexToBytes(recipient.mlkem768_d_seed_hex),
    hexToBytes(recipient.mlkem768_z_seed_hex),
    hexToBytes(recipient.x25519_sk_seed_hex),
  );
  const exitId = hexToBytes(fwd.exit_id_hex);
  const client = WarrenPqClientSession.createDeterministic(
    publicKey,
    exitId,
    hexToBytes(encaps.mlkem768_m_seed_hex),
    hexToBytes(encaps.x25519_ephemeral_seed_hex),
  );
  const exit = WarrenPqExitSession.create(secretKey, client.encapsulatedKey, client.pqCt, exitId);
  return { client, exit, publicKey, secretKey };
}

describe('/v2 post-quantum seal golden vector (X-Wing hybrid HPKE)', () => {
  it('derives the exit recipient key matching the vector (ek + x25519 pubkey)', () => {
    const { publicKey } = xwingRecipientFromComponentSeeds(
      hexToBytes(recipient.mlkem768_d_seed_hex),
      hexToBytes(recipient.mlkem768_z_seed_hex),
      hexToBytes(recipient.x25519_sk_seed_hex),
    );
    expect(bytesToHex(publicKey.mlkem768Ek)).toBe(recipient.mlkem768_ek_hex);
    expect(bytesToHex(publicKey.x25519Pubkey)).toBe(recipient.x25519_pubkey_hex);
  });

  it('places ct_X in encapsulated_key and ct_M in pq_ct', () => {
    const { client } = pair();
    expect(bytesToHex(client.encapsulatedKey)).toBe(fwd.encapsulated_key_hex);
    expect(bytesToHex(client.pqCt)).toBe(fwd.pq_ct_hex);
    expect(client.pqCt.length).toBe(1088);
  });

  it('seals the forward setup frame to the frozen golden bytes', () => {
    const { client } = pair();
    const frame = client.sealSetup(hexToBytes(fwd.payload_hex), fwd.epoch, BigInt(fwd.seq));
    expect(bytesToHex(frame.ciphertext)).toBe(fwd.ciphertext_hex);
    expect(bytesToHex(frame.aeadTag)).toBe(fwd.aead_tag_hex);
    expect(bytesToHex(encodeMultihopFrameV2(frame))).toBe(fwd.frame_bytes_hex);
  });

  it('lets the exit open the forward setup frame (X-Wing decapsulation round-trip)', () => {
    const { client, exit } = pair();
    const frame = client.sealSetup(hexToBytes(fwd.payload_hex), fwd.epoch, BigInt(fwd.seq));
    expect(bytesToHex(exit.open(frame))).toBe(fwd.payload_hex);
  });

  it('omits pq_ct on a steady-state data frame yet still opens', () => {
    const { client, exit } = pair();
    // Establish the session with the setup frame, then a data frame re-sends no ct_M.
    client.sealSetup(hexToBytes(fwd.payload_hex), fwd.epoch, BigInt(fwd.seq));
    const data = client.seal(new TextEncoder().encode('steady payload'), 0, 1n);
    expect(data.pqCt.length).toBe(0);
    expect(new TextDecoder().decode(exit.open(data))).toBe('steady payload');
  });

  it('seals the reverse reply frame to the frozen golden bytes and the client opens it', () => {
    const { client, exit } = pair();
    const reply = exit.sealResponse(hexToBytes(rev.payload_hex), rev.epoch, BigInt(rev.seq));
    expect(bytesToHex(reply.ciphertext)).toBe(rev.ciphertext_hex);
    expect(bytesToHex(reply.aeadTag)).toBe(rev.aead_tag_hex);
    expect(reply.pqCt.length).toBe(0);
    expect(bytesToHex(encodeMultihopFrameV2(reply))).toBe(rev.frame_bytes_hex);
    expect(bytesToHex(client.openResponse(reply))).toBe(rev.payload_hex);
  });

  it('keeps forward and reverse per-packet keys distinct (direction tag)', () => {
    const { client, exit } = pair();
    const reply = exit.sealResponse(hexToBytes(rev.payload_hex), rev.epoch, BigInt(rev.seq));
    // Feeding a reverse frame into the forward opener must fail on the AEAD tag.
    expect(() => exit.open(reply)).toThrow();
    // And the client can open its own forward frame nowhere (it is the sender).
    expect(bytesToHex(client.openResponse(reply))).toBe(rev.payload_hex);
  });

  it('rejects a tampered ciphertext', () => {
    const { client, exit } = pair();
    const frame = client.sealSetup(hexToBytes(fwd.payload_hex), fwd.epoch, BigInt(fwd.seq));
    frame.ciphertext[0] ^= 0x01;
    expect(() => exit.open(frame)).toThrow();
  });

  it('rejects a frame that targets a different exit', () => {
    const { client, exit } = pair();
    const frame = client.sealSetup(hexToBytes(fwd.payload_hex), fwd.epoch, BigInt(fwd.seq));
    frame.exitId = new Uint8Array(16).fill(0xff);
    expect(() => exit.open(frame)).toThrow();
  });
});

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import { describe, expect, it } from 'vitest';
import {
  BLINDING_PURPOSE_BROWSER_PROXY,
  BLINDING_PURPOSE_SESSION,
  type TokenIssuerDirectory,
  type TokenTransport,
  blindToken,
  blindingKeyFromSeed,
  challengeDigestForEpoch,
  deterministicTokenRandom,
  finalizeToken,
  issuerPublicKeyFromSpki,
  mintEpoch,
  seedFromMnemonic,
} from '../src/index.js';

/**
 * Shared cross-implementation golden vector for the wallet-derived token
 * blinding (`warren-vectors/token_blinding_v1.json`). Every client of a wallet
 * must build the identical batch, or the issuer serves only the first one and
 * locks the others out for the epoch; the Rust SDK replays the same file.
 */
const vectorPath = fileURLToPath(
  new URL('../../../vectors/token_blinding_v1.json', import.meta.url),
);

interface Slot {
  index: string;
  nonce_hex: string;
  salt_hex: string;
  blinding_draw_hex: string;
  blinding_factor_hex: string;
  token_input_hex: string;
  blinded_hex: string;
  blind_signature_hex: string;
  token_hex: string;
}
interface Batch {
  purpose: string;
  epoch: number;
  challenge_digest_hex: string;
  slots: Slot[];
}
interface Vector {
  version: number;
  salt_utf8: string;
  wallet: { mnemonic: string; seed_hex: string };
  blinding_keys: { purpose: string; key_hex: string }[];
  issuer: {
    name: string;
    context_label: string;
    epoch_secs: number;
    quota_per_epoch: number;
    spki_hex: string;
    token_key_id_hex: string;
  };
  batches: Batch[];
}

const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as Vector;
const seed = seedFromMnemonic(vector.wallet.mnemonic);
const pk = issuerPublicKeyFromSpki(hexToBytes(vector.issuer.spki_hex));

function keyOf(purpose: string): Uint8Array {
  return blindingKeyFromSeed(seed, purpose);
}

function directoryFor(epoch: number): TokenIssuerDirectory {
  return {
    issuer_name: vector.issuer.name,
    token_type: 2,
    epoch_secs: vector.issuer.epoch_secs,
    context_label: vector.issuer.context_label,
    quota_per_epoch: vector.issuer.quota_per_epoch,
    prefetch_epochs: 1,
    keys: [
      {
        epoch,
        token_key_id: vector.issuer.token_key_id_hex,
        spki_b64: base64urlnopad.encode(hexToBytes(vector.issuer.spki_hex)),
        not_before: 0,
        not_after: 0,
      },
    ],
  };
}

describe('token_blinding_v1 golden vector', () => {
  it('pins the schema this replay reads', () => {
    expect(vector.version).toBe(1);
    expect(vector.salt_utf8).toBe('warren/token-blinding/v1');
    expect(bytesToHex(pk.keyId)).toBe(vector.issuer.token_key_id_hex);
  });

  it('derives the wallet seed the identity derives from', () => {
    expect(bytesToHex(seed)).toBe(vector.wallet.seed_hex);
  });

  it('names both credential classes with the canonical purposes', () => {
    expect(vector.blinding_keys.map((k) => k.purpose).sort()).toEqual(
      [BLINDING_PURPOSE_BROWSER_PROXY, BLINDING_PURPOSE_SESSION].sort(),
    );
    expect(new Set(vector.batches.map((b) => b.purpose))).toEqual(
      new Set([BLINDING_PURPOSE_BROWSER_PROXY, BLINDING_PURPOSE_SESSION]),
    );
  });

  for (const { purpose, key_hex } of vector.blinding_keys) {
    it(`derives the ${purpose} blinding key`, () => {
      expect(bytesToHex(keyOf(purpose))).toBe(key_hex);
    });
  }

  for (const batch of vector.batches) {
    describe(`${batch.purpose} epoch ${batch.epoch}`, () => {
      it('binds the epoch challenge', () => {
        const digest = challengeDigestForEpoch(
          vector.issuer.name,
          vector.issuer.context_label,
          BigInt(batch.epoch),
        );
        expect(bytesToHex(digest)).toBe(batch.challenge_digest_hex);
      });

      for (const slot of batch.slots) {
        it(`reproduces slot ${slot.index}: draws, blinded request and finalized token`, () => {
          const index = Number(slot.index);
          const draw = deterministicTokenRandom(keyOf(batch.purpose), batch.epoch, index);
          expect(bytesToHex(draw(32))).toBe(slot.nonce_hex);
          expect(bytesToHex(draw(48))).toBe(slot.salt_hex);
          expect(bytesToHex(draw(256))).toBe(slot.blinding_draw_hex);

          const { blindedRequest, state } = blindToken(pk, hexToBytes(batch.challenge_digest_hex), {
            random: deterministicTokenRandom(keyOf(batch.purpose), batch.epoch, index),
          });
          expect(bytesToHex(state.tokenInput)).toBe(slot.token_input_hex);
          expect(bytesToHex(blindedRequest)).toBe(slot.blinded_hex);

          const token = finalizeToken(pk, hexToBytes(slot.blind_signature_hex), state);
          expect(bytesToHex(token.serialize())).toBe(slot.token_hex);
        });
      }

      it('sends the pinned batch through mintEpoch and finalizes the pinned tokens', async () => {
        const sent: string[][] = [];
        const transport: TokenTransport = {
          getDirectory: async () => directoryFor(batch.epoch),
          issue: async (req) => {
            sent.push(req.epochs[0]?.blinded ?? []);
            return {
              epochs: [
                {
                  epoch: batch.epoch,
                  issued: true,
                  blind_signatures: batch.slots.map((s) =>
                    base64urlnopad.encode(hexToBytes(s.blind_signature_hex)),
                  ),
                  token_key_id: vector.issuer.token_key_id_hex,
                },
              ],
            };
          },
        };

        const tokens = await mintEpoch(
          transport,
          directoryFor(batch.epoch),
          batch.epoch,
          vector.issuer.quota_per_epoch,
          keyOf(batch.purpose),
        );

        expect(sent).toHaveLength(1);
        expect(sent[0]?.map((b) => bytesToHex(base64urlnopad.decode(b)))).toEqual(
          batch.slots.map((s) => s.blinded_hex),
        );
        expect(tokens.map((t) => bytesToHex(t.serialize()))).toEqual(
          batch.slots.map((s) => s.token_hex),
        );
      });
    });
  }
});

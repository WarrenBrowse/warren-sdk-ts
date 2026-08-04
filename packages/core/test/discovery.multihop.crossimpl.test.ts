import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { verifyMultihopDirectory } from '../src/index.js';

/**
 * Shared cross-implementation golden vector (`warren-vectors/multihop_directory.json`),
 * minted by warren-core (`warren-relay-selector::sign_multihop_directory`) and
 * also replayed by warren-core's own conformance suite. The TS verifier accepting
 * these exact bytes proves byte-for-byte compatibility with the source of truth
 * across the whole v2 PKI chain (server envelope + operational cert + per-node
 * relay/exit/attestation), exactly as `relays.json` does for the signed relay list.
 */
const vectorsPath = fileURLToPath(
  new URL('../../../vectors/multihop_directory.json', import.meta.url),
);
const vector = JSON.parse(readFileSync(vectorsPath, 'utf8'));

describe('multi-hop directory golden vector (warren-core minted)', () => {
  it('verifies the shared vector and resolves every node with 0 dropped', () => {
    const dir = verifyMultihopDirectory(
      vector.signed_json,
      [vector.server_pubkey_hex],
      [vector.root_pubkey_hex],
    );
    const e = vector.expected;
    expect(dir.generation).toBe(e.generation);
    expect(dir.signedAt).toBe(e.signed_at);
    expect(dir.expiresAt).toBe(e.expires_at);
    expect(dir.dropped).toBe(e.dropped);
    expect(dir.exits).toHaveLength(e.node_count);

    const en = e.nodes[0];
    const node = dir.exits[0]!;
    expect(node.exitIdHex).toBe(en.exit_id_hex);
    expect(node.exitEd25519PubkeyHex).toBe(en.exit_ed25519_pubkey_hex);
    expect(node.exitX25519PubkeyHex).toBe(en.exit_x25519_multihop_pubkey_hex);
    expect(node.country).toBe(en.country);
    expect(node.city).toBe(en.city);
    expect(node.weight).toBe(en.weight);
    expect(node.endpoint).toBe(en.endpoint);
    expect(node.dnsDisabled).toBe(en.dns_disabled);
  });

  it('rejects the shared bytes under a wrong root pin', () => {
    expect(() =>
      verifyMultihopDirectory(vector.signed_json, [vector.server_pubkey_hex], ['00'.repeat(32)]),
    ).toThrow();
  });

  it('rejects a one-byte tamper of the shared bytes', () => {
    const tampered = vector.signed_json.replace('"fr"', '"xx"');
    expect(() => verifyMultihopDirectory(tampered, [vector.server_pubkey_hex])).toThrow();
  });
});

/**
 * Cross-impl golden for the additive `edge_cert_sha256` field, minted by
 * warren-discovery-core (`print_edge_cert_golden_for_ts_crossimpl`, root=key(1),
 * op=key(2), server=key(3), one fr node, edge pin `ab`*32). The TS verifier
 * accepting these exact Rust bytes proves the Rust<->TS BYTE match of the pin in
 * its frozen-last canonical-preimage position; a serialization drift would fail
 * the server envelope. Regenerate with
 * `cargo test -p warren-discovery-core print_edge_cert_golden_for_ts_crossimpl -- --ignored --nocapture`.
 */
describe('multi-hop directory edge cert pin (warren-core minted, cross-impl)', () => {
  const GOLDEN =
    '{"version":2,"nodes":[{"relay":{"relay_id":"01010101010101010101010101010101","relay_ed25519_pubkey":"0202020202020202020202020202020202020202020202020202020202020202","endpoint":"198.51.100.1:443","signature":"4db9c1aa6a43fde42660a3a4985f050099620a4df7d8cc4f215ed7e700866e52f835f423780a658117e89e0b215d3a96c85ae104be2a2cb9102297f7c187a500"},"exit":{"exit_id":"01010101010101010101010101010101","exit_ed25519_pubkey":"0202020202020202020202020202020202020202020202020202020202020202","exit_x25519_multihop_pubkey":"0303030303030303030303030303030303030303030303030303030303030303","endpoint":"198.51.100.1:443","signature":"ab89679fc753778c0af4342b2def520a9c0f99ab2033ea30c478b9f93b4782a7b28951600c188dca32a55b6a3488f3b0168e8b66f909f881d810c1b1e3184c0c"},"country":"fr","city":"City","asn":24940,"weight":100,"attestation_hex":"b778714f72403c192438f195f6d39cce55acd9e4698da279b1e7b9fa4a1e754385bf462571575bf471c16e7d312d494f34c214b6974adf8eb0311be04c536800","edge_cert_sha256":"abababababababababababababababababababababababababababababababab"}],"generation":7,"signed_at":1000,"expires_at":22600,"operational_pubkey_hex":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394","operational_cert_hex":"fc98890d66d17ff65b7006182b9ad3d499bed1f0f64b9d003e1e6c8e241ac24d8acf9cc13724132f6c230b67583b315538b62b15d72f9bb5b7bd1c8a85c13b06","server_pubkey_hex":"ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1","signature_hex":"2471cc5aa6c676613ba150ca1d7e510ce9777fd8c579c8d29348cdb6d78814ea919cb369dd84018ff9d69b100638b6300267cd8ab8c0e40dfd5ae1295390c90d"}';
  const SERVER_PIN = 'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1';
  const ROOT_PIN = '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c';

  it('verifies the Rust-minted edge-cert golden and surfaces the pin', () => {
    const dir = verifyMultihopDirectory(GOLDEN, [SERVER_PIN], [ROOT_PIN]);
    expect(dir.exits).toHaveLength(1);
    expect(dir.exits[0]!.country).toBe('fr');
    expect(dir.exits[0]!.edgeCertSha256).toBe('ab'.repeat(32));
  });

  it('rejects the golden if the signed edge pin is tampered', () => {
    const tampered = GOLDEN.replace('ab'.repeat(32), 'cd'.repeat(32));
    expect(() => verifyMultihopDirectory(tampered, [SERVER_PIN], [ROOT_PIN])).toThrow();
  });
});

/**
 * Cross-impl golden for the additive `exit_mlkem768_pubkey` field, minted by
 * warren-discovery-core (`print_pq_descriptor_golden_for_ts_crossimpl`,
 * root=key(1), op=key(2), server=key(3), one fr node whose exit descriptor is
 * PQ-signed over the deterministic 1184-byte ML-KEM key). The TS verifier
 * accepting these exact Rust bytes proves the Rust<->TS BYTE match of the key
 * in its frozen-last canonical-preimage position AND that the PQ-context exit
 * signature vouches the node. Regenerate with
 * `cargo test -p warren-discovery-core print_pq_descriptor_golden_for_ts_crossimpl -- --ignored --nocapture`.
 */
describe('multi-hop directory PQ descriptor (warren-discovery-core minted, cross-impl)', () => {
  const GOLDEN =
    '{"version":2,"nodes":[{"relay":{"relay_id":"01010101010101010101010101010101","relay_ed25519_pubkey":"0202020202020202020202020202020202020202020202020202020202020202","endpoint":"198.51.100.1:443","signature":"4db9c1aa6a43fde42660a3a4985f050099620a4df7d8cc4f215ed7e700866e52f835f423780a658117e89e0b215d3a96c85ae104be2a2cb9102297f7c187a500"},"exit":{"exit_id":"01010101010101010101010101010101","exit_ed25519_pubkey":"0202020202020202020202020202020202020202020202020202020202020202","exit_x25519_multihop_pubkey":"0303030303030303030303030303030303030303030303030303030303030303","endpoint":"198.51.100.1:443","signature":"9060da175a5d8ed17231ddc1ea868448a1d3304c9910ceaebdccb74c0a0255362c729cfcf61c60cb3d3325545fbd2224b400bdb233db2ff026eeb29d5a59e607","exit_mlkem768_pubkey":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"},"country":"fr","city":"City","asn":24940,"weight":100,"attestation_hex":"b778714f72403c192438f195f6d39cce55acd9e4698da279b1e7b9fa4a1e754385bf462571575bf471c16e7d312d494f34c214b6974adf8eb0311be04c536800"}],"generation":7,"signed_at":1000,"expires_at":22600,"operational_pubkey_hex":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394","operational_cert_hex":"fc98890d66d17ff65b7006182b9ad3d499bed1f0f64b9d003e1e6c8e241ac24d8acf9cc13724132f6c230b67583b315538b62b15d72f9bb5b7bd1c8a85c13b06","server_pubkey_hex":"ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1","signature_hex":"fb39a494cbf37036daf0a983715d538aa732180cb4e6304f556db3c6aff3496b12477f2c47a1bba8b3d5b25aa161cb0ed33597058208586ba6e36daadf4c500c"}';
  const SERVER_PIN = 'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1';
  const ROOT_PIN = '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c';

  it('verifies the Rust-minted PQ golden and surfaces the signed ML-KEM key', () => {
    const dir = verifyMultihopDirectory(GOLDEN, [SERVER_PIN], [ROOT_PIN]);
    expect(dir.dropped).toBe(0);
    expect(dir.exits).toHaveLength(1);
    const ekHex = Array.from({ length: 1184 }, (_, i) =>
      (i % 251).toString(16).padStart(2, '0'),
    ).join('');
    expect(dir.exits[0]!.exitMlkem768PubkeyHex).toBe(ekHex);
  });

  it('rejects the golden if the signed ML-KEM key is tampered', () => {
    const tampered = GOLDEN.replace(
      '"exit_mlkem768_pubkey":"000102',
      '"exit_mlkem768_pubkey":"010102',
    );
    expect(tampered).not.toBe(GOLDEN);
    expect(() => verifyMultihopDirectory(tampered, [SERVER_PIN], [ROOT_PIN])).toThrow();
  });
});

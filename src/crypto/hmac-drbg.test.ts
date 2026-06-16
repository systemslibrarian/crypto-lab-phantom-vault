import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  hmacDrbgGenerate,
  hmacDrbgInstantiate,
  hmacDrbgUpdate,
  snapshotState,
} from './hmac-drbg';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Official NIST CAVP known-answer test for HMAC_DRBG / SHA-256, the
 * [PredictionResistance = False], no-reseed profile (drbgvectors_pr_false),
 * COUNT 0. Vector mirrored from the `hmac-drbg` npm fixture used by `elliptic`,
 * which is taken verbatim from NIST's DRBGVS test data.
 *
 * Procedure for this profile: Instantiate, Generate (discard), Generate again;
 * the second Generate output is the known answer. EntropyInputLen 256,
 * NonceLen 128, PersonalizationStringLen 0, AdditionalInputLen 0,
 * ReturnedBitsLen 1024 (= 128 bytes).
 *
 * If this test fails, the DRBG does NOT conform to SP 800-90A Rev.1 §10.1.2 —
 * the spec citations in the source would be a lie. This is the load-bearing
 * correctness proof for the whole project.
 */
test('HMAC-DRBG matches the NIST SP 800-90A SHA-256 known-answer vector', async () => {
  const entropy = hexToBytes('ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488');
  const nonce = hexToBytes('659ba96c601dc69fc902940805ec0ca8');
  const personalization = new Uint8Array(0);
  const expected =
    'e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89' +
    'd54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1' +
    '07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668' +
    '961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8';

  const { state } = await hmacDrbgInstantiate(entropy, nonce, personalization);

  // First Generate call (output discarded per the test profile).
  const first = await hmacDrbgGenerate(state, expected.length / 2);
  // Second Generate call — its output is the known answer.
  const second = await hmacDrbgGenerate(first.state, expected.length / 2);

  assert.equal(toHex(second.bytes), expected);
});

test('Instantiate is deterministic and advances state off the all-zero seed', async () => {
  const entropy = new Uint8Array(32).fill(0xab);
  const nonce = new Uint8Array(16).fill(0xcd);
  const pers = new Uint8Array(0);

  const a = await hmacDrbgInstantiate(entropy, nonce, pers);
  const b = await hmacDrbgInstantiate(entropy, nonce, pers);

  assert.deepEqual(snapshotState(a.state), snapshotState(b.state));
  assert.equal(a.state.reseedCounter, 1);
  // K starts as 32 zero bytes and MUST be replaced by the first Update.
  assert.notEqual(a.snapshot.K, '00'.repeat(32));
  assert.equal(a.snapshot.K.length, 64);
  assert.equal(a.snapshot.V.length, 64);
});

test('Generate advances the reseed counter and changes K/V each call', async () => {
  const entropy = new Uint8Array(32).fill(0x11);
  const nonce = new Uint8Array(16).fill(0x22);
  const { state } = await hmacDrbgInstantiate(entropy, nonce, new Uint8Array(0));

  const g1 = await hmacDrbgGenerate(state, 32);
  const g2 = await hmacDrbgGenerate(g1.state, 32);

  assert.equal(g1.state.reseedCounter, 2);
  assert.equal(g2.state.reseedCounter, 3);
  assert.notDeepEqual(g1.snapshot, g2.snapshot);
  // Same instantiation, same request size, but successive blocks differ.
  assert.notEqual(toHex(g1.bytes), toHex(g2.bytes));
});

test('Generate rejects a non-positive request', async () => {
  const { state } = await hmacDrbgInstantiate(
    new Uint8Array(32),
    new Uint8Array(16),
    new Uint8Array(0),
  );
  await assert.rejects(() => hmacDrbgGenerate(state, 0));
});

test('Update with provided data takes the two-pass branch (differs from no-data)', async () => {
  const K = new Uint8Array(32).fill(0x01);
  const V = new Uint8Array(32).fill(0x02);

  const withData = await hmacDrbgUpdate(new Uint8Array([0xde, 0xad]), K, V);
  const withoutData = await hmacDrbgUpdate(null, K, V);

  assert.notEqual(toHex(withData.K), toHex(withoutData.K));
  assert.notEqual(toHex(withData.V), toHex(withoutData.V));
});

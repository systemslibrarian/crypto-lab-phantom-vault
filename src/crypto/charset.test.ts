import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildCharset,
  chiSquareUniformity,
  estimateEntropyBits,
  estimatePassphraseEntropyBits,
  hasRequiredCharacterClasses,
  mapBytesToPassword,
} from './charset';
import type { CharsetConfig } from '../types/vault';

const ALL: CharsetConfig = { lowercase: true, uppercase: true, digits: true, symbols: true };

test('buildCharset concatenates selected classes and de-duplicates', () => {
  const set = buildCharset(ALL);
  assert.ok(set.includes('a') && set.includes('Z') && set.includes('9') && set.includes('!'));
  // No character appears twice.
  assert.equal(new Set(set).size, set.length);
});

test('buildCharset throws when no class is selected', () => {
  assert.throws(() =>
    buildCharset({ lowercase: false, uppercase: false, digits: false, symbols: false }),
  );
});

test('mapBytesToPassword only ever emits characters from the charset', async () => {
  const charset = buildCharset(ALL);
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i += 1) bytes[i] = i;
  const { password } = await mapBytesToPassword(bytes, charset, 50, async () => bytes);
  for (const ch of password) {
    assert.ok(charset.includes(ch), `unexpected char: ${ch}`);
  }
});

test('rejection sampling rejects exactly the biased tail (deterministic vector)', async () => {
  // charset length 3 -> threshold = floor(256/3)*3 = 255, so only byte 255 is rejected.
  const charset = 'abc';
  const initial = new Uint8Array([0, 1, 2, 3, 255]); // 'a','b','c','a', then 255 rejected
  const { password, rejectionCount } = await mapBytesToPassword(
    initial,
    charset,
    5,
    async () => new Uint8Array([4]), // 4 % 3 = 1 -> 'b'
  );
  assert.equal(password, 'abcab');
  assert.equal(rejectionCount, 1);
});

test('mapped output is statistically uniform (chi-square, no modulo bias)', async () => {
  const charset = buildCharset(ALL); // length 89
  const SAMPLE = 60_000;

  const draw = (n: number): Uint8Array => {
    const buf = new Uint8Array(n);
    // crypto.getRandomValues caps at 65536 bytes per call.
    for (let off = 0; off < n; off += 65536) {
      crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, n)));
    }
    return buf;
  };

  const { password } = await mapBytesToPassword(draw(SAMPLE * 2), charset, SAMPLE, async () =>
    draw(SAMPLE),
  );
  const chi = chiSquareUniformity(password, charset);

  // Wilson-Hilferty upper-tail critical value, df = 88, alpha = 1e-5 (~157).
  // A correct uniform mapping sits near df (=88); biased mapping blows past this.
  // The huge margin makes false failures astronomically unlikely.
  const df = charset.length - 1;
  const z = 4.2649; // standard-normal quantile for alpha = 1e-5
  const critical = df * (1 - 2 / (9 * df) + z * Math.sqrt(2 / (9 * df))) ** 3;
  assert.ok(chi < critical, `chi-square ${chi.toFixed(1)} exceeded critical ${critical.toFixed(1)}`);
});

test('NEGATIVE CONTROL: naive byte % N mapping IS detectably biased', async () => {
  // This is the failure mode rejection sampling exists to prevent. If this test
  // ever "passed" (low chi-square), the uniformity test above would be vacuous.
  // 256 is not a multiple of 89, so `byte % 89` over-weights the low characters,
  // and chi-square explodes (~1300 for 100k samples) far past any critical value.
  const charset = buildCharset(ALL); // length 89
  const SAMPLE = 100_000;

  const buf = new Uint8Array(SAMPLE);
  for (let off = 0; off < SAMPLE; off += 65536) {
    crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, SAMPLE)));
  }

  let biased = '';
  for (const byte of buf) {
    biased += charset[byte % charset.length]; // NO rejection — deliberately wrong
  }

  const chi = chiSquareUniformity(biased, charset);
  const df = charset.length - 1;
  const z = 4.2649; // alpha = 1e-5
  const critical = df * (1 - 2 / (9 * df) + z * Math.sqrt(2 / (9 * df))) ** 3;
  assert.ok(
    chi > critical,
    `expected biased mapping to exceed critical ${critical.toFixed(1)}, got chi-square ${chi.toFixed(1)}`,
  );
});

test('estimateEntropyBits uses length x log2(size) and never overflows', () => {
  assert.ok(Math.abs(estimateEntropyBits(89, 20) - 20 * Math.log2(89)) < 1e-9);
  // The old log2(size ** length) form overflows to Infinity here; this must not.
  const big = estimateEntropyBits(89, 5000);
  assert.ok(Number.isFinite(big));
  assert.ok(Math.abs(big - 5000 * Math.log2(89)) < 1e-6);
  // Degenerate inputs are clamped to 0.
  assert.equal(estimateEntropyBits(1, 10), 0);
  assert.equal(estimateEntropyBits(89, 0), 0);
});

test('estimatePassphraseEntropyBits reflects pool size and grows with classes', () => {
  assert.equal(estimatePassphraseEntropyBits(''), 0);
  assert.ok(Math.abs(estimatePassphraseEntropyBits('aaaa') - 4 * Math.log2(26)) < 1e-9);
  const lower = estimatePassphraseEntropyBits('abcdefgh');
  const mixed = estimatePassphraseEntropyBits('abcdEF12');
  assert.ok(mixed > lower, 'adding character classes must raise the upper-bound estimate');
});

test('hasRequiredCharacterClasses enforces every enabled class', () => {
  assert.equal(
    hasRequiredCharacterClasses('abc123', {
      lowercase: true,
      uppercase: false,
      digits: true,
      symbols: false,
    }),
    true,
  );
  // digits required but absent
  assert.equal(
    hasRequiredCharacterClasses('abcdef', {
      lowercase: true,
      uppercase: false,
      digits: true,
      symbols: false,
    }),
    false,
  );
  // symbols required but absent
  assert.equal(
    hasRequiredCharacterClasses('Abc123', {
      lowercase: true,
      uppercase: true,
      digits: true,
      symbols: true,
    }),
    false,
  );
});

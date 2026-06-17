import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deriveSeeds } from './pbkdf2';
import type { CharsetConfig, VaultInputs } from '../types/vault';

const CHARSET: CharsetConfig = { lowercase: true, uppercase: true, digits: true, symbols: true };

function inputs(overrides: Partial<VaultInputs> = {}): VaultInputs {
  return {
    masterPassphrase: 'pass',
    service: 'a',
    username: 'b',
    version: 1,
    length: 20,
    charset: CHARSET,
    ...overrides,
  };
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

test('deriveSeeds is deterministic for identical context', async () => {
  const a = await deriveSeeds(inputs());
  const b = await deriveSeeds(inputs());
  assert.equal(hex(a), hex(b));
  assert.equal(a.length, 32);
});

/**
 * Regression test for a context-collision / delimiter-injection bug.
 *
 * The salt was built as `${service}:${username}:${version}`. Because the
 * delimiter ":" can legally appear inside a service or username, two DIFFERENT
 * (service, username) pairs could serialize to the SAME salt string, e.g.
 *   service="a",  username="b:c"  -> "a:b:c:1"
 *   service="a:b", username="c"   -> "a:b:c:1"
 * yielding identical passwords across distinct accounts — the exact "context
 * collision" failure mode the README warns about. The fix uses a NUL ("\0")
 * delimiter, which cannot occur in normal input. These seeds MUST differ.
 */
test('deriveSeeds resists delimiter-collision between distinct contexts', async () => {
  const left = await deriveSeeds(inputs({ service: 'a', username: 'b:c' }));
  const right = await deriveSeeds(inputs({ service: 'a:b', username: 'c' }));
  assert.notEqual(hex(left), hex(right), 'colliding contexts must not share a seed');
});

test('deriveSeeds separates service, username, and version independently', async () => {
  const base = hex(await deriveSeeds(inputs()));
  assert.notEqual(base, hex(await deriveSeeds(inputs({ service: 'other' }))));
  assert.notEqual(base, hex(await deriveSeeds(inputs({ username: 'other' }))));
  assert.notEqual(base, hex(await deriveSeeds(inputs({ version: 2 }))));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { derivePassword } from './pipeline';
import type { CharsetConfig, VaultInputs } from '../types/vault';

const CHARSET: CharsetConfig = { lowercase: true, uppercase: true, digits: true, symbols: true };

function inputs(overrides: Partial<VaultInputs> = {}): VaultInputs {
  return {
    masterPassphrase: 'correct horse battery staple',
    service: 'github.com',
    username: 'octocat@example.com',
    version: 1,
    length: 20,
    charset: CHARSET,
    ...overrides,
  };
}

const noop = (): void => {};

// These derivations each run 600k PBKDF2 iterations, so derive once per distinct
// input and assert relationships over the cached results.
test('determinism: identical inputs reproduce the identical password', async () => {
  const a = await derivePassword(inputs(), noop);
  const b = await derivePassword(inputs(), noop);
  assert.equal(a.password, b.password);
  assert.equal(a.password.length, 20);
});

test('rotation: bumping the version yields a different password, old version still reproducible', async () => {
  const v1 = await derivePassword(inputs({ version: 1 }), noop);
  const v2 = await derivePassword(inputs({ version: 2 }), noop);
  const v1Again = await derivePassword(inputs({ version: 1 }), noop);

  assert.notEqual(v1.password, v2.password, 'a new version must produce a new password');
  assert.equal(v1.password, v1Again.password, 'an old version must remain reproducible');
});

test('context separation: changing service or username changes the output', async () => {
  const base = await derivePassword(inputs({ service: 'github.com' }), noop);
  const otherService = await derivePassword(inputs({ service: 'gitlab.com' }), noop);
  const otherUser = await derivePassword(inputs({ username: 'someone-else@example.com' }), noop);

  assert.notEqual(base.password, otherService.password);
  assert.notEqual(base.password, otherUser.password);
});

test('output honors length and required character classes', async () => {
  const result = await derivePassword(inputs({ length: 32 }), noop);
  assert.equal(result.password.length, 32);
  assert.match(result.password, /[a-z]/);
  assert.match(result.password, /[A-Z]/);
  assert.match(result.password, /[0-9]/);
  assert.match(result.password, /[^a-zA-Z0-9]/);
});

test('progress callback walks the full pipeline to completion', async () => {
  const steps = new Set<string>();
  await derivePassword(inputs(), (step) => steps.add(step));
  for (const expected of ['stretching', 'instantiating', 'generating', 'mapping', 'complete']) {
    assert.ok(steps.has(expected), `missing pipeline step: ${expected}`);
  }
});

test('metadata reports the PBKDF2 work factor and DRBG byte accounting', async () => {
  const result = await derivePassword(inputs(), noop);
  assert.equal(result.pbkdf2Iterations, 600_000);
  assert.ok(result.bytesGenerated >= result.password.length);
  assert.ok(result.drbgStates.length >= 2); // instantiate + at least one generate
  assert.ok(result.meta.attempts >= 1);
});

test('validation: empty passphrase and version < 1 are rejected', async () => {
  await assert.rejects(() => derivePassword(inputs({ masterPassphrase: '   ' }), noop));
  await assert.rejects(() => derivePassword(inputs({ version: 0 }), noop));
});

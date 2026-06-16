import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// End-to-end: drive the real derivation pipeline into the real UI controllers,
// exactly as main.ts's runDerivation() does, but headless. Proves the pieces are
// wired together correctly — a class of bug the per-module unit tests can't see.

const dom = new JSDOM('<!doctype html><html><body></body></html>');
(globalThis as unknown as { document: Document }).document = dom.window.document;
(globalThis as unknown as { window: unknown }).window = dom.window;

const { createForm } = await import('./ui/form');
const { createOutput } = await import('./ui/output');
const { createStateDisplay } = await import('./ui/state-display');
const { derivePassword } = await import('./derive/pipeline');
const { buildCharset, estimatePassphraseEntropyBits } = await import('./crypto/charset');

test('form inputs flow through the pipeline and populate the output + state panels', async () => {
  const form = createForm();
  const output = createOutput();
  const stateDisplay = createStateDisplay();
  dom.window.document.body.append(form.element, output.element, stateDisplay.element);

  // Populate the form the way a user would.
  form.element.querySelector<HTMLInputElement>('#master-passphrase')!.value =
    'correct horse battery staple';
  form.element.querySelector<HTMLInputElement>('#service')!.value = 'github.com';
  form.element.querySelector<HTMLInputElement>('#username')!.value = 'octocat@example.com';
  form.element.querySelector<HTMLInputElement>('#length')!.value = '24';

  const inputs = form.getInputs();
  const result = await derivePassword(inputs, () => {});

  const charset = buildCharset(inputs.charset);
  const passEntropy = estimatePassphraseEntropyBits(inputs.masterPassphrase);
  output.setOutput(result.password, charset.length, inputs.length, passEntropy);
  stateDisplay.setStates(result.drbgStates, result.bytesGenerated, result.rejectionCount);

  // The output panel holds exactly the derived password, at the requested length.
  const field = output.element.querySelector<HTMLInputElement>('#password-value');
  assert.equal(field?.value, result.password);
  assert.equal(result.password.length, 24);

  // Effective entropy is the min of passphrase and format ceiling, and a real
  // number was rendered (not "n/a").
  assert.match(
    output.element.querySelector('#entropy-effective')?.textContent ?? '',
    /^\d+\.\d bits$/,
  );

  // The DRBG state panel reflects the snapshots produced by this run.
  assert.equal(
    stateDisplay.element.querySelectorAll('.state-item').length,
    result.drbgStates.length,
  );
});

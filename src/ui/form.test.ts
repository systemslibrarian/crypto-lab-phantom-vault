import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
(globalThis as unknown as { document: Document }).document = dom.window.document;
(globalThis as unknown as { window: unknown }).window = dom.window;
(globalThis as unknown as { Event: unknown }).Event = dom.window.Event;

const { createForm } = await import('./form');

test('getInputs reads defaults and trims service/username', () => {
  const form = createForm();
  const el = form.element;
  el.querySelector<HTMLInputElement>('#master-passphrase')!.value = 'hunter2';
  el.querySelector<HTMLInputElement>('#service')!.value = '  github.com  ';
  el.querySelector<HTMLInputElement>('#username')!.value = '  me@x.com ';

  const inputs = form.getInputs();
  assert.equal(inputs.masterPassphrase, 'hunter2');
  assert.equal(inputs.service, 'github.com');
  assert.equal(inputs.username, 'me@x.com');
  assert.equal(inputs.version, 1);
  assert.equal(inputs.length, 20);
  assert.deepEqual(inputs.charset, {
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
  });
});

test('the last remaining character class cannot be unchecked', () => {
  const form = createForm();
  const el = form.element;
  const boxes = {
    lower: el.querySelector<HTMLInputElement>('#charset-lower')!,
    upper: el.querySelector<HTMLInputElement>('#charset-upper')!,
    digits: el.querySelector<HTMLInputElement>('#charset-digits')!,
    symbols: el.querySelector<HTMLInputElement>('#charset-symbols')!,
  };

  const uncheck = (box: HTMLInputElement): void => {
    box.checked = false;
    box.dispatchEvent(new dom.window.Event('change'));
  };

  uncheck(boxes.upper);
  uncheck(boxes.digits);
  uncheck(boxes.symbols);
  // Try to remove the final class — the handler must force it back on.
  uncheck(boxes.lower);

  assert.equal(boxes.lower.checked, true, 'last class must stay enabled');
  assert.equal(boxes.lower.disabled, true, 'last class is disabled so it cannot be removed');
  assert.deepEqual(form.getInputs().charset, {
    lowercase: true,
    uppercase: false,
    digits: false,
    symbols: false,
  });
});

test('clearSensitive wipes only the passphrase; clearAllInputs resets everything', () => {
  const form = createForm();
  const el = form.element;
  const pass = el.querySelector<HTMLInputElement>('#master-passphrase')!;
  const service = el.querySelector<HTMLInputElement>('#service')!;
  pass.value = 'topsecret';
  service.value = 'gitlab.com';

  form.clearSensitive();
  assert.equal(pass.value, '');
  assert.equal(service.value, 'gitlab.com', 'non-secret context is preserved');

  form.clearAllInputs();
  assert.equal(service.value, '');
  assert.equal(el.querySelector<HTMLInputElement>('#version')!.value, '1');
});

/**
 * Regression — the live entropy panel outlived the passphrase it described.
 *
 * main.ts calls clearSensitive() at the end of every successful derivation.
 * Assigning to `input.value` fires no `input` event, so the onInputChange
 * listeners never learned the field had emptied: the entropy-cap panel kept the
 * cleared passphrase's dashed line, bit count and "Capped: … caps effective
 * strength at N" verdict beside a blank field, on 100% of derivations.
 */
test('clearSensitive notifies input listeners, so nothing keeps describing the wiped passphrase', () => {
  const form = createForm();
  const pass = form.element.querySelector<HTMLInputElement>('#master-passphrase')!;

  const seen: string[] = [];
  form.onInputChange(() => {
    seen.push(form.getInputs().masterPassphrase);
  });

  pass.value = 'topsecret';
  pass.dispatchEvent(new dom.window.Event('input'));
  assert.deepEqual(seen, ['topsecret'], 'typing notifies, as it always did');

  form.clearSensitive();
  assert.equal(seen.length, 2, 'clearing notifies too');
  // The claim: whatever a listener renders after this call describes an EMPTY
  // passphrase, because that is the state the page is now in.
  assert.equal(seen[1], '', 'the listener was told the field is now empty');
});

test('passphrase visibility toggle flips the input type', () => {
  const form = createForm();
  const el = form.element;
  const pass = el.querySelector<HTMLInputElement>('#master-passphrase')!;
  const toggle = el.querySelector<HTMLButtonElement>('#toggle-passphrase')!;

  assert.equal(pass.type, 'password');
  toggle.dispatchEvent(new dom.window.Event('click'));
  assert.equal(pass.type, 'text');
  toggle.dispatchEvent(new dom.window.Event('click'));
  assert.equal(pass.type, 'password');
});
